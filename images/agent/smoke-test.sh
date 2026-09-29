#!/usr/bin/env bash
# Runs the agent image with no network and the restrictions of
# internal/sandbox, and checks its tools, the stand-ins and the session
# script. Usage: smoke-test.sh IMAGE
set -euo pipefail
image=${1:?usage: smoke-test.sh IMAGE}
runtime=${CONTAINER_RUNTIME:-docker}
dir=$(mktemp -d "${TMPDIR:-/tmp}/sealroom-smoke.XXXXXX")
# On Linux, what the agent writes is owned by its uid, so cleanup may leave files behind.
trap 'rm -rf "$dir" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

want_claude=$(sed -n 's/^ARG CLAUDE_CODE_VERSION=//p' "$(dirname "$0")/Dockerfile")
want_gh=$(sed -n 's/^ARG GH_VERSION=//p' "$(dirname "$0")/Dockerfile")

# A repository with an origin, as the launcher's clone has.
git init -q --bare "$dir/origin.git"
git clone -q "$dir/origin.git" "$dir/seed" 2>/dev/null
git -C "$dir/seed" -c user.name=t -c user.email=t@t commit -q --allow-empty -m first
git -C "$dir/seed" push -q origin HEAD 2>/dev/null
git clone -q "$dir/origin.git" "$dir/src"
mkdir -p "$dir/out" "$dir/session-out" "$dir/fake" && chmod 777 "$dir/out" "$dir/session-out"
# A stand-in for Claude Code that edits a file, for the session test.
printf '#!/bin/sh\necho changed > file.txt\n' > "$dir/fake/claude" && chmod 755 "$dir/fake/claude"

sealed=(run --rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --tmpfs /tmp --tmpfs "/home/agent:uid=10001,gid=10001" --tmpfs "/work:uid=10001,gid=10001"
  --mount "type=bind,src=$dir/src,dst=/src,readonly")

# shellcheck disable=SC2016 # expanded inside the container
out=$($runtime "${sealed[@]}" --mount "type=bind,src=$dir/out,dst=/out" --entrypoint bash "$image" -c '
  echo "uid=$(id -u)"
  echo "claude=$(claude --version | cut -d" " -f1)"
  echo "gh=$(/usr/bin/gh --version | head -1 | cut -d" " -f3)"
  env | grep -iE "token|api_key|secret|password" && echo "credential=present" || echo "credential=none"
  cd /tmp && /usr/bin/git init -q r && cd r && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m x
  git switch -q -c feature && git -C /tmp/r push origin feature >/dev/null && echo "push=$(cat /out/push-branch)"
  gh pr create --repo attacker/elsewhere --title "The title" --body "The body" --base main >/dev/null
  echo "pr=$(cat /out/pr/title)|$(cat /out/pr/body)|$(cat /out/pr/base)|$(ls /out/pr | tr "\n" " ")"
  gh pr view >/dev/null 2>&1 && echo "view=ok" || echo "view=refused"
  echo "status=$(git status --short --branch | head -1)"
  touch /usr/bin/x 2>/dev/null && echo "root=writable" || echo "root=read-only"
')
echo "$out"
grep -qx 'uid=10001' <<<"$out" || fail "the agent does not run as uid 10001"
grep -qx "claude=$want_claude" <<<"$out" || fail "Claude Code is not $want_claude"
grep -qx "gh=$want_gh" <<<"$out" || fail "gh is not $want_gh"
grep -qx 'credential=none' <<<"$out" || fail "a credential variable is present"
grep -qx 'push=feature' <<<"$out" || fail "the push was not recorded"
grep -qx 'pr=The title|The body|main|base body title ' <<<"$out" || fail "the pull request was not recorded as expected, or the repository was"
grep -qx 'view=refused' <<<"$out" || fail "gh pr view did not say the pull request does not exist yet"
grep -q '^status=## feature' <<<"$out" || fail "other git commands do not reach the real git"
grep -qx 'root=read-only' <<<"$out" || fail "the root filesystem is writable"

# The session copies the repository, runs Claude Code, and turns what changed into a patch.
$runtime "${sealed[@]}" --mount "type=bind,src=$dir/session-out,dst=/out" \
  --mount "type=bind,src=$dir/fake/claude,dst=/usr/local/sbin/claude,readonly" "$image"
grep -q '^+changed$' "$dir/session-out/changes.patch" || fail "the session's changes are not in the patch"
[ -s "$dir/session-out/branch" ] || fail "the session did not record its branch"
[ ! -e "$dir/src/file.txt" ] || fail "the session wrote to the host's repository"
echo "agent image ok"
