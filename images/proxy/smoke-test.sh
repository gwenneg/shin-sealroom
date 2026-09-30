#!/usr/bin/env bash
# Starts the proxy image with no capabilities and the minimal configuration,
# and checks that it listens and refuses a request. Usage: smoke-test.sh IMAGE
set -euo pipefail
image=${1:?usage: smoke-test.sh IMAGE}
runtime=${CONTAINER_RUNTIME:-docker}
curl_image=docker.io/curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
dir=$(mktemp -d "${TMPDIR:-/tmp}/sealroom-smoke.XXXXXX")
name=sealroom-smoke-$$
trap '$runtime rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=sealroom smoke test" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$dir/ca.key" -out "$dir/ca.crt" 2>/dev/null
chmod 644 "$dir/ca.key"
cp "$(dirname "$0")/testdata/proxy.yaml" "$dir/proxy.yaml"
$runtime run --detach --pull never --name "$name" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  --mount "type=bind,src=$dir/proxy.yaml,dst=/etc/sealroom/proxy.yaml,readonly" \
  --mount "type=bind,src=$dir/ca.crt,dst=/etc/sealroom/ca.crt,readonly" \
  --mount "type=bind,src=$dir/ca.key,dst=/etc/sealroom/ca.key,readonly" \
  "$image" -config /etc/sealroom/proxy.yaml >/dev/null
# The logs are read whole before searching: with pipefail, grep -q closing
# the pipe early would fail the pipeline even when the line is there.
logs=
for _ in $(seq 20); do
  logs=$($runtime logs "$name" 2>&1)
  grep -q 'https proxy starting' <<<"$logs" && break
  sleep 0.5
done
for listener in 'dns server starting' 'https proxy starting' 'http proxy starting'; do
  grep -q "$listener" <<<"$logs" || { echo "missing: $listener"; echo "$logs"; exit 1; }
done
# A request through the proxy, from inside its own network namespace, must be refused.
code=$($runtime run --rm --pull never --network "container:$name" \
  --mount "type=bind,src=$dir/ca.crt,dst=/ca.crt,readonly" \
  "$curl_image" -s -o /dev/null -w '%{http_code}' --cacert /ca.crt \
  --resolve example.com:443:127.0.0.1 https://example.com/ || true)
[ "$code" = 403 ] || { echo "a request was not refused: HTTP $code"; exit 1; }
echo "proxy image ok: listening, and refusing by default"
