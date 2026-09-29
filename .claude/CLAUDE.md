# Working in this repository

Sealroom runs untrusted plugins with the user's credentials within reach of a proxy. Every change is judged by whether it keeps the tool easy to trust. Read [the design](../docs/design.md) and [the threat model](../docs/threat-model.md) before changing anything.

## Building and testing

[docs/development.md](../docs/development.md) has the layout and the commands. Run all of them before pushing: CI runs the same ones, and a pull request goes up only when they pass locally.

## Rules the design must keep

- No credential ever enters the agent container, not even short-lived. The proxy adds credentials; the agent holds placeholders.
- The agent container has no route out except the proxy, no capabilities, a read-only root, and nothing from the host but the plugin and the repository read-only, the proxy's CA certificate, and the output directory.
- The container never pushes. The push and the pull request happen on the host, after the user's yes.
- Everything the agent container writes is untrusted input on the host: validated, size-limited, never executed, and never allowed to pick the target repository.
- Container restrictions live only in `internal/sandbox`, and `TestArgsSeal` pins them. Never weaken the test to make a change pass.
- The proxy's rules live only in `internal/proxy`, pinned by `TestConfigRules` and, against the real proxy and services, by `TestProxyRules`. Never weaken either to make a change pass.
- The proxy is built from a verified release commit, never taken from a published image or binary. [docs/development.md](../docs/development.md) has the steps to move to a new release.
- Every download in an image is pinned to a version and checked against a checksum written in the image's definition. [docs/development.md](../docs/development.md) has the steps to move Claude Code and the GitHub CLI.
- A change to what the proxy allows, or to the containers' restrictions, updates the design or the threat model in the same pull request.
- **Everything added is at its latest release**: languages, dependencies, GitHub Actions, tools, container images, Claude Code. Look the version up at the time of adding, never reuse one from memory or from the local toolchain. Actions and images are pinned by SHA or digest, with the version in a comment.
- A new dependency needs a reason in the pull request description.

## Supported platforms

Sealroom must work on macOS, where Docker and Podman run in a virtual machine that often shares only the home directory (Colima's default), so anything mounted into a container must live under it, and on Linux, Fedora with Podman first.

## Commits and pull requests

- **Every commit is signed.** Signing is on in the git config; never turn it off with `--no-gpg-sign` or `-c commit.gpgsign=false`. If signing fails, stop and report it. Before pushing, check every new commit shows `G`:

  ```
  git log --format='%h %G? %s' origin/main..HEAD
  ```

- **Nothing reaches `main` without a pull request.** Every push goes to a branch, and every branch gets a pull request.
- **Every branch starts from the latest remote `main`**, never from another branch and never from a stale local `main`:

  ```
  git fetch origin && git switch -c <branch> origin/main
  ```

  Before pushing an existing branch, rebase it on the latest `origin/main`. Pull requests are not stacked.
- **One commit per pull request.** Squash a branch's commits into one before pushing, unless told otherwise, and force-push with `--force-with-lease`.
- **The pull request title and description follow the latest change.** After any change, reread both and update them so they describe what the branch contains now.
- Messages follow Conventional Commits. History stays linear.
- Small pull requests, one step at a time. Wait for the maintainer's approval of a pull request before starting the next one.

## Writing Markdown

- One line per paragraph and per list item. No hard line breaks inside a sentence or paragraph.

## Keeping this file current

Every pull request that establishes something a future session needs, a command, a layout, a contract, a decision, updates this file in the same pull request.
