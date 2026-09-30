# Development

## Layout

| Path | Holds |
|---|---|
| `cmd/sealroom/` | The entry point, nothing else |
| `internal/cli/` | Command-line parsing and dispatch, and the exit codes; no launcher logic |
| `internal/launcher/` | A sealed session: the run directory, the clone, the networks, the proxy, the agent on the user's terminal, and the cleanup |
| `internal/container/` | Finds Podman or Docker and runs its commands, with arguments from `internal/sandbox` only |
| `images/agent/` | The agent image: Claude Code and the GitHub CLI, pinned by checksum, the `git` and `gh` stand-ins, the session script, and its smoke test |
| `images/proxy/` | The proxy image: iron-proxy built from a pinned, verified commit, and its smoke test |
| `internal/proxy/` | The proxy's rules for a run, its environment file and the run's CA, pinned by `TestConfigRules` |
| `internal/e2e/` | End-to-end tests against a real container runtime and the real services, skipped unless `SEALROOM_E2E=1` |
| `internal/sandbox/` | Every restriction of both containers, as Podman and Docker arguments, pinned by `TestArgsSeal`. It starts nothing |

Everything lives under `internal/` so no other module can import it: Sealroom is a tool, not a library.

## Running a session locally

Build both images with the `:dev` tags above, with `podman build` or `docker build`, then:

```
export CLAUDE_CODE_OAUTH_TOKEN=...   # from claude setup-token, or ANTHROPIC_API_KEY
go run ./cmd/sealroom run <plugin-dir> --repo <owner/repo> --prompt '/<plugin>:<command>'
```

The run directory is under the user's cache directory, printed at the start. `SEALROOM_RUNTIME` picks `podman` or `docker`; Podman comes first when both are installed. The review and the push after the session are not built yet: the session's changes stay in the run's `out` directory.

## Go version

`go.mod` pins the Go version, the latest stable release when it was last updated. A newer or older local Go downloads the pinned version automatically, since `GOTOOLCHAIN` defaults to `auto`, and CI installs it from `go.mod`.

## Commands

```
go test -race ./...                                    # tests
go vet ./... && GOOS=linux go vet ./... && GOOS=darwin go vet ./...   # static checks, both platforms
gofmt -l .                                             # must print nothing
CGO_ENABLED=0 go build -trimpath -o sealroom ./cmd/sealroom
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...  # known vulnerabilities
docker build -t sealroom-proxy:dev images/proxy        # the proxy image
TMPDIR=$HOME/.cache images/proxy/smoke-test.sh sealroom-proxy:dev   # starts it sealed, checks it refuses by default
docker build -t sealroom-agent:dev images/agent        # the agent image
TMPDIR=$HOME/.cache images/agent/smoke-test.sh sealroom-agent:dev   # its tools, the stand-ins and the session, with no network
SEALROOM_E2E=1 go test -count=1 ./internal/e2e/       # a run's rules and a whole session, against the real services; needs both :dev images
```

CI runs the same commands on every pull request. The smoke tests mount files from `TMPDIR`, which the container runtime must be able to mount: under the home directory when the runtime runs in a virtual machine that shares only the home directory, as Colima does on macOS. Set `CONTAINER_RUNTIME=podman` to run the smoke tests and the end-to-end tests with Podman, and use `podman build` for the images.

## Moving to a new iron-proxy release

The proxy is never taken from iron-proxy's published image or binaries, which are not signed. To move to a new release:

1. Read the release notes and the changes since the pinned commit, looking for anything that affects what the proxy allows, refuses or logs.
2. Resolve the release tag to its commit, and check that GitHub reports the commit's signature as valid:

   ```
   sha=$(gh api repos/paradigmxyz/iron-proxy/commits/<tag> --jq .sha)
   gh api repos/paradigmxyz/iron-proxy/commits/$sha --jq '.commit.verification | "\(.verified) \(.reason)"'
   ```

3. Put the commit in `IRON_PROXY_COMMIT` in `images/proxy/Dockerfile`, with the tag in the comment above it, and bump the Go image if iron-proxy's `go.mod` needs a newer Go.
4. Build the image and run the smoke test.

## Moving to a new Claude Code or GitHub CLI release

Both are downloaded at a pinned version and checked against a checksum in `images/agent/Dockerfile`, for amd64 and arm64.

- **Claude Code** follows the stable channel: `curl -fsS https://downloads.claude.ai/claude-code-releases/stable` gives the version, and the `linux-x64` and `linux-arm64` checksums are in that version's `manifest.json` in the same place.
- **The GitHub CLI**: the latest release of `cli/cli`, with the checksums of the two `linux` archives from the release's checksums file.

Build the image and run its smoke test, which checks the versions.

## What Dependabot does not move

Dependabot keeps the base images current. The iron-proxy commit, Claude Code, the GitHub CLI, and the curl image of the proxy's smoke test are moved by hand, as described above.
