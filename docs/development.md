# Development

## Layout

| Path | Holds |
|---|---|
| `cmd/sealroom/` | The entry point, nothing else |
| `internal/cli/` | Command-line parsing and dispatch, and the exit codes; no launcher logic |
| `internal/launcher/` | A sealed session: the run directory, the clone, the networks, the proxy, the agent on the user's terminal, and the cleanup |
| `internal/publish/` | After the user's yes: where to push, the push, the fork, and the pull request, with the user's GitHub login |
| `internal/credentials/` | The Claude credential: from the environment, or from the keychain that `sealroom login` saves it in |
| `internal/declare/` | What a plugin declares in `sealroom.json`, read as untrusted input and validated |
| `internal/review/` | Reads the session's output as untrusted input, applies it to the host's clone, and shows it, sanitised |
| `internal/container/` | Finds Podman or Docker and runs its commands, with arguments from `internal/sandbox` only |
| `images/agent/` | The agent image: Claude Code and the GitHub CLI, pinned by checksum, the `git` and `gh` stand-ins, the session script, and its smoke test |
| `images/proxy/` | The proxy image: the `sealroom` binary in its proxy role, built from this repository, and its smoke test |
| `internal/egress/` | Sealroom's own proxy, specified in [the proxy](proxy.md), run as `sealroom proxy` in its container |
| `internal/proxy/` | The proxy's rules for a run, its environment file and the run's CA, pinned by `TestConfigRules` |
| `internal/e2e/` | End-to-end tests against a real container runtime and the real services, skipped unless `SEALROOM_E2E=1` |
| `internal/sandbox/` | Every restriction of both containers, as Podman and Docker arguments, pinned by `TestArgsSeal`. It starts nothing |

Everything lives under `internal/` so no other module can import it: Sealroom is a tool, not a library.

## Running a session locally

Build both images with the `:dev` tags above, with `podman build` or `docker build`, then:

```
go run ./cmd/sealroom login   # once: a token from claude setup-token, or an API key
go run ./cmd/sealroom run <plugin-dir> --repo <owner/repo> --prompt '/<plugin>:<command>'
```

The run directory is under the user's cache directory, printed at the start. `SEALROOM_RUNTIME` picks `podman` or `docker`; Podman comes first when both are installed. After the session, the launcher applies its changes to a branch of the run's clone, shows them, and asks before pushing and opening the pull request. On no, the branch stays in the run's `src` directory until `go run ./cmd/sealroom clean` removes it, 7 days later, or right away with `--all`.

## Published images

The `Images` workflow builds both images for amd64 and arm64 on every pull request that changes them, and on `main`. Publishing them is a separate decision, off until the repository variable `PUBLISH_IMAGES` is set to `true`. Then, on `main`, the workflow pushes them to GitHub's container registry, as `ghcr.io/gwenneg/sealroom-proxy` and `ghcr.io/gwenneg/sealroom-agent`, tagged with the full commit SHA and `main`, and attests their build provenance. To check that an image was built by this repository's workflow:

```
gh attestation verify oci://ghcr.io/gwenneg/sealroom-agent:main --owner gwenneg
```

A package that a workflow creates inherits the visibility of the repository, which is public. To publish privately first, create both packages as private before setting the variable:

1. `gh auth refresh -s write:packages`, then log in to the registry: `gh auth token | docker login ghcr.io -u <user> --password-stdin`.
2. Push any small image to each name, for example a build of `images/proxy` tagged `ghcr.io/gwenneg/sealroom-proxy:placeholder`, and the same for `sealroom-agent`. Packages pushed this way start private.
3. In each package's settings on GitHub, connect it to this repository and give the repository's Actions write access.
4. Set `PUBLISH_IMAGES` to `true` in the repository's Actions variables.

The workflow's pushes then keep the packages private, until each is made public in its settings. The launcher still uses the locally built `:dev` images: using the published ones, pinned by digest and verified, comes next.

## Checking on Fedora

SELinux cannot be checked in CI, since GitHub's Linux runners do not enforce it. On Fedora or RHEL, with SELinux enforcing (`getenforce` prints `Enforcing`) and rootless Podman:

```
podman build -t sealroom-proxy:dev images/proxy
podman build -t sealroom-agent:dev images/agent
podman pull "$(sed -n 's/^curl_image=//p' images/proxy/smoke-test.sh)"
CONTAINER_RUNTIME=podman SEALROOM_E2E=1 go test -count=1 -v ./internal/e2e/
```

Both end-to-end tests must pass. A denial shows as a permission error on a mounted file, and in `sudo ausearch -m avc -ts recent`.

Vertex with real credentials cannot be checked in CI. With access to Claude on Vertex, and Claude Code's own Vertex variables set (`CLAUDE_CODE_USE_VERTEX=1`, `ANTHROPIC_VERTEX_PROJECT_ID`, `CLOUD_ML_REGION`) after `gcloud auth application-default login`, a session must answer, and the proxy's log (`podman logs` or `docker logs` of the `-proxy` container while the session runs) must show `"injected"` on the model's requests. A refusal from Google, rather than from the proxy, can mean that the organization only accepts requests from its own network or devices.

The keychain on Linux, the Secret Service, cannot be checked in CI either. In a desktop session with GNOME Keyring or KWallet, `go run ./cmd/sealroom login` must save the credential (`secret-tool search service sealroom` shows it), a run must find it, and `go run ./cmd/sealroom logout` must remove it.

## Go version

`go.mod` pins the Go version, the latest stable release when it was last updated. A newer or older local Go downloads the pinned version automatically, since `GOTOOLCHAIN` defaults to `auto`, and CI installs it from `go.mod`.

## Commands

```
go test -race ./...                                    # tests, the fuzz seeds included; -short skips the 30-second waits
go test -run='^$' -fuzz=FuzzCheckRequest -fuzztime=5m ./internal/egress   # fuzz the proxy's request checks
go test -run='^$' -fuzz=FuzzParDifferential -fuzztime=5m ./internal/egress   # the proxy against a strict HTTP/1.1 parser
go vet ./... && GOOS=linux go vet ./... && GOOS=darwin go vet ./...   # static checks, both platforms
gofmt -l .                                             # must print nothing
CGO_ENABLED=0 go build -trimpath -o sealroom ./cmd/sealroom
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...  # known vulnerabilities
docker build -t sealroom-proxy:dev -f images/proxy/Dockerfile .   # the proxy image, from the repository's root
TMPDIR=$HOME/.cache images/proxy/smoke-test.sh sealroom-proxy:dev   # starts it sealed, checks it refuses by default
docker build -t sealroom-agent:dev images/agent        # the agent image
TMPDIR=$HOME/.cache images/agent/smoke-test.sh sealroom-agent:dev   # its tools, the stand-ins and the session, with no network
SEALROOM_E2E=1 go test -count=1 ./internal/e2e/       # a run's rules, a whole session and a hostile plugin, against the real services; needs both :dev images
```

CI runs the same commands on every pull request. The smoke tests mount files from `TMPDIR`, which the container runtime must be able to mount: under the home directory when the runtime runs in a virtual machine that shares only the home directory, as Colima does on macOS. Set `CONTAINER_RUNTIME=podman` to run the smoke tests and the end-to-end tests with Podman, and use `podman build` for the images.

## Moving to a new Claude Code or GitHub CLI release

Both are downloaded at a pinned version and checked against a checksum in `images/agent/Dockerfile`, for amd64 and arm64.

- **Claude Code** follows the stable channel: `curl -fsS https://downloads.claude.ai/claude-code-releases/stable` gives the version, and the `linux-x64` and `linux-arm64` checksums are in that version's `manifest.json` in the same place.
- **The GitHub CLI**: the latest release of `cli/cli`, with the checksums of the two `linux` archives from the release's checksums file.

Build the image and run its smoke test, which checks the versions.

## What Dependabot does not move

Dependabot keeps the base images current. Claude Code, the GitHub CLI, and the curl image of the smoke tests are moved by hand, as described above.
