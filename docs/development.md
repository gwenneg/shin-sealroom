# Development

## Layout

| Path | Holds |
|---|---|
| `cmd/sealroom/` | The entry point, nothing else |
| `internal/cli/` | Command-line parsing and dispatch, and the exit codes; no launcher logic |
| `images/proxy/` | The proxy image: iron-proxy built from a pinned, verified commit, and its smoke test |
| `internal/sandbox/` | Every restriction of both containers, as Podman and Docker arguments, pinned by `TestArgsSeal`. It starts nothing |

Everything lives under `internal/` so no other module can import it: Sealroom is a tool, not a library.

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
```

CI runs the same commands on every pull request. The smoke test mounts files from `TMPDIR`, which must be shared with the container runtime: under the home directory with Colima. Set `CONTAINER_RUNTIME=podman` to run it with Podman.

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

Dependabot keeps the base images current. The iron-proxy commit and the curl image of the smoke test are moved by hand.
