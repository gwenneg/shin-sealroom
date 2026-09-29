# Development

## Layout

| Path | Holds |
|---|---|
| `cmd/sealroom/` | The entry point, nothing else |
| `internal/cli/` | Command-line parsing and dispatch, and the exit codes; no launcher logic |

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
```

CI runs the same commands on every pull request.
