# The proxy, the agent's only way out: Sealroom's own binary, in its proxy
# role, built from this repository's source alone. Build it from the
# repository's root: docker build -f images/proxy/Dockerfile .
FROM docker.io/library/golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd cmd
COPY internal internal
# Modules are checked against go.sum, and the toolchain is the image's own.
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
RUN go build -trimpath -ldflags="-s -w" -o /out/sealroom ./cmd/sealroom

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/sealroom /sealroom
USER 65532:65532
ENTRYPOINT ["/sealroom"]
