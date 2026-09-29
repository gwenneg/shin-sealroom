# The proxy, the agent's only way out: iron-proxy, built from source at a
# release commit whose signature was checked when it was pinned, never from
# its published image or binaries, which are not signed. See
# docs/development.md for how to move to a new release.
FROM docker.io/library/golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
# iron-proxy v0.52.0
ARG IRON_PROXY_COMMIT=8a0eb0beb6524f4a7739b799842a13159d8b739e
RUN git clone --quiet --filter=blob:none https://github.com/paradigmxyz/iron-proxy /src \
 && git -C /src checkout --quiet --detach "$IRON_PROXY_COMMIT" \
 && test "$(git -C /src rev-parse HEAD)" = "$IRON_PROXY_COMMIT"
WORKDIR /src
# Modules are checked against go.sum, and the toolchain is the image's own.
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
RUN go build -trimpath -ldflags="-s -w" -o /out/iron-proxy ./cmd/iron-proxy

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/iron-proxy /iron-proxy
USER 65532:65532
ENTRYPOINT ["/iron-proxy"]
