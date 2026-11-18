# Multi-arch (`linux/amd64` + `linux/arm64`) Home Assistant OS Add-on Dockerfile (~9 MB distroless, zero shell).
# Home Assistant Supervisor passes `--build-arg BUILD_VERSION=<config.yaml version>` automatically on every install/update;
# referencing `BUILD_VERSION` before `git clone` invalidates Docker's layer cache whenever a new version ships.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH
RUN apk add --no-cache git
ARG BUILD_VERSION=1.0.5
RUN echo "Building EdgeFetch ${BUILD_VERSION}" && \
    git clone --depth 1 https://github.com/bartrumb/edgefetch.git /src && \
    cd /src && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -trimpath \
      -ldflags="-s -w -X github.com/bartrumb/edgefetch/internal/agent.Version=${BUILD_VERSION}" \
      -o /out/edgefetch ./cmd/edgefetch

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.title="EdgeFetch Cold-Standby Worker" \
      org.opencontainers.image.description="Outbound-only Go HTTP/2 worker for Cloudflare Hibernating WebSockets" \
      org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/edgefetch /edgefetch
ENV GOMEMLIMIT=128MiB
ENTRYPOINT ["/edgefetch", "--mode=agent"]
