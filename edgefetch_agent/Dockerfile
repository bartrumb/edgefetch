# Multi-arch (`linux/amd64` + `linux/arm64`) Home Assistant OS Add-on image (~9 MB distroless, zero shell).
# Built from repository root by `.github/workflows/addon-ghcr.yml`:
#   docker buildx build --platform linux/amd64 -f edgefetch_agent/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/edgefetch ./cmd/edgefetch

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.title="EdgeFetch Cold-Standby Worker" \
      org.opencontainers.image.description="Outbound-only Go HTTP/2 worker for Cloudflare Hibernating WebSockets" \
      org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/edgefetch /edgefetch
ENV GOMEMLIMIT=128MiB
ENTRYPOINT ["/edgefetch", "--mode=agent"]
