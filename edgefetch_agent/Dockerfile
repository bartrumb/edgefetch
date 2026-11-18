# Multi-arch (`linux/amd64` + `linux/arm64`) Home Assistant OS Add-on Dockerfile (~9 MB distroless, zero shell).
# Works both when Home Assistant Supervisor builds `/addons/edgefetch_agent` directly from GitHub Add-on Store
# (build context = `edgefetch_agent/`) AND when GitHub Actions builds from the repository root!
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/bartrumb/edgefetch.git /src && \
    cd /src && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -trimpath -ldflags="-s -w" -o /out/edgefetch ./cmd/edgefetch

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.title="EdgeFetch Cold-Standby Worker" \
      org.opencontainers.image.description="Outbound-only Go HTTP/2 worker for Cloudflare Hibernating WebSockets" \
      org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/edgefetch /edgefetch
ENV GOMEMLIMIT=128MiB
ENTRYPOINT ["/edgefetch", "--mode=agent"]
