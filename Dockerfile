# Minimal Distroless Dockerfile (~9 MB, `linux/amd64` + `linux/arm64`, zero OS shell).
# Supports `--mode=server` (default), `--mode=agent` (`ghcr.io/bartrumb/edgefetch-agent:lite`), `--mode=hub`,
# and one-shot CLI (`docker run --rm ghcr.io/bartrumb/edgefetch-agent:lite scrape https://example.com`).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETARCH
ARG BUILD_VERSION=2.7.1
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath \
      -ldflags="-s -w -X github.com/bartrumb/edgefetch/v2/internal/agent.Version=${BUILD_VERSION}" \
      -o /out/edgefetch ./cmd/edgefetch

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="EdgeFetch Lite" \
      org.opencontainers.image.description="Minimal 9 MB distroless Go HTTP/2 crawler, agent, and self-hosted WebSocket Hub" \
      org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.bartrumb/edgefetch"
COPY --from=build /out/edgefetch /edgefetch
USER nonroot:nonroot
ENV GOMEMLIMIT=200MiB
EXPOSE 8080
ENTRYPOINT ["/edgefetch"]
CMD ["--mode=server"]
