# Multi-arch (`linux/amd64` + `linux/arm64`) Home Assistant OS Add-on Dockerfile:
# Static Go binary + Headless Chromium (`browser-v1`) + Poppler `pdftotext` (`pdf-v1`) on minimal Alpine 3.24.
# Every Chromium subresource socket is forced through EdgeFetch's in-process loopback `SSRFProxy` (`MAP * ~NOTFOUND`).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETARCH
ARG BUILD_VERSION=2.8.17
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -trimpath \
      -ldflags="-s -w -X github.com/bartrumb/edgefetch/v2/internal/agent.Version=${BUILD_VERSION}" \
      -o /out/edgefetch ./cmd/edgefetch

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.title="EdgeFetch" \
      org.opencontainers.image.description="Outbound-only Go HTTP/2 + SSRF-proxied Headless Chromium + Poppler PDF worker for Cloudflare Hibernating WebSockets" \
      org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.bartrumb/edgefetch"

RUN apk add --no-cache \
      ca-certificates \
      chromium \
      chromium-swiftshader \
      font-noto \
      poppler-utils \
      ttf-freefont \
      tzdata \
    && mkdir -p /tmp /var/cache/fontconfig \
    && chmod 1777 /tmp /var/cache/fontconfig

COPY --from=build /out/edgefetch /edgefetch
# The real binary, not /usr/bin/chromium-browser: on Alpine that is a /bin/sh launcher script, and the AppArmor
# profile lets no shell run, so every launch failed with "permission denied" (2.0.0).
ENV EDGEFETCH_CHROME_BIN=/usr/lib/chromium/chromium \
    GOMEMLIMIT=384MiB \
    HOME=/tmp
ENTRYPOINT ["/edgefetch", "--mode=agent"]
