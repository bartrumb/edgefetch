# Multi-arch (`linux/amd64` + `linux/arm64`) Home Assistant OS "Fat" Add-on Dockerfile:
# Static Go binary + Headless Chromium (`browser-v1`) + Poppler `pdftotext` (`pdf-v1`) on minimal Alpine 3.21.
# Every Chromium subresource socket is forced through EdgeFetch's in-process loopback `SSRFProxy` (`MAP * ~NOTFOUND`).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETARCH
ARG BUILD_VERSION=2.0.1
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -trimpath \
      -ldflags="-s -w -X github.com/bartrumb/edgefetch/internal/agent.Version=${BUILD_VERSION}" \
      -o /out/edgefetch ./cmd/edgefetch

FROM alpine:3.21
LABEL org.opencontainers.image.title="EdgeFetch Fat Worker (Browser + PDF)" \
      org.opencontainers.image.description="Outbound-only Go HTTP/2 + SSRF-proxied Headless Chromium + Poppler PDF worker for Cloudflare Hibernating WebSockets" \
      org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache \
      ca-certificates \
      chromium \
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
