# Multi-arch (`linux/amd64` + `linux/arm64`) Home Assistant OS Add-on Dockerfile (~9 MB distroless, zero shell).
# Builds directly from the checked-out repository context (never cloning remote branches during build) so CI and GHCR
# SLSA provenance attestations always match the exact reviewed commit.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETARCH
ARG BUILD_VERSION=2.0.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -trimpath \
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
