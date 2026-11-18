# Server-mode Dockerfile (for Cloudflare Containers, Cloud Run, Fly.io, or standalone Docker).
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/edgefetch ./cmd/edgefetch

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/bartrumb/edgefetch" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/edgefetch /edgefetch
USER nonroot:nonroot
ENV GOMEMLIMIT=200MiB
EXPOSE 8080
ENTRYPOINT ["/edgefetch", "--mode=server"]
