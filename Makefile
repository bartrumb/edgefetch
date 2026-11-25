.PHONY: build build-wasm test race fuzz bench bench-extract doctor hub-test up down fmt vet

VERSION ?= 2.7.8
LDFLAGS := -s -w -X github.com/bartrumb/edgefetch/v2/internal/agent.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o edgefetch ./cmd/edgefetch

build-wasm:
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o edgefetch-wasm.wasm ./cmd/edgefetch-wasm

fmt:
	gofmt -s -w .

vet:
	go vet ./...

test: vet
	go test -v -race -cover ./...

fuzz:
	go test -fuzz=FuzzRobotsParseAndMatch -fuzztime=3s ./internal/politeness
	go test -fuzz=FuzzParseRetryAfter -fuzztime=3s ./internal/politeness
	go test -fuzz=FuzzIsPublicIP -fuzztime=3s ./internal/politeness
	go test -fuzz=FuzzClassify -fuzztime=3s ./internal/classify
	go test -fuzz=FuzzExtractHTML -fuzztime=3s ./internal/extract
	go test -fuzz=FuzzParseLlmsTxt -fuzztime=3s ./internal/extract

bench:
	go test -bench=. -benchmem ./...

bench-extract:
	node bench/run-bench.mjs

doctor: build
	./edgefetch doctor

hub-test:
	cd hub && npm ci --no-audit --no-fund && npm run type-check && npm test && npm run deploy:dry

up:
	docker compose up --build -d

down:
	docker compose down
