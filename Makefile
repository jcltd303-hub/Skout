# Skout — build, test, and release helpers.
# certscout is pure Go (CGO_ENABLED=0 everywhere). ip4scout links libpcap
# via cgo and only builds on linux/amd64, where libpcap-dev is installed.
# No GoReleaser: the release matrix below is the whole release story
# (see .github/workflows/release.yml for the tagged-release equivalent).

GO ?= go
VERSION ?= dev
LDFLAGS := -trimpath -ldflags='-s -w -X github.com/jcltd303-hub/Skout/version.Version=$(VERSION)'

.PHONY: build test vet lint release clean termux

build: ## Build both binaries for the host platform into bin/.
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o bin/certscout ./cmd/certscout
	$(GO) build $(LDFLAGS) -o bin/ip4scout ./cmd/ip4scout

test: ## Go race suite + Python tool suite.
	$(GO) test -race ./... -count=1 -timeout=180s
	python3 -m unittest discover -s tools -p 'test_*.py' -v

vet: ## go vet + gofmt check.
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt: unformatted files:"; gofmt -l .; exit 1; }

lint: vet ## vet + gofmt check + Python byte-compile check.
	python3 -m compileall -q tools

release: ## Build the full release matrix into bin/ (local, unstamped except VERSION).
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o bin/certscout-linux-amd64 ./cmd/certscout
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o bin/certscout-linux-arm64 ./cmd/certscout
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o bin/certscout-darwin-arm64 ./cmd/certscout
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o bin/ip4scout-linux-amd64 ./cmd/ip4scout
	cp LICENSE bin/LICENSE
	mkdir -p bin/data
	cp data/masscan-exclude.conf data/MASSCAN.md data/MASSCAN-LICENSE bin/data/

termux: ## Android ARM64 certscout (pure Go, no libpcap) for Termux.
	mkdir -p bin
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 $(GO) build $(LDFLAGS) -o bin/certscout-termux ./cmd/certscout

clean: ## Remove built binaries.
	rm -rf bin certscout ip4scout certscout-termux
