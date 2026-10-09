BIN      := bin/iolens
PKG      := github.com/ramyak-sharma/iolens
IMAGE    ?= iolens:dev
GOFLAGS  := -trimpath
LDFLAGS  := -s -w

.PHONY: all generate build test itest image validate demo-up demo-run demo demo-down clean

all: build

# needs clang + libbpf headers, output is committed so plain go build works without them
generate:
	go generate ./...

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/iolens

test:
	go vet ./...
	go test ./...
	@command -v staticcheck >/dev/null && staticcheck ./... || echo "staticcheck not installed, skipping"

# root only, loads the real program into the running kernel
itest:
	sudo -E go test -tags itest -count=1 -v ./internal/probe/

image:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE) .

validate: build
	sudo ./scripts/v1_latency.sh
	sudo ./scripts/v2_iostat.sh
	sudo ./scripts/v3_attribution.sh
	sudo ./scripts/v4_overhead.sh
	./scripts/results.sh > docs/results.md

demo-up:
	./scripts/demo_up.sh

demo-run:
	./scripts/demo.sh

demo: demo-up demo-run

demo-down:
	./scripts/demo_down.sh

clean:
	rm -rf bin dist
