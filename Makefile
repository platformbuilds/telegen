# Main binary configuration
CMD ?= telegen
MAIN_GO_FILE ?= cmd/$(CMD)/main.go

GOOS ?= linux
GOARCH ?= $(shell go env GOARCH || echo amd64)

# Build info
RELEASE_VERSION := $(shell git describe --all 2>/dev/null | cut -d/ -f2 || echo "dev")
RELEASE_REVISION := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILDINFO_PKG ?= github.com/platformbuilds/telegen/pkg/buildinfo

# Container image
IMG_REGISTRY ?= docker.io
IMG_ORG ?= platformbuilds
IMG_NAME ?= telegen
VERSION ?= dev
IMG ?= $(IMG_REGISTRY)/$(IMG_ORG)/$(IMG_NAME):$(VERSION)

# BPF code generator dependencies
CLANG ?= clang
CFLAGS := -std=gnu17 -O2 -g -Wunaligned-access -Wpacked -Wpadded -Wall -Werror $(CFLAGS)
OCI_BIN ?= docker

# Generator image for reproducible eBPF compilation
GEN_IMG ?= ghcr.io/open-telemetry/obi-generator:0.2.6

# Tools directory
TOOLS = $(CURDIR)/.tools
TOOLS_MOD_DIR := ./internal/tools

# cilium/ebpf bpf2go tool
CILIUM_EBPF_VER ?= v0.20.0
BPF2GO ?= $(TOOLS)/bpf2go

.DEFAULT_GOAL := build

$(TOOLS):
	@mkdir -p $@

$(TOOLS)/bpf2go: | $(TOOLS)
	cd $(TOOLS_MOD_DIR) 2>/dev/null || GOBIN=$(TOOLS) go install github.com/cilium/ebpf/cmd/bpf2go@$(CILIUM_EBPF_VER)

.PHONY: tools
tools: $(BPF2GO)
	@echo "### Tools installed"

### BPF Code Generation #####################################################
# Note: //go:generate directives are in internal/ packages, not bpf/
# The bpf/ directory contains only C source files

.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export BPF2GO := $(BPF2GO)
generate: $(BPF2GO)
	@echo "### Generating eBPF code locally..."
	go generate ./internal/ebpf/common/...
	go generate ./internal/tracers/...
	go generate ./internal/netollyebpf/...
	go generate ./internal/ebpflogger/...
	go generate ./internal/ebpfwatcher/...
	go generate ./internal/rdns/...

.PHONY: docker-generate
docker-generate:
	@echo "### Generating eBPF code (docker)..."
	$(OCI_BIN) run --rm \
		-v $(PWD):/src \
		-w /src \
		-e BPF_CLANG=clang \
		-e "BPF_CFLAGS=-O2 -g -Wall -Werror" \
		-e BPF2GO=bpf2go \
		-e "PATH=/usr/lib/llvm20/bin:/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
		--entrypoint /bin/sh \
		$(GEN_IMG) \
		-c "go generate ./internal/ebpf/common/... && \
		    go generate ./internal/tracers/... && \
		    go generate ./internal/netollyebpf/... && \
		    go generate ./internal/ebpflogger/... && \
		    go generate ./internal/ebpfwatcher/... && \
		    go generate ./internal/rdns/..."

### Build Targets ###########################################################

.PHONY: build
build:
	@echo "### Building telegen..."
	go mod tidy
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags="-X '$(BUILDINFO_PKG).Version=$(RELEASE_VERSION)' -X '$(BUILDINFO_PKG).Revision=$(RELEASE_REVISION)'" \
		-a -o bin/$(CMD) $(MAIN_GO_FILE)
	@echo "Built bin/$(CMD)"

.PHONY: build-all
build-all: docker-generate build
	@echo "### Full build complete"

.PHONY: run
run:
	go run ./cmd/telegen --config ./api/config.example.yaml

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	golangci-lint run ./...

### Docker Targets ##########################################################

.PHONY: docker
docker:
	$(OCI_BIN) build -t $(IMG) .

.PHONY: docker-push
docker-push: docker
	$(OCI_BIN) push $(IMG)

### Cleanup #################################################################

.PHONY: clean
clean:
	rm -rf bin/ $(TOOLS)

### Development #############################################################

.PHONY: dev
dev: generate build
	@echo "### Development build complete"

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

### Help ####################################################################

.PHONY: help
help:
	@echo "Telegen - One Agent Many Signals"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the telegen binary"
	@echo "  build-all      Generate eBPF code (docker) and build"
	@echo "  generate       Generate eBPF code locally (requires clang)"
	@echo "  docker-generate Generate eBPF code via docker"
	@echo "  run            Run telegen with example config"
	@echo "  test           Run tests"
	@echo "  lint           Run linter"
	@echo "  docker         Build docker image"
	@echo "  docker-push    Push docker image"
	@echo "  clean          Remove build artifacts"
	@echo "  dev            Development build (generate + build)"
	@echo "  tools          Install development tools"
	@echo "  help           Show this help"
