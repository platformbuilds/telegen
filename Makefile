# Main binary configuration
CMD ?= telegen
MAIN_GO_FILE ?= cmd/$(CMD)/main.go

GOOS ?= linux
GOARCH ?= $(shell go env GOARCH || echo amd64)

# Build info - VERSION is the single source of truth for version string
# Can be overridden: make docker-for-server VERSION=v2.12.37
VERSION ?= $(shell git describe --tags 2>/dev/null || git describe --all 2>/dev/null | cut -d/ -f2 || echo "dev")
REVISION := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILDINFO_PKG ?= github.com/platformbuilds/telegen/pkg/buildinfo
VERSION_PKG ?= github.com/platformbuilds/telegen/internal/version

# Container image
IMG_REGISTRY ?= docker.io
IMG_ORG ?= platformbuilds
IMG_NAME ?= telegen
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
	go generate ./internal/profiler/...

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
		    go generate ./internal/rdns/... && \
		    go generate ./internal/profiler/..."

### Build Targets ###########################################################

.PHONY: build
build:
	@echo "### Building telegen..."
	go mod tidy
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags="-X '$(BUILDINFO_PKG).Version=$(VERSION)' -X '$(BUILDINFO_PKG).Revision=$(REVISION)' \
		         -X '$(VERSION_PKG).version=$(VERSION)' -X '$(VERSION_PKG).commit=$(REVISION)' -X '$(VERSION_PKG).buildDate=$(BUILD_DATE)'" \
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

# Docker buildx platforms
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: docker
docker:
	$(OCI_BIN) build -t $(IMG) .

.PHONY: docker-push
docker-push: docker
	$(OCI_BIN) push $(IMG)

# Build for specific platform (useful for M1 Mac building for amd64 servers)
.PHONY: docker-amd64
docker-amd64:
	$(OCI_BIN) build --platform linux/amd64 -t $(IMG)-amd64 .

.PHONY: docker-arm64
docker-arm64:
	$(OCI_BIN) build --platform linux/arm64 -t $(IMG)-arm64 .

# Multi-platform build (requires buildx)
.PHONY: docker-buildx-setup
docker-buildx-setup:
	@if ! $(OCI_BIN) buildx inspect telegen-builder >/dev/null 2>&1; then \
		echo "### Creating buildx builder..."; \
		$(OCI_BIN) buildx create --name telegen-builder --use --bootstrap; \
	else \
		echo "### Using existing buildx builder"; \
		$(OCI_BIN) buildx use telegen-builder; \
	fi

# Build multi-platform image and load to local docker (only current platform)
.PHONY: docker-buildx
docker-buildx: docker-buildx-setup
	$(OCI_BIN) buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMG) \
		.

# Build multi-platform and push to registry
.PHONY: docker-buildx-push
docker-buildx-push: docker-buildx-setup
	$(OCI_BIN) buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMG) \
		--push \
		.

# Build for amd64 and load locally (for M1 Mac users deploying to x86 servers)
.PHONY: docker-for-server
docker-for-server: docker-buildx-setup
	$(OCI_BIN) buildx build \
		--platform linux/amd64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMG) \
		--load \
		.

# Build for current platform and load locally
.PHONY: docker-local
docker-local: docker-buildx-setup
	$(OCI_BIN) buildx build \
		--platform linux/$(GOARCH) \
		--build-arg VERSION=$(VERSION) \
		--build-arg REVISION=$(REVISION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMG) \
		--load \
		.

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
	@echo "  build              Build the telegen binary"
	@echo "  build-all          Generate eBPF code (docker) and build"
	@echo "  generate           Generate eBPF code locally (requires clang)"
	@echo "  docker-generate    Generate eBPF code via docker"
	@echo "  run                Run telegen with example config"
	@echo "  test               Run tests"
	@echo "  lint               Run linter"
	@echo "  clean              Remove build artifacts"
	@echo "  dev                Development build (generate + build)"
	@echo "  tools              Install development tools"
	@echo ""
	@echo "Docker Targets:"
	@echo "  docker             Build docker image (current platform)"
	@echo "  docker-push        Build and push docker image"
	@echo "  docker-amd64       Build for linux/amd64 only"
	@echo "  docker-arm64       Build for linux/arm64 only"
	@echo "  docker-buildx      Build multi-platform image (amd64+arm64)"
	@echo "  docker-buildx-push Build multi-platform and push to registry"
	@echo "  docker-for-server  Build amd64 image on M1 Mac for x86 servers"
	@echo "  docker-local       Build for current platform with buildx"
	@echo ""
	@echo "Variables:"
	@echo "  IMG                Container image name (default: $(IMG))"
	@echo "  PLATFORMS          Build platforms (default: $(PLATFORMS))"
	@echo "  VERSION            Image version tag (default: $(VERSION))"
	@echo ""
	@echo "Examples:"
	@echo "  make docker-for-server VERSION=v2.1.0  # Build amd64 on M1 Mac"
	@echo "  make docker-buildx-push VERSION=v2.1.0 # Multi-arch push"
	@echo "  make docker IMG=myregistry/telegen:dev # Custom image name"
