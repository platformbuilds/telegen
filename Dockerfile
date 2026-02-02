# Telegen v2.0 Multi-stage Dockerfile
# Task: DEP-014
# Builds the Telegen observability agent with eBPF support

# =============================================================================
# Stage 1: Generate eBPF bytecode
# Uses BUILDPLATFORM to run natively on the build host
# =============================================================================
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM ghcr.io/open-telemetry/obi-generator:0.2.6 AS bpf-gen

WORKDIR /src

# Copy BPF source files
COPY bpf/ ./bpf/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY go.mod go.sum ./

# Generate eBPF bytecode (CO-RE) - architecture independent
RUN go generate ./bpf/...

# =============================================================================
# Stage 2: Build Go binary
# Uses BUILDPLATFORM to run natively, cross-compiles for TARGETPLATFORM
# =============================================================================
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

# These args are automatically set by Docker buildx
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Copy go module files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy generated eBPF files from previous stage
COPY --from=bpf-gen /src/bpf/ ./bpf/
COPY --from=bpf-gen /src/internal/ ./internal/
COPY --from=bpf-gen /src/pkg/ ./pkg/

# Build arguments for version info
ARG VERSION=2.0.0
ARG REVISION=unknown
ARG BUILD_DATE

# Build the binary - Go cross-compilation (no QEMU needed)
# CGO_ENABLED=0 allows cross-compilation without C toolchain
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w \
        -X 'github.com/platformbuilds/telegen/pkg/buildinfo.Version=${VERSION}' \
        -X 'github.com/platformbuilds/telegen/pkg/buildinfo.Revision=${REVISION}' \
        -X 'github.com/platformbuilds/telegen/pkg/buildinfo.BuildDate=${BUILD_DATE}'" \
    -o /out/telegen ./cmd/telegen

# =============================================================================
# Stage 3: Final runtime image (Distroless)
# =============================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

# Labels
LABEL org.opencontainers.image.title="Telegen"
LABEL org.opencontainers.image.description="Zero-config universal observability agent powered by eBPF"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.vendor="Platform Builds"
LABEL org.opencontainers.image.source="https://github.com/platformbuilds/telegen"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /

# Copy binary
COPY --from=build /out/telegen /telegen

# Copy default configuration
COPY api/config.example.yaml /etc/telegen/config.yaml

# eBPF requires specific capabilities at runtime:
# - CAP_SYS_ADMIN: BPF operations
# - CAP_BPF: BPF operations (kernel 5.8+)
# - CAP_NET_ADMIN: Network tracing
# - CAP_PERFMON: Perf events (kernel 5.8+)
# - CAP_SYS_PTRACE: Process tracing
# - CAP_SYS_RESOURCE: Memory locking
# These are granted via K8s securityContext or docker --cap-add

# Expose metrics port
EXPOSE 19090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/telegen", "--health-check"]

# Default entrypoint
ENTRYPOINT ["/telegen"]
CMD ["--config", "/etc/telegen/config.yaml"]

# =============================================================================
# Stage 4: Debug image with shell (Alpine-based)
# =============================================================================
FROM alpine:3.23 AS debug

RUN apk add --no-cache \
    ca-certificates \
    curl \
    jq \
    strace \
    tcpdump \
    iproute2 \
    busybox-extras

WORKDIR /

COPY --from=build /out/telegen /telegen
COPY api/config.example.yaml /etc/telegen/config.yaml

EXPOSE 19090

ENTRYPOINT ["/telegen"]
CMD ["--config", "/etc/telegen/config.yaml"]
