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

# Environment variables required by go:generate directives
# These match what's used in `make docker-generate`
ENV BPF_CLANG=clang
ENV BPF_CFLAGS="-O2 -g -Wall -Werror"
ENV BPF2GO=bpf2go
ENV PATH="/usr/lib/llvm20/bin:/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Copy all source files needed for BPF generation
# BPF C source files are in bpf/, but go:generate directives are in internal/
COPY bpf/ ./bpf/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY go.mod go.sum ./

# Generate eBPF bytecode (CO-RE) - runs go:generate in all packages
# The directives are in internal/tracers/*, internal/ebpf/*, etc.
RUN go generate ./internal/ebpf/common/... && \
    go generate ./internal/tracers/... && \
    go generate ./internal/netollyebpf/... && \
    go generate ./internal/ebpflogger/... && \
    go generate ./internal/ebpfwatcher/... && \
    go generate ./internal/rdns/... && \
    go generate ./internal/profiler/...

# =============================================================================
# Stage 2: Build Java Agent
# Uses BUILDPLATFORM to run natively on the build host
# Gradle 9.x requires JDK 17+, but we target Java 8 bytecode for compatibility
# =============================================================================
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM eclipse-temurin:17-jdk AS java-build

WORKDIR /src/internal/java

# Copy Java agent source
COPY internal/java/ ./

# Build the Java agent using Gradle wrapper
RUN chmod +x gradlew && ./gradlew clean shadowJar copyLoaderJar --no-daemon

# =============================================================================
# Stage 2b: Build perf-map-agent for Java symbol resolution
# =============================================================================
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM eclipse-temurin:17-jdk AS perfmap-build

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 https://github.com/jvm-profiling-tools/perf-map-agent.git && \
    cd perf-map-agent && \
    cmake . && \
    make

# =============================================================================
# Stage 3: Build Go binary
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

# Copy source code (this includes any stale generated files from local)
COPY . .

# IMPORTANT: Copy generated eBPF files from bpf-gen stage AFTER COPY . .
# This ensures freshly generated BPF bytecode overwrites any stale local files
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

# Copy Java agent jar (must be in same directory as telegen executable)
COPY --from=java-build /src/internal/java/build/obi-java-agent.jar /obi-java-agent.jar

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
# Copy Java agent jar (must be in same directory as telegen executable)
COPY --from=java-build /src/internal/java/build/obi-java-agent.jar /obi-java-agent.jar
COPY api/config.example.yaml /etc/telegen/config.yaml

EXPOSE 19090

ENTRYPOINT ["/telegen"]
CMD ["--config", "/etc/telegen/config.yaml"]

# =============================================================================
# Stage 5: Java Profiling image (includes JRE + perf-map-agent for Java symbols)
# Use this when profiling Java applications with eBPF
# Build with: docker build --target java-profiling -t telegen:java-profiling .
# =============================================================================
FROM eclipse-temurin:21-jre-alpine AS java-profiling

RUN apk add --no-cache \
    ca-certificates \
    curl \
    jq

WORKDIR /

COPY --from=build /out/telegen /telegen
COPY --from=java-build /src/internal/java/build/obi-java-agent.jar /obi-java-agent.jar
COPY --from=perfmap-build /src/perf-map-agent/out/attach-main.jar /opt/perf-map-agent/attach-main.jar
COPY --from=perfmap-build /src/perf-map-agent/out/libperfmap.so /opt/perf-map-agent/libperfmap.so
COPY api/config.example.yaml /etc/telegen/config.yaml

# Set environment for perf-map-agent
ENV PERF_MAP_AGENT_JAR=/opt/perf-map-agent/attach-main.jar
ENV PERF_MAP_AGENT_LIB=/opt/perf-map-agent/libperfmap.so

EXPOSE 19090

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/telegen", "--health-check"]

ENTRYPOINT ["/telegen"]
CMD ["--config", "/etc/telegen/config.yaml"]
