# Multi-stage build for telegen with eBPF support
# Stage 1: Generate eBPF code
FROM ghcr.io/open-telemetry/obi-generator:0.2.6 AS bpf-gen
WORKDIR /src
COPY bpf/ ./bpf/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY go.mod go.sum ./
# Generate eBPF bytecode
RUN go generate ./bpf/...

# Stage 2: Build Go binary
FROM golang:1.23 AS build
WORKDIR /src
COPY . .
# Copy generated eBPF files
COPY --from=bpf-gen /src/bpf/ ./bpf/
COPY --from=bpf-gen /src/internal/ ./internal/
COPY --from=bpf-gen /src/pkg/ ./pkg/

ARG VERSION=dev
ARG REVISION=unknown
ARG TARGETARCH=amd64

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-X 'github.com/platformbuilds/telegen/pkg/buildinfo.Version=${VERSION}' -X 'github.com/platformbuilds/telegen/pkg/buildinfo.Revision=${REVISION}'" \
    -a -o /out/telegen ./cmd/telegen

# Stage 3: Final minimal image
FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/telegen /telegen
COPY api/config.example.yaml /etc/telegen/config.yaml
# For eBPF, we may need CAP_SYS_ADMIN, CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON
# These are granted at runtime via K8s securityContext or docker --cap-add
USER 65532:65532
EXPOSE 19090
ENTRYPOINT ["/telegen","--config","/etc/telegen/config.yaml"]
