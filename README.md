# Telegen

Telegen is a high-performance telemetry collection and export framework.

## Why Telegen
- Unified pipelines for metrics, traces, and logs.
- Built-in self-telemetry and health endpoints.
- Configurable exporters (Remote Write, OTLP).
- Modular queueing, backoff, and pipeline controls.

## Build Metadata
Telegen embeds build metadata via Go `-ldflags`:

| Field      | Example                    | Description                         |
|------------|----------------------------|-------------------------------------|
| version    | v3.1.0                     | Semantic version                    |
| commit     | abc1234                    | Git short SHA                       |
| buildDate  | 2025-08-15T14:32:05Z       | RFC3339 UTC timestamp               |

Local builds default all fields to `"unknown"`. CI/CD sets them automatically.

### Local build with metadata
```bash
MODULE=github.com/platformbuilds/telegen
go build -trimpath -ldflags "\
  -X ${MODULE}/internal/version.version=v3.1.0 \
  -X ${MODULE}/internal/version.commit=$(git rev-parse --short=12 HEAD) \
  -X ${MODULE}/internal/version.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./cmd/telegen
```

## GitHub Actions CI/CD & Security

This repository uses **GitHub Actions** to build, test, secure, and release `telegen`.

### Workflows
- **CI** (`.github/workflows/ci.yml`)
  - Lint: `gofmt -s`, `go vet`
  - Test: `go test -race` (coverage as artifact)
  - Build:
    - Linux/amd64 binary on every push/PR
    - Cross‑compile matrix (linux/darwin/windows × amd64/arm64) on tags
  - Release (tags only): Creates a GitHub Release and uploads binaries
- **Docker** (`.github/workflows/docker.yml`)
  - Builds multi‑arch image and pushes to **GHCR**: `ghcr.io/platformbuilds/telegen`
  - Runs **Trivy** container scan on the built image
- **Security** (`.github/workflows/security.yml`)
  - **CodeQL** static analysis (Go)
  - **govulncheck** (reachable vulnerabilities in Go deps)
  - **gosec** security linter
  - **SBOM** generation with Syft (artifact)

### Required repository settings
1. **Actions permissions**: Settings → Actions → General → Workflow permissions → enable “Read and write permissions” (for Releases and GHCR pushes).
2. **Packages permissions** (GHCR): Settings → Actions → General → Workflow permissions should cover `packages: write` (see per‑workflow `permissions`).
3. (Optional) Set `GHCR_IMAGE` env to customize image name. Defaults to `ghcr.io/platformbuilds/telegen`.

### Local security scans
```bash
# govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
govulncheck -format=json ./... > govulncheck.json

# gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
```

## Deployment

### Linux Service
1. Copy the binary to `/usr/local/bin/telegen`.
2. Create a systemd service file:
```ini
[Unit]
Description=Telegen Service
After=network.target

[Service]
ExecStart=/usr/local/bin/telegen --config /etc/telegen/config.yaml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```
3. Enable & start:
```bash
sudo systemctl enable telegen
sudo systemctl start telegen
```

### Docker (GHCR)
```bash
docker run --rm -v $(pwd)/config.yaml:/etc/telegen/config.yaml \
  ghcr.io/platformbuilds/telegen:latest
```

### Helm (Kubernetes)
```bash
helm repo add platformbuilds https://platformbuilds.github.io/charts
helm install telegen platformbuilds/telegen -f values.yaml
```

## Contributing
1. Fork the repo and create a feature branch.
2. Run tests and lint before submitting:
```bash
go test ./...
gofmt -s -w .
```
3. Open a pull request with a clear description.

## License
Apache-2.0
