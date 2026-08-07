#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TELEGEN_BIN="${TELEGEN_BIN:-$ROOT_DIR/bin/telegen}"
PRIVATE_CHART_DIR="${PRIVATE_CHART_DIR:-}"

if [[ ! -x "$TELEGEN_BIN" ]]; then
  echo "telegen binary not found or not executable: $TELEGEN_BIN" >&2
  exit 1
fi

python3 - "$ROOT_DIR" "$TELEGEN_BIN" "$PRIVATE_CHART_DIR" <<'PY'
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
telegen_bin = Path(sys.argv[2])
private_chart_dir = Path(sys.argv[3]) if sys.argv[3] else None

results = []


def parse_validator_output(raw: str):
    raw = raw.strip()
    if not raw:
        return ["empty validator output"]

    first = raw.splitlines()[0]
    try:
        first_obj = json.loads(first)
    except Exception:
        first_obj = None

    if isinstance(first_obj, dict) and first_obj.get("msg") == "failed to load config":
        err = first_obj.get("error", "")
        return [line.strip() for line in err.split("\n") if line.strip().startswith("line ")]

    try:
        json.loads(raw)
        return []
    except Exception:
        return [f"unparsable validator output: {first[:160]}"]


def validate_config_content(content: str, label: str):
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(content)
        path = tf.name
    try:
        proc = subprocess.run(
            [str(telegen_bin), "--config", path, "--dump-config"],
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        os.unlink(path)
    raw = (proc.stdout or "") + (proc.stderr or "")
    errs = parse_validator_output(raw)
    results.append((label, errs))


def validate_file(path: Path, label: str):
    validate_config_content(path.read_text(), label)


def extract_embedded_config(path: Path):
    lines = path.read_text().splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith("  config.yaml: |"):
            start = i + 1
            break
    if start is None:
        raise ValueError("missing config.yaml block")

    block = []
    for line in lines[start:]:
        if line.startswith("    "):
            block.append(line[4:])
            continue
        if line.strip() == "":
            block.append("")
            continue
        break
    return "\n".join(block) + "\n"


def validate_embedded(path: Path, label: str):
    cfg = extract_embedded_config(path)
    validate_config_content(cfg, label)


def extract_config_from_helm_render(rendered: str):
    marker = "config.yaml: |\n"
    idx = rendered.find(marker)
    if idx < 0:
        raise ValueError("rendered manifest missing config.yaml block")

    body = rendered[idx + len(marker) :]
    block = []
    for line in body.splitlines():
        if line.startswith("    "):
            block.append(line[4:])
            continue
        if line.strip() == "":
            block.append("")
            continue
        break
    return "\n".join(block) + "\n"


def validate_helm_chart(chart_dir: Path, values_file: Path, label: str, set_values=None):
    cmd = [
        "helm",
        "template",
        "telegen",
        str(chart_dir),
        "-f",
        str(values_file),
        "-s",
        "templates/configmap.yaml",
    ]
    for set_value in set_values or []:
        cmd.extend(["--set", set_value])
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        results.append((label, [f"helm template failed: {proc.stderr.strip()[:300]}"]))
        return
    try:
        cfg = extract_config_from_helm_render(proc.stdout)
    except Exception as exc:
        results.append((label, [str(exc)]))
        return
    validate_config_content(cfg, label)


# Plain config files
validate_file(root / "api/config.example.yaml", "api/config.example.yaml")
validate_file(root / "deployments/systemd/config.yaml", "deployments/systemd/config.yaml")
validate_file(root / "deployments/systemd/collector-config.yaml", "deployments/systemd/collector-config.yaml")
validate_file(root / "deployments/docker/configs/agent.yaml", "deployments/docker/configs/agent.yaml")
validate_file(root / "deployments/docker/configs/collector.yaml", "deployments/docker/configs/collector.yaml")
validate_file(root / "deployments/ecs/config.yaml", "deployments/ecs/config.yaml")
validate_file(root / "deployments/ecs/collector-config.yaml", "deployments/ecs/collector-config.yaml")

# Embedded config files
validate_embedded(root / "deployments/kubernetes/configmap.yaml", "deployments/kubernetes/configmap.yaml#config.yaml")
validate_embedded(root / "deployments/openshift/agent-daemonset.yaml", "deployments/openshift/agent-daemonset.yaml#config.yaml")

# Public chart
validate_helm_chart(
    root / "deployments/helm",
    root / "deployments/helm/values.yaml",
    "deployments/helm/templates/configmap.yaml (values.yaml render)",
)
validate_helm_chart(
    root / "deployments/helm",
    root / "deployments/helm/values.yaml",
    "deployments/helm/templates/configmap.yaml (mode=collector render)",
    set_values=["mode=collector"],
)

# Private chart (optional)
if private_chart_dir and private_chart_dir.exists():
    validate_helm_chart(
        private_chart_dir,
        private_chart_dir / "values-agent.yaml",
        "private helm values-agent.yaml render",
    )
    validate_helm_chart(
        private_chart_dir,
        private_chart_dir / "values-collector.yaml",
        "private helm values-collector.yaml render",
    )
    validate_helm_chart(
        private_chart_dir,
        private_chart_dir / "values.yaml",
        "private helm values.yaml render",
    )
else:
    print("SKIP private chart validation (PRIVATE_CHART_DIR not set or missing)")

failed = 0
for label, errs in results:
    print(f"{len(errs)}  {label}")
    if errs:
        failed += 1
        for err in errs:
            print(f"  {err}")

if failed:
    sys.exit(1)
PY
