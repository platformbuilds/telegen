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
import re
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
        # Report every line of the error. Filtering to "line N:" prefixes hides
        # whole-document failures such as YAML syntax errors, which is how a
        # broken ConfigMap previously passed this gate.
        detail = [line.strip() for line in err.split("\n") if line.strip()]
        return detail or ["failed to load config (no detail)"]

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


def extract_embedded_config(path: Path, key: str = "config.yaml"):
    """Pull the literal block following `<key>: |`.

    The key's indentation and the block body's indentation both vary between
    manifests, so derive the body indent from the first non-blank line instead
    of assuming a fixed two/four space layout.
    """
    lines = path.read_text().splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() in (f"{key}: |", f"{key}: |-"):
            start = i + 1
            break
    if start is None:
        raise ValueError(f"missing {key} block")

    body_indent = None
    for line in lines[start:]:
        if line.strip() == "":
            continue
        body_indent = line[: len(line) - len(line.lstrip(" "))]
        break
    if not body_indent:
        raise ValueError(f"{key} block is empty")

    block = []
    for line in lines[start:]:
        if line.strip() == "":
            block.append("")
            continue
        if not line.startswith(body_indent):
            break
        block.append(line[len(body_indent) :])
    return "\n".join(block) + "\n"


def validate_embedded(path: Path, label: str, key: str = "config.yaml"):
    cfg = extract_embedded_config(path, key)
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


def telegen_top_level_keys():
    """Authoritative top-level key set, read from the binary itself."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
        tf.write("agent:\n  service_name: probe\n")
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
    if proc.returncode != 0:
        raise RuntimeError(f"probe dump-config failed: {proc.stderr.strip()[:300]}")
    return set(json.loads(proc.stdout).keys())


KNOWN_TOP_LEVEL = telegen_top_level_keys()


# Docs that deliberately document a schema other than the agent config. The
# Helm chart's values.yaml shares several top-level key names with the agent
# config (agent, ebpf, profiling, security, network), so it cannot be told apart
# by shape alone.
NON_AGENT_SCHEMA_DOCS = {
    "installation/helm.md",
}

# Agent config keys are snake_case. selfTelemetry is the single exception.
CAMEL_CASE_KEY = re.compile(r"^[a-z]+[A-Z]")
CAMEL_CASE_ALLOWED = {"selfTelemetry"}


def looks_like_telegen_config(text: str):
    """A fenced block is telegen-shaped when every top-level key it declares is
    a real telegen key and no key is camelCase. Blocks that are Kubernetes
    manifests, Collector configs, Helm values, or prose fail this test."""
    keys = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        if ":" not in stripped:
            if line and line[0] not in " \t":
                return False, keys
            continue
        name = stripped.split(":", 1)[0].strip()
        if name not in CAMEL_CASE_ALLOWED and CAMEL_CASE_KEY.match(name):
            return False, keys
        if line and line[0] not in " \t":
            keys.add(name)
    if not keys:
        return False, keys
    return keys <= KNOWN_TOP_LEVEL, keys


def validate_doc_fences(docs_dir: Path):
    """Docs are where operators copy config from, so a fenced telegen config
    that cannot load is the same defect as a broken shipped file."""
    checked = 0
    for md in sorted(docs_dir.rglob("*.md")):
        if str(md.relative_to(docs_dir)) in NON_AGENT_SCHEMA_DOCS:
            continue
        lines = md.read_text(errors="replace").splitlines()
        inside = False
        buf = []
        fence_line = 0
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not inside and stripped in ("```yaml", "```yml"):
                inside, buf, fence_line = True, [], i
                continue
            if inside and stripped == "```":
                block = "\n".join(buf) + "\n"
                ok, _ = looks_like_telegen_config(block)
                if ok:
                    checked += 1
                    rel = md.relative_to(root)
                    validate_config_content(block, f"{rel}:{fence_line} (yaml fence)")
                inside = False
                continue
            if inside:
                buf.append(line)
    print(f"checked {checked} telegen-shaped yaml fences under {docs_dir.relative_to(root)}")


# Plain config files
validate_file(root / "api/config.example.yaml", "api/config.example.yaml")

# configs/ also holds non-agent schemas (an OTel Collector config, per-feature
# fragments), so the agent configs are listed explicitly. Keep this list in sync
# with shippedConfigFiles in internal/config/shipped_configs_test.go.
for name in (
    "telegen-full.yaml",
    "telegen-kafka-logs.yaml",
    "kafka-auto-discovery.yaml",
    "netinfra-firewalls.yaml",
    "snmp_receiver.example.yaml",
    "storage.yaml",
):
    validate_file(root / "configs" / name, f"configs/{name}")
validate_file(root / "deployments/systemd/config.yaml", "deployments/systemd/config.yaml")
validate_file(root / "deployments/systemd/collector-config.yaml", "deployments/systemd/collector-config.yaml")
validate_file(root / "deployments/docker/configs/agent.yaml", "deployments/docker/configs/agent.yaml")
validate_file(root / "deployments/docker/configs/collector.yaml", "deployments/docker/configs/collector.yaml")
validate_file(root / "deployments/ecs/config.yaml", "deployments/ecs/config.yaml")
validate_file(root / "deployments/ecs/collector-config.yaml", "deployments/ecs/collector-config.yaml")

# Embedded config files
validate_embedded(root / "deployments/kubernetes/configmap.yaml", "deployments/kubernetes/configmap.yaml#config.yaml")
validate_embedded(
    root / "deployments/kubernetes/collector-deployment.yaml",
    "deployments/kubernetes/collector-deployment.yaml#collector.yaml",
    key="collector.yaml",
)
validate_embedded(root / "deployments/openshift/agent-daemonset.yaml", "deployments/openshift/agent-daemonset.yaml#config.yaml")

# Customer deployment bundles. These are gitignored, so they never reached CI —
# which is exactly how a non-loadable config was handed to a customer.
custdeploy = root / "custdeploy"
if custdeploy.exists():
    for cfg_file in sorted(custdeploy.glob("*/configs/*.yaml")):
        validate_file(cfg_file, str(cfg_file.relative_to(root)))
else:
    print("SKIP custdeploy validation (no custdeploy/ directory)")

# Documentation fences
validate_doc_fences(root / "docs")

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
