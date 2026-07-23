#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <go-file-or-directory> [more paths...]" >&2
  exit 2
fi

files=()
for input_path in "$@"; do
  if [ -f "$input_path" ]; then
    files+=("$input_path")
    continue
  fi
  if [ -d "$input_path" ]; then
    while IFS= read -r f; do
      files+=("$f")
    done < <(find "$input_path" -type f -name '*.go' -print)
    continue
  fi
  echo "path does not exist: $input_path" >&2
  exit 2
done

if [ "${#files[@]}" -eq 0 ]; then
  echo "no .go files found under provided paths" >&2
  exit 0
fi

python3 - "$@" <<'PY'
import pathlib
import sys

inputs = [pathlib.Path(p) for p in sys.argv[1:]]
files = []
for p in inputs:
    if p.is_file():
        files.append(p)
    elif p.is_dir():
        files.extend(sorted(p.rglob("*.go")))

rewrite_rules = [
    (
        "go.opentelemetry.io/obi/pkg/internal/ebpf/common",
        "github.com/mirastacklabs-ai/telegen/internal/ebpf/common",
    ),
    (
        "go.opentelemetry.io/obi/pkg/ebpf/common",
        "github.com/mirastacklabs-ai/telegen/internal/ebpf/common",
    ),
    (
        "go.opentelemetry.io/obi/pkg/appolly/app/request",
        "github.com/mirastacklabs-ai/telegen/internal/appolly/app/request",
    ),
    (
        "go.opentelemetry.io/obi/pkg/config",
        "github.com/mirastacklabs-ai/telegen/internal/obiconfig",
    ),
    (
        "go.opentelemetry.io/obi/pkg/obi",
        "github.com/mirastacklabs-ai/telegen/internal/obi",
    ),
    (
        "go.opentelemetry.io/obi/pkg/instrumenter",
        "github.com/mirastacklabs-ai/telegen/internal/instrumenter",
    ),
    (
        "go.opentelemetry.io/obi/pkg/appolly",
        "github.com/mirastacklabs-ai/telegen/internal/appolly",
    ),
    (
        "go.opentelemetry.io/obi/pkg/kube",
        "github.com/mirastacklabs-ai/telegen/internal/kube",
    ),
    (
        "go.opentelemetry.io/obi/pkg/ebpf",
        "github.com/mirastacklabs-ai/telegen/internal/ebpf",
    ),
    (
        "go.opentelemetry.io/obi/pkg/netolly",
        "github.com/mirastacklabs-ai/telegen/internal/netolly",
    ),
    (
        "go.opentelemetry.io/obi/pkg/internal/",
        "github.com/mirastacklabs-ai/telegen/internal/",
    ),
    (
        "go.opentelemetry.io/obi/pkg/export",
        "github.com/mirastacklabs-ai/telegen/pkg/export",
    ),
    (
        "go.opentelemetry.io/obi/pkg/filter",
        "github.com/mirastacklabs-ai/telegen/pkg/filter",
    ),
    (
        "go.opentelemetry.io/obi/pkg/pipe",
        "github.com/mirastacklabs-ai/telegen/pkg/pipe",
    ),
    (
        "go.opentelemetry.io/obi/pkg/buildinfo",
        "github.com/mirastacklabs-ai/telegen/pkg/buildinfo",
    ),
]

changed = 0
for file_path in files:
    original = file_path.read_text(encoding="utf-8")
    updated = original
    for old, new in rewrite_rules:
        updated = updated.replace(old, new)
    if updated != original:
        file_path.write_text(updated, encoding="utf-8")
        changed += 1
        print(f"rewrote imports in: {file_path}")

print(f"rewrite complete, files changed: {changed}")
PY
