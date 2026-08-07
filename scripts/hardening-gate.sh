#!/usr/bin/env bash
# Phase gate for the hardening runbook. Usage: ./scripts/hardening-gate.sh <wave-number>
set -uo pipefail
WAVE="${1:?usage: hardening-gate.sh <wave-number>}"
FAIL=0
step() { echo "=== $1"; }

step "go build ./..."
go build ./... || FAIL=1

step "go vet ./..."
go vet ./... || FAIL=1

step "gofmt check (edited files only)"
CHANGED=$(git diff --name-only --diff-filter=ACM | grep '\.go$' || true)
if [ -n "$CHANGED" ]; then
  BAD=$(gofmt -l $CHANGED)
  if [ -n "$BAD" ]; then echo "unformatted: $BAD"; FAIL=1; fi
fi

step "go test -race ./..."
go test -race ./... || FAIL=1

step "git diff --stat (must list every file the wave touched)"
git diff --stat

step "wave POST re-verification"
bash "scripts/hardening-post-wave${WAVE}.sh" || FAIL=1

if [ "$FAIL" -ne 0 ]; then echo "GATE ${WAVE}: FAIL"; exit 1; fi
echo "GATE ${WAVE}: PASS"
