#!/usr/bin/env bash
# Build the exact first-public archives twice, install the wheel without resolution, and run the
# validator from outside the checkout. No chain coordinate, signing packet, or prior package
# participates.
set -euo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR/dist}"
case "$OUTPUT_DIR" in
  -h|--help)
    echo "usage: ./reproduce.sh [OUTPUT_DIR]"
    exit 0
    ;;
esac

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/coretex-validator-1.0.0.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== deterministic archives =="
python3 "$SCRIPT_DIR/build_release.py" --out-dir "$WORK_DIR/a" > "$WORK_DIR/a.json"
python3 "$SCRIPT_DIR/build_release.py" --out-dir "$WORK_DIR/b" > "$WORK_DIR/b.json"
cmp "$WORK_DIR/a/coretex_validator-1.0.0-py3-none-any.whl" \
    "$WORK_DIR/b/coretex_validator-1.0.0-py3-none-any.whl"
cmp "$WORK_DIR/a/coretex_validator-1.0.0.tar.gz" \
    "$WORK_DIR/b/coretex_validator-1.0.0.tar.gz"

mkdir -p "$OUTPUT_DIR"
cp "$WORK_DIR/a/coretex_validator-1.0.0-py3-none-any.whl" "$OUTPUT_DIR/"
cp "$WORK_DIR/a/coretex_validator-1.0.0.tar.gz" "$OUTPUT_DIR/"
python3 "$SCRIPT_DIR/build_release.py" --out-dir "$OUTPUT_DIR" --check > "$WORK_DIR/check.json"

echo "== clean no-index install =="
python3 -m venv "$WORK_DIR/venv"
"$WORK_DIR/venv/bin/python" -m pip install --no-index --no-deps \
  "$OUTPUT_DIR/coretex_validator-1.0.0-py3-none-any.whl"
( cd "$WORK_DIR" && "$WORK_DIR/venv/bin/coretex-validator" selftest )
( cd "$WORK_DIR" && "$WORK_DIR/venv/bin/coretex-validator" topics )

echo "== source tests =="
( cd "$SCRIPT_DIR" && python3 -m pytest -q )

cat "$WORK_DIR/check.json"
echo "validator 1.0.0 deterministic build and clean install: PASS"
