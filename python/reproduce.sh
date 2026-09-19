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

# `build_release.py` resolves relative --out-dir values from SCRIPT_DIR, while this wrapper is
# intentionally callable from any working directory. Canonicalize once here so copying and the
# final --check always address the same directory.
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"

# The builder owns the target. Ask it rather than restating a version here: a hardcoded filename
# in this wrapper is a second declaration of the version, and the one that goes stale first.
TARGET_JSON="$(python3 "$SCRIPT_DIR/build_release.py" --print-target)"
target_field() {
  printf '%s' "$TARGET_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}
VERSION="$(target_field version)"
WHEEL_NAME="$(target_field wheel_name)"
SDIST_NAME="$(target_field sdist_name)"
echo "== target =="
echo "$TARGET_JSON"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/coretex-validator-$VERSION.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "== deterministic archives =="
python3 "$SCRIPT_DIR/build_release.py" --version "$VERSION" --out-dir "$WORK_DIR/a" > "$WORK_DIR/a.json"
python3 "$SCRIPT_DIR/build_release.py" --version "$VERSION" --out-dir "$WORK_DIR/b" > "$WORK_DIR/b.json"
cmp "$WORK_DIR/a/$WHEEL_NAME" "$WORK_DIR/b/$WHEEL_NAME"
cmp "$WORK_DIR/a/$SDIST_NAME" "$WORK_DIR/b/$SDIST_NAME"

cp "$WORK_DIR/a/$WHEEL_NAME" "$OUTPUT_DIR/"
cp "$WORK_DIR/a/$SDIST_NAME" "$OUTPUT_DIR/"
python3 "$SCRIPT_DIR/build_release.py" --out-dir "$OUTPUT_DIR" --check > "$WORK_DIR/check.json"

echo "== clean no-index install =="
python3 -m venv "$WORK_DIR/venv"
"$WORK_DIR/venv/bin/python" -m pip install --no-index --no-deps "$OUTPUT_DIR/$WHEEL_NAME"
( cd "$WORK_DIR" && "$WORK_DIR/venv/bin/coretex-validator" selftest )
( cd "$WORK_DIR" && "$WORK_DIR/venv/bin/coretex-validator" topics )

echo "== source tests =="
( cd "$SCRIPT_DIR" && python3 -m pytest -q )

cat "$WORK_DIR/check.json"
echo "validator $VERSION deterministic build and clean install: PASS"
