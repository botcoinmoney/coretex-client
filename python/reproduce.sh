#!/usr/bin/env bash
#
# THE CLEAN-MACHINE REPRODUCTION. This is the command an external agent runs.
#
# It is a real test rather than a claim because of where it runs the validator FROM: a wheel is
# built, installed into a throwaway virtualenv, and then executed with the working directory
# OUTSIDE this source tree. A package that only works next to its own sources is not installed,
# it is merely nearby — and every "it works on my machine" report is that mistake.
#
#   ./reproduce.sh                          # offline: build, install clean, run the test suite
#   ./reproduce.sh --rpc URL --release R    # ...then replay a live chain end to end
#
# Optional extras for the live leg:
#   --snapshot FILE     a published resolver snapshot to reproduce BYTE FOR BYTE
#   --artifact-dir DIR  a local content-addressed artifact store
#   --export FILE       write the MAINNET_REHEARSAL activation export here
#
# EXIT CODES mirror the CLI: 0 = nothing was contradicted, 1 = a check ran and disagreed,
# 2 = the run could not start. A 0 with a non-empty "unverified" list is the NORMAL clean-machine
# outcome, because deterministic Benchmark-v2 admission needs trees that are not published — see
# docs/V5-RIG-VALIDATOR.md. Pass --require-complete to the CLI if you want that to be a failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/coretex-validator-clean.XXXXXX")"
# Somewhere that is definitely not the source tree, so a stray relative import cannot resolve.
OUTSIDE="$(mktemp -d "${TMPDIR:-/tmp}/coretex-validator-outside.XXXXXX")"
trap 'rm -rf "$WORK" "$OUTSIDE"' EXIT

RPC=""; RELEASE=""; SNAPSHOT=""; ARTIFACT_DIR=""; EXPORT_TO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rpc) RPC="$2"; shift 2 ;;
    --release) RELEASE="$2"; shift 2 ;;
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --artifact-dir) ARTIFACT_DIR="$2"; shift 2 ;;
    --export) EXPORT_TO="$2"; shift 2 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

echo "== 1. build a wheel from source =========================================="
python3 -m venv "$WORK/build"
"$WORK/build/bin/pip" install --quiet --upgrade pip build
"$WORK/build/bin/python" -m build --wheel --outdir "$WORK/dist" "$HERE" >/dev/null
WHEEL="$(ls "$WORK"/dist/*.whl | head -1)"
echo "   $WHEEL"

echo "== 2. install it into a FRESH venv ======================================="
python3 -m venv "$WORK/clean"
# --no-deps is the assertion, not an optimisation: the package declares zero runtime
# dependencies, so a clean install must succeed with dependency resolution switched off.
# If this ever fails, a dependency was added and the package's central promise changed.
"$WORK/clean/bin/pip" install --quiet --no-deps "$WHEEL"
"$WORK/clean/bin/pip" install --quiet 'pytest==8.3.3'

echo "== 3. prove the primitives, from OUTSIDE the source tree ================="
( cd "$OUTSIDE" && "$WORK/clean/bin/coretex-validator" selftest )

echo "== 4. show both dispatch tables and the topic0 collision ================="
( cd "$OUTSIDE" && "$WORK/clean/bin/coretex-validator" topics )

echo "== 5. run the test suite against the INSTALLED package =================="
# The tests are copied next to the venv, so they import `coretex_validator` from site-packages
# rather than from the checkout sitting one directory up.
cp -R "$HERE/tests" "$OUTSIDE/tests"
( cd "$OUTSIDE" && "$WORK/clean/bin/python" -m pytest tests -q )

if [ -n "$RPC" ] && [ -n "$RELEASE" ]; then
  echo "== 6. replay the chain, steps 1-8 ======================================"
  ARGS=(reproduce --release "$RELEASE" --rpc "$RPC")
  [ -n "$SNAPSHOT" ] && ARGS+=(--snapshot "$SNAPSHOT")
  [ -n "$ARTIFACT_DIR" ] && ARGS+=(--artifact-dir "$ARTIFACT_DIR")
  [ -n "$EXPORT_TO" ] && ARGS+=(--export "$EXPORT_TO")
  ( cd "$OUTSIDE" && "$WORK/clean/bin/coretex-validator" "${ARGS[@]}" )
else
  echo "== 6. chain replay SKIPPED =============================================="
  echo "   no --rpc/--release given. The offline legs above prove the package installs"
  echo "   and runs clean; they prove nothing about any deployment."
fi

echo
echo "clean-machine reproduction finished."
