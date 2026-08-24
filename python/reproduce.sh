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
#   ./reproduce.sh --law-mirror URL --law-root ROOT  # ...with a named verified law
#
# Optional extras for the live leg:
#   --law-mirror URL    a mirror of the published admission law. `sync-law` fetches all seven
#                       sealed objects (six trees and one file), re-derives every address from the bytes that
#                       arrived, and pins the verified cache for the replay below. This is what
#                       removes step 5's BACKLOG on a machine that started with nothing.
#   --law-root ROOT     the publication root to fetch. Required with --law-mirror; no default.
#   --snapshot FILE     a published resolver snapshot to reproduce BYTE FOR BYTE
#   --artifact-dir DIR  a local content-addressed artifact store
#   --export FILE       write the reproduced activation export here
#   --confirmation-depth N   how deep a block must be to count as settled (default 15).
#                            Lower it only for a local test chain; on a real chain this is the
#                            difference between reading confirmed state and reading a guess.
#
# EXIT CODES mirror the CLI: 0 = nothing was contradicted, 1 = a check ran and disagreed,
# 2 = the run could not start. A 0 with a non-empty "unverified" list is the normal outcome when no
# law mirror was given, because deterministic Benchmark-v2 admission needs all seven published objects
# — see docs/V5-RIG-VALIDATOR.md. Pass --law-mirror to remove that, and --require-complete to the
# CLI if you want any remaining gap to be a failure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO" ]; then
  echo "reproduce.sh must run from a git checkout so it can build committed archive bytes" >&2
  exit 2
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/coretex-validator-clean.XXXXXX")"
# Somewhere that is definitely not the source tree, so a stray relative import cannot resolve.
OUTSIDE="$(mktemp -d "${TMPDIR:-/tmp}/coretex-validator-outside.XXXXXX")"
trap 'rm -rf "$WORK" "$OUTSIDE"' EXIT

RPC=""; RELEASE=""; SNAPSHOT=""; ARTIFACT_DIR=""; EXPORT_TO=""; DEPTH=""
LAW_MIRROR=""; LAW_ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rpc) RPC="$2"; shift 2 ;;
    --release) RELEASE="$2"; shift 2 ;;
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --artifact-dir) ARTIFACT_DIR="$2"; shift 2 ;;
    --export) EXPORT_TO="$2"; shift 2 ;;
    --confirmation-depth) DEPTH="$2"; shift 2 ;;
    --law-mirror) LAW_MIRROR="$2"; shift 2 ;;
    --law-root) LAW_ROOT="$2"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if { [ -n "$LAW_MIRROR" ] && [ -z "$LAW_ROOT" ]; } || \
   { [ -z "$LAW_MIRROR" ] && [ -n "$LAW_ROOT" ]; }; then
  echo "--law-mirror and --law-root must be supplied together; no law root is inferred" >&2
  exit 2
fi

BUILD_PIP="24.3.1"
BUILD_FRONTEND="1.2.2.post1"
BUILD_SETUPTOOLS="75.3.0"
BUILD_WHEEL="0.44.0"
COMMIT="$(git -C "$REPO" rev-parse HEAD)"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" show -s --format=%ct "$COMMIT")}"
export SOURCE_DATE_EPOCH
CANONICAL_SOURCE="$WORK/source"
mkdir -p "$CANONICAL_SOURCE"
# Build exactly the COMMITTED python subtree. git-archive normalizes modes and excludes dirty
# workspace bytes; SOURCE_DATE_EPOCH plus the exact backend/frontend versions makes the release
# input and toolchain explicit rather than a property of this host's filesystem.
git -C "$REPO" archive --format=tar "$COMMIT:python" | tar -xf - -C "$CANONICAL_SOURCE"

echo "== 1. build a wheel from canonical committed bytes ======================"
echo "   commit=$COMMIT source_date_epoch=$SOURCE_DATE_EPOCH"
echo "   pip=$BUILD_PIP build=$BUILD_FRONTEND setuptools=$BUILD_SETUPTOOLS wheel=$BUILD_WHEEL"
python3 -m venv "$WORK/build"
"$WORK/build/bin/pip" install --quiet --upgrade \
  "pip==$BUILD_PIP" "build==$BUILD_FRONTEND" \
  "setuptools==$BUILD_SETUPTOOLS" "wheel==$BUILD_WHEEL"
"$WORK/build/bin/python" -m build --no-isolation --wheel --outdir "$WORK/dist" \
  "$CANONICAL_SOURCE" >/dev/null
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
cp -R "$CANONICAL_SOURCE/tests" "$OUTSIDE/tests"
( cd "$OUTSIDE" && "$WORK/clean/bin/python" -m pytest tests -q )

LAW_ARGS=()
if [ -n "$LAW_MIRROR" ]; then
  echo "== 6. fetch + VERIFY the published admission law ========================"
  # The cache goes inside the throwaway work dir, so this leg proves what a machine that started
  # with NOTHING can do — not what a machine with a warm ~/.local/share/coretex happens to have.
  LAW_CACHE="$WORK/law"
  SYNC=(sync-law --mirror "$LAW_MIRROR" --root "$LAW_ROOT" --cache-dir "$LAW_CACHE")
  ( cd "$OUTSIDE" && "$WORK/clean/bin/coretex-validator" "${SYNC[@]}" )
  LAW_ARGS=(--law-cache "$LAW_CACHE")
  LAW_ARGS+=(--law-root "$LAW_ROOT")
else
  echo "== 6. law sync SKIPPED =================================================="
  echo "   no --law-mirror given. Deterministic admission will BACKLOG rather"
  echo "   than run; that is honest, not broken. See docs/V5-RIG-VALIDATOR.md F4."
fi

if [ -n "$RPC" ]; then
  echo "== 7. replay the chain, steps 1-8 ======================================"
  ARGS=(reproduce --rpc "$RPC" "${LAW_ARGS[@]+"${LAW_ARGS[@]}"}")
  [ -n "$RELEASE" ] && ARGS+=(--release "$RELEASE")
  [ -n "$SNAPSHOT" ] && ARGS+=(--snapshot "$SNAPSHOT")
  [ -n "$ARTIFACT_DIR" ] && ARGS+=(--artifact-dir "$ARTIFACT_DIR")
  [ -n "$EXPORT_TO" ] && ARGS+=(--export "$EXPORT_TO")
  [ -n "$DEPTH" ] && ARGS+=(--confirmation-depth "$DEPTH")
  ( cd "$OUTSIDE" && "$WORK/clean/bin/coretex-validator" "${ARGS[@]}" )
else
  echo "== 7. chain replay SKIPPED =============================================="
  echo "   no --rpc given. The offline legs above prove the package installs"
  echo "   and runs clean; they prove nothing about any deployment."
fi

echo
echo "clean-machine reproduction finished."
