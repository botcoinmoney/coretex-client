# SPDX-License-Identifier: Apache-2.0
"""Prove this wheel's VENDORED law tree still says what the canonical law tree says.

WHY THIS EXISTS. ``coretex_validator`` is a standalone public validator: it must verify a
descriptor-v3 advance on a clean machine with no access to the private canonical repository, so it
carries its OWN copy of the law it decides against — the counter-resource law documents, the
canonical suite, the exact-parent authority, and hand-ported mirrors of the artifact layer and the
suite loader. That vendoring is maintained BY HAND. There is no build step that copies from
canonical, and for a long time there was no check either, which is exactly how it drifted:

  * ``COUNTER_RESOURCE_LAW.v1.json`` sat two revisions behind canonical — not merely pre-cut but
    an older document than the preserved walk-era one — so a cache populated by ``sync-law``
    carried a counter law matching NO artifact ever minted;
  * ``EXACT-PARENT-AUTHORITY.production.json`` was missing an entire code-root set, so frozen
    tier-1 historical receipts could not resolve;
  * the artifact layer's CLOSED field sets predated the law cut that added
    ``measurements.*.logical_durable_storage_bytes`` and ``replay_inputs.candidate_module_bytes``,
    so every artifact minted under the current law was rejected as malformed.

Each of those is a wrong VERDICT, not a cosmetic lag, and none of them announced itself. So the
vendored surface is now pinned by a manifest and checked two ways.

THE TWO MODES, AND WHAT EACH ACTUALLY PROVES.

``--check`` (offline; runs in the normal test suite via ``tests/test_law_vendoring.py``)
    Re-derives every vendored document's sha256 and every recorded law-bearing constant from the
    INSTALLED package and compares them to ``LAW-SYNC.v1.json``. This proves the vendored tree has
    not been edited away from its recorded provenance. It CANNOT prove the recorded provenance is
    still current, because the canonical tree is not present on a public machine — and pretending
    otherwise is the failure this file exists to stop, so it does not pretend.

``--canonical PATH`` (cross-repo; run wherever the canonical release tree is checked out)
    Compares the manifest — and therefore, transitively, the vendored tree — to the canonical tree
    itself: document bytes, law-bearing constant values, and the recorded canonical commit. THIS
    is the mode that detects "canonical moved and nobody re-vendored", and it is a standing
    obligation of every law cut, not an optional convenience.

``--write --canonical PATH`` regenerates the manifest from the canonical tree. It is deliberately
the only way to change a pinned value: a divergence is resolved by re-vendoring and regenerating,
never by editing the pin to match whatever the wheel currently holds.

Constants are read by IMPORTING both modules rather than by parsing them, because several of the
field sets are derived (``SIDE_FIELDS_V3 = tuple(sorted(SIDE_FIELDS + (...)))``) and a parser that
understood only literals would silently record nothing for exactly the entries that drifted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE_DIR = os.path.join(os.path.dirname(HERE), "coretex_validator")
MANIFEST_PATH = os.path.join(PACKAGE_DIR, "LAW-SYNC.v1.json")

MANIFEST_FORMAT = "coretex.client-law-vendoring/v1"

#: Vendored document -> its path inside the canonical release tree. These are DATA: the vendored
#: copy must be byte-identical to canonical, and any difference is a defect rather than a port
#: decision. (A hand-ported *module* cannot be byte-compared — see :data:`MIRRORED_MODULES`.)
VENDORED_DOCUMENTS: Tuple[Tuple[str, str], ...] = (
    ("COUNTER_RESOURCE_LAW.v1.json", "v5/COUNTER_RESOURCE_LAW.v1.json"),
    ("COUNTER_RESOURCE_LAW.walk-era.v1.json", "v5/COUNTER_RESOURCE_LAW.walk-era.v1.json"),
    ("CANONICAL-SUITE.v1.json", "benchmark-v2/validator/CANONICAL-SUITE.v1.json"),
    ("EXACT-PARENT-AUTHORITY.production.json",
     "benchmark-v2/validator/EXACT-PARENT-AUTHORITY.production.json"),
)

#: Hand-ported module -> (canonical module path, the law-bearing symbols that must agree).
#:
#: These modules are NOT byte-identical to canonical and are not supposed to be: the client port
#: drops the minting/worker halves and adds chain-side capability canonical has no use for. What
#: must agree is the LAW they encode — the closed schemas, the protected vocabularies and the
#: fixed identities — because those are what decide a verdict. A symbol listed here is a symbol a
#: divergence in which would change what this validator accepts.
MIRRORED_MODULES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "coretex_validator.eval_artifact": ("v5/eval_artifact.py", (
        # --- closed artifact schemas -------------------------------------------------------- #
        "ARTIFACT_FIELDS",
        "ARTIFACT_FIELDS_V3",
        "OPTIONAL_ARTIFACT_FIELDS",
        "MEASUREMENT_FIELDS",
        "SIDE_FIELDS",
        "SIDE_FIELDS_V3",
        "REPLAY_INPUT_FIELDS",
        "REPLAY_INPUT_FIELDS_V3",
        "RECEIPT_FIELDS",
        "RECEIPT_FIELDS_V1_SIGNED_ERA",
        "INCUMBENT_FIELDS",
        "INCUMBENT_EXACT_FIELDS",
        "RESOURCE_ACCOUNTING_FIELDS",
        "VERDICT_FIELDS",
        "CANARY_FIELDS",
        "COUNTER_LAW_FIELDS",
        "CASE_FIELDS",
        "SELECTION_FIELDS",
        # --- the dominance vector and its witness ------------------------------------------- #
        "VECTOR_FIELDS",
        "MEASURABLE_VECTOR_FIELDS",
        "DETERMINISM_WITNESS_FIELDS",
        "WITNESS_SOURCE_KINDS",
        "BRIDGE_VECTOR_FORMAT",
        "BRIDGE_VECTOR_FIELDS",
        # --- fixed identities ---------------------------------------------------------------- #
        "ARTIFACT_FORMAT",
        "ARTIFACT_FORMAT_V3",
        "FIXED_SUITE_LAW_ID",
        "SELECTION_LABELS",
        "MICRO",
        "MAX_UINT32",
        "MAX_UINT64",
    )),
    "coretex_validator.canonical_suite": ("v5/canonical_suite.py", (
        "HARD_GATE_VOCABULARY",
        "PROTECTED_QUALITY_VOCABULARY",
        "FIXED_SUITE_ROUND_ID",
        "FIXED_SUITE_AUTHOR_ID",
        "FIXED_SUITE_ENTROPY_DOMAIN",
        "SUITE_FORMAT",
        "SUITE_FIELDS",
        "PROFILE_FIELDS",
        "CASE_FIELDS",
        "PARTITIONS",
        "CANONICAL_SUITE_INVALID",
        "GENESIS_FLOOR_PENDING",
    )),
}


class LawSyncError(RuntimeError):
    """The vendored law tree disagrees with its recorded provenance, or with canonical."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _normalize(value: Any) -> Any:
    """A JSON-comparable shape for a constant, order-preserving where order is meaning.

    Tuples become lists (JSON has one sequence type). Sets become SORTED lists, because a set's
    iteration order is not part of its value and a manifest that recorded it would fail at random.
    Everything else must already be JSON-representable; anything exotic is refused rather than
    stringified, so a symbol whose value this cannot capture is never silently "checked".
    """
    if isinstance(value, tuple) or isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_normalize(item) for item in value)
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise LawSyncError(
        f"cannot pin a {type(value).__name__} — extend _normalize deliberately rather than "
        "letting a law-bearing constant go unchecked")


def _import_client_module(name: str):
    """Import a vendored module, preferring an INSTALLED ``coretex_validator`` if one is present.

    Falling back to the source tree beside this script is what lets the check run from a checkout
    (and from ``--write``) without an install; it is a fallback rather than the default so that a
    clean-install run really does check the installed wheel's bytes.
    """
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        source_root = os.path.dirname(PACKAGE_DIR)
        if source_root not in sys.path:
            sys.path.insert(0, source_root)
        return importlib.import_module(name)


def _import_canonical_module(canonical_root: str, relpath: str):
    """Import a canonical module by path, with its own directory first on ``sys.path``.

    The canonical modules use flat imports (``import frontier as fr``) resolved against their own
    package directory, so that directory goes on the path — and comes off again, because leaving
    it there would let a later import in the same process resolve a canonical module in place of
    the vendored one, which is the precise confusion this script exists to detect.
    """
    path = os.path.join(canonical_root, relpath)
    if not os.path.isfile(path):
        raise LawSyncError(f"canonical tree has no {relpath} (looked in {canonical_root})")
    directory = os.path.dirname(path)
    module_name = "_canonical_" + os.path.splitext(os.path.basename(path))[0]
    sys.path.insert(0, directory)
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:            # pragma: no cover - unreachable
            raise LawSyncError(f"cannot load {relpath}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(directory)
        except ValueError:                                 # pragma: no cover - defensive
            pass
        sys.modules.pop(module_name, None)


def _symbols(module, names: Tuple[str, ...], where: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    missing: List[str] = []
    for name in names:
        if not hasattr(module, name):
            missing.append(name)
            continue
        out[name] = _normalize(getattr(module, name))
    if missing:
        raise LawSyncError(
            f"{where} does not define {missing} — a law-bearing symbol that exists on one side "
            "and not the other IS the drift, so this is a failure rather than a skip")
    return out


def build_manifest(canonical_root: str) -> Dict[str, Any]:
    """Derive the manifest FROM CANONICAL. Canonical is the authority; this records it."""
    documents = []
    for vendored, canonical_relpath in VENDORED_DOCUMENTS:
        canonical_path = os.path.join(canonical_root, canonical_relpath)
        if not os.path.isfile(canonical_path):
            raise LawSyncError(f"canonical tree has no {canonical_relpath}")
        documents.append({
            "vendored": vendored,
            "canonical": canonical_relpath,
            "sha256": _sha256(_read(canonical_path)),
        })
    modules = {}
    for module_name, (canonical_relpath, names) in sorted(MIRRORED_MODULES.items()):
        module = _import_canonical_module(canonical_root, canonical_relpath)
        modules[module_name] = {
            "canonical": canonical_relpath,
            "symbols": _symbols(module, names, canonical_relpath),
        }
    return {
        "format": MANIFEST_FORMAT,
        "canonical_commit": _git_commit(canonical_root),
        "documents": documents,
        "modules": modules,
        "note": (
            "Generated by tools/check_law_sync.py --write --canonical <canonical release tree>. "
            "Canonical is the authority; this file records what it said, and "
            "tests/test_law_vendoring.py fails if the vendored tree stops matching. Regenerate at "
            "every law cut and re-run with --canonical; NEVER hand-edit a pin to make a check "
            "pass."
        ),
    }


def _git_commit(root: str) -> str:
    try:
        out = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):          # pragma: no cover - no git available
        return "unknown"
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def load_manifest() -> Dict[str, Any]:
    if not os.path.isfile(MANIFEST_PATH):
        raise LawSyncError(f"no vendoring manifest at {MANIFEST_PATH}")
    manifest = json.loads(_read(MANIFEST_PATH).decode("utf-8"))
    if manifest.get("format") != MANIFEST_FORMAT:
        raise LawSyncError(
            f"vendoring manifest format {manifest.get('format')!r} is not {MANIFEST_FORMAT!r}")
    return manifest


def check_vendored(manifest: Dict[str, Any]) -> List[str]:
    """OFFLINE: the installed package still matches its recorded provenance."""
    problems: List[str] = []

    pinned_documents = {entry["vendored"]: entry for entry in manifest["documents"]}
    expected_documents = {vendored for vendored, _ in VENDORED_DOCUMENTS}
    if set(pinned_documents) != expected_documents:
        problems.append(
            f"manifest pins documents {sorted(pinned_documents)}; this validator vendors "
            f"{sorted(expected_documents)}")
    for vendored, entry in sorted(pinned_documents.items()):
        path = os.path.join(PACKAGE_DIR, vendored)
        if not os.path.isfile(path):
            problems.append(f"{vendored}: vendored copy is missing from the package")
            continue
        observed = _sha256(_read(path))
        if observed != entry["sha256"]:
            problems.append(
                f"{vendored}: vendored bytes hash to {observed}, the manifest pins "
                f"{entry['sha256']} (canonical {entry['canonical']})")

    pinned_modules = manifest["modules"]
    if set(pinned_modules) != set(MIRRORED_MODULES):
        problems.append(
            f"manifest pins modules {sorted(pinned_modules)}; this validator mirrors "
            f"{sorted(MIRRORED_MODULES)}")
    for module_name, entry in sorted(pinned_modules.items()):
        if module_name not in MIRRORED_MODULES:
            continue
        module = _import_client_module(module_name)
        for name, expected in sorted(entry["symbols"].items()):
            if not hasattr(module, name):
                problems.append(f"{module_name}.{name} is missing from the vendored mirror")
                continue
            observed = _normalize(getattr(module, name))
            if observed != expected:
                problems.append(
                    f"{module_name}.{name} is {observed!r}; the manifest pins {expected!r} "
                    f"(canonical {entry['canonical']})")
    return problems


def check_against_canonical(manifest: Dict[str, Any], canonical_root: str) -> List[str]:
    """CROSS-REPO: the recorded provenance is still what canonical says today."""
    problems: List[str] = []
    current = build_manifest(canonical_root)

    for entry, observed in zip(manifest["documents"], current["documents"]):
        if entry["vendored"] != observed["vendored"]:      # pragma: no cover - order is generated
            problems.append("manifest document order does not match; regenerate it")
            continue
        if entry["sha256"] != observed["sha256"]:
            problems.append(
                f"{entry['vendored']}: manifest pins {entry['sha256']}, canonical "
                f"{observed['canonical']} now hashes to {observed['sha256']} — RE-VENDOR")

    for module_name, observed_entry in sorted(current["modules"].items()):
        pinned_entry = manifest["modules"].get(module_name)
        if pinned_entry is None:
            problems.append(f"manifest pins no symbols for {module_name}")
            continue
        for name, observed in sorted(observed_entry["symbols"].items()):
            expected = pinned_entry["symbols"].get(name, _MISSING)
            if expected is _MISSING:
                problems.append(f"manifest pins no value for {module_name}.{name}")
            elif expected != observed:
                problems.append(
                    f"{module_name}.{name}: manifest pins {expected!r}, canonical "
                    f"{observed_entry['canonical']} now defines {observed!r} — RE-VENDOR")

    recorded = manifest.get("canonical_commit")
    observed_commit = current["canonical_commit"]
    if recorded != observed_commit and "unknown" not in (recorded, observed_commit):
        problems.append(
            f"NOTE: manifest was generated at canonical {recorded}, this tree is at "
            f"{observed_commit}. Every pinned value above still agrees, so this is a stale "
            "provenance note rather than a law divergence — regenerate to clear it.")
    return problems


_MISSING = object()


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--canonical", metavar="PATH",
                        help="canonical release tree; enables the cross-repo comparison")
    parser.add_argument("--write", action="store_true",
                        help="regenerate the manifest from --canonical")
    args = parser.parse_args(argv)

    if args.write:
        if not args.canonical:
            parser.error("--write needs --canonical")
        manifest = build_manifest(args.canonical)
        with open(MANIFEST_PATH, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {MANIFEST_PATH} from canonical {manifest['canonical_commit']}")
        return 0

    manifest = load_manifest()
    problems = check_vendored(manifest)
    scope = "vendored tree vs recorded provenance"
    if args.canonical:
        problems += check_against_canonical(manifest, args.canonical)
        scope += " AND recorded provenance vs canonical"

    fatal = [p for p in problems if not p.startswith("NOTE:")]
    for problem in problems:
        print(("NOTE  " if problem.startswith("NOTE:") else "DRIFT ") + problem, file=sys.stderr)
    if fatal:
        print(f"\nLAW SYNC FAILED ({len(fatal)} divergence(s)): {scope}", file=sys.stderr)
        return 1
    print(f"law sync OK: {scope}")
    return 0


if __name__ == "__main__":                                 # pragma: no cover
    sys.exit(main(sys.argv[1:]))
