# SPDX-License-Identifier: Apache-2.0
"""Preview a candidate against the CURRENT CONFIRMED PARENT, on public dev cases only.

THE GAP THIS CLOSES. The miner kit's ``kit/self_check.py`` scores a submission against the FROZEN
REFERENCE BASELINE — the initial release the benchmark shipped with. The live incumbent is whatever
has since won the frontier slot, and it has usually moved past that baseline. So a candidate can
pass the self-check comfortably and still LOSE the adjudicated comparison, because the adjudicator
compares it against the live parent, not against the reference. This command runs the same public
dev cases against the arm the adjudicator will actually put on the other side.

WHAT IT IS NOT. It is not an admission prediction and it must never read as one:

* the corpus here is the kit's PUBLIC dev seeds, resolved at runtime from the pinned tree's own
  ``kit/dev_instances.py``. The adjudicator draws CONFIRMATION cases from future public entropy
  over the full seed space — cases that do not exist yet and that nothing on a miner's machine can
  generate;
* the prerequisites the adjudicating host executes (portability above all) are not executed here
  unless explicitly asked for, so the frozen verdict's ``hard_ok`` is reported as-is rather than
  massaged into a pass;
* consequently the report's comparison is the PARETO comparison against the parent
  (``pareto_ok``), never "you will be admitted". ``predictsAdmission`` is a hard ``false`` in every
  report this module emits.

Losing to the current parent is INFORMATION, not an error: the command exits 0 either way, and
non-zero only when it could not run.

HOW THE PARENT IS AUTHENTICATED. Nothing here trusts a label. The confirmed frontier root is
resolved through the public content-addressed graph and every object is re-hashed under its own
rule before it is used:

    frontier manifest   sha256-frontier-canonical-json   (the root the caller named)
    composition         sha256-signed-manifest-body      (manifest.default_composition_root)
    release manifest    sha256-signed-manifest-body      (manifest.profiles[target_profile])
    module bytes        sha256-bytes                     (release.module_sha256)

then :func:`parent_execution.resolve_parent_execution` — the same public resolution the replay lane
uses — validates the composition graph, the schema-4 release law and the module identity, and
classifies the parent as ``reference`` or ``candidate_module``. That classification is EXACT ROOT
EQUALITY against the packaged ``EXACT-PARENT-AUTHORITY.production.json``; there is no similarity,
prefix or heuristic path to "this looks like the reference".

WHICH ARM GETS WHICH ENVELOPE. This is the subtle part, and it mirrors ``validator/evaluate.py``
exactly (``:562`` for the candidate arm, ``:419-434`` for the exact incumbent arm):

* the CANDIDATE arm runs with the CANDIDATE manifest's ``capabilities`` and its
  ``resource_requirements.max_compute_ms`` fuel ceiling;
* the PARENT arm runs with the PARENT RELEASE manifest's ``capabilities`` and
  ``resource_requirements.max_compute_ms`` — never the candidate's. A parent scored under the
  candidate's roster would be a different program from the one that actually holds the slot.

THE SCORING SEAM. Real scoring must happen inside the pinned law trees, in a child interpreter with
an allow-listed ``sys.path`` and an enforced+proven networkless filter — the same discipline
:mod:`replay`'s sandbox uses, for the same reasons (``benchmark-v2`` ships a package named
``frontier`` and so does this lane; and candidate code must never run unconfined). That child is
:class:`LawTreeChild`, and it is deliberately a SEAM: one callable, one JSON payload in, one JSON
result out, three modes (``probe``/``score``/``aggregate``). Everything above it — chain
resolution, arm construction, the comparison and the report — is plain data manipulation that a
test can drive with a fake child, so the parts that are ours are tested for real instead of being
gated behind a host that has ``wasmtime`` and a law cache.
"""
from __future__ import annotations

from collections import abc
from dataclasses import dataclass, field
import hashlib
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from . import parent_execution as pe
from . import publication as pub


REPORT_FORMAT = "coretex-validator/preview-current-parent/v1"

#: The four content-addressed hops between "a confirmed frontier root" and "the bytes the parent
#: arm executes". Named so a refusal can say WHICH hop disagreed.
STEP_FRONTIER = "frontier_manifest"
STEP_COMPOSITION = "composition_manifest"
STEP_RELEASE = "release_manifest"
STEP_MODULE = "module_bytes"
CHAIN_STEPS = (STEP_FRONTIER, STEP_COMPOSITION, STEP_RELEASE, STEP_MODULE)

DEFAULT_SCALE = "small"

#: Printed in every report, including refusals. The wording is load-bearing: a miner who reads
#: only this line must not come away thinking the number is an admission.
DISCLAIMER = (
    "This is a PREVIEW on the kit's PUBLIC dev cases only. It does NOT predict admission. The "
    "official evaluation re-runs on FRESH confirmation cases selected from future public entropy "
    "over the whole seed space — cases that do not exist yet and that this command cannot see — "
    "and applies the full composite law including the hard prerequisites (portability above all) "
    "that an adjudicating host executes and a local preview does not.")

#: The fixed-suite era's wording. It says the opposite of the line above, on purpose, because the
#: fact it describes is the opposite: the exam is immutable, public and identical for every
#: candidate, so the verdict this command computes is the verdict the adjudicator computes. What
#: is left is the chain race and the local hard prerequisites, and both are named rather than
#: hidden behind a blanket "this predicts nothing".
FIXED_SUITE_DISCLAIMER = (
    "This scores the IMMUTABLE CANONICAL SUITE — the same cases, in the same partitions, that "
    "the adjudicator scores for every candidate under this law — against the exact parent "
    "observed here, under the same componentwise engine and the same law-bound "
    "constructor-genesis floor. The verdict is therefore DETERMINISTIC and is the one the "
    "adjudicator will reach for THIS parent. Two things remain outside it: the CHAIN RACE (if "
    "another advance lands first, the next job's exact parent is a different release with a "
    "different stored vector), and any hard prerequisite this host did not execute — "
    "portability above all, which is reported as not established rather than assumed.")

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))

#: Mirrors ``replay.PINNED_RUNTIME_DEPENDENCIES``. Kept as its own literal so importing this module
#: never drags in ``replay`` — ``replay`` reads the law pins at IMPORT time, and pulling it in from
#: here would re-create exactly the import-ordering trap ``law.activate`` exists to refuse.
PINNED_RUNTIME_DEPENDENCIES = {"wasmtime": ">=46.0.1,<47"}


class PreviewError(Exception):
    """A named, actionable refusal. Never a silently degraded score."""

    def __init__(self, message: str, *, code: str, step: Optional[str] = None,
                 remedy: Optional[str] = None) -> None:
        super().__init__(message)
        self.code = code
        self.step = step
        self.remedy = remedy

    def as_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ok": False, "format": REPORT_FORMAT, "code": self.code, "reason": str(self),
            "publicDevCasesOnly": True, "predictsAdmission": False, "disclaimer": DISCLAIMER}
        if self.step:
            payload["step"] = self.step
        if self.remedy:
            payload["remedy"] = self.remedy
        return payload


def reference_release_roots() -> Dict[str, str]:
    """The initial-release roots that make a parent the frozen REFERENCE arm.

    Deliberately a passthrough to :mod:`parent_execution`, which loads them from the
    ``EXACT-PARENT-AUTHORITY.production.json`` shipped in the wheel. A second copy of this list
    would be a second authority, and the two would eventually disagree.
    """
    return pe.PRODUCTION_REFERENCE_RELEASE_ROOTS


# --------------------------------------------------------------------------- #
# 0. WHERE THE SCORING TREES COME FROM (two publications, not one)
# --------------------------------------------------------------------------- #
#: The ``benchmark-v2`` subtrees the law publication SEALS. These are code roots: their tree hash
#: is the identity ``evaluation_law.code_roots`` binds and a signed receipt commits to, so they
#: come from the verified law cache and from nowhere else.
SEALED_BENCH_SUBTREES: Tuple[str, ...] = (
    "frontier", "generators", "miner_abi", "scoring", "validator")

#: The ``benchmark-v2`` subtrees the law publication can NEVER carry, because they are not sealed
#: code roots at all (``v5/RUNTIME-INTEGRATION.production.json`` lists seven roots and neither of
#: these is one). They are still needed to SCORE:
#:
#:   ``kit``          ``self_check._aggregate``/``._measurements`` (the tree's own aggregation law)
#:                    and ``dev_instances`` (the published public dev set)
#:   ``integration``  ``portability_matrix`` — required in the canonical current miner-kit
#:
#: They arrive in the HASH-PINNED MINER-KIT TAR that ``setup`` downloads: the kit manifest binds
#: its sha256 and :func:`setup.download_kit_file` refuses bytes that disagree, so provenance holds
#: exactly as it does for the sealed trees — a different publication, verified a different way,
#: never an unpinned local checkout.
SUPPORT_BENCH_SUBTREES: Tuple[str, ...] = ("kit", "integration")

#: ``kit`` without these is not a scoring tree, so its presence is decided by the files the child
#: actually imports rather than by the directory existing.
KIT_REQUIRED_FILES: Tuple[str, ...] = ("self_check.py", "dev_instances.py")

#: Both are required by the one canonical current miner-kit. Retained frozen packet tarballs are
#: audit material and never participate in selection.
REQUIRED_SUPPORT_SUBTREES: Tuple[str, ...] = ("kit", "integration")

#: How ``setup`` names the extracted miner-kit tar under the packages directory.
KIT_TAR_PREFIX = "coretex-validator-miner-kit-"
#: ``setup.maybe_extract_tars`` writes this marker, holding the tar's verified sha256.
KIT_EXTRACTED_MARKER = ".extracted"


def default_packages_dir() -> str:
    """Where ``setup`` caches the kit packages. Imported lazily so this module stays standalone."""
    from . import setup as su

    return su.default_packages_dir()


def extraction_tree_sha256(root: str) -> str:
    """The setup extraction identity, imported lazily to avoid a second hashing rule."""
    from . import setup as su

    return su.extraction_tree_sha256(root)


def extracted_kit_trees(packages_dir: Optional[str] = None, *,
                        active_install: Optional[Mapping[str, Any]] = None) -> List[Dict[str, str]]:
    """Load only the miner-kit bound by the active install tuple, rechecking bytes on every use.

    Retained package directories are a cache, not a version selector.  No active tuple means no
    implicit kit.  A tuple whose archive, extraction marker or extracted bytes changed is refused
    rather than falling through to another directory.
    """
    base = os.path.abspath(os.path.expanduser(packages_dir or default_packages_dir()))
    if active_install is None:
        return []
    miner = active_install.get("miner_kit") if isinstance(active_install, Mapping) else None
    if not isinstance(miner, Mapping):
        raise PreviewError("the active install does not bind a miner-kit",
                           code="KIT_BINDING_INVALID", step="miner_kit")
    filename = miner.get("filename")
    archive_sha = miner.get("sha256")
    tree_sha = miner.get("tree_sha256")
    expected_name = f"{KIT_TAR_PREFIX}{archive_sha}.tar"
    if (not isinstance(archive_sha, str) or len(archive_sha) != 64
            or any(ch not in "0123456789abcdef" for ch in archive_sha)
            or not isinstance(tree_sha, str) or len(tree_sha) != 64
            or any(ch not in "0123456789abcdef" for ch in tree_sha)
            or filename != expected_name):
        raise PreviewError("the active miner-kit identity is malformed",
                           code="KIT_BINDING_INVALID", step="miner_kit")
    archive = os.path.join(base, filename)
    tree = os.path.join(base, os.path.splitext(filename)[0])
    marker_path = os.path.join(tree, KIT_EXTRACTED_MARKER)
    try:
        with open(archive, "rb") as handle:
            observed_archive = hashlib.sha256(handle.read()).hexdigest()
        with open(marker_path, "r", encoding="utf-8") as handle:
            marker = json.load(handle)
        observed_tree = extraction_tree_sha256(tree)
    except (OSError, ValueError, RuntimeError) as exc:
        raise PreviewError(
            f"the active miner-kit cannot be verified: {exc}", code="KIT_BINDING_INVALID",
            step="miner_kit", remedy="re-run `coretex-validator setup` to repair the active tuple") \
            from exc
    from . import setup as su
    if (observed_archive != archive_sha or not isinstance(marker, Mapping)
            or marker.get("format") != su.KIT_EXTRACTION_FORMAT
            or marker.get("archive_sha256") != archive_sha
            or marker.get("tree_sha256") != tree_sha or observed_tree != tree_sha):
        raise PreviewError(
            "the active miner-kit archive or extracted bytes no longer match the activated tuple",
            code="KIT_BINDING_INVALID", step="miner_kit",
            remedy="re-run `coretex-validator setup` to verify and repair the current kit")
    bench = os.path.join(tree, "benchmark-v2")
    return [{"tree": tree, "bench_v2_dir": bench, "sha256": archive_sha,
             "tar": filename}]


@dataclass(frozen=True)
class TreeResolution:
    """Which directory supplies each ``benchmark-v2`` subtree the scoring child imports.

    The composition is PATH LAYERING, not a merge: :attr:`support_dirs` are appended AFTER the
    sealed ``benchmark-v2`` directory, so the sealed tree wins every module name it defines and the
    kit tar can only ever supply names the seal does not carry. That ordering is the whole safety
    property — the kit tar also ships older ``frontier``/``scoring``/``miner_abi`` copies, and a
    preview scored inside those would be a number the adjudicator never computes.
    """

    bench_v2_dir: str
    coretex_dir: str
    support_dirs: Tuple[str, ...] = ()
    sources: Dict[str, str] = field(default_factory=dict)
    missing_required: Tuple[str, ...] = ()
    missing_optional: Tuple[str, ...] = ()
    kit_tars: Tuple[str, ...] = ()
    packages_dir: str = ""

    @property
    def sealed_ok(self) -> bool:
        return (bool(self.bench_v2_dir) and bool(self.coretex_dir)
                and all(name in self.sources for name in SEALED_BENCH_SUBTREES))

    @property
    def ok(self) -> bool:
        return self.sealed_ok and not self.missing_required

    def as_dict(self) -> Dict[str, Any]:
        """The availability report. Internally consistent BY CONSTRUCTION: it says separately
        whether the sealed law is present and whether the unsealed support trees are, so a refusal
        can never read as "the law is active" and "the law trees are missing" at the same time."""
        return {
            "sealed_trees_present": self.sealed_ok,
            "sufficient_for_scoring": self.ok,
            "sealed_subtrees": list(SEALED_BENCH_SUBTREES),
            "unsealed_support_trees": list(SUPPORT_BENCH_SUBTREES),
            "missing_required": list(self.missing_required),
            "missing_optional": list(self.missing_optional),
            "sources": {name: self.sources[name] for name in sorted(self.sources)},
            "support_dirs": list(self.support_dirs),
            "kit_tars": list(self.kit_tars),
            "packages_dir": self.packages_dir,
            "note": ("the five sealed benchmark-v2 subtrees and coretex-memory come from the "
                     "verified law cache; kit and integration are NOT sealed code roots and can "
                     "never be in a law publication, so they come from the hash-pinned miner-kit "
                     "tar `setup` downloads"),
        }


def _subtree_present(bench_dir: str, name: str) -> bool:
    path = os.path.join(bench_dir, name)
    if not os.path.isdir(path):
        return False
    if name == "kit":
        return all(os.path.isfile(os.path.join(path, f)) for f in KIT_REQUIRED_FILES)
    return True


def resolve_scoring_trees(*, bench_v2_dir: str, coretex_dir: str,
                          packages_dir: Optional[str] = None,
                          kit_bench_dirs: Optional[List[str]] = None,
                          active_install: Optional[Mapping[str, Any]] = None) -> TreeResolution:
    """Compose the scoring child's tree view out of the law cache PLUS the miner-kit tar.

    A ``--repo-root`` that already carries ``kit``/``integration`` (a full checkout) resolves them
    from itself and needs no tar; that is why the sealed directory is searched first for the
    support subtrees too.
    """
    bench_v2_dir = (bench_v2_dir or "").strip()
    coretex_dir = (coretex_dir or "").strip()
    packages_dir = os.path.abspath(os.path.expanduser(packages_dir or default_packages_dir()))
    sources: Dict[str, str] = {}
    # `bool(dir)` FIRST — an unconfigured tree is "" and `os.path.join("", x)` is a RELATIVE path a
    # stray working directory could satisfy (the `replay.py` discipline).
    if bench_v2_dir:
        for name in SEALED_BENCH_SUBTREES + SUPPORT_BENCH_SUBTREES:
            if _subtree_present(bench_v2_dir, name):
                sources[name] = bench_v2_dir
    needs_support = any(name not in sources for name in SUPPORT_BENCH_SUBTREES)
    kits = ([{"bench_v2_dir": d, "sha256": "", "tar": ""} for d in kit_bench_dirs]
            if kit_bench_dirs is not None else
            extracted_kit_trees(packages_dir, active_install=active_install)
            if needs_support else [])
    support_dirs: List[str] = []
    for name in SUPPORT_BENCH_SUBTREES:
        if name in sources:
            continue
        for kit in kits:
            if _subtree_present(kit["bench_v2_dir"], name):
                sources[name] = kit["bench_v2_dir"]
                if kit["bench_v2_dir"] not in support_dirs:
                    support_dirs.append(kit["bench_v2_dir"])
                break
    missing_required = tuple(n for n in REQUIRED_SUPPORT_SUBTREES if n not in sources)
    missing_optional = tuple(n for n in SUPPORT_BENCH_SUBTREES
                             if n not in sources and n not in missing_required)
    return TreeResolution(
        bench_v2_dir=bench_v2_dir, coretex_dir=coretex_dir,
        support_dirs=tuple(support_dirs), sources=sources,
        missing_required=missing_required, missing_optional=missing_optional,
        kit_tars=tuple(k["sha256"] for k in kits if k["sha256"]),
        packages_dir=packages_dir)


def require_scoring_trees(resolution: TreeResolution) -> TreeResolution:
    """Raise a refusal whose remedy is ACHIEVABLE, or return the resolution unchanged.

    The shipped command answered a missing ``kit`` with "run `coretex-validator sync-law`" — which
    the reader had already done, and which could never have worked: ``kit`` is not a sealed code
    root, so no publication can contain it. A remedy that cannot be followed is worse than none,
    because it sends the reader round the same loop.
    """
    if resolution.ok:
        return resolution
    if not resolution.sealed_ok:
        wanted = ", ".join(f"{resolution.bench_v2_dir or '(unset)'}/{n}"
                           for n in SEALED_BENCH_SUBTREES)
        raise PreviewError(
            f"the sealed law trees are not provisioned on this host (need {wanted} and "
            f"{resolution.coretex_dir or '(unset)'})",
            code="SCORER_UNAVAILABLE",
            remedy="run `coretex-validator setup` (it discovers and installs the published law)")
    missing = ", ".join(f"benchmark-v2/{n}" for n in resolution.missing_required)
    raise PreviewError(
        f"the sealed law trees ARE installed, but the scoring child also needs {missing}, which "
        "is not a sealed code root and therefore can never be in a law publication. It ships in "
        "the miner-kit tar instead, and no verified copy of that tar was found under "
        f"{resolution.packages_dir or '(no packages directory)'}",
        code="SUPPORT_TREES_UNAVAILABLE",
        remedy=("run `coretex-validator setup` — it downloads and hash-verifies the miner-kit tar "
                f"({KIT_TAR_PREFIX}<sha256>.tar, pinned by the coordinator kit manifest) and "
                "extracts benchmark-v2/kit beside the law cache; or pass --packages-dir at the "
                "directory holding an already-extracted one"))


# --------------------------------------------------------------------------- #
# 1. resolve + re-hash the parent chain
# --------------------------------------------------------------------------- #
def _fetch(step: str, root: str, *, hash_rule: str, store: pub.ContentStore) -> Any:
    """One hop, re-hashed. Every failure carries the step that failed."""
    try:
        fr.check_root(root, step)
        if hash_rule == pub.HASH_RULE_BYTES:
            return pub.read_back(root, hash_rule=hash_rule, store=store)
        return pub.fetch_json(root, hash_rule=hash_rule, store=store)
    except (pub.PublicationError, fr.FrontierError) as exc:
        raise PreviewError(
            f"{step}: {exc}", code="PARENT_CHAIN_UNVERIFIED", step=step,
            remedy=("point --artifact-dir / --artifact-base-url at a publication surface that "
                    "serves the objects the confirmed frontier root names")) from exc


def resolve_parent(*, store: pub.ContentStore, parent_root: str,
                   target_profile: str) -> Dict[str, Any]:
    """Authenticate the confirmed parent's executable for one profile, hop by hop.

    Returns the resolved execution plus a ``chain`` listing every root and the rule it was
    re-hashed under, so the report can show what was actually checked rather than asserting it.
    """
    manifest = _fetch(STEP_FRONTIER, parent_root, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                      store=store)
    if not isinstance(manifest, abc.Mapping):
        raise PreviewError("the frontier root does not address a JSON object",
                           code="PARENT_CHAIN_UNVERIFIED", step=STEP_FRONTIER)
    profiles = manifest.get("profiles")
    if not isinstance(profiles, abc.Mapping) or target_profile not in profiles:
        raise PreviewError(
            f"the confirmed parent frontier has no slot for {target_profile!r}",
            code="PARENT_CHAIN_UNVERIFIED", step=STEP_FRONTIER)

    composition_root = manifest.get("default_composition_root")
    composition = _fetch(STEP_COMPOSITION, composition_root,
                         hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    release_root = profiles.get(target_profile)
    release_manifest = _fetch(STEP_RELEASE, release_root,
                              hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    module_root = release_manifest.get("module_sha256") \
        if isinstance(release_manifest, abc.Mapping) else None
    module_bytes = _fetch(STEP_MODULE, module_root, hash_rule=pub.HASH_RULE_BYTES, store=store)

    try:
        execution = pe.resolve_parent_execution(
            parent_manifest=manifest, target_profile=target_profile,
            parent_composition=composition, parent_release_manifest=release_manifest,
            parent_module_bytes=module_bytes)
    except pe.ParentExecutionError as exc:
        raise PreviewError(str(exc), code="PARENT_CHAIN_UNVERIFIED", step=STEP_MODULE) from exc

    return {
        "parent_root": parent_root,
        "target_profile": target_profile,
        "epoch": manifest.get("epoch"),
        "composition_root": composition_root,
        "execution": execution,
        "chain": [
            {"step": STEP_FRONTIER, "root": parent_root,
             "hash_rule": pub.HASH_RULE_FRONTIER_JSON},
            {"step": STEP_COMPOSITION, "root": composition_root,
             "hash_rule": pub.HASH_RULE_SIGNED_MANIFEST_BODY},
            {"step": STEP_RELEASE, "root": release_root,
             "hash_rule": pub.HASH_RULE_SIGNED_MANIFEST_BODY},
            {"step": STEP_MODULE, "root": module_root, "hash_rule": pub.HASH_RULE_BYTES},
        ],
    }


# --------------------------------------------------------------------------- #
# 2. the two arms, each with ITS OWN envelope
# --------------------------------------------------------------------------- #
def _fuel_ceiling(limits: Any) -> Optional[int]:
    """``validator/evaluate.py``'s rule verbatim: 0/absent means "the pinned default", not 0."""
    if not isinstance(limits, abc.Mapping):
        return None
    raw = limits.get("max_compute_ms")
    if raw in (None, "", False):
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value or None


def _capabilities(value: Any, where: str) -> List[str]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(c, str) or not c
                                                   for c in value):
        raise PreviewError(
            f"{where} must declare a list of capability ids; the evaluator and production serving "
            "expose the same granted roster, so it cannot be inferred here",
            code="CANDIDATE_MANIFEST_INVALID" if "candidate" in where
                 else "PARENT_CHAIN_UNVERIFIED")
    return list(value)


def build_candidate_arm(*, module_source: str, manifest: Mapping[str, Any]) -> Dict[str, Any]:
    """The candidate arm: the CANDIDATE manifest's roster and ceiling (evaluate.py :562)."""
    if not isinstance(manifest, abc.Mapping):
        raise PreviewError("the candidate manifest must be a JSON object",
                           code="CANDIDATE_MANIFEST_INVALID")
    if not isinstance(module_source, str) or not module_source:
        raise PreviewError("the candidate module must be non-empty UTF-8 Python source",
                           code="CANDIDATE_MODULE_INVALID")
    sha256 = hashlib.sha256(module_source.encode("utf-8")).hexdigest()
    declared = manifest.get("module_sha256")
    if isinstance(declared, str) and declared and declared != sha256:
        raise PreviewError(
            f"the candidate manifest declares module_sha256 {declared} but the module on disk "
            f"hashes to {sha256}", code="CANDIDATE_MANIFEST_INVALID")
    return {"kind": "module", "source": module_source, "sha256": sha256,
            "capabilities": _capabilities(manifest.get("capabilities"), "candidate manifest"),
            "fuel_ceiling": _fuel_ceiling(manifest.get("resource_requirements"))}


def build_parent_arm(execution: Mapping[str, Any]) -> Dict[str, Any]:
    """The parent arm.

    ``reference`` runs the frozen reference runtime and has no module, roster or ceiling of its
    own. ``candidate_module`` runs the parent's OWN release envelope — ``evaluate.py``'s
    ``_score_exact_incumbent`` (:419-434), not the candidate's declaration.
    """
    if execution.get("exec") == "reference":
        return {"kind": "reference"}
    release_manifest = execution.get("release_manifest") or {}
    module = execution.get("module") or {}
    return {"kind": "module", "source": module.get("source"), "sha256": module.get("sha256"),
            "capabilities": _capabilities(release_manifest.get("capabilities"),
                                          "parent release manifest"),
            "fuel_ceiling": _fuel_ceiling(release_manifest.get("resource_requirements"))}


# --------------------------------------------------------------------------- #
# 3. the scoring seam
# --------------------------------------------------------------------------- #
#: THE CHILD. Same shape as ``replay._SANDBOX_CHILD``: an allow-listed ``sys.path`` built from
#: scratch (the pinned trees plus the verified interpreter's stdlib/site-packages, and NOTHING
#: ambient), a dependency preflight that fails with a named error instead of a shrug, and the
#: networkless filter installed AND proven before a single line of miner code runs.
#:
#: Three modes, one process each:
#:   probe      read DEV_SEEDS/DEV_SCALES/profile ids out of the pinned kit. The published dev set
#:              is the TREE's, never a constant copied into this client.
#:   score      one dev instance, both arms, one process — one wasm world per process, the same
#:              discipline ``kit/self_check.py`` uses for its per-instance workers.
#:   aggregate  fold the per-instance rows and decide, through the tree's OWN aggregation
#:              (``kit.self_check``) and its OWN Pareto law (``frontier.pareto2``). This client
#:              does not own a second scoring or comparison law.
#: Defensive ``integration`` shim, mirrored from ``benchmark-v2/kit/self_check.py``.
#:
#: Canonical active tuples require the real integration tree before starting the child. This shim
#: remains only for an explicit noncanonical test harness, where absence must be NOT EXECUTED
#: evidence rather than a fabricated pass.
#:
#: FAIL CLOSED either way: ``ok`` is False and ``executed`` is False, so the hard gate rejects. It
#: is kept as its own source string so a test can execute it against a controlled ``sys.path``
#: instead of inferring the behaviour from the text of a bigger child.
PORTABILITY_SHIM_SOURCE = r'''
def _local_portability(breadth):
    """Portability-prerequisite evidence for a LOCAL preview (LAW 3.1 gate 7)."""
    try:
        from integration import portability_matrix as _pm
    except ModuleNotFoundError as _exc:
        if getattr(_exc, "name", None) not in (None, "integration") \
                and "integration" not in str(_exc):
            raise
        return {
            "executed": False,
            "ok": False,
            "missing_module": "integration",
            "reason":
                "benchmark-v2/integration is not on sys.path; portability was NOT executed "
                "locally (canonical current kits are refused before this point).",
            "reason_code": "portability_prerequisite_not_executed_locally",
            "breadth": breadth,
        }
    if breadth is None:
        return _pm.not_executed(
            "preview-current-parent did not run the support matrix (pass --portability to "
            "execute it); the adjudicating host executes it for real")
    try:
        return _pm.run_matrix(breadth=breadth)
    except Exception as _exc:                             # noqa: BLE001 - fail closed
        return _pm.not_executed(type(_exc).__name__ + ": " + str(_exc), breadth=breadth)
'''

_PREVIEW_CHILD = r'''
import json, sys
import importlib.util, os as _os, site as _site, sysconfig as _sysconfig, tempfile
_allowed = [{bench!r}] + list({support!r}) + [{coretex!r}]
for _key in ("stdlib", "platstdlib"):
    _p = _sysconfig.get_path(_key)
    if _p:
        _allowed.append(_p)
        _allowed.append(_os.path.join(_p, "lib-dynload"))
try:
    _allowed.extend(_site.getsitepackages())
except AttributeError:                                # pragma: no cover - virtualenv shim
    pass
_seen = set()
sys.path[:] = [p for p in _allowed
               if p and p not in _seen and not _seen.add(p) and _os.path.isdir(p)]
{shim}
payload = json.loads(sys.stdin.read())
mode = payload["mode"]

if mode != "probe":
    for _dependency in ("wasmtime",):
        try:
            __import__(_dependency)
        except ImportError as _exc:
            print("<<<MISSING_DEPENDENCY>>>" + json.dumps(
                {{"dependency": _dependency, "detail": str(_exc)}}))
            raise SystemExit(97)

_proof = None
if mode == "score":
    # Fail CLOSED: miner bytes (the candidate's AND the parent's) never execute unconfined.
    _spec = importlib.util.spec_from_file_location("v5_worker_isolation", {isolation!r})
    _iso = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_iso)
    _install = _iso.apply_networkless()
    _proof = _iso.prove_networkless(install=_install)

if mode == "probe":
    from generators import GENERATOR_PROFILE_IDS
    from kit.dev_instances import DEV_SCALES, DEV_SEEDS
    out = {{"dev_seeds": [int(s) for s in DEV_SEEDS], "dev_scales": list(DEV_SCALES),
            "profiles": list(GENERATOR_PROFILE_IDS)}}
    # THE ERA IS READ OFF THE PINNED LAW TREES, never off this client's build. If the installed
    # `validator` tree carries a canonical suite and the installed `frontier` tree carries the
    # componentwise engine, then the deployment being previewed against decides under the
    # fixed-suite law and the preview must score that exam. If they are absent, this is a
    # walk-era deployment and the public dev cases remain the only honest preview.
    try:
        from validator import canonical_suite as _cs
        from frontier import dominance as _dom
        out["law_era"] = "fixed-suite"
        out["suite_root"] = _cs.suite_root()
        out["suite_law_id"] = _cs.suite_law_id()
        out["suite_version"] = str(_cs.suite_version())
        out["dominance_engine"] = _dom.ENGINE_ID
        out["genesis_floor_resolved"] = bool(_cs.genesis_floor_resolved())
        _pid = payload.get("profile_id")
        if _pid:
            out["suite_cases"] = _cs.suite_cases(_pid)
            out["suite_case_hashes"] = _cs.suite_case_hashes(_pid)
            out["suite_scales"] = list(_cs.suite_scales(_pid))
            out["suite_counts"] = dict(_cs.suite_counts(_pid))
    except Exception as _exc:
        out["law_era"] = "walk"
        out["law_era_reason"] = type(_exc).__name__ + ": " + str(_exc)
elif mode == "score":
    from kit.dev_instances import dev_instance
    from miner_abi import seam as _seam
    from scoring import layer_b as _layer_b
    if payload.get("instance_hash"):
        # A CANONICAL-SUITE CASE. The suite is PUBLIC law (LAW §3A.1), so it is generated from the
        # pinned generators directly rather than through the dev-case allow-list — and the
        # generated instance is re-hashed and required to equal the hash the SUITE DOCUMENT binds.
        # Without that equality this would score whatever the local generators produced and call it
        # the law's case.
        import hashlib as _hashlib
        from generators import generate as _generate
        inst = _generate(payload["profile_id"], int(payload["seed"]), payload["scale"])
        _got = _hashlib.sha256(inst.canonical_json().encode("utf-8")).hexdigest()
        if _got != payload["instance_hash"]:
            raise SystemExit(
                "the pinned generators produced instance " + _got + " for "
                + payload["profile_id"] + "@" + payload["scale"] + "#s" + str(payload["seed"])
                + ", and the canonical suite binds " + payload["instance_hash"]
                + "; the law's case is not what this host generated")
    else:
        # FAIL CLOSED on any non-public (profile, seed, scale): the kit refuses to generate a
        # held-out instance and this command inherits that refusal rather than working around it.
        inst = dev_instance(payload["profile_id"], int(payload["seed"]), payload["scale"])
    corpus_bytes = sum(len(e["content"].encode("utf-8")) for e in inst.all_envelopes())
    arms = {{}}
    replay_identical = {{}}
    for name in sorted(payload["arms"]):
        arm = payload["arms"][name]
        if arm["kind"] == "reference":
            work = tempfile.mkdtemp(prefix="pcp-ref-")
            scored = _layer_b.score_submission(inst, work, corpus_bytes=corpus_bytes)
            integrity = _layer_b.measure_reference_integrity(
                inst, _os.path.join(work, "run1"))
            replay_identical[name] = True
        else:
            kwargs = {{}}
            if arm.get("fuel_ceiling") is not None:
                kwargs["fuel_ceiling"] = int(arm["fuel_ceiling"])
            scored = _seam.score_candidate_submission(
                inst, tempfile.mkdtemp(prefix="pcp-mod-"), arm["source"],
                expected_sha256=arm["sha256"], declared=list(arm["capabilities"]),
                double_run=True, corpus_bytes=corpus_bytes, **kwargs)
            integrity = scored["integrity"]
            replay_identical[name] = bool(scored.get("replay_identical"))
        arms[name] = {{"measurement": scored["quality"], "resource": scored["resource"],
                       "integrity": integrity}}
    out = {{"arms": arms, "replay_identical": replay_identical}}
elif mode == "aggregate":
    from frontier import pareto2 as _pareto2
    from frontier import profiles as _profiles
    from kit import self_check as _self_check
    for _name in ("_aggregate", "_measurements"):
        if not hasattr(_self_check, _name):
            raise SystemExit(
                "the pinned kit does not expose kit.self_check." + _name + "; refusing to "
                "re-implement the aggregation law in the client")
    profile = _profiles.get_profile(payload["profile_id"])
    aggregates = {{name: _self_check._aggregate(rows, profile)
                   for name, rows in payload["per_arm"].items()}}
    portability = _local_portability(payload.get("portability_breadth"))
    candidate, parent = _self_check._measurements(
        aggregates["candidate"], aggregates["parent"], payload["declared_limits"],
        bool(payload["replay_identical"]), portability)
    verdict = _pareto2.decide(candidate, parent, profile, tuple(payload["targeted"]))
    out = {{"candidate": candidate, "parent": parent, "verdict": verdict,
            "aggregates": aggregates, "portability": portability}}
elif mode == "aggregate_suite":
    from frontier import dominance as _dominance
    from frontier import profiles as _profiles
    from kit import self_check as _self_check
    from validator import canonical_suite as _cs
    for _name in ("_aggregate", "_measurements"):
        if not hasattr(_self_check, _name):
            raise SystemExit(
                "the pinned kit does not expose kit.self_check." + _name + "; refusing to "
                "re-implement the aggregation law in the client")
    profile = _profiles.get_profile(payload["profile_id"])
    portability = _local_portability(payload.get("portability_breadth"))
    out = {{"partitions": {{}}, "portability": portability,
            "engine": _dominance.ENGINE_ID, "suite_root": _cs.suite_root()}}
    for label in ("gate", "confirm"):
        rows = payload["per_partition"][label]
        aggregates = {{name: _self_check._aggregate(arm_rows, profile)
                       for name, arm_rows in rows.items()}}
        candidate, parent = _self_check._measurements(
            aggregates["candidate"], aggregates["parent"], payload["declared_limits"],
            bool(payload["replay_identical"]), portability)
        # THE FLOOR IS RESOLVED FROM THE LAW, not supplied by the caller: a pending floor is a
        # refusal at the resolver, so "no floor" can never arrive here as "no floor check".
        floor = _cs.genesis_floor_vector(payload["profile_id"], label)
        verdict = _dominance.decide(candidate, parent, profile, label, floor_vector=floor,
                                    targeted_objectives=tuple(payload["targeted"]))
        out["partitions"][label] = {{"candidate": candidate, "parent": parent,
                                     "verdict": verdict, "aggregates": aggregates,
                                     "floor_vector": floor}}
    out["admit"] = bool(out["partitions"]["gate"]["verdict"]["admit"]
                        and out["partitions"]["confirm"]["verdict"]["admit"])
else:
    raise SystemExit("unknown preview child mode " + repr(mode))

if _proof is not None:
    out["networkless"] = bool(_proof.get("enforced") is True)
    out["networkless_evidence"] = _proof
print("<<<JSON>>>" + json.dumps(out, sort_keys=True, default=str))
'''


class LawTreeChild:
    """The real scorer: the pinned law trees, in an isolated networkless child interpreter.

    ``available()`` is honest — it reports False when the trees are not on this host, and the
    command then REFUSES rather than scoring against something else. A preview that quietly fell
    back to an unpinned local runtime would be the one failure mode worth avoiding here: it would
    hand a miner a number produced by different law than the adjudicator's.

    ``support_dirs`` are the UNSEALED trees (:data:`SUPPORT_BENCH_SUBTREES`), layered AFTER the
    sealed ``benchmark-v2`` directory on the child's ``sys.path`` — see :class:`TreeResolution`.
    """

    name = "benchmark-v2/kit.self_check + frontier.pareto2 (child-interpreter)"

    def __init__(self, *, bench_v2_dir: str, coretex_dir: str, repo_root: str = "",
                 support_dirs: Sequence[str] = (),
                 isolation_path: Optional[str] = None, timeout: int = 7200) -> None:
        self.bench_v2_dir = (bench_v2_dir or "").strip()
        self.coretex_dir = (coretex_dir or "").strip()
        self.repo_root = (repo_root or "").strip()
        self.support_dirs = tuple(d for d in (str(s).strip() for s in support_dirs) if d)
        self.isolation_path = isolation_path or os.path.join(_PKG_DIR, "isolation.py")
        self.timeout = timeout

    @property
    def _tree_dirs(self) -> Tuple[str, ...]:
        """The layered search order the child's ``sys.path`` uses. Sealed first, always."""
        return (self.bench_v2_dir,) + self.support_dirs if self.bench_v2_dir else ()

    def _find(self, *relative: str) -> Optional[str]:
        for base in self._tree_dirs:
            path = os.path.join(base, *relative)
            if os.path.exists(path):
                return path
        return None

    def available(self) -> bool:
        # `bool(dir)` FIRST — an unconfigured tree is "" and `os.path.join("", x)` is a RELATIVE
        # path a stray working directory could satisfy (the `replay.py` discipline).
        return (bool(self.bench_v2_dir) and bool(self.coretex_dir)
                and self._find("kit", "self_check.py") is not None
                and self._find("kit", "dev_instances.py") is not None
                and os.path.isdir(os.path.join(self.bench_v2_dir, "miner_abi"))
                and os.path.isdir(self.coretex_dir)
                and os.path.isfile(self.isolation_path))

    @property
    def unavailable_reason(self) -> str:
        """Name the trees that are ACTUALLY absent, sealed and unsealed kept apart.

        The shipped message listed three prerequisites of which two were present, and pointed at
        ``sync-law`` for a tree ``sync-law`` can never install. Separating the two publications is
        what makes the sentence actionable.
        """
        if not self.bench_v2_dir or not self.coretex_dir:
            return ("no pinned trees are configured for the scoring child (benchmark-v2="
                    f"{self.bench_v2_dir or '(unset)'}, coretex-memory="
                    f"{self.coretex_dir or '(unset)'})")
        gaps = []
        if not os.path.isdir(os.path.join(self.bench_v2_dir, "miner_abi")):
            gaps.append(f"the SEALED tree {self.bench_v2_dir}/miner_abi (install it with "
                        "`coretex-validator setup`)")
        if not os.path.isdir(self.coretex_dir):
            gaps.append(f"the SEALED tree {self.coretex_dir} (install it with "
                        "`coretex-validator setup`)")
        if self._find("kit", "self_check.py") is None \
                or self._find("kit", "dev_instances.py") is None:
            gaps.append(
                "the UNSEALED support tree benchmark-v2/kit (self_check.py + dev_instances.py). "
                "It is not a sealed code root, so no law publication carries it: it ships in the "
                f"hash-pinned {KIT_TAR_PREFIX}<sha256>.tar that `coretex-validator setup` "
                "downloads, and the searched directories were "
                f"{list(self._tree_dirs)}")
        if not os.path.isfile(self.isolation_path):
            gaps.append(f"{self.isolation_path} — what enforces AND proves networkless execution, "
                        "so without it the candidate would run unconfined")
        return "the scoring child cannot run: " + "; ".join(gaps or ["(no gap identified)"])

    @property
    def unavailable_remedy(self) -> str:
        if self._find("kit", "self_check.py") is None:
            return ("run `coretex-validator setup` — it downloads and hash-verifies the miner-kit "
                    f"tar ({KIT_TAR_PREFIX}<sha256>.tar) that carries benchmark-v2/kit, alongside "
                    "installing the sealed law publication")
        return "run `coretex-validator setup` first"

    def __call__(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not self.available():
            raise PreviewError(self.unavailable_reason, code="SCORER_UNAVAILABLE",
                               remedy=self.unavailable_remedy)
        source = _PREVIEW_CHILD.format(bench=self.bench_v2_dir, coretex=self.coretex_dir,
                                       support=list(self.support_dirs),
                                       shim=PORTABILITY_SHIM_SOURCE,
                                       isolation=self.isolation_path)
        env = dict(os.environ)
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(key, None)
        env["NO_PROXY"] = "*"
        try:
            proc = subprocess.run([sys.executable, "-c", source], input=json.dumps(dict(payload)),
                                  cwd=(self.bench_v2_dir or None), capture_output=True, text=True,
                                  env=env, timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise PreviewError(f"the scoring child failed to start: {exc}",
                               code="SCORER_UNAVAILABLE") from exc
        if "<<<MISSING_DEPENDENCY>>>" in proc.stdout:
            detail = json.loads(
                proc.stdout.split("<<<MISSING_DEPENDENCY>>>", 1)[1].splitlines()[0])
            name = str(detail.get("dependency", "?"))
            pin = PINNED_RUNTIME_DEPENDENCIES.get(name, "")
            raise PreviewError(
                f"the pinned runtime could not import {name} in the scoring child "
                f"({detail.get('detail')})", code="MISSING_DEPENDENCY",
                remedy=f"pip install '{name}{pin}'" if pin else f"pip install {name}")
        if proc.returncode != 0 or "<<<JSON>>>" not in proc.stdout:
            raise PreviewError(
                f"the scoring child exited {proc.returncode}: "
                f"{proc.stderr[-2000:] or proc.stdout[-2000:]}", code="SCORER_FAILED")
        return json.loads(proc.stdout.split("<<<JSON>>>", 1)[1].strip())


# --------------------------------------------------------------------------- #
# 4. the preview itself
# --------------------------------------------------------------------------- #
#: The axes shown side by side. Utility is the profile's objectives plus the composite; resource is
#: the ``final-render-hostwork.v3`` block ``kit/self_check.py`` prints.
_RESOURCE_AXES = ("rendered_cost", "compute_ms", "storage_bytes", "latency_ms",
                  "corpus_supported", "input_corpus_bytes", "logical_durable_storage_bytes")


def _axis_row(candidate: Mapping[str, Any], parent: Mapping[str, Any], key: str):
    left, right = candidate.get(key), parent.get(key)
    row = {"candidate": left, "parent": right, "delta": None}
    if isinstance(left, (int, float)) and isinstance(right, (int, float)) \
            and not isinstance(left, bool) and not isinstance(right, bool):
        row["delta"] = left - right
    return row


def _comparison(candidate: Mapping[str, Any], parent: Mapping[str, Any],
                verdict: Mapping[str, Any]) -> Dict[str, Any]:
    objectives = candidate.get("objectives") or {}
    parent_objectives = parent.get("objectives") or {}
    utility = {name: _axis_row(objectives, parent_objectives, name)
               for name in sorted(set(objectives) | set(parent_objectives))}
    utility["composite"] = _axis_row(candidate, parent, "composite")
    resource = {axis: _axis_row(candidate, parent, axis) for axis in _RESOURCE_AXES
                if axis in candidate or axis in parent}
    # BEATS = the Pareto comparison against the parent, and nothing more. It deliberately does NOT
    # fold in `hard_ok`: the hard prerequisites are executed by the adjudicating host, so folding
    # them in here would turn "we did not run the portability matrix" into "you lost".
    beats = bool(verdict.get("pareto_ok"))
    meaning = (
        "the candidate satisfies at least one Pareto clause against the CURRENT CONFIRMED "
        "PARENT on the public dev cases; it is not an admission" if beats else
        "the candidate does not satisfy any Pareto clause against the CURRENT CONFIRMED "
        "PARENT on the public dev cases; it is not an admission")
    return {
        "beats_current_parent": beats,
        "meaning": meaning,
        "satisfied_clauses": list(verdict.get("satisfied_clauses") or ()),
        "hard_gates_ok": bool(verdict.get("hard_ok")),
        "failed_hard": list(verdict.get("failed_hard") or ()),
        "delta": {"composite": utility["composite"]["delta"]},
        "utility": utility,
        "resource": resource,
    }


def _preview_fixed_suite(*, child, store, parent_root, target_profile, module_source,
                         candidate_manifest, probe, portability_breadth):
    """Score the candidate and the current parent on THE LAW'S OWN EXAM, and predict the verdict.

    WHY THIS IS A DIFFERENT PROMISE FROM THE WALK-ERA PREVIEW. Under the walk law the official
    evaluation drew fresh cases from future public entropy, so a preview on the public dev cases
    was a sanity check and ``predictsAdmission`` was a hard ``false`` — anything else would have
    been a lie about a number that was going to be re-rolled. Under the fixed suite the exam is
    IMMUTABLE and PUBLIC (LAW §3A.1) and the decision is componentwise dominance over the exact
    parent plus the constructor-genesis floor, with no input from the epoch secret, the candidate
    id, the rig or the author (LAW §3A.4). So this scores the same cases, against the same parent,
    under the same engine, with the same law-bound floor, and reports the verdict it computed as a
    DETERMINISTIC prediction.

    The one caveat that survives, and it is named in the report rather than buried: the chain race.
    The prediction is for the parent OBSERVED here; if another advance lands first, the next job's
    exact parent is a different release and its stored vector is a different comparand.
    """
    resolved = resolve_parent(store=store, parent_root=parent_root,
                              target_profile=target_profile)
    execution = resolved["execution"]
    arms = {"candidate": build_candidate_arm(module_source=module_source,
                                             manifest=candidate_manifest),
            "parent": build_parent_arm(execution)}

    if not probe.get("genesis_floor_resolved"):
        raise PreviewError(
            "the pinned law tree's constructor-genesis floor is PENDING, so no v4 admission is "
            "computable and none can be predicted (LAW §3A.3)",
            code="GENESIS_FLOOR_PENDING")

    suite_cases = probe["suite_cases"]
    hashes = dict(probe.get("suite_case_hashes") or {})
    per_partition: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    replay_identical = {"candidate": True, "parent": True}
    networkless = True
    for label in ("gate", "confirm"):
        rows: Dict[str, List[Dict[str, Any]]] = {"candidate": [], "parent": []}
        for case in suite_cases[label]:
            scored = child({"mode": "score", "profile_id": case["profile_id"],
                            "scale": case["scale"], "seed": int(case["seed"]),
                            "instance_hash": hashes.get(case["instance_id"]),
                            "arms": arms})
            for name in rows:
                row = (scored.get("arms") or {}).get(name)
                if not isinstance(row, abc.Mapping):
                    raise PreviewError(
                        f"the scorer returned no {name} arm for suite case "
                        f"{case['instance_id']}", code="SCORER_FAILED")
                rows[name].append(dict(row))
                replay_identical[name] = replay_identical[name] and bool(
                    (scored.get("replay_identical") or {}).get(name, True))
            networkless = networkless and bool(scored.get("networkless", True))
        per_partition[label] = rows

    limits = candidate_manifest.get("resource_requirements")
    decided = child({
        "mode": "aggregate_suite", "profile_id": target_profile,
        "declared_limits": dict(limits) if isinstance(limits, abc.Mapping) else {},
        "targeted": list(candidate_manifest.get("objectives_targeted") or ()),
        "replay_identical": bool(replay_identical["candidate"]),
        "portability_breadth": portability_breadth,
        "per_partition": per_partition})

    partitions = decided.get("partitions") or {}
    confirm = partitions.get("confirm") or {}
    gate = partitions.get("gate") or {}
    admit = bool(decided.get("admit"))
    return {
        "ok": True,
        "format": REPORT_FORMAT,
        # THE HONESTY FIELDS, ERA-AWARE. The walk-era values were true of the walk era and would
        # be false here: these cases are not dev cases, and the verdict is not a hint.
        "publicDevCasesOnly": False,
        "predictsAdmission": admit,
        "predictsDeterministicAdmission": True,
        "disclaimer": FIXED_SUITE_DISCLAIMER,
        "lawEra": "fixed-suite",
        "canonicalSuite": {
            "root": probe.get("suite_root"),
            "version": probe.get("suite_version"),
            "law_id": probe.get("suite_law_id"),
            "engine": decided.get("engine"),
            "counts": probe.get("suite_counts"),
            "scales": probe.get("suite_scales"),
            "cases": {label: [case["instance_id"] for case in suite_cases[label]]
                      for label in ("gate", "confirm")},
        },
        "profile": target_profile,
        "candidate": {
            "module_sha256": arms["candidate"]["sha256"],
            "capabilities": arms["candidate"]["capabilities"],
            "fuel_ceiling": arms["candidate"]["fuel_ceiling"],
            "declared_limits": dict(limits) if isinstance(limits, abc.Mapping) else {},
            "objectives_targeted": list(candidate_manifest.get("objectives_targeted") or ()),
            "replay_identical": bool(replay_identical["candidate"]),
        },
        "parent": {
            "frontier_root": parent_root,
            "epoch": resolved["epoch"],
            "composition_root": resolved["composition_root"],
            "release_root": execution["release_root"],
            "exec": execution["exec"],
            "id": execution["id"],
            "candidate_hash": execution["candidate_hash"],
            "module_sha256": (arms["parent"].get("sha256")
                              if arms["parent"]["kind"] == "module" else None),
            "capabilities": arms["parent"].get("capabilities"),
            "fuel_ceiling": arms["parent"].get("fuel_ceiling"),
            "replay_identical": bool(replay_identical["parent"]),
            "chain": resolved["chain"],
            "authority": ("classified by EXACT release-root equality against the packaged "
                          "EXACT-PARENT-AUTHORITY.production.json; never by similarity"),
        },
        # BOTH PARTITIONS DECIDE, and the admission is their conjunction — reporting only the
        # confirm branch would let a gate-failing candidate read as admissible.
        "partitions": {
            label: {
                "admit": bool((partitions.get(label) or {}).get("verdict", {}).get("admit")),
                "verdict": (partitions.get(label) or {}).get("verdict"),
                "arms": {"candidate": (partitions.get(label) or {}).get("candidate"),
                         "parent": (partitions.get(label) or {}).get("parent")},
                "floor_vector": (partitions.get(label) or {}).get("floor_vector"),
            }
            for label in ("gate", "confirm")
        },
        "arms": {"candidate": confirm.get("candidate"), "parent": confirm.get("parent")},
        "comparison": _comparison(confirm.get("candidate") or {}, confirm.get("parent") or {},
                                  confirm.get("verdict") or {}),
        "verdict": confirm.get("verdict"),
        "gate_verdict": gate.get("verdict"),
        "portability": decided.get("portability"),
        "scorer": {"name": getattr(child, "name", type(child).__name__),
                   "networkless": networkless},
    }


def preview_current_parent(*, child, store: pub.ContentStore, parent_root: str,
                           target_profile: str, module_source: str,
                           candidate_manifest: Mapping[str, Any],
                           scale: str = DEFAULT_SCALE,
                           portability_breadth: Optional[str] = None) -> Dict[str, Any]:
    """Score a candidate and the current confirmed parent on the identical public dev cases."""
    if not callable(child):
        raise PreviewError("the scorer must be callable", code="SCORER_UNAVAILABLE")
    if hasattr(child, "available") and not child.available():
        raise PreviewError(getattr(child, "unavailable_reason", "the scorer is unavailable"),
                           code="SCORER_UNAVAILABLE",
                           remedy=getattr(child, "unavailable_remedy",
                                          "run `coretex-validator setup` first"))

    probe = child({"mode": "probe", "profile_id": target_profile})
    law_era = str(probe.get("law_era") or "walk")
    if law_era == "fixed-suite" and probe.get("suite_cases"):
        return _preview_fixed_suite(
            child=child, store=store, parent_root=parent_root, target_profile=target_profile,
            module_source=module_source, candidate_manifest=candidate_manifest, probe=probe,
            portability_breadth=portability_breadth)
    dev_seeds = [int(seed) for seed in probe.get("dev_seeds") or ()]
    dev_scales = list(probe.get("dev_scales") or ())
    profiles = list(probe.get("profiles") or ())
    if not dev_seeds:
        raise PreviewError("the pinned kit published no dev seeds", code="NON_PUBLIC_DEV_CASE")
    if profiles and target_profile not in profiles:
        raise PreviewError(
            f"{target_profile!r} is not a profile the pinned generators publish ({profiles})",
            code="NON_PUBLIC_DEV_CASE")
    if dev_scales and scale not in dev_scales:
        raise PreviewError(
            f"{scale!r} is not a published dev scale ({dev_scales}); the kit refuses to generate "
            "anything outside the public dev set and so does this command",
            code="NON_PUBLIC_DEV_CASE")

    resolved = resolve_parent(store=store, parent_root=parent_root,
                              target_profile=target_profile)
    execution = resolved["execution"]
    arms = {"candidate": build_candidate_arm(module_source=module_source,
                                             manifest=candidate_manifest),
            "parent": build_parent_arm(execution)}

    rows: Dict[str, List[Dict[str, Any]]] = {"candidate": [], "parent": []}
    replay_identical: Dict[str, bool] = {"candidate": True, "parent": True}
    networkless = True
    for seed in dev_seeds:
        scored = child({"mode": "score", "profile_id": target_profile, "scale": scale,
                        "seed": int(seed), "arms": arms})
        for name in rows:
            row = (scored.get("arms") or {}).get(name)
            if not isinstance(row, abc.Mapping):
                raise PreviewError(f"the scorer returned no {name} arm for dev seed {seed}",
                                   code="SCORER_FAILED")
            rows[name].append(dict(row))
            replay_identical[name] = replay_identical[name] and bool(
                (scored.get("replay_identical") or {}).get(name, True))
        networkless = networkless and bool(scored.get("networkless", True))

    limits = candidate_manifest.get("resource_requirements")
    aggregated = child({
        "mode": "aggregate", "profile_id": target_profile,
        "declared_limits": dict(limits) if isinstance(limits, abc.Mapping) else {},
        "targeted": list(candidate_manifest.get("objectives_targeted") or ()),
        "replay_identical": bool(replay_identical["candidate"]),
        "portability_breadth": portability_breadth,
        "per_arm": rows})
    candidate_side = aggregated.get("candidate") or {}
    parent_side = aggregated.get("parent") or {}
    verdict = aggregated.get("verdict") or {}

    return {
        "ok": True,
        "format": REPORT_FORMAT,
        # THE THREE MANDATORY HONESTY FIELDS. Top level, not buried in a note.
        "publicDevCasesOnly": True,
        "predictsAdmission": False,
        "disclaimer": DISCLAIMER,
        "profile": target_profile,
        "scale": scale,
        "dev_seeds": dev_seeds,
        "candidate": {
            "module_sha256": arms["candidate"]["sha256"],
            "capabilities": arms["candidate"]["capabilities"],
            "fuel_ceiling": arms["candidate"]["fuel_ceiling"],
            "declared_limits": dict(limits) if isinstance(limits, abc.Mapping) else {},
            "objectives_targeted": list(candidate_manifest.get("objectives_targeted") or ()),
            "replay_identical": bool(replay_identical["candidate"]),
        },
        "parent": {
            "frontier_root": parent_root,
            "epoch": resolved["epoch"],
            "composition_root": resolved["composition_root"],
            "release_root": execution["release_root"],
            "exec": execution["exec"],
            "id": execution["id"],
            "candidate_hash": execution["candidate_hash"],
            "module_sha256": (arms["parent"].get("sha256")
                              if arms["parent"]["kind"] == "module" else None),
            "capabilities": arms["parent"].get("capabilities"),
            "fuel_ceiling": arms["parent"].get("fuel_ceiling"),
            "replay_identical": bool(replay_identical["parent"]),
            "chain": resolved["chain"],
            "authority": ("classified by EXACT release-root equality against the packaged "
                          "EXACT-PARENT-AUTHORITY.production.json; never by similarity"),
        },
        "arms": {"candidate": candidate_side, "parent": parent_side},
        "comparison": _comparison(candidate_side, parent_side, verdict),
        "verdict": verdict,
        "portability": aggregated.get("portability"),
        "scorer": {"name": getattr(child, "name", type(child).__name__),
                   "networkless": networkless},
    }
