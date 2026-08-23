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
import hashlib
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Mapping, Optional

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
_PREVIEW_CHILD = r'''
import json, sys
import importlib.util, os as _os, site as _site, sysconfig as _sysconfig, tempfile
_allowed = [{bench!r}, {coretex!r}]
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
elif mode == "score":
    from kit.dev_instances import dev_instance
    from miner_abi import seam as _seam
    from scoring import layer_b as _layer_b
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
    from integration import portability_matrix as _pm
    from kit import self_check as _self_check
    for _name in ("_aggregate", "_measurements"):
        if not hasattr(_self_check, _name):
            raise SystemExit(
                "the pinned kit does not expose kit.self_check." + _name + "; refusing to "
                "re-implement the aggregation law in the client")
    profile = _profiles.get_profile(payload["profile_id"])
    aggregates = {{name: _self_check._aggregate(rows, profile)
                   for name, rows in payload["per_arm"].items()}}
    breadth = payload.get("portability_breadth")
    if breadth is None:
        portability = _pm.not_executed(
            "preview-current-parent did not run the support matrix (pass --portability to "
            "execute it); the adjudicating host executes it for real")
    else:
        try:
            portability = _pm.run_matrix(breadth=breadth)
        except Exception as exc:                      # noqa: BLE001 - fail closed
            portability = _pm.not_executed(type(exc).__name__ + ": " + str(exc), breadth=breadth)
    candidate, parent = _self_check._measurements(
        aggregates["candidate"], aggregates["parent"], payload["declared_limits"],
        bool(payload["replay_identical"]), portability)
    verdict = _pareto2.decide(candidate, parent, profile, tuple(payload["targeted"]))
    out = {{"candidate": candidate, "parent": parent, "verdict": verdict,
            "aggregates": aggregates, "portability": portability}}
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
    """

    name = "benchmark-v2/kit.self_check + frontier.pareto2 (child-interpreter)"

    def __init__(self, *, bench_v2_dir: str, coretex_dir: str, repo_root: str = "",
                 isolation_path: Optional[str] = None, timeout: int = 7200) -> None:
        self.bench_v2_dir = (bench_v2_dir or "").strip()
        self.coretex_dir = (coretex_dir or "").strip()
        self.repo_root = (repo_root or "").strip()
        self.isolation_path = isolation_path or os.path.join(_PKG_DIR, "isolation.py")
        self.timeout = timeout

    def available(self) -> bool:
        # `bool(dir)` FIRST — an unconfigured tree is "" and `os.path.join("", x)` is a RELATIVE
        # path a stray working directory could satisfy (the `replay.py` discipline).
        return (bool(self.bench_v2_dir) and bool(self.coretex_dir)
                and os.path.isfile(os.path.join(self.bench_v2_dir, "kit", "self_check.py"))
                and os.path.isfile(os.path.join(self.bench_v2_dir, "kit", "dev_instances.py"))
                and os.path.isdir(os.path.join(self.bench_v2_dir, "miner_abi"))
                and os.path.isdir(self.coretex_dir)
                and os.path.isfile(self.isolation_path))

    @property
    def unavailable_reason(self) -> str:
        return (f"the pinned law trees are not provisioned on this host (need "
                f"{self.bench_v2_dir or '(unset)'}/kit/self_check.py, "
                f"{self.coretex_dir or '(unset)'} and {self.isolation_path} — the last one is "
                f"what enforces AND proves networkless execution, so without it the candidate "
                f"would run unconfined)")

    def __call__(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not self.available():
            raise PreviewError(self.unavailable_reason, code="SCORER_UNAVAILABLE",
                               remedy="run `coretex-validator sync-law --mirror URL` first")
        source = _PREVIEW_CHILD.format(bench=self.bench_v2_dir, coretex=self.coretex_dir,
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
    return {
        "beats_current_parent": bool(verdict.get("pareto_ok")),
        "meaning": ("the candidate satisfies at least one Pareto clause against the CURRENT "
                    "CONFIRMED PARENT on the public dev cases; it is not an admission"),
        "satisfied_clauses": list(verdict.get("satisfied_clauses") or ()),
        "hard_gates_ok": bool(verdict.get("hard_ok")),
        "failed_hard": list(verdict.get("failed_hard") or ()),
        "delta": {"composite": utility["composite"]["delta"]},
        "utility": utility,
        "resource": resource,
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
                           remedy="run `coretex-validator sync-law --mirror URL` first")

    probe = child({"mode": "probe"})
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
