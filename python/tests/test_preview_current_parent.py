# SPDX-License-Identifier: Apache-2.0
"""``coretex-validator preview-current-parent`` — the miner-facing parent preview.

WHAT THESE TESTS ARE FOR. The kit's ``self_check`` scores a candidate against the FROZEN REFERENCE
BASELINE. The live incumbent has usually moved past that baseline, so a candidate can pass the
self-check and still lose the adjudicated comparison. This command closes that gap, and the
load-bearing test here is exactly that shape: ONE candidate, TWO parents (the reference, then the
live arm), opposite verdicts.

THE SCORING SEAM. Real scoring runs the pinned law trees in a child interpreter, which needs a
verified law cache, a benchmark tree and ``wasmtime``. That is far too heavy for a unit test and
would make the suite depend on host provisioning, so
:class:`coretex_validator.preview.LawTreeChild` is a SEAM: a callable taking one JSON payload and
returning one JSON result. The fake below plays the pinned tree deterministically, which lets every
piece of logic that is OURS — chain resolution, arm construction, capability/fuel sourcing per arm,
the comparison, the report and the exit codes — be tested for real.
``test_real_child_scores_two_arms_on_one_public_dev_case`` exercises the actual child and skips
cleanly on a host without the trees.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os

import pytest

from coretex_validator import cli
from coretex_validator import frontier as fr
from coretex_validator import law as law_mod
from coretex_validator import parent_execution as pe
from coretex_validator import preview as pv
from coretex_validator import publication as pub
from coretex_validator import release_graph as rg


TARGET = "doc.tool.v1"

#: Two distinct module bodies. Only their BYTES matter to these tests — the fake scorer keys its
#: composite off the module sha256, so "which arm ran which bytes" is directly observable.
PARENT_MODULE = (
    b"from coretex_memory import abi2\n"
    b"from coretex_memory.hooks import HookDispatch\n\n"
    b"def make_hooks(context):\n"
    b"    dispatch = HookDispatch()\n"
    b"    dispatch.set_override(abi2.M6, context.ref_m6_pack)\n"
    b"    return dispatch\n"
)
CANDIDATE_MODULE = (
    b"from coretex_memory import abi2\n"
    b"from coretex_memory.hooks import HookDispatch\n\n"
    b"def make_hooks(context):\n"
    b"    dispatch = HookDispatch()\n"
    b"    dispatch.set_override(abi2.M5, context.ref_m5_stream)\n"
    b"    return dispatch\n"
)

PARENT_SHA = hashlib.sha256(PARENT_MODULE).hexdigest()
CANDIDATE_SHA = hashlib.sha256(CANDIDATE_MODULE).hexdigest()

#: The A -> B fixture, in one table. B (the candidate) BEATS the frozen reference baseline and
#: LOSES to the live parent A. Everything else in the suite reads off this.
COMPOSITES = {
    "reference": 0.500,
    PARENT_SHA: 0.800,                            # live parent A
    CANDIDATE_SHA: 0.650,                         # candidate B
}

PARENT_CAPABILITIES = ["cap.text.v1"]
PARENT_MAX_COMPUTE_MS = 4000
CANDIDATE_CAPABILITIES = ["cap.lexicon.v1", "cap.text.v1"]
CANDIDATE_MAX_COMPUTE_MS = 9000


# --------------------------------------------------------------------------- #
# The public CAS fixture: frontier manifest -> composition -> release -> module
# --------------------------------------------------------------------------- #
def _publish_signed(document, store):
    root = pub.root_of(pub.encode(document, pub.HASH_RULE_SIGNED_MANIFEST_BODY),
                       pub.HASH_RULE_SIGNED_MANIFEST_BODY)
    addressed = {**document, "manifest_self_sha256": root}
    published = pub.publish_item(addressed, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY,
                                 store=store)
    assert published["root"] == root
    return root, addressed


def _release_body(profile_id, module_sha256):
    return {
        "schema": "coretex-memory/release-manifest",
        "manifest_schema_version": rg.SANDBOXED_RELEASE_SCHEMA,
        "policy_id": f"fixture-{profile_id}",
        "module_sha256": module_sha256,
        "source_provenance": {"entry": "Fixture", "miner": f"miner-{profile_id}",
                              "profile_id": profile_id, "base_modules": {}},
        "abi_version": "memory-hooks.v1",
        "runtime_version_min": "0.1.5",
        "runtime_version_max": "0.1.5",
        "candidate_provider": "fixture",
        "counter": "fixture",
        "store_schema_version": "1",
        "deployment_profile": profile_id,
        "rollback_id": f"rollback-{profile_id}",
        "hooks": {"m6_pack": "1"},
        # The PARENT arm's capability roster and fuel ceiling. The whole point of the sourcing
        # tests is that these — not the candidate manifest's — reach the parent arm.
        "capabilities": list(PARENT_CAPABILITIES),
        "capabilities_used": list(PARENT_CAPABILITIES),
        "resource_requirements": {"max_compute_ms": PARENT_MAX_COMPUTE_MS,
                                  "max_storage_bytes": 2_000_000},
        "content_authority": rg.CONTENT_AUTHORITY,
        "admission_report_hash": "ab" * 32,
        "analyzer_ruleset_root": "cd" * 32,
        "wrapper_format": rg.DIRECT_WRAPPER_FORMAT,
    }


def parent_graph():
    """A complete, self-consistent public parent graph published into an in-memory CAS."""
    store = pub.InMemoryCAS()
    module_sha256 = pub.publish_item(PARENT_MODULE, hash_rule=pub.HASH_RULE_BYTES,
                                     store=store)["root"]
    releases, manifests = {}, {}
    for profile_id in fr.PROFILE_IDS:
        releases[profile_id], manifests[profile_id] = _publish_signed(
            _release_body(profile_id, module_sha256), store)
    candidates = {p: hashlib.sha256(f"candidate:{p}".encode()).hexdigest()
                  for p in fr.PROFILE_IDS}
    miners = {p: f"miner-{p}" for p in fr.PROFILE_IDS}
    composition_body = {
        "format": rg.COMPOSITION_FORMAT,
        "content_authority": rg.CONTENT_AUTHORITY,
        "profile_bindings": {
            **{p: {"release_id": releases[p], "bundle_manifest_sha256": releases[p],
                   "candidate_hash": candidates[p], "module_sha256": module_sha256,
                   "miner_sha256": module_sha256, "miner_id": miners[p],
                   "bundle_dir": f"bundles/{miners[p]}", "is_baseline": False}
              for p in fr.PROFILE_IDS},
            fr.LEGACY_PROFILE_ID: {"bundle_dir": None, "is_baseline": True, "miner_id": None},
        },
        "delegation_candidate_hashes": {**candidates, fr.LEGACY_PROFILE_ID: None},
        "bundles": {**{p: f"bundles/{miners[p]}" for p in fr.PROFILE_IDS},
                    fr.LEGACY_PROFILE_ID: None},
        "composition": {**miners, fr.LEGACY_PROFILE_ID: None},
    }
    composition_root, _ = _publish_signed(composition_body, store)
    manifest = {
        "benchmark_law_root": "11" * 32,
        "default_composition_root": composition_root,
        "epoch": 181,
        "format": fr.MANIFEST_FORMAT,
        "parent_frontier_root": "22" * 32,
        "profiles": releases,
        "runtime_abi_root": "33" * 32,
    }
    parent_root = pub.publish_item(manifest, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                   store=store)["root"]
    return {"store": store, "parent_root": parent_root, "manifest": manifest,
            "composition_root": composition_root, "releases": releases,
            "release_manifests": manifests, "module_sha256": module_sha256}


def candidate_manifest():
    return {
        "schema": "coretex-memory/candidate-manifest",
        "manifest_schema_version": 4,
        "profile_id": TARGET,
        "module_sha256": CANDIDATE_SHA,
        "capabilities": list(CANDIDATE_CAPABILITIES),
        "capabilities_used": list(CANDIDATE_CAPABILITIES),
        "objectives_targeted": ["retrieval_precision"],
        "resource_requirements": {"max_compute_ms": CANDIDATE_MAX_COMPUTE_MS,
                                  "max_storage_bytes": 4_000_000},
    }


# --------------------------------------------------------------------------- #
# The fake pinned tree
# --------------------------------------------------------------------------- #
class FakeLawTreeChild:
    """A deterministic stand-in for the pinned law trees.

    It is NOT a re-implementation of the scoring law: it maps an arm's identity to a composite
    straight out of :data:`COMPOSITES` and calls the Pareto comparison "candidate composite beats
    parent composite". Everything it is asked to do is recorded in ``calls``, so the tests can
    assert precisely which bytes, capabilities and fuel ceiling each arm was scored with.
    """

    name = "fake-pinned-tree"
    unavailable_reason = "the fake is always available"

    def __init__(self, *, dev_seeds=(1002, 1003, 1006, 1007), available=True):
        self.dev_seeds = list(dev_seeds)
        self._available = available
        self.calls = []

    def available(self) -> bool:
        return self._available

    @staticmethod
    def _composite(arm):
        if arm["kind"] == "reference":
            return COMPOSITES["reference"]
        return COMPOSITES[arm["sha256"]]

    def __call__(self, payload):
        self.calls.append(copy.deepcopy(payload))
        mode = payload["mode"]
        if mode == "probe":
            return {"dev_seeds": list(self.dev_seeds), "dev_scales": ["small", "medium"],
                    "profiles": list(fr.PROFILE_IDS), "networkless": True}
        if mode == "score":
            arms = {}
            for name, arm in payload["arms"].items():
                composite = self._composite(arm)
                arms[name] = {
                    "measurement": {"composite": composite,
                                    "dims": {"retrieval_precision": composite}},
                    "resource": {"work_fuel": 100, "rendered_cost": 10.0},
                    "integrity": {"measured": True, "violations": 0, "reasons": []},
                }
            return {"arms": arms, "replay_identical": {n: True for n in payload["arms"]},
                    "networkless": True}
        if mode == "aggregate":
            sides = {}
            for name, rows in payload["per_arm"].items():
                composite = round(sum(r["measurement"]["composite"] for r in rows) / len(rows), 6)
                sides[name] = {"composite": composite,
                               "objectives": {"retrieval_precision": composite},
                               "rendered_cost": 10.0, "compute_ms": 100.0,
                               "storage_bytes": 1024, "latency_ms": 7,
                               "corpus_supported": 40}
            sides["candidate"]["declared_limits"] = dict(payload["declared_limits"])
            delta = sides["candidate"]["composite"] - sides["parent"]["composite"]
            pareto_ok = delta > 0
            return {
                "candidate": sides["candidate"], "parent": sides["parent"],
                "verdict": {"admit": False, "verdict": "ADMIT" if pareto_ok else "REJECT",
                            "pareto_ok": pareto_ok, "hard_ok": False,
                            "satisfied_clauses": ["a_higher_utility_held_cost"] if pareto_ok
                                                 else [],
                            "failed_hard": ["portability_matrix"],
                            "targeted_objectives": list(payload["targeted"]),
                            "deltas": {"delta_composite": round(delta, 6)},
                            "reason": "fake comparison"},
                "networkless": True,
            }
        raise AssertionError(f"unexpected child mode {mode!r}")


def _score_calls(child):
    return [c for c in child.calls if c["mode"] == "score"]


def run_preview(graph, *, child=None, module=CANDIDATE_MODULE, manifest=None, **kwargs):
    child = child or FakeLawTreeChild()
    report = pv.preview_current_parent(
        child=child, store=graph["store"], parent_root=graph["parent_root"],
        target_profile=TARGET, module_source=module.decode("utf-8"),
        candidate_manifest=manifest or candidate_manifest(), **kwargs)
    return report, child


# --------------------------------------------------------------------------- #
# 1. parser wiring
# --------------------------------------------------------------------------- #
def test_the_subcommand_is_wired_into_the_parser_with_the_shared_law_arguments():
    args = cli.build_parser().parse_args([
        "preview-current-parent", "module.py", "--manifest", "manifest.json",
        "--profile", TARGET, "--parent-root", "ab" * 32, "--artifact-dir", "/tmp/cas"])

    assert args.func is cli._cmd_preview_current_parent
    assert (args.module, args.manifest, args.profile) == ("module.py", "manifest.json", TARGET)
    assert args.parent_root == "ab" * 32
    assert args.artifact_dir == "/tmp/cas"
    assert args.scale == "small"
    # `_add_law_arguments` supplies exactly these three on every admission-driving command.
    assert (args.law_root, args.law_cache, args.no_law_cache) == (None, None, False)


def test_the_command_is_listed_in_the_cli_docstring_table():
    assert "preview-current-parent" in cli.__doc__


# --------------------------------------------------------------------------- #
# 2. the law cache is a hard prerequisite
# --------------------------------------------------------------------------- #
def test_no_law_cache_is_a_named_refusal_with_a_remedy_not_a_silent_local_score(
        tmp_path, capsys):
    graph = parent_graph()
    cas = tmp_path / "cas"
    cas.mkdir()
    for root, data in graph["store"]._objects.items():
        (cas / root).write_bytes(data)
    module = tmp_path / "candidate.py"
    module.write_bytes(CANDIDATE_MODULE)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(candidate_manifest()))

    code = cli.main(["preview-current-parent", str(module), "--manifest", str(manifest),
                     "--profile", TARGET, "--parent-root", graph["parent_root"],
                     "--artifact-dir", str(cas), "--no-law-cache"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["ok"] is False
    assert payload["code"] == "LAW_TREES_UNAVAILABLE"
    assert "sync-law" in payload["remedy"]
    # Even a refusal keeps the honesty fields: nothing was scored, so nothing may read as scored.
    assert payload["publicDevCasesOnly"] is True
    assert payload["predictsAdmission"] is False


def test_ambient_tree_pins_alone_do_not_authorize_a_preview(tmp_path, monkeypatch, capsys):
    """Inherited env pins are HOST STATE, not a verified law cache.

    A preview scored against whatever happened to be exported in the caller's shell is the exact
    unpinned number this command exists to avoid handing a miner, so `--no-law-cache` still
    refuses even with all three pins set in the environment.
    """
    graph = parent_graph()
    for name in (law_mod.ENV_REPO_ROOT, law_mod.ENV_BENCHMARK_V2, law_mod.ENV_MEMORY_RUNTIME):
        monkeypatch.setenv(name, str(tmp_path / "ambient"))
    module = tmp_path / "candidate.py"
    module.write_bytes(CANDIDATE_MODULE)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(candidate_manifest()))
    cas = tmp_path / "cas"
    cas.mkdir()

    code = cli.main(["preview-current-parent", str(module), "--manifest", str(manifest),
                     "--profile", TARGET, "--parent-root", graph["parent_root"],
                     "--artifact-dir", str(cas), "--no-law-cache"])

    assert code == 2
    assert json.loads(capsys.readouterr().out)["code"] == "LAW_TREES_UNAVAILABLE"


def test_an_unavailable_scorer_backlogs_instead_of_reporting_an_unscored_comparison():
    graph = parent_graph()
    with pytest.raises(pv.PreviewError) as excinfo:
        run_preview(graph, child=FakeLawTreeChild(available=False))
    assert excinfo.value.code == "SCORER_UNAVAILABLE"


# --------------------------------------------------------------------------- #
# 3. the chain is resolved and re-hashed at every step
# --------------------------------------------------------------------------- #
def test_the_resolved_chain_reports_every_root_and_its_hash_rule():
    graph = parent_graph()
    resolved = pv.resolve_parent(store=graph["store"], parent_root=graph["parent_root"],
                                 target_profile=TARGET)

    chain = {entry["step"]: entry for entry in resolved["chain"]}
    assert [entry["step"] for entry in resolved["chain"]] == [
        pv.STEP_FRONTIER, pv.STEP_COMPOSITION, pv.STEP_RELEASE, pv.STEP_MODULE]
    assert chain[pv.STEP_FRONTIER]["root"] == graph["parent_root"]
    assert chain[pv.STEP_FRONTIER]["hash_rule"] == pub.HASH_RULE_FRONTIER_JSON
    assert chain[pv.STEP_COMPOSITION]["root"] == graph["composition_root"]
    assert chain[pv.STEP_COMPOSITION]["hash_rule"] == pub.HASH_RULE_SIGNED_MANIFEST_BODY
    assert chain[pv.STEP_RELEASE]["root"] == graph["releases"][TARGET]
    assert chain[pv.STEP_RELEASE]["hash_rule"] == pub.HASH_RULE_SIGNED_MANIFEST_BODY
    assert chain[pv.STEP_MODULE]["root"] == graph["module_sha256"]
    assert chain[pv.STEP_MODULE]["hash_rule"] == pub.HASH_RULE_BYTES
    assert resolved["execution"]["exec"] == "candidate_module"


@pytest.mark.parametrize("step", [pv.STEP_FRONTIER, pv.STEP_COMPOSITION, pv.STEP_RELEASE,
                                  pv.STEP_MODULE])
def test_substituted_bytes_are_refused_at_every_resolution_step(step):
    graph = parent_graph()
    store = graph["store"]
    root = {pv.STEP_FRONTIER: graph["parent_root"],
            pv.STEP_COMPOSITION: graph["composition_root"],
            pv.STEP_RELEASE: graph["releases"][TARGET],
            pv.STEP_MODULE: graph["module_sha256"]}[step]
    if step == pv.STEP_MODULE:
        store._objects[root] = b"def substituted():\n    return True\n"
    elif step == pv.STEP_FRONTIER:
        other = dict(graph["manifest"], epoch=182)
        store._objects[root] = pub.encode(other, pub.HASH_RULE_FRONTIER_JSON)
    else:
        document = json.loads(store._objects[root].decode("utf-8"))
        document["policy_id" if step == pv.STEP_RELEASE else "format"] = "substituted"
        store._objects[root] = pub.encode(document, pub.HASH_RULE_SIGNED_MANIFEST_BODY)

    with pytest.raises(pv.PreviewError) as excinfo:
        pv.resolve_parent(store=store, parent_root=graph["parent_root"], target_profile=TARGET)

    assert excinfo.value.step == step
    assert excinfo.value.code == "PARENT_CHAIN_UNVERIFIED"


def test_a_missing_object_is_refused_rather_than_scored_against_nothing():
    graph = parent_graph()
    del graph["store"]._objects[graph["module_sha256"]]
    with pytest.raises(pv.PreviewError) as excinfo:
        pv.resolve_parent(store=graph["store"], parent_root=graph["parent_root"],
                          target_profile=TARGET)
    assert excinfo.value.step == pv.STEP_MODULE


# --------------------------------------------------------------------------- #
# 4. reference vs candidate_module classification: EXACT root, never similarity
# --------------------------------------------------------------------------- #
def test_the_parent_is_classified_reference_only_on_exact_initial_root_equality(monkeypatch):
    graph = parent_graph()
    monkeypatch.setitem(pe.PRODUCTION_REFERENCE_RELEASE_ROOTS, TARGET, graph["releases"][TARGET])

    report, child = run_preview(graph)

    assert report["parent"]["exec"] == "reference"
    assert report["parent"]["id"] == "reference-runtime"
    for call in _score_calls(child):
        assert call["arms"]["parent"] == {"kind": "reference"}


def test_a_near_miss_root_is_a_candidate_module_parent_not_a_reference_one(monkeypatch):
    graph = parent_graph()
    actual = graph["releases"][TARGET]
    near_miss = actual[:-1] + ("0" if actual[-1] != "0" else "1")
    monkeypatch.setitem(pe.PRODUCTION_REFERENCE_RELEASE_ROOTS, TARGET, near_miss)

    report, child = run_preview(graph)

    assert report["parent"]["exec"] == "candidate_module"
    assert report["parent"]["module_sha256"] == graph["module_sha256"]
    for call in _score_calls(child):
        assert call["arms"]["parent"]["kind"] == "module"


def test_the_reference_authority_is_the_packaged_exact_parent_authority_file():
    # No second list of "reference-ish" roots may exist in this command: it defers to the
    # authority document shipped in the wheel, which is what the adjudicator binds.
    assert pv.reference_release_roots() == pe.PRODUCTION_REFERENCE_RELEASE_ROOTS
    assert set(pv.reference_release_roots()) == set(fr.PROFILE_IDS)


# --------------------------------------------------------------------------- #
# 5. capability + fuel sourcing is PER ARM
# --------------------------------------------------------------------------- #
def test_each_arm_is_scored_with_its_own_capabilities_and_fuel_ceiling():
    graph = parent_graph()
    report, child = run_preview(graph)

    scored = _score_calls(child)
    assert scored, "the candidate was never scored"
    for call in scored:
        candidate_arm = call["arms"]["candidate"]
        parent_arm = call["arms"]["parent"]
        # candidate arm: from the CANDIDATE manifest
        assert candidate_arm["capabilities"] == CANDIDATE_CAPABILITIES
        assert candidate_arm["fuel_ceiling"] == CANDIDATE_MAX_COMPUTE_MS
        assert candidate_arm["sha256"] == CANDIDATE_SHA
        # parent arm: from the PARENT RELEASE manifest, never the candidate's
        assert parent_arm["capabilities"] == PARENT_CAPABILITIES
        assert parent_arm["fuel_ceiling"] == PARENT_MAX_COMPUTE_MS
        assert parent_arm["sha256"] == graph["module_sha256"]

    assert report["candidate"]["capabilities"] == CANDIDATE_CAPABILITIES
    assert report["candidate"]["fuel_ceiling"] == CANDIDATE_MAX_COMPUTE_MS
    assert report["parent"]["capabilities"] == PARENT_CAPABILITIES
    assert report["parent"]["fuel_ceiling"] == PARENT_MAX_COMPUTE_MS


def test_a_parent_release_without_a_compute_ceiling_uses_the_pinned_default_not_the_candidates():
    graph = parent_graph()
    store = graph["store"]
    body = {k: v for k, v in graph["release_manifests"][TARGET].items()
            if k not in ("manifest_self_sha256", "resource_requirements")}
    root, addressed = _publish_signed(body, store)
    # Re-point the whole graph at the ceiling-free release.
    composition = json.loads(store._objects[graph["composition_root"]].decode("utf-8"))
    composition["profile_bindings"][TARGET]["release_id"] = root
    composition["profile_bindings"][TARGET]["bundle_manifest_sha256"] = root
    composition_body = {k: v for k, v in composition.items() if k != "manifest_self_sha256"}
    composition_root, _ = _publish_signed(composition_body, store)
    manifest = dict(graph["manifest"], default_composition_root=composition_root,
                    profiles=dict(graph["manifest"]["profiles"], **{TARGET: root}))
    parent_root = pub.publish_item(manifest, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                   store=store)["root"]
    graph = dict(graph, parent_root=parent_root)

    report, child = run_preview(graph)

    assert report["parent"]["fuel_ceiling"] is None
    for call in _score_calls(child):
        assert call["arms"]["parent"]["fuel_ceiling"] is None


def test_the_candidate_manifest_must_declare_the_capabilities_the_arm_is_granted():
    graph = parent_graph()
    broken = candidate_manifest()
    del broken["capabilities"]
    with pytest.raises(pv.PreviewError) as excinfo:
        run_preview(graph, manifest=broken)
    assert excinfo.value.code == "CANDIDATE_MANIFEST_INVALID"


# --------------------------------------------------------------------------- #
# 6. THE A -> B CASE. One candidate, two parents, opposite answers.
# --------------------------------------------------------------------------- #
def test_a_candidate_that_beats_the_reference_baseline_can_still_lose_to_the_live_parent(
        monkeypatch):
    """The whole reason this command exists.

    B beats the frozen reference baseline — that is what ``kit.self_check`` would tell the miner —
    and LOSES to the live incumbent A. Same candidate bytes, same dev cases, both runs here.
    """
    reference_graph = parent_graph()
    monkeypatch.setitem(pe.PRODUCTION_REFERENCE_RELEASE_ROOTS, TARGET,
                        reference_graph["releases"][TARGET])
    against_reference, _ = run_preview(reference_graph)
    monkeypatch.undo()

    live_graph = parent_graph()
    against_live_parent, _ = run_preview(live_graph)

    assert against_reference["parent"]["exec"] == "reference"
    assert against_reference["comparison"]["beats_current_parent"] is True

    assert against_live_parent["parent"]["exec"] == "candidate_module"
    assert against_live_parent["comparison"]["beats_current_parent"] is False
    assert against_live_parent["comparison"]["delta"]["composite"] == pytest.approx(
        COMPOSITES[CANDIDATE_SHA] - COMPOSITES[PARENT_SHA])
    assert against_live_parent["verdict"]["verdict"] == "REJECT"


def test_both_arms_are_scored_on_the_identical_public_dev_cases():
    graph = parent_graph()
    child = FakeLawTreeChild(dev_seeds=(1002, 1003))
    report, _ = run_preview(graph, child=child)

    scored = _score_calls(child)
    assert [call["seed"] for call in scored] == [1002, 1003]
    assert report["dev_seeds"] == [1002, 1003]
    for call in scored:
        # one child per dev case, both arms inside it: identical instance, by construction
        assert set(call["arms"]) == {"candidate", "parent"}
        assert call["scale"] == "small"
        assert call["profile_id"] == TARGET


def test_the_dev_seeds_come_from_the_pinned_tree_and_are_never_hardcoded_here():
    graph = parent_graph()
    child = FakeLawTreeChild(dev_seeds=(4242, 4343, 4444))
    report, _ = run_preview(graph, child=child)
    assert report["dev_seeds"] == [4242, 4343, 4444]
    assert child.calls[0]["mode"] == "probe"


def test_a_scale_outside_the_pinned_trees_published_dev_set_is_refused():
    graph = parent_graph()
    with pytest.raises(pv.PreviewError) as excinfo:
        run_preview(graph, scale="enormous")
    assert excinfo.value.code == "NON_PUBLIC_DEV_CASE"


# --------------------------------------------------------------------------- #
# 7. the report says what it is, and what it is not
# --------------------------------------------------------------------------- #
def test_the_report_carries_the_mandatory_honesty_fields():
    graph = parent_graph()
    report, _ = run_preview(graph)

    assert report["publicDevCasesOnly"] is True
    assert report["predictsAdmission"] is False
    prose = report["disclaimer"].lower()
    assert "entropy" in prose                      # fresh entropy-selected confirmation cases
    assert "composite" in prose or "full composite law" in prose
    assert "not" in prose


def test_the_report_carries_both_arms_axes_and_the_frozen_verdict_verbatim():
    graph = parent_graph()
    report, _ = run_preview(graph)

    assert report["arms"]["candidate"]["composite"] == COMPOSITES[CANDIDATE_SHA]
    assert report["arms"]["parent"]["composite"] == COMPOSITES[PARENT_SHA]
    assert report["comparison"]["utility"]["composite"] == {
        "candidate": COMPOSITES[CANDIDATE_SHA], "parent": COMPOSITES[PARENT_SHA],
        "delta": pytest.approx(COMPOSITES[CANDIDATE_SHA] - COMPOSITES[PARENT_SHA])}
    assert set(report["comparison"]["resource"]) >= {
        "rendered_cost", "compute_ms", "storage_bytes", "latency_ms"}
    assert report["verdict"]["reason"] == "fake comparison"
    assert report["comparison"]["hard_gates_ok"] is False
    assert report["comparison"]["failed_hard"] == ["portability_matrix"]
    assert report["scorer"]["name"] == "fake-pinned-tree"


# --------------------------------------------------------------------------- #
# 8. exit codes: losing is information, not an error
# --------------------------------------------------------------------------- #
def _cli_run(tmp_path, graph, monkeypatch, capsys, child, extra=()):
    cas = tmp_path / "cas"
    cas.mkdir(exist_ok=True)
    for root, data in graph["store"]._objects.items():
        (cas / root).write_bytes(data)
    module = tmp_path / "candidate.py"
    module.write_bytes(CANDIDATE_MODULE)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(candidate_manifest()))
    # A --repo-root is a FULL checkout: it carries the five sealed benchmark-v2 subtrees, the
    # runtime tree AND the unsealed support trees. Building it for real here is what makes the CLI
    # tests exercise the same tree-resolution gate a stranger's host goes through.
    repo = tmp_path / "repo"
    for subtree in pv.SEALED_BENCH_SUBTREES + pv.SUPPORT_BENCH_SUBTREES:
        (repo / "benchmark-v2" / subtree).mkdir(parents=True, exist_ok=True)
        (repo / "benchmark-v2" / subtree / "__init__.py").write_text("\n")
    for name in pv.KIT_REQUIRED_FILES:
        (repo / "benchmark-v2" / "kit" / name).write_text("\n")
    (repo / "coretex-memory" / "coretex_memory").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(pv, "LawTreeChild", lambda **kwargs: child)
    code = cli.main(["preview-current-parent", str(module), "--manifest", str(manifest),
                     "--profile", TARGET, "--parent-root", graph["parent_root"],
                     "--artifact-dir", str(cas), "--repo-root", str(repo), *extra])
    return code, json.loads(capsys.readouterr().out)


def test_losing_to_the_current_parent_is_exit_zero(tmp_path, monkeypatch, capsys):
    graph = parent_graph()
    code, payload = _cli_run(tmp_path, graph, monkeypatch, capsys, FakeLawTreeChild())
    assert code == 0
    assert payload["comparison"]["beats_current_parent"] is False
    assert payload["comparison"]["satisfied_clauses"] == []
    assert payload["verdict"]["verdict"] == "REJECT"
    assert payload["comparison"]["meaning"] == (
        "the candidate does not satisfy any Pareto clause against the CURRENT CONFIRMED "
        "PARENT on the public dev cases; it is not an admission")
    assert "satisfies at least one" not in payload["comparison"]["meaning"]
    assert payload["ok"] is True


def test_beating_the_current_parent_is_also_exit_zero(tmp_path, monkeypatch, capsys):
    graph = parent_graph()
    monkeypatch.setitem(pe.PRODUCTION_REFERENCE_RELEASE_ROOTS, TARGET, graph["releases"][TARGET])
    code, payload = _cli_run(tmp_path, graph, monkeypatch, capsys, FakeLawTreeChild())
    assert code == 0
    assert payload["comparison"]["beats_current_parent"] is True


def test_an_unverifiable_parent_chain_is_an_operational_failure_exit_two(
        tmp_path, monkeypatch, capsys):
    graph = parent_graph()
    graph["store"]._objects[graph["module_sha256"]] = b"def substituted():\n    return True\n"
    code, payload = _cli_run(tmp_path, graph, monkeypatch, capsys, FakeLawTreeChild())
    assert code == 2
    assert payload["ok"] is False
    assert payload["code"] == "PARENT_CHAIN_UNVERIFIED"
    assert payload["step"] == pv.STEP_MODULE


# --------------------------------------------------------------------------- #
# 9. the real child. Skips cleanly on a host without the pinned trees.
# --------------------------------------------------------------------------- #
def _real_child():
    """Compose the real child, and FAIL — never skip — when `setup` would have provisioned it.

    D-1's lesson about this suite. The old gate returned ``None`` whenever the child was not
    available and the caller skipped, so the one condition that broke the documented miner flow —
    a verified law cache present and ``benchmark-v2/kit`` absent, which is the NORMAL state of a
    law cache — read as "not provisioned on this host" and the suite stayed green through a
    blocking defect. Absence of a law cache is still a legitimate skip (nothing was installed);
    a law cache WITHOUT the support trees the composition is supposed to supply is a failure.
    """
    bench = os.environ.get(law_mod.ENV_BENCHMARK_V2, "").strip()
    coretex = os.environ.get(law_mod.ENV_MEMORY_RUNTIME, "").strip()
    repo = os.environ.get(law_mod.ENV_REPO_ROOT, "").strip()
    if not (bench and coretex):
        cache = None
        try:
            cache = law_mod.find_cache()
        except Exception:                                      # noqa: BLE001 - absence, not error
            cache = None
        if cache is None:
            pytest.skip("no verified law cache on this host: nothing was ever installed")
        bench, coretex, repo = (cache.benchmark_v2_dir, cache.coretex_memory_dir, cache.root_dir)
    resolution = pv.resolve_scoring_trees(bench_v2_dir=bench, coretex_dir=coretex)
    child = pv.LawTreeChild(bench_v2_dir=bench, coretex_dir=coretex, repo_root=repo,
                            support_dirs=resolution.support_dirs)
    if not child.available():
        pytest.fail(
            "a law cache is installed but the scoring child is still not runnable — this is the "
            "exact D-1 shape (the law publication can never carry benchmark-v2/kit; `setup` has "
            "to supply it from the miner-kit tar). Skipping here is what hid the defect.\n"
            f"  resolution: {json.dumps(resolution.as_dict(), indent=2, sort_keys=True)}\n"
            f"  reason: {child.unavailable_reason}")
    return child


@pytest.mark.skipif(os.environ.get("CORETEX_PREVIEW_INTEGRATION", "") != "1",
                    reason="slow (minutes): set CORETEX_PREVIEW_INTEGRATION=1 to run the real "
                           "pinned child")
def test_real_child_scores_two_arms_on_one_public_dev_case():
    """The real thing: probe -> score -> aggregate through the pinned trees.

    Deliberately ONE dev seed rather than the whole published set — this exercises every branch of
    the child (both arm kinds, the networkless enforcement+proof, the tree's own aggregation and
    Pareto law) while staying inside a couple of minutes. The seeds themselves come out of the
    probe, so this test cannot drift from whatever the pinned kit publishes.
    """
    child = _real_child()
    probe = child({"mode": "probe"})
    assert probe["dev_seeds"] and TARGET in probe["profiles"]
    assert "small" in probe["dev_scales"]

    kit = child._find("kit", "example_submission") or ""
    if not kit or not os.path.isfile(os.path.join(kit, "module.py")):
        pytest.skip("the pinned kit ships no example submission to preview")
    with open(os.path.join(kit, "module.py"), "r", encoding="utf-8") as fh:
        source = fh.read()
    with open(os.path.join(kit, "manifest.json"), "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    arms = {"candidate": pv.build_candidate_arm(module_source=source, manifest=manifest),
            "parent": {"kind": "reference"}}

    seed = int(probe["dev_seeds"][0])
    scored = child({"mode": "score", "profile_id": TARGET, "scale": "small", "seed": seed,
                    "arms": arms})
    assert scored["networkless"] is True             # enforced AND proven, never asserted
    assert set(scored["arms"]) == {"candidate", "parent"}
    for row in scored["arms"].values():
        assert row["integrity"]["measured"] is True
        assert isinstance(row["measurement"]["composite"], (int, float))

    aggregated = child({
        "mode": "aggregate", "profile_id": TARGET,
        "declared_limits": dict(manifest.get("resource_requirements") or {}),
        "targeted": list(manifest.get("objectives_targeted") or ()),
        "replay_identical": bool(scored["replay_identical"]["candidate"]),
        "portability_breadth": None,
        "per_arm": {name: [scored["arms"][name]] for name in ("candidate", "parent")}})

    # The contract `preview_current_parent` relies on, checked against the real law.
    verdict = aggregated["verdict"]
    assert set(verdict) >= {"pareto_ok", "hard_ok", "satisfied_clauses", "failed_hard", "verdict"}
    comparison = pv._comparison(aggregated["candidate"], aggregated["parent"], verdict)
    assert comparison["beats_current_parent"] is bool(verdict["pareto_ok"])
    assert "composite" in comparison["utility"]
    assert {"rendered_cost", "compute_ms", "storage_bytes", "latency_ms"} <= set(
        comparison["resource"])
    # The local run does not execute the portability prerequisite, and says so rather than
    # quietly passing it.
    assert aggregated["portability"]["executed"] is False


def test_the_integration_gate_fails_rather_than_skips_when_setup_should_have_provisioned(
        tmp_path, monkeypatch):
    """The gate itself, exercised without the env flag.

    A law cache that verifies but leaves the scoring child unrunnable is a DEFECT, and this suite
    now says so out loud. Reproducing D-1 exactly: six sealed trees present, benchmark-v2/kit
    absent, no miner-kit tar anywhere.
    """
    cache_root = tmp_path / "law" / ("a" * 64)
    for subtree in pv.SEALED_BENCH_SUBTREES:
        (cache_root / "benchmark-v2" / subtree).mkdir(parents=True, exist_ok=True)
        (cache_root / "benchmark-v2" / subtree / "__init__.py").write_text("\n")
    (cache_root / "coretex-memory" / "coretex_memory").mkdir(parents=True, exist_ok=True)

    class _Cache:
        benchmark_v2_dir = str(cache_root / "benchmark-v2")
        coretex_memory_dir = str(cache_root / "coretex-memory")
        root_dir = str(cache_root)

    for name in (law_mod.ENV_BENCHMARK_V2, law_mod.ENV_MEMORY_RUNTIME, law_mod.ENV_REPO_ROOT):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(law_mod, "find_cache", lambda **kwargs: _Cache())
    monkeypatch.setattr(pv, "default_packages_dir", lambda: str(tmp_path / "no-packages"))

    with pytest.raises(pytest.fail.Exception) as excinfo:
        _real_child()
    assert "benchmark-v2/kit" in str(excinfo.value)
    assert "Skipping here is what hid the defect" in str(excinfo.value)


def test_the_integration_gate_still_skips_when_nothing_was_ever_installed(monkeypatch):
    for name in (law_mod.ENV_BENCHMARK_V2, law_mod.ENV_MEMORY_RUNTIME, law_mod.ENV_REPO_ROOT):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(law_mod, "find_cache", lambda **kwargs: None)
    with pytest.raises(pytest.skip.Exception):
        _real_child()
