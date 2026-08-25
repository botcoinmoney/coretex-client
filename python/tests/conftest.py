# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the ported validator suite — and the shim that lets it run VERBATIM.

WHY THE ALIASES BELOW EXIST. Every test file in this directory is a byte-for-byte copy of the
staged validator's own suite. They import ``frontier``, ``publication``, ``eval_artifact``,
``keccak256`` and ``validator.*`` as TOP-LEVEL names, because in the coordinator tree those were
top-level modules on ``sys.path``. Here they are submodules of :mod:`coretex_validator`.

The choice was: rewrite ~4500 lines of imports, or map the names. Mapping wins, and not only for
effort — a ported test that had to be EDITED to pass proves the edit rather than the port. The
tests are the evidence that the port did not change behaviour, so they must be able to run
unmodified. ``sys.modules`` aliasing is exactly the tool for that, and it is confined to this
file so no shipped module depends on it.

``validator`` is synthesised as a package whose ``dispatch``/``replay``/``sync``/``backlog``/
``chain_first`` attributes are the packaged modules — the same objects, not copies, so identity
checks and monkeypatching in the tests behave as they did.
"""
from __future__ import annotations

import os
import sys
import types

import pytest

_PYTHON_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PYTHON_ROOT not in sys.path:
    sys.path.insert(0, _PYTHON_ROOT)

import coretex_validator                                           # noqa: E402
from coretex_validator import (                                    # noqa: E402
    backlog as _backlog,
    chain_first as _chain_first,
    dispatch as _dispatch,
    eval_artifact as _eval_artifact,
    frontier as _frontier,
    keccak256 as _keccak256,
    publication as _publication,
    replay as _replay,
    sync as _sync,
)

for _name, _module in (("frontier", _frontier), ("publication", _publication),
                       ("eval_artifact", _eval_artifact), ("keccak256", _keccak256)):
    sys.modules.setdefault(_name, _module)

_validator_pkg = sys.modules.get("validator")
if _validator_pkg is None:
    _validator_pkg = types.ModuleType("validator")
    _validator_pkg.__path__ = []                                   # a package, so `from` works
    sys.modules["validator"] = _validator_pkg
for _name, _module in (("backlog", _backlog), ("chain_first", _chain_first),
                       ("dispatch", _dispatch), ("replay", _replay), ("sync", _sync)):
    setattr(_validator_pkg, _name, _module)
    sys.modules[f"validator.{_name}"] = _module

import frontier as fr                                              # noqa: E402

#: The staged suite reads ``V5_DIR``/``REPO`` for tree-relative fixtures. Only the GENESIS record
#: actually needs one, and it is not shipped with the client, so the fixture skips rather than
#: pretending a path exists.
V5_DIR = _PYTHON_ROOT
REPO = os.path.dirname(_PYTHON_ROOT)


ROOT_A = "a" * 64
ROOT_B = "4e81744ee61fd58602c04b23210b8ac7dad66cc126986ac82db2af66200dbe9c"
ROOT_C = "c" * 64
ROOT_LAW = "1" * 64
ROOT_ABI = "2" * 64
ROOT_COMP = "3" * 64
ROOT_COMP2 = "4" * 64


def make_manifest(**overrides):
    """A valid, non-genesis manifest (parent is a real root, not the ZERO sentinel)."""
    manifest = {
        "benchmark_law_root": ROOT_LAW,
        "default_composition_root": ROOT_COMP,
        "epoch": 7,
        "format": fr.MANIFEST_FORMAT,
        "parent_frontier_root": "9" * 64,
        "profiles": {"conv.pref.v1": ROOT_A, "doc.tool.v1": ROOT_B, "event.schema.v1": ROOT_C},
        "runtime_abi_root": ROOT_ABI,
    }
    manifest.update(overrides)
    return manifest


@pytest.fixture()
def manifest():
    return make_manifest()


@pytest.fixture()
def transition():
    return fr.make_transition(
        target_profile="doc.tool.v1",
        expected_prior_release_root=ROOT_B,
        new_release_root="d" * 64,
        resulting_composition_root=ROOT_COMP2)


@pytest.fixture(scope="session")
def genesis_record():
    # GENESIS.json is the coordinator's committed genesis record and is NOT part of the public
    # client. Skipping is the honest outcome; shipping a copy would mean the client carried a
    # value it cannot re-derive.
    path = os.path.join(V5_DIR, "GENESIS.json")
    if not os.path.isfile(path):
        pytest.skip("GENESIS.json is a coordinator artifact and is not shipped with the client")
    with open(path, "r", encoding="utf-8") as fh:
        return fr.parse_json(fh.read())


# --------------------------------------------------------------------------- #
# V5-C: eval-artifact fixtures
#
# A SYNTHETIC but structurally faithful Benchmark-v2 signed receipt. It is deliberately built
# here rather than imported from ``benchmark-v2``: the two trees both ship a package named
# ``frontier`` and must never be on one sys.path (see the module docstring above), and a real
# receipt would need wasm + the frozen runtime, which the V5 lane must not require. The SHAPES
# are the real ones (``validator/receipt.py::build_receipt_body``,
# ``validator/evaluate.py::_side_measurements``), floats included — that is exactly what the
# artifact has to project into exact micro-integers.
# --------------------------------------------------------------------------- #
import eval_artifact as ea                                          # noqa: E402
import publication as pub                                           # noqa: E402

SEASON_ROOT = "5" * 64
ROUND_ID = "round-0001"
SCALES = ["small", "medium"]
ENTROPY_SECRET = "7" * 64
CANDIDATE_HASH = "e" * 64
NEW_RELEASE_ROOT = "d" * 64
TARGET_PROFILE = "doc.tool.v1"
EPOCH = 7

OBJECTIVES = ("consolidation", "retrieval", "workflow_provenance")


def measured_side(*, composite, rendered_cost, work_fuel, storage_bytes, store_ops=400,
                  events_scanned=9000, store_events=1200, corpus_supported=1500,
                  hook_fuel=None):
    """One measured side in the Benchmark-v2 ``fuel-metered.v1`` shape (floats and all)."""
    resource = {"policy": "fuel-metered.v1", "work_fuel": work_fuel, "store_ops": store_ops,
                "events_scanned": events_scanned, "store_events": store_events,
                "storage_bytes": storage_bytes, "host_profile": "g4-4core-x86_64"}
    if hook_fuel is not None:
        resource["hook_fuel"] = hook_fuel
    return {
        "latency_ms": round(float(work_fuel) / float(store_ops), 6),
        "storage_bytes": storage_bytes,
        "compute_ms": float(work_fuel),
        "corpus_supported": corpus_supported,
        "resource": resource,
        "objectives": {o: round(composite + i * 0.5, 6) for i, o in enumerate(OBJECTIVES)},
        "composite": composite,
        "rendered_cost": rendered_cost,
    }


def selection_cases(base, indices, profile_id=TARGET_PROFILE, scales=None):
    """Cases that GENUINELY sit at ``indices`` of the entropy-derived walk."""
    scales = scales or SCALES
    out = []
    for idx in indices:
        seed, scale = ea.derive_step(base, idx, scales)
        out.append({"derivation_index": idx, "profile_id": profile_id, "scale": scale,
                    "seed": seed, "instance_id": ea.instance_id(profile_id, seed, scale),
                    "instance_hash": fr.sha256_hex(f"instance:{idx}:{seed}".encode("utf-8"))})
    return out


def make_receipt_wrapper(*, gate_entropy, confirm_entropy, gate_cases, confirm_cases,
                         admit=True, candidate_hash=CANDIDATE_HASH,
                         profile_id=TARGET_PROFILE, candidate_composite=71.5,
                         candidate_rendered=880.25, incumbent_composite=64.0,
                         incumbent_rendered=1020.5, key_id="g4-validator-test-1"):
    candidate = measured_side(composite=candidate_composite, rendered_cost=candidate_rendered,
                              work_fuel=48000, storage_bytes=310000, hook_fuel=6000)
    incumbent = measured_side(composite=incumbent_composite, rendered_cost=incumbent_rendered,
                              work_fuel=52000, storage_bytes=340000)
    candidate = dict(candidate,
                     hard={"canonical_event_integrity_violations": 0, "provenance_violations": 0,
                           "validity_violations": 0, "stale_or_retracted_disclosures": 0,
                           "replay_identical": True,
                           "resource_usage": {"latency_ms": candidate["latency_ms"],
                                              "storage_bytes": candidate["storage_bytes"],
                                              "compute_ms": candidate["compute_ms"],
                                              "rendered_tokens": candidate_rendered}},
                     declared_limits={"max_compute_ms": 100000})
    verdict = {"admit": admit, "reason": "clause-a" if admit else "no-improvement",
               "targeted_objectives": ["consolidation"]}
    decision = {"admit": admit, "verdict": "ADMIT" if admit else "REJECT",
                "reason": {"gate": verdict["reason"], "confirm": verdict["reason"]}}
    body = {
        "format": ea.RECEIPT_BODY_FORMAT,
        "measurement_policy": "fuel-metered.v1",
        "season_root": SEASON_ROOT,
        "profile_id": profile_id,
        "round_id": ROUND_ID,
        "round_hash": "6" * 64,
        "scales": list(SCALES),
        "candidate": {"candidate_hash": candidate_hash, "manifest_hash": "a1" * 32,
                      "declaration_id": "a1" * 32, "exec": "candidate_module",
                      "manifest": {"candidate_hash": candidate_hash}},
        "incumbent": {"id": "reference-runtime", "candidate_hash": None, "exec": "reference"},
        # Frozen R12 production roots. Three-field identities are historical evidence only and
        # are accepted solely when the addressed report binds this exact pre-cut tree.
        "code_roots": {
            "candidate_isolation_posture":
                "77e581c35758e0e1bef0b58e07322b7d3f4a7e8c5f120ea7067a48f41cbf0e69",
            "frontier": "9ccdfe9bcabca32015dd5b5a809f1fa4e383500310cd5b18fbafb86dbdbbfea1",
            "generators": "20a8402bc5de5ca791963efd33a31df09ab9cd451e926399a546d8e431d65d15",
            "miner_abi": "074511156e7bb1088596e81dc0794b11221cbd5a35aa875e6a34d9ac28d9f73d",
            "runtime_coretex_memory":
                "e0e334dba9d88020e59c493ba1bf9d1ef0cbb9ebbf5b572353a43b9c9261e25b",
            "scoring": "867a96b0bfca26ac462978964f3e6fb238821c0e95c002c5641c4c51b83e07a5",
            "validator": "9f55f31169e08dbb6c695e4edb26e6299e84ee1264f84788b76bc9fdd0939e04",
        },
        "entropy": {"provider": "file.v1", "ref": "gate-fixture", "value": gate_entropy,
                    "proof": {"fixture": "gate-fixture", "sha256": "20" * 32}},
        "confirm_entropy": {"provider": "file.v1", "ref": "confirm-fixture",
                            "value": confirm_entropy,
                            "proof": {"fixture": "confirm-fixture", "sha256": "21" * 32}},
        "burned_head": {"record_hash": "0" * 64, "records": 0},
        "selection": {"gate": [dict(c) for c in gate_cases],
                      "confirm": [dict(c) for c in confirm_cases]},
        "replay_check": {"instance_id": gate_cases[0]["instance_id"], "identical": True},
        "outputs_hash": "30" * 32,
        "scores": {"gate": {"candidate": candidate, "incumbent": incumbent},
                   "confirm": {"candidate": candidate, "incumbent": incumbent}},
        "verdicts": {"gate": verdict, "confirm": verdict},
        "decision": decision,
    }
    return {"format": ea.RECEIPT_WRAPPER_FORMAT, "receipt": body,
            "receipt_hash": ea.receipt_body_hash(body),
            "signature": {"key_id": key_id, "ed25519_hex": "ab" * 64}}


def make_parts(*, admit=True, epoch=EPOCH, secret=ENTROPY_SECRET,
               candidate_hash=CANDIDATE_HASH, **receipt_kwargs):
    """Every consistent input an artifact needs: parent, transition, receipt, law, entropy."""
    parent = make_manifest(epoch=epoch)
    transition = fr.make_transition(
        target_profile=TARGET_PROFILE, expected_prior_release_root=ROOT_B,
        new_release_root=NEW_RELEASE_ROOT, resulting_composition_root=ROOT_COMP2)
    parent_root = fr.frontier_root(parent)
    gate_entropy = ea.derive_entropy_value(revealed_secret=secret, epoch=epoch,
                                           parent_frontier_root=parent_root, label="gate")
    confirm_entropy = ea.derive_entropy_value(revealed_secret=secret, epoch=epoch,
                                              parent_frontier_root=parent_root, label="confirm")
    bases = {label: ea.selection_base(
        label=label, entropy_value=gate_entropy if label == "gate" else confirm_entropy,
        candidate_hash=candidate_hash, season_root=SEASON_ROOT, profile_id=TARGET_PROFILE,
        round_id=ROUND_ID) for label in ea.SELECTION_LABELS}
    cases = {label: selection_cases(bases[label], (0, 1, 2)) for label in ea.SELECTION_LABELS}
    wrapper = make_receipt_wrapper(gate_entropy=gate_entropy, confirm_entropy=confirm_entropy,
                                   gate_cases=cases["gate"], confirm_cases=cases["confirm"],
                                   admit=admit, candidate_hash=candidate_hash, **receipt_kwargs)
    # walk-era fixture -> the walk-era counter law (LAW 3A.6). See tests/test_law_vendoring.py.
    law = ea.load_counter_resource_law(ea.WALK_ERA_COUNTER_RESOURCE_LAW_PATH)
    return {"parent": parent, "transition": transition, "parent_root": parent_root,
            "new_root": fr.frontier_root(fr.apply_transition(parent, transition)),
            "secret": secret, "epoch": epoch, "candidate_hash": candidate_hash,
            "wrapper": wrapper, "law": law, "bases": bases, "cases": cases,
            "gate_entropy": gate_entropy, "confirm_entropy": confirm_entropy}


def publish_required(parts, store):
    """Publish the five objects a broadcastable receipt requires and return the availability map."""
    return {
        "candidate_bundle": pub.publish_item(b"<signed candidate bundle archive>",
                                             hash_rule=pub.HASH_RULE_BYTES, store=store),
        "composition_manifest": pub.publish_item(
            {"format": "benchmark-v2/g8-deployment-signed/v1", "operator_key_id": "test",
             "manifest_self_sha256": "unused", "operator_signature": "unused"},
            hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store),
        "counter_resource_law": pub.publish_item(parts["law"],
                                                 hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                                 store=store),
        "parent_frontier_manifest": pub.publish_item(parts["parent"],
                                                     hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                                     store=store),
        "receipt_wrapper": pub.publish_item(parts["wrapper"],
                                            hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store),
    }


def make_artifact(parts=None, *, store=None, canary=None, **kwargs):
    """A complete, self-consistent eval artifact (plus the store it was published into)."""
    parts = parts or make_parts(**kwargs)
    store = store if store is not None else pub.InMemoryCAS()
    availability = publish_required(parts, store)
    artifact = ea.build_artifact(
        epoch=parts["epoch"], parent_manifest=parts["parent"], transition=parts["transition"],
        candidate_hash=parts["candidate_hash"], receipt_wrapper=parts["wrapper"],
        revealed_entropy_secret=parts["secret"], counter_resource_law=parts["law"],
        availability=availability, canary=canary)
    return artifact, parts, store


def verify_kwargs(artifact, parts):
    """The chain-asserted expectations :func:`eval_artifact.verify_artifact` takes."""
    return {
        "expected_parent_root": parts["parent_root"],
        "expected_new_root": parts["new_root"],
        "expected_release_root": NEW_RELEASE_ROOT,
        "expected_composition_root": ROOT_COMP2,
        "expected_runtime_abi_root": ROOT_ABI,
        "expected_benchmark_law_root": ROOT_LAW,
        "expected_counter_resource_law_root": artifact["counter_resource_law_root"],
        "expected_entropy_commitment": ea.entropy_commitment_of(parts["secret"]),
        "expected_epoch": parts["epoch"],
        "expected_target_profile": TARGET_PROFILE,
        "receipt_wrapper": parts["wrapper"],
        "counter_resource_law": parts["law"],
    }


def make_sealed_transcript(artifact, *, verdict="PASS", policy=None, **overrides):
    """A sealed canary transcript whose bindings agree with ``artifact`` (float-bearing policy
    included — which is exactly why it lives OUTSIDE the artifact's canonical bytes)."""
    policy = policy or {
        "format": "benchmark-v2/canary/policy/v1", "model_id": "claude-haiku-test",
        "temperature": 0.0, "max_answer_tokens": 64, "scale": "small", "n_questions": 48,
        "per_run_usd_cap": 1.0, "max_accuracy_drop_pp": 5.0,
        "selection_domain": "benchmark-v2/canary/select/v1",
    }
    entropy_hex = artifact["entropy"]["gate_value"]
    candidate_hash = artifact["candidate"]["candidate_hash"]
    incumbent_root = artifact["frontier"]["parent_frontier_root"]
    epoch_id = str(artifact["epoch"])
    profile_id = artifact["candidate"]["target_profile"]
    import hashlib
    base = hashlib.sha256("|".join(
        (policy["selection_domain"], entropy_hex, candidate_hash, incumbent_root, profile_id,
         epoch_id, policy["scale"])).encode("utf-8")).hexdigest()
    sealed = {
        "format": ea.CANARY_TRANSCRIPT_FORMAT,
        "external_model_attestation": True,
        "policy_hash": ea.canary_policy_hash(policy),
        "policy": policy,
        "code_identity": {"format": "benchmark-v2/canary/code-identity/v1",
                          "scorer_version": "canary-scorer.v3",
                          "scoring.py_sha256": "40" * 32, "questions.py_sha256": "41" * 32},
        "epoch_id": epoch_id,
        "run_id": "canary-run-1",
        "mode": "dryrun",
        "entropy": {"hex": entropy_hex, "domain": policy["selection_domain"],
                    "selection_base_sha256": base},
        "candidate_hash": candidate_hash,
        "incumbent_root": incumbent_root,
        "selection": {"profile_id": profile_id, "scale": policy["scale"], "n_questions": 48},
        "verdict": {"verdict": verdict, "reasons": []},
    }
    sealed.update(overrides)
    return sealed


# --------------------------------------------------------------------------- #
# Process-environment isolation for the law pins and the law cache
#
# `law.LawCache.apply()` sets CORETEX_ADMISSION_REPO_ROOT / CORETEX_BENCHMARK_V2_DIR /
# CORETEX_MEMORY_RUNTIME_DIR in `os.environ`, because that is how the CLI hands a verified law
# cache to its child interpreters. Any test that drives a CLI command in-process therefore leaks
# those pins into the pytest process, and from 0.5.0 the scorers read them when they are
# CONSTRUCTED rather than when `replay` was imported — so a later test that expected an
# unconfigured host would build a scorer pointed at an earlier test's tree and shell out to it.
#
# `law.default_cache_dir()` resolves under $XDG_DATA_HOME (else ~/.local/share), so on a machine
# where an operator has actually run `sync-law` the suite would find that REAL law cache, activate
# it, and run the real oracle screen against the real generators — minutes per case, and a
# different outcome on every host. A suite whose result depends on whether the developer has
# synced a law is not a suite. Both are ambient state, and both are isolated here.
# --------------------------------------------------------------------------- #
from coretex_validator import law as _law                          # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_law_environment(tmp_path_factory):
    names = tuple(_law.ENV_PINS) + ("XDG_DATA_HOME",)
    saved = {name: os.environ.get(name) for name in names}
    for name in _law.ENV_PINS:
        os.environ.pop(name, None)
    os.environ["XDG_DATA_HOME"] = str(tmp_path_factory.mktemp("xdg"))
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
