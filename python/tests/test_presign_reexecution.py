from __future__ import annotations

from types import SimpleNamespace

import pytest

from coretex_validator import canonical_suite, eval_artifact, replay


PROFILE = "doc.tool.v1"
OTHER = "conv.pref.v1"
PARENT_ROOT = "1" * 64
CHILD_ROOT = "2" * 64
RELEASE_ROOT = "3" * 64
MODULE_ROOT = "4" * 64
COMPOSITION_ROOT = "5" * 64
REPORT_ROOT = "6" * 64


def _fixture(monkeypatch, *, non_target_changes=False, installed_module=MODULE_ROOT):
    parent = {"state": "parent", "profiles": {PROFILE: "a" * 64, OTHER: "b" * 64}}
    child = {"state": "child", "profiles": {PROFILE: RELEASE_ROOT, OTHER: "b" * 64}}

    monkeypatch.setattr(
        replay.frontier, "frontier_root",
        lambda manifest: PARENT_ROOT if manifest["state"] == "parent" else CHILD_ROOT)
    monkeypatch.setattr(replay.frontier, "apply_transition", lambda *args, **kwargs: child)
    monkeypatch.setattr(replay.publication, "read_back", lambda *args, **kwargs: b"verified")

    def execution(*, parent_manifest, target_profile, **_kwargs):
        if target_profile == PROFILE and parent_manifest["state"] == "child":
            return {
                "compact": "installed", "exec": "candidate_module",
                "release_root": RELEASE_ROOT, "candidate_hash": "7" * 64,
                "module": {"sha256": installed_module, "source": "def make_hooks():\n return {}\n"},
            }
        if target_profile == OTHER and parent_manifest["state"] == "child" \
                and non_target_changes:
            return {"compact": "other-changed", "exec": "reference"}
        return {
            "compact": "inc-parent" if target_profile == PROFILE else "other-stable",
            "exec": "reference", "release_root": parent_manifest["profiles"][target_profile],
        }

    monkeypatch.setattr(replay.parent_execution, "fetch_parent_execution", execution)
    monkeypatch.setattr(replay.parent_execution, "compact_identity", lambda value: value["compact"])

    report = {
        "candidate": {
            "module": {
                "sha256": MODULE_ROOT,
                "source": "def make_hooks():\n return {}\n",
            },
        },
    }
    availability = {
        "candidate_bundle": {
            "bytes": 1, "hash_rule": replay.publication.HASH_RULE_MANIFEST_BODY,
            "root": RELEASE_ROOT,
        },
        "candidate_module": {
            "bytes": 1, "hash_rule": replay.publication.HASH_RULE_BYTES,
            "root": MODULE_ROOT,
        },
        "candidate_adapter_module": {
            "bytes": 1, "hash_rule": replay.publication.HASH_RULE_BYTES,
            "root": MODULE_ROOT,
        },
        "composition_manifest": {
            "bytes": 1, "hash_rule": replay.publication.HASH_RULE_MANIFEST_BODY,
            "root": COMPOSITION_ROOT,
        },
        "parent_frontier_manifest": {
            "bytes": 1, "hash_rule": replay.publication.HASH_RULE_FRONTIER_JSON,
            "root": PARENT_ROOT,
        },
        "resulting_frontier_manifest": {
            "bytes": 1, "hash_rule": replay.publication.HASH_RULE_FRONTIER_JSON,
            "root": CHILD_ROOT,
        },
    }
    artifact = {
        "availability": availability,
        "candidate": {
            "candidate_hash": "7" * 64,
            "prior_release_root": "a" * 64,
            "release_root": RELEASE_ROOT,
            "target_profile": PROFILE,
        },
        "epoch": 9,
        "frontier": {
            "benchmark_law_root": "8" * 64,
            "composition_root": COMPOSITION_ROOT,
            "new_frontier_root": CHILD_ROOT,
            "parent_frontier_root": PARENT_ROOT,
            "runtime_abi_root": "9" * 64,
            "transition": {
                "resulting_composition_root": COMPOSITION_ROOT,
                "target_profile": PROFILE,
            },
        },
        "receipt": {"eval_report_root": REPORT_ROOT},
        "replay_inputs": {"incumbent": "inc-parent", "parent_manifest": parent},
        "determinism_witness": eval_artifact.build_determinism_witness(
            profile_id=PROFILE,
            release_root="a" * 64,
            source_kind="genesis",
            source_root=REPORT_ROOT,
            partitions={
                label: canonical_suite.genesis_floor_vector(PROFILE, label)
                for label in eval_artifact.SELECTION_LABELS
            },
        ),
    }
    release = SimpleNamespace(release=SimpleNamespace(raw={
        "genesis": {"profile_releases": {
            PROFILE: {"root": "a" * 64}, OTHER: {"root": "b" * 64},
        }},
    }))

    class Runner:
        def __init__(self):
            self.calls = []

        def validate_execution(self, _execution):
            return None

        def replay_report(self, body, *, expected_root, incumbent_execution,
                          parent_stored_vector):
            self.calls.append((body, expected_root, incumbent_execution, parent_stored_vector))
            return {"reproduced": True, "report_root": expected_root}

    return artifact, report, release, Runner(), child


def test_presign_reexecutes_exact_parent_and_proves_installed_child(monkeypatch):
    artifact, report, release, runner, child = _fixture(monkeypatch)
    result = replay.pre_sign_reexecute(
        evaluation_artifact=artifact, evaluation_report=report, release=release,
        store=SimpleNamespace(), benchmark_runner=runner, child_manifest=child)
    assert result["ok"] is True
    assert result["incumbent"] == "inc-parent"
    assert result["installed"] == "installed"
    assert runner.calls[0][1] == REPORT_ROOT
    assert runner.calls[0][3]["source_kind"] == "genesis"


def test_presign_refuses_missing_determinism_witness(monkeypatch):
    artifact, report, release, runner, child = _fixture(monkeypatch)
    del artifact["determinism_witness"]
    with pytest.raises(replay.ReplayError, match="PARENT_STORED_VECTOR_MISSING"):
        replay.pre_sign_reexecute(
            evaluation_artifact=artifact, evaluation_report=report, release=release,
            store=SimpleNamespace(), benchmark_runner=runner, child_manifest=child)


def test_presign_refuses_score_replay_failure(monkeypatch):
    artifact, report, release, runner, child = _fixture(monkeypatch)

    def refused(*_args, **_kwargs):
        raise RuntimeError("reproduced report root differs")

    runner.replay_report = refused
    with pytest.raises(RuntimeError, match="report root differs"):
        replay.pre_sign_reexecute(
            evaluation_artifact=artifact, evaluation_report=report, release=release,
            store=SimpleNamespace(), benchmark_runner=runner, child_manifest=child)


def test_presign_refuses_wrong_scored_or_installed_module(monkeypatch):
    artifact, report, release, runner, child = _fixture(
        monkeypatch, installed_module="f" * 64)
    with pytest.raises(replay.ReplayError, match="different candidate/module bytes"):
        replay.pre_sign_reexecute(
            evaluation_artifact=artifact, evaluation_report=report, release=release,
            store=SimpleNamespace(), benchmark_runner=runner, child_manifest=child)


def test_presign_refuses_non_target_execution_change(monkeypatch):
    artifact, report, release, runner, child = _fixture(
        monkeypatch, non_target_changes=True)
    with pytest.raises(replay.ReplayError, match="non-target public execution"):
        replay.pre_sign_reexecute(
            evaluation_artifact=artifact, evaluation_report=report, release=release,
            store=SimpleNamespace(), benchmark_runner=runner, child_manifest=child)


def test_presign_refuses_availability_that_does_not_name_scored_module(monkeypatch):
    artifact, report, release, runner, child = _fixture(monkeypatch)
    artifact["availability"]["candidate_module"]["root"] = "e" * 64
    with pytest.raises(replay.ReplayError, match="candidate_module"):
        replay.pre_sign_reexecute(
            evaluation_artifact=artifact, evaluation_report=report, release=release,
            store=SimpleNamespace(), benchmark_runner=runner, child_manifest=child)
