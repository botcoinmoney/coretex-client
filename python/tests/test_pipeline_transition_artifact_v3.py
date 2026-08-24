# SPDX-License-Identifier: Apache-2.0
"""Focused orchestration tests for pipeline admission of generalized v3 artifacts."""
from __future__ import annotations

import copy
import inspect
from types import SimpleNamespace
from typing import Optional

import pytest

from coretex_validator import dispatch as dp
from coretex_validator import frontier as fr
from coretex_validator import pipeline
from coretex_validator import publication as pub
from coretex_validator import resolver_snapshot as rsn
from coretex_validator import rig_events as rig


class RecordingStore(pub.InMemoryCAS):
    def __init__(self) -> None:
        super().__init__()
        self.reads = []

    def get(self, root):
        self.reads.append(root)
        return super().get(root)


class TransportUnavailableAt(pub.ContentStore):
    def __init__(self, delegate, root):
        self.delegate = delegate
        self.root = root

    def put(self, root, data):
        self.delegate.put(root, data)

    def get(self, root):
        if root == self.root:
            raise pub.TransportUnavailableError(f"fixture transport failed at {root}")
        return self.delegate.get(root)

    def has(self, root):
        return root != self.root and self.delegate.has(root)


def _fixture(*, candidate_release: str = "cd" * 32,
             moved_release: Optional[str] = None,
             eval_composition: Optional[str] = None):
    prior_release = "ab" * 32
    signed_release = "cd" * 32
    composition = "ef" * 32
    benchmark = "12" * 32
    runtime = "13" * 32
    counter = "14" * 32
    moved_release = moved_release or signed_release
    eval_composition = eval_composition or composition

    parent = fr.new_manifest(
        epoch=8, parent_frontier_root="01" * 32,
        benchmark_law_root=benchmark, runtime_abi_root=runtime,
        default_composition_root="02" * 32,
        profiles={"conv.pref.v1": "03" * 32, "doc.tool.v1": "04" * 32,
                  "event.schema.v1": prior_release})
    parent_root = fr.frontier_root(parent)
    epoch_context_document = {
        "format": rig.EPOCH_CONTEXT_FORMAT,
        "epoch": 9,
        "corpus_root": "15" * 32,
        "active_frontier_root": parent_root,
        "baseline_manifest_hash": "16" * 32,
        "benchmark_law_root": benchmark,
        "runtime_abi_root": runtime,
        "counter_resource_law_root": counter,
        "selection_law_root": "17" * 32,
        "admission_thresholds_ppm": {"minimum_improvement": 1},
        "seed_commitment": {
            "scheme": "keccak256",
            "binding_rule": "confirmed-epoch-context",
            "commitment_source": "EpochCommitSet",
        },
    }
    epoch_context_bytes = fr.canonical_bytes(
        rig.validate_epoch_context(epoch_context_document))
    epoch_context = rig.epoch_context_root(epoch_context_document)
    resulting = fr.new_manifest(
        epoch=9, parent_frontier_root=parent_root,
        benchmark_law_root=benchmark, runtime_abi_root=runtime,
        default_composition_root=composition,
        profiles={"conv.pref.v1": "03" * 32, "doc.tool.v1": "04" * 32,
                  "event.schema.v1": moved_release})
    new_root = fr.frontier_root(resulting)
    eval_transition = fr.make_transition(
        target_profile="event.schema.v1",
        expected_prior_release_root=prior_release,
        new_release_root=candidate_release,
        resulting_composition_root=eval_composition)
    eval_artifact = {
        "candidate": {"release_root": candidate_release},
        "frontier": {
            "parent_frontier_root": parent_root,
            "new_frontier_root": new_root,
            "composition_root": eval_composition,
            "benchmark_law_root": benchmark,
            "runtime_abi_root": runtime,
            "transition": eval_transition,
        },
        "counter_resource_law_root": counter,
    }
    eval_bytes = fr.canonical_bytes(eval_artifact)
    eval_root = fr.sha256_hex(eval_bytes)

    # The pure rig_events verifier owns the v3 closed schema. These bytes only exercise the
    # pipeline's read-back discipline; the verifier is replaced below so this test stays focused
    # on orchestration rather than duplicating the authoritative artifact validator's suite.
    served_patch = fr.canonical_bytes({"fixture": "pipeline-v3"})
    patch_root = fr.sha256_hex(served_patch)
    descriptor = rig.encode_transition_descriptor(
        patch_artifact_hash=patch_root, parent_state_root=parent_root,
        new_state_root=new_root)
    advance = rig.StateAdvanced(
        epoch=9, transition_index=0, miner="0x" + "11" * 20,
        parent_state_root=parent_root, new_state_root=new_root,
        patch_hash=rig.transition_descriptor_hash(descriptor), eval_report_hash=eval_root,
        core_version_hash="16" * 32, epoch_context_root=epoch_context,
        improvement_credits=1, transition_format_version=0x21,
        compact_patch_bytes=descriptor, provenance=dp.LogProvenance())
    selected = SimpleNamespace(
        advance=advance,
        receipt={"scoreBeforePpm": 100, "scoreAfterPpm": 200,
                 "artifactHash": signed_release})
    patch_document = {
        "profile_releases": {
            "event.schema.v1": {
                "expected_prior_release_root": prior_release,
                "hooks": ["m6_pack"], "new_release_root": moved_release,
            },
        },
        "resulting_composition_root": composition,
        "resulting_frontier_manifest": resulting,
    }
    store = RecordingStore()
    for root, data in ((eval_root, eval_bytes),
                       (patch_root, served_patch),
                       (parent_root, fr.canonical_bytes(parent)),
                       (epoch_context, epoch_context_bytes)):
        store.put(root, data)
    return SimpleNamespace(
        selected=selected, store=store, patch_document=patch_document,
        served_patch=served_patch, patch_root=patch_root, parent=parent,
        parent_root=parent_root, resulting=resulting, composition=composition,
        epoch_context=epoch_context, epoch_context_document=epoch_context_document,
        signed_release=signed_release)


def _install_pure_port_spies(monkeypatch, fixture):
    calls = SimpleNamespace(verify=[], replay=[], materialized=[], projected=[])

    def verify(served, *, descriptor, score_delta_ppm=None, epoch_context_root_=None):
        calls.verify.append((served, descriptor, score_delta_ppm, epoch_context_root_))
        return copy.deepcopy(fixture.patch_document)

    def replay(parent, artifact, *, component_references=None, epoch_pins=None):
        calls.replay.append((parent, artifact, component_references, epoch_pins))
        return copy.deepcopy(fixture.resulting)

    def materialize(*, releases, composition_root, expected_candidate_hashes, store):
        calls.materialized.append((dict(releases), composition_root,
                                   dict(expected_candidate_hashes), store))
        return {"composition": {},
                "releases": {profile: {} for profile in fr.PROFILE_IDS}}

    class UnavailableSandbox:
        bench_v2_dir = None
        coretex_dir = None

        @staticmethod
        def available():
            return False

    class UnavailableScreen:
        @staticmethod
        def available():
            return False

    def replay_advance(projected, **_kwargs):
        calls.projected.append(projected)
        return SimpleNamespace(outcome="PASS", reason="focused pipeline fixture",
                               checks=("v3_pipeline",), code=None, stage=None)

    monkeypatch.setattr(rig, "verify_transition_artifact_bytes", verify, raising=False)
    monkeypatch.setattr(rig, "replay_transition_artifact", replay, raising=False)
    monkeypatch.setattr(pipeline.rg, "verify_materializable_release_state", materialize)
    monkeypatch.setattr(pipeline.rp, "default_sandbox", lambda: UnavailableSandbox())
    monkeypatch.setattr(pipeline.rp, "default_oracle_screen", lambda: UnavailableScreen())
    monkeypatch.setattr(pipeline.rp, "replay_advance", replay_advance)
    return calls


def _admit(monkeypatch, fixture):
    calls = _install_pure_port_spies(monkeypatch, fixture)
    law = SimpleNamespace(epoch_context_root=fixture.epoch_context,
                          entropy_commitment="18" * 32, revealed_secret=None)
    artifact, report = pipeline._admit(
        fixture.selected, law, fixture.store, allow_test_doubles=False)
    return artifact, report, calls


def test_v3_admission_passes_exact_served_bytes_through_full_parent_replay(monkeypatch):
    fixture = _fixture()
    artifact, report, calls = _admit(monkeypatch, fixture)

    assert artifact["candidate"]["release_root"] == fixture.signed_release
    assert report["outcome"] == "PASS"
    assert fixture.patch_root in fixture.store.reads
    assert fixture.parent_root in fixture.store.reads
    assert fixture.epoch_context in fixture.store.reads
    served, descriptor, delta, context_root = calls.verify[0]
    assert served == fixture.served_patch
    assert descriptor.patch_artifact_hash == fixture.patch_root
    assert delta == 100
    assert context_root == fixture.epoch_context
    parent, patch, component_references, epoch_pins = calls.replay[0]
    assert parent == fixture.parent
    assert patch == fixture.patch_document
    assert component_references is None
    assert epoch_pins == {
        "epoch": 9,
        "epoch_context_root": fixture.epoch_context,
        "benchmark_law_root": fixture.epoch_context_document["benchmark_law_root"],
        "runtime_abi_root": fixture.epoch_context_document["runtime_abi_root"],
    }
    releases, composition, candidates, store = calls.materialized[0]
    assert releases == fixture.resulting["profiles"]
    assert composition == fixture.composition
    # This focused orchestration double omits the full eval-artifact candidate block; the real
    # production shape supplies it and release_graph tests cover the binding itself.
    assert candidates == {}
    assert store is fixture.store
    projected = calls.projected[0]
    assert projected.candidate_release_root == fixture.signed_release
    assert projected.composition_root == fixture.composition
    assert projected.transition_bytes == fr.canonical_bytes(artifact["frontier"]["transition"])


def test_eval_candidate_must_equal_signed_artifact_hash(monkeypatch):
    fixture = _fixture(candidate_release="de" * 32, moved_release="de" * 32)
    _artifact, report, calls = _admit(monkeypatch, fixture)
    assert report["outcome"] == "FAIL"
    assert report["code"] == "RIG_ARTIFACT_HASH_SUBSTITUTION"
    assert "signed artifactHash" in report["reason"]
    assert calls.projected == []


def test_eval_candidate_must_be_among_nonempty_moved_release_roots(monkeypatch):
    fixture = _fixture(moved_release="de" * 32)
    _artifact, report, calls = _admit(monkeypatch, fixture)
    assert report["outcome"] == "FAIL"
    assert report["code"] == "RIG_ARTIFACT_HASH_SUBSTITUTION"
    assert "transition artifact moves" in report["reason"]
    assert calls.projected == []


def test_eval_composition_must_equal_v3_resulting_composition(monkeypatch):
    fixture = _fixture(eval_composition="de" * 32)
    _artifact, report, calls = _admit(monkeypatch, fixture)
    assert report["outcome"] == "FAIL"
    assert report["code"] == "RIG_COMPOSITION_ROOT_SUBSTITUTION"
    assert calls.projected == []


def test_epoch_context_must_be_available_before_transition_replay(monkeypatch):
    fixture = _fixture()
    fixture.store._objects.pop(fixture.epoch_context)
    artifact, report, calls = _admit(monkeypatch, fixture)

    assert artifact["candidate"]["release_root"] == fixture.signed_release
    assert report["outcome"] == "BACKLOG"
    assert report["code"] == rig.EPOCH_CONTEXT_UNAVAILABLE
    assert calls.replay == []


@pytest.mark.parametrize(
    "root_name,expected_code",
    [
        ("epoch_context", rig.EPOCH_CONTEXT_UNAVAILABLE),
        ("patch_root", rig.TRANSITION_ARTIFACT_UNAVAILABLE),
        ("parent_root", rig.TRANSITION_ARTIFACT_UNAVAILABLE),
    ],
)
def test_pipeline_transport_failures_are_backlogs_at_every_fetch_stage(
        monkeypatch, root_name, expected_code):
    fixture = _fixture()
    fixture.store = TransportUnavailableAt(fixture.store, getattr(fixture, root_name))
    artifact, report, _calls = _admit(monkeypatch, fixture)

    assert artifact is not None
    assert report["outcome"] == "BACKLOG"
    assert report["code"] == expected_code


def test_pipeline_release_graph_transport_failure_is_a_backlog(monkeypatch):
    fixture = _fixture()
    _install_pure_port_spies(monkeypatch, fixture)

    def transport_unavailable(**kwargs):
        raise pub.TransportUnavailableError("fixture release graph transport failed")

    monkeypatch.setattr(pipeline.rg, "verify_materializable_release_state",
                        transport_unavailable)
    law = SimpleNamespace(epoch_context_root=fixture.epoch_context,
                          entropy_commitment="18" * 32, revealed_secret=None)
    artifact, report = pipeline._admit(
        fixture.selected, law, fixture.store, allow_test_doubles=False)

    assert artifact is not None
    assert report["outcome"] == "BACKLOG"
    assert report["code"] == "RELEASE_STATE_UNAVAILABLE"


def test_substituted_epoch_context_bytes_fail_before_transition_replay(monkeypatch):
    fixture = _fixture()
    substituted = dict(fixture.epoch_context_document)
    substituted["runtime_abi_root"] = "99" * 32
    fixture.store.put(fixture.epoch_context, fr.canonical_bytes(substituted))
    artifact, report, calls = _admit(monkeypatch, fixture)

    assert artifact["candidate"]["release_root"] == fixture.signed_release
    assert report["outcome"] == "FAIL"
    assert report["code"] == rig.EPOCH_CONTEXT_ADDRESS_MISMATCH
    assert calls.replay == []


def test_confirmed_advance_and_historical_law_must_name_one_context(monkeypatch):
    fixture = _fixture()
    calls = _install_pure_port_spies(monkeypatch, fixture)
    law = SimpleNamespace(epoch_context_root="99" * 32,
                          entropy_commitment="18" * 32, revealed_secret=None)
    artifact, report = pipeline._admit(
        fixture.selected, law, fixture.store, allow_test_doubles=False)

    assert artifact["candidate"]["release_root"] == fixture.signed_release
    assert report["outcome"] == "FAIL"
    assert report["code"] == rig.TRANSITION_EPOCH_CONTEXT_MISMATCH
    assert calls.replay == []


def test_pipeline_delegates_every_supported_resolver_schema():
    source = inspect.getsource(pipeline.run)
    assert 'published_payload.get("schema") in rsn.SUPPORTED_SCHEMAS' in source
    assert rsn.SCHEMA_V3 in rsn.SUPPORTED_SCHEMAS


def test_prelaunch_without_an_accepted_transition_is_unverified_not_a_chain_failure():
    source = inspect.getsource(pipeline.run)
    assert '"code": "NO_ACCEPTED_TRANSITION"' in source
    assert 'record("join_transition", "UNVERIFIED"' in source
    assert "return stop(report_ok=True)" in source
