# SPDX-License-Identifier: UNLICENSED
from __future__ import annotations

import copy
import dataclasses
import hashlib

import publication as pub
from validator import chain_first as cf
from validator_fixtures import Scenario


class Chain(cf.CanonicalChainSource):
    def __init__(self, scenario, commitments, identity_roots):
        self.scenario = scenario
        self.commitments = tuple(commitments)
        self.local_epoch = scenario.epoch
        self.identity_roots = identity_roots

    def snapshot(self, event):
        deterministic_root = self.scenario.artifact["receipt"]["receipt_hash"]
        fresh_root = hashlib.sha256(
            pub.benchmark_canonical_bytes(self.scenario.artifact["selection"])).hexdigest()
        return cf.CanonicalSnapshot(
            chain_id=8453, block_number=100, block_hash="aa" * 32, finalized_block=90,
            epoch=self.local_epoch, incumbent_root=event.new_frontier_root,
            runtime_root=self.scenario.parent["runtime_abi_root"],
            law_root=self.scenario.parent["benchmark_law_root"],
            counter_root=self.scenario.artifact["counter_resource_law_root"],
            scorer_root=self.identity_roots["scorer_package"],
            deterministic_receipt_root=deterministic_root,
            fresh_selection_root=fresh_root,
            supported_historical_laws=(self.scenario.parent["benchmark_law_root"],),
            artifacts=self.commitments,
        )

    def pins(self, epoch):
        return self.scenario.pins()


def setup():
    s = Scenario()
    manifest = {
        "format": "fixture/candidate-manifest/v1",
        "runtime_root": s.parent["runtime_abi_root"],
        "law_root": s.parent["benchmark_law_root"],
        "operator_signature": "fixture-signature",
    }
    root = pub.publish_and_read_back(
        manifest, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=s.store)
    composition = {
        "format": "fixture/composition-manifest/v1",
        "runtime_root": s.parent["runtime_abi_root"],
        "law_root": s.parent["benchmark_law_root"],
        "operator_signature": "fixture-signature",
    }
    composition_root = pub.publish_and_read_back(
        composition, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=s.store)
    event = dataclasses.replace(
        s.event(candidate_release_root=root), composition_root=composition_root)
    # Keep the transition/event/artifact internally coherent for downstream replay. These tests
    # target the PRE-EXECUTION envelope, so most negative controls stop before replay.
    commitment = cf.ArtifactCommitment(
        "candidate_manifest", root, pub.HASH_RULE_SIGNED_MANIFEST_BODY,
        "application/json", len(s.store.get(root)), True,
        {"runtime_root": s.parent["runtime_abi_root"],
         "law_root": s.parent["benchmark_law_root"]},
    )
    composition_commitment = cf.ArtifactCommitment(
        "composition_manifest", composition_root, pub.HASH_RULE_SIGNED_MANIFEST_BODY,
        "application/json", len(s.store.get(composition_root)), True,
        {"runtime_root": s.parent["runtime_abi_root"],
         "law_root": s.parent["benchmark_law_root"]},
    )
    eval_root = pub.publish_and_read_back(
        s.artifact, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=s.store)
    eval_commitment = cf.ArtifactCommitment(
        "eval_artifact", eval_root, pub.HASH_RULE_BENCHMARK_JSON,
        "application/json", len(s.store.get(eval_root)),
    )
    identity_roots = {}
    identity_commitments = []
    for kind, data in (
            ("runtime_package", b"runtime-package"),
            ("law_package", b"law-package"),
            ("counter_package", b"counter-package"),
            ("scorer_package", b"scorer-package")):
        payload_root = pub.root_of(data, pub.HASH_RULE_BYTES)
        s.store.put(payload_root, data)
        selected_identity = {
            "runtime_package": s.parent["runtime_abi_root"],
            "law_package": s.parent["benchmark_law_root"],
            "counter_package": s.artifact["counter_resource_law_root"],
            "scorer_package": "77" * 32,
        }[kind]
        identity_roots[kind] = selected_identity
        descriptor = {
            "format": "fixture/signed-identity-descriptor/v1",
            "identity_root": selected_identity,
            "payload_root": payload_root,
            "operator_signature": "fixture-signature",
        }
        root = pub.publish_and_read_back(
            descriptor, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=s.store)
        identity_commitments.append(cf.ArtifactCommitment(
            kind, root, pub.HASH_RULE_SIGNED_MANIFEST_BODY, "application/json",
            len(s.store.get(root)), signature_required=True))
        identity_commitments.append(cf.ArtifactCommitment(
            kind.replace("_package", "_payload"), payload_root, pub.HASH_RULE_BYTES,
            "application/octet-stream", len(data)))
    chain = Chain(
        s, [commitment, composition_commitment, eval_commitment, *identity_commitments],
        identity_roots)
    deterministic_root = s.artifact["receipt"]["receipt_hash"]
    fresh_root = hashlib.sha256(
        pub.benchmark_canonical_bytes(s.artifact["selection"])).hexdigest()
    receipt = {
        "epoch": s.epoch,
        "parent_root": event.parent_frontier_root,
        "candidate_artifact_root": event.candidate_release_root,
        "candidate_manifest_root": event.composition_root,
        "deterministic_receipt_root": deterministic_root,
        "fresh_selection_root": fresh_root,
        "runtime_root": s.parent["runtime_abi_root"],
        "law_root": s.parent["benchmark_law_root"],
        "counter_root": s.artifact["counter_resource_law_root"],
        "scorer_root": identity_roots["scorer_package"],
        "transition_root": __import__("hashlib").sha256(event.transition_bytes).hexdigest(),
        "proposed_new_root": event.new_frontier_root,
        "issued_at": 100,
        "evaluated_at": 98,
        "chain_observed_at": 99,
        "expires_at": 200,
        "signature": "ok",
    }
    return s, event, chain, receipt


def call(mutator=None, **kwargs):
    s, event, chain, receipt = setup()
    if mutator:
        mutator(s, event, chain, receipt)
    return cf.validate_chain_first(
        event, chain=chain, store=s.store,
        manifest_verifier=kwargs.pop("manifest_verifier", lambda *_: True),
        deterministic_receipt_verifier=lambda _: True,
        candidate_receipt=receipt,
        candidate_receipt_verifier=kwargs.pop("receipt_verifier", lambda _: True),
        now=100, replay_kwargs={"screen": None, "sandbox": None}, **kwargs)


def test_unsigned_or_wrongly_signed_manifest_fails_before_candidate_execution():
    result = call(manifest_verifier=lambda *_: False)
    assert result.code == "MANIFEST_SIGNATURE_INVALID"
    assert result.replay is None


def test_wrong_runtime_or_law_manifest_fails_before_candidate_execution():
    def wrong(_s, _e, chain, _r):
        c = chain.commitments[0]
        chain.commitments = (cf.ArtifactCommitment(
            c.kind, c.root, c.hash_rule, c.media_type, c.size, True,
            {"runtime_root": "00" * 32}),)
    result = call(wrong)
    assert result.code == "MANIFEST_IDENTITY_MISMATCH" and result.replay is None


def test_candidate_artifact_and_manifest_substitution_are_distinct_refusals():
    assert call(lambda _s, _e, _c, r: r.__setitem__(
        "candidate_artifact_root", "aa" * 32)).code == "CANDIDATE_ARTIFACT_ROOT_SUBSTITUTION"
    def manifest(_s, _e, chain, _r):
        c = chain.commitments[0]
        chain.commitments = (cf.ArtifactCommitment(
            c.kind, "ab" * 32, c.hash_rule, c.media_type, c.size, True, c.expected_fields),)
    assert call(manifest).code in ("MISSING_ARTIFACT", "ARTIFACT_INTEGRITY_FAILURE")


def test_eval_artifact_must_be_the_root_committed_by_the_chain_event():
    def substitute(s, _event, chain, _receipt):
        altered = copy.deepcopy(s.artifact)
        altered["verdict"]["verdict"] = "SUBSTITUTED"
        root = pub.publish_and_read_back(
            altered, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=s.store)
        commitments = list(chain.commitments)
        original = next(c for c in commitments if c.kind == "eval_artifact")
        commitments[commitments.index(original)] = dataclasses.replace(
            original, root=root, size=len(s.store.get(root)))
        chain.commitments = tuple(commitments)
    assert call(substitute).code == "EVAL_ARTIFACT_SUBSTITUTION"


def test_parent_selection_runtime_law_counter_and_receipt_substitution_fail():
    fields = {
        "parent_root": "PARENT_ROOT_SUBSTITUTION",
        "fresh_selection_root": "FRESH_SELECTION_ROOT_SUBSTITUTION",
        "runtime_root": "RUNTIME_ROOT_SUBSTITUTION",
        "law_root": "LAW_ROOT_SUBSTITUTION",
        "counter_root": "COUNTER_ROOT_SUBSTITUTION",
        "deterministic_receipt_root": "DETERMINISTIC_RECEIPT_ROOT_SUBSTITUTION",
    }
    for field, code in fields.items():
        result = call(lambda _s, _e, _c, r, field=field: r.__setitem__(field, "ab" * 32))
        assert result.code == code


def test_expired_receipt_wrong_epoch_and_chain_database_disagreement_fail_closed():
    assert call(lambda _s, _e, _c, r: r.__setitem__("expires_at", 99)).code == "EXPIRED_RECEIPT"
    assert call(lambda _s, _e, c, _r: setattr(c, "local_epoch", 10)).code == "WRONG_EPOCH"
    assert call(local_state={"epoch": 9, "frontier_root": "ff" * 32}).code \
        == "CHAIN_DATABASE_DISAGREEMENT"


def test_missing_malformed_artifact_and_unsupported_historical_law_fail_closed():
    assert call(lambda _s, _e, c, _r: setattr(c, "commitments", ())).code == "MISSING_ARTIFACT"
    def unsupported(_s, _e, chain, _r):
        original = chain.snapshot
        chain.snapshot = lambda event: __import__("dataclasses").replace(
            original(event), supported_historical_laws=())
    assert call(unsupported).code == "UNSUPPORTED_HISTORICAL_LAW"


def test_canary_transcript_and_candidate_binding_are_verified_without_model_rerun():
    s, event, chain, receipt = setup()
    transcript = {"format": "fixture/transcript/v1", "responses": ["redacted"]}
    tr = pub.publish_and_read_back(
        transcript, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=s.store)
    canary = {k: receipt[k] for k in (
        "candidate_artifact_root", "candidate_manifest_root", "deterministic_receipt_root",
        "fresh_selection_root", "runtime_root", "law_root", "scorer_root", "epoch",
        "transition_root")}
    canary.update({
        "incumbent_root": receipt["parent_root"],
        "counter_root": receipt["counter_root"],
        "renderer_root": "aa" * 32,
        "prompt_root": "bb" * 32,
        "model_root": "cc" * 32,
        "configuration_root": "dd" * 32,
        "provider_input_tokens": 10,
        "provider_output_tokens": 5,
        "cost_usd_micros": 0,
        "verdict": "PASS",
        "issued_at": 100,
        "expires_at": 150,
        "proposed_new_root": receipt["proposed_new_root"],
        "transcript_root": tr,
        "signature": "ok",
    })
    result = cf.validate_chain_first(
        event, chain=chain, store=s.store, manifest_verifier=lambda *_: True,
        deterministic_receipt_verifier=lambda _: True, candidate_receipt=receipt,
        candidate_receipt_verifier=lambda _: True, now=100, canary=canary,
        canary_verifier=lambda _: True, replay_kwargs={"screen": None, "sandbox": None})
    # Deterministic replay backlogs because real runtime ports were intentionally absent, but the
    # canary proof itself is complete and never invoked a model.
    assert result.canary["verified"] is True and result.canary["model_rerun"] is False
    foreign = copy.deepcopy(canary)
    foreign["candidate_artifact_root"] = "ee" * 32
    result = cf.validate_chain_first(
        event, chain=chain, store=s.store, manifest_verifier=lambda *_: True,
        deterministic_receipt_verifier=lambda _: True, candidate_receipt=receipt,
        candidate_receipt_verifier=lambda _: True, now=100, canary=foreign,
        canary_verifier=lambda _: True)
    assert result.code == "CANARY_CANDIDATE_MISMATCH" and result.replay is None
