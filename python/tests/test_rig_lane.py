# SPDX-License-Identifier: Apache-2.0
"""The rig lane's own tests: the event surface, the §7 join, the snapshot, the export.

These are NOT ports. Everything here proves something written for this package, and the
properties under test are the ones a public validator would be wrong about silently:

* topic0 is not an identity (the V4 collision), so routing is by address;
* the join key includes ``patchHash``, and a head CYCLE is where a two-part key breaks;
* ``receiptHash`` is what binds calldata to the confirmed credit — not the signature;
* the unsigned payload reproduces byte-for-byte WITHOUT any curve code being loaded;
* a valid signature never rescues a payload that failed to reproduce.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from coretex_validator import abi
from coretex_validator import dispatch as dp
from coretex_validator import export as ex
from coretex_validator import frontier as fr
from coretex_validator import historical_law as hl
from coretex_validator import join as jn
from coretex_validator import receipt_chain as rc
from coretex_validator import release as rel
from coretex_validator import rig_events as rig
from coretex_validator import snapshot as snap
from coretex_validator.keccak256 import keccak256, keccak256_hex

REGISTRY = "0x1111111111111111111111111111111111111111"
MINING = "0x2222222222222222222222222222222222222222"
VERIFIER = "0x3333333333333333333333333333333333333333"
OTHER = "0x9999999999999999999999999999999999999999"
DEPLOYMENT = rig.RigDeployment(chain_id=8453, registry=REGISTRY, mining=MINING,
                               verifier=VERIFIER)


def word(value: str) -> str:
    return value.rjust(64, "0")


def topic_uint(value: int) -> str:
    return "0x" + f"{value:064x}"


def topic_address(value: str) -> str:
    return "0x" + value.lower().replace("0x", "").rjust(64, "0")


def advance_log(*, address: str = REGISTRY, epoch: int = 7, index: int = 0,
                parent: str = "aa" * 32, new_root: str = "bb" * 32,
                patch: bytes = b'{"x":1}', tx: str = "0x" + "ab" * 32,
                miner: str = "0x00000000000000000000000000000000000000aa",
                credits: int = 100, block: int = 16, log_index: int = 0):
    patch_hash = rig.patch_hash(patch)
    padded = patch + b"\x00" * ((32 - len(patch) % 32) % 32)
    data = "".join([
        word(parent), word(new_root), word(patch_hash), word("dd" * 32), word("ee" * 32),
        word("11" * 32), word("22" * 32), word(f"{credits:x}"), word("1"),
        word(f"{10 * 32:x}"), word(f"{len(patch):x}"), padded.hex(),
    ])
    return {"address": address,
            "topics": ["0x" + rig.STATE_ADVANCED_TOPIC0, topic_uint(epoch), topic_uint(index),
                       topic_address(miner)],
            "data": "0x" + data, "blockNumber": hex(block), "logIndex": hex(log_index),
            "transactionHash": tx}


# --------------------------------------------------------------------------- #
# The event surface
# --------------------------------------------------------------------------- #
class TestEventSurface:
    def test_the_rig_advance_topic0_is_the_v4_advance_topic0(self):
        # The finding this whole module exists for. The staged dispatcher asserts the OPPOSITE
        # ("V5 must never emit an event that collides"), and it only passes because it registers
        # a signature no deployed contract emits.
        assert rig.STATE_ADVANCED_TOPIC0 == dp.V4_STATE_ADVANCED_TOPIC0
        assert rig.EPOCH_FINALIZED_TOPIC0 == dp.V4_EPOCH_FINALIZED_TOPIC0

    def test_the_staged_rig_events_are_not_what_any_contract_emits(self):
        staged = {dp.RIG_STATE_ADVANCED_TOPIC0, dp.RIG_SCREENER_PASS_TOPIC0,
                  dp.RIG_EPOCH_INHERITED_TOPIC0, dp.RIG_EPOCH_CONTEXT_SET_TOPIC0}
        assert staged.isdisjoint(set(rig.RIG_LOG_TOPICS))

    def test_the_staged_subscription_would_retrieve_zero_advances(self):
        # dispatch.RIG_TOPICS is what a validator built on the staged table would pass to
        # eth_getLogs. It does not contain the topic the registry actually emits, so the filter
        # comes back empty — indistinguishable from a deployment that never mined.
        assert rig.STATE_ADVANCED_TOPIC0 not in dp.RIG_TOPICS
        assert rig.STATE_ADVANCED_TOPIC0 in rig.RIG_LOG_TOPICS

    def test_routing_is_by_address_because_topic0_is_not_an_identity(self):
        mine = rig.route_rig_log(advance_log(address=REGISTRY), DEPLOYMENT)
        assert mine.event == "CoreTexStateAdvanced" and mine.emitter_role == "registry"
        theirs = rig.route_rig_log(advance_log(address=OTHER), DEPLOYMENT)
        assert theirs.event is None                       # not ours; quietly ignored

    def test_a_known_event_from_the_wrong_own_address_is_refused(self):
        with pytest.raises(rig.RigAddressError):
            rig.route_rig_log(advance_log(address=MINING), DEPLOYMENT)

    def test_an_unknown_topic0_is_ignored_not_an_error(self):
        log = advance_log()
        log["topics"] = ["0x" + "fe" * 32]
        assert rig.route_rig_log(log, DEPLOYMENT).event is None

    def test_the_patch_hash_label_is_the_verifier_s_not_the_memory_lane_s(self):
        # The staged chain_first uses the SUPERSEDED memory-lane label. The two digests differ
        # for every input, so the staged check refuses every real advance rather than differing
        # in style.
        patch = b'{"x":1}'
        assert rig.PATCH_HASH_LABEL == b"coretex-patch-hash-v1"
        assert rig.patch_hash(patch) != keccak256_hex(rig.SUPERSEDED_PATCH_HASH_LABEL + patch)
        from coretex_validator import chain_first as cf
        assert cf.RIG_PATCH_HASH_LABEL == rig.SUPERSEDED_PATCH_HASH_LABEL

    def test_decoding_recovers_the_verbatim_patch(self):
        decoded = rig.decode_state_advanced(advance_log(patch=b'{"hello":"world"}'))
        assert decoded.compact_patch_bytes == b'{"hello":"world"}'
        rig.check_patch_hash(decoded)                     # self-verifying: bytes AND their hash


# --------------------------------------------------------------------------- #
# The join key
# --------------------------------------------------------------------------- #
class TestJoinKey:
    def test_the_key_is_three_parts(self):
        advance = rig.decode_state_advanced(advance_log())
        assert advance.join_key == (7, "aa" * 32, advance.patch_hash)

    def test_a_head_cycle_collides_a_two_part_key_but_not_the_real_one(self):
        # P -> A -> P -> C is legal: the only self-referential rule is newStateRoot != parent.
        # So `P` occurs as a parent twice and (epoch, parentStateRoot) collapses two REAL
        # transitions into one. patchHash is what keeps them apart.
        p, a, c = "aa" * 32, "bb" * 32, "cc" * 32
        advances = [
            rig.decode_state_advanced(advance_log(index=0, parent=p, new_root=a,
                                                  patch=b'{"n":1}')),
            rig.decode_state_advanced(advance_log(index=1, parent=a, new_root=p,
                                                  patch=b'{"n":2}')),
            rig.decode_state_advanced(advance_log(index=2, parent=p, new_root=c,
                                                  patch=b'{"n":3}')),
        ]
        report = jn.assert_key_is_patch_keyed(advances)
        assert report["cycled"] is True
        assert report["distinct_three_part_keys"] == 3
        assert len(report["two_part_key_collisions"][f"7:{p}"]) == 2
        assert len(jn.index_advances(advances)) == 3      # the real key survives the cycle

    def test_a_genuine_duplicate_triple_is_a_chain_level_fault(self):
        duplicate = [rig.decode_state_advanced(advance_log(index=0)),
                     rig.decode_state_advanced(advance_log(index=1))]
        with pytest.raises(jn.JoinError) as excinfo:
            jn.index_advances(duplicate)
        assert excinfo.value.code == "JOIN_KEY_COLLISION"


# --------------------------------------------------------------------------- #
# Receipt continuity
# --------------------------------------------------------------------------- #
def credit(rig_id: int, solve_index: int, *, coretex: bool = True, receipt_hash: str = "",
           block: int = 16, log_index: int = 1):
    return rig.CoreTexCreditAccepted(
        epoch=7, rig_id=rig_id, operator="0x" + "aa" * 20, solve_index=solve_index,
        receipt_hash=receipt_hash or f"{solve_index:064x}", challenge_id="cc" * 32,
        work_units_bps=100000, credits_earned=100,
        provenance=dp.LogProvenance(block_number=block, log_index=log_index,
                                    transaction_hash="0x" + "ab" * 32, removed=False),
        coretex=coretex)


class TestReceiptContinuity:
    def test_coretex_and_standard_receipts_share_one_chain(self):
        # The single easiest thing to get wrong here: a replay that consumed only the CoreTex
        # events would report a gap at every standard receipt.
        decoded = rig.DecodedLogs([], [credit(1, 0), credit(1, 2, block=18)],
                                  [credit(1, 1, coretex=False, block=17)], [], [], [], [], [])
        result = rc.replay_all(decoded)[1]
        assert result.ok, result.problems
        assert result.replayed_next_index == 3
        assert (result.as_dict()["coretex_receipts"], result.as_dict()["standard_receipts"]) == (2, 1)

    def test_a_missing_receipt_is_reported(self):
        decoded = rig.DecodedLogs([], [credit(1, 0), credit(1, 2, block=18)], [], [], [], [],
                                  [], [])
        result = rc.replay_all(decoded)[1]
        assert not result.ok
        assert "solveIndex 2 where 1 was due" in result.problems[0]

    def test_without_a_chain_anchor_completeness_is_unknown_not_true(self):
        decoded = rig.DecodedLogs([], [credit(1, 0)], [], [], [], [], [], [])
        assert rc.replay_all(decoded)[1].complete is None


# --------------------------------------------------------------------------- #
# Historical law
# --------------------------------------------------------------------------- #
def context(epoch: int):
    return rig.EpochContextSet(
        epoch=epoch, parent_state_root="aa" * 32, corpus_root="11" * 32,
        active_frontier_root="22" * 32, baseline_manifest_hash="33" * 32,
        core_version_hash="ee" * 32,
        provenance=dp.LogProvenance(1, 0, "0x" + "cd" * 32, False))


def policy(version: int, effective: int):
    return rig.PolicyScheduled(rules_version=version, effective_epoch=effective,
                               policy_hash=f"{version:064x}", screener_work_bps=20000,
                               provenance=dp.LogProvenance(1, 0, "0x" + "ce" * 32, False))


class TestHistoricalLaw:
    def test_the_policy_in_force_is_the_one_scheduled_at_or_before_the_epoch(self):
        policies = [policy(1, 0), policy(2, 5), policy(3, 90)]
        assert hl.policy_in_force(policies, 7).rules_version == 2       # not 3: not yet effective
        assert hl.policy_in_force(policies, 100).rules_version == 3
        assert hl.policy_in_force([policy(3, 90)], 7) is None

    def test_law_comes_from_the_verifier_context_not_the_registry(self):
        decoded = rig.DecodedLogs([], [], [], [], [context(7)], [], [], [policy(2, 5)])
        law = hl.law_for_epoch(decoded, 7)
        assert law.enforced_pins() == {"corpus_root": "11" * 32,
                                       "active_frontier_root": "22" * 32,
                                       "core_version_hash": "ee" * 32}
        assert law.rules_version == 2

    def test_a_scan_that_missed_the_verifier_refuses_rather_than_using_current_state(self):
        with pytest.raises(hl.LawError) as excinfo:
            hl.law_for_epoch(rig.DecodedLogs([], [], [], [], [], [], [], []), 7)
        assert excinfo.value.code == "EPOCH_CONTEXT_UNAVAILABLE"

    def test_a_receipt_claiming_a_not_yet_effective_version_is_a_fault(self):
        decoded = rig.DecodedLogs([], [], [], [], [context(7)], [], [], [policy(2, 5)])
        law = hl.law_for_epoch(decoded, 7)
        problems = hl.check_receipt_against_law(
            {"rulesVersion": 3, "corpusRoot": "11" * 32, "activeFrontierRoot": "22" * 32,
             "coreVersionHash": "ee" * 32}, law)
        assert any("priced under rulesVersion 3" in p for p in problems)

    def test_an_unscheduled_policy_is_unchecked_not_accepted(self):
        decoded = rig.DecodedLogs([], [], [], [], [context(7)], [], [], [])
        law = hl.law_for_epoch(decoded, 7)
        problems = hl.check_receipt_against_law(
            {"rulesVersion": 1, "corpusRoot": "11" * 32, "activeFrontierRoot": "22" * 32,
             "coreVersionHash": "ee" * 32}, law)
        assert any("UNCHECKED (not accepted)" in p for p in problems)


# --------------------------------------------------------------------------- #
# The snapshot: reproduction first, signature second
# --------------------------------------------------------------------------- #
def minimal_payload():
    return {"format": snap.SNAPSHOT_FORMAT, "classification": snap.CLASSIFICATION_REHEARSAL,
            "epoch": {"epoch": 7}, "join_key": {"epoch": 7, "parent_state_root": "aa" * 32,
                                                "patch_hash": "cc" * 32}}


class TestSnapshotReproduction:
    def test_identical_payloads_reproduce(self):
        result = snap.reproduce(minimal_payload(), minimal_payload())
        assert result.reproduced
        assert result.reconstructed_hash == result.published_hash

    def test_a_single_changed_field_is_located(self):
        published = minimal_payload()
        published["join_key"]["patch_hash"] = "dd" * 32
        result = snap.reproduce(minimal_payload(), published)
        assert not result.reproduced
        assert any("join_key.patch_hash" in d for d in result.differences)

    def test_no_published_snapshot_means_not_reproduced_rather_than_passed(self):
        result = snap.reproduce(minimal_payload(), None)
        assert not result.reproduced and result.published_hash is None

    def test_reproduction_never_loads_curve_code(self):
        # The property the reproduction path exists to have: it rebuilds bytes from chain facts
        # and compares them. No key material, no curve arithmetic, nothing that could make the
        # answer depend on a signer. Checked in a FRESH interpreter, because this one has
        # already imported secp256k1 for other tests in this file.
        script = (
            "import sys;"
            "from coretex_validator import snapshot as s;"
            "p={'format':s.SNAPSHOT_FORMAT,'classification':s.CLASSIFICATION_REHEARSAL,'a':1};"
            "r=s.reproduce(p,dict(p));"
            "assert r.reproduced;"
            "assert s.canonical_bytes(p);"
            "print('curve_loaded=%s' % ('coretex_validator.secp256k1' in sys.modules))")
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                             cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]))
        assert out.returncode == 0, out.stderr
        assert "curve_loaded=False" in out.stdout

    def test_a_valid_signature_does_not_rescue_a_failed_reproduction(self):
        published = minimal_payload()
        published["epoch"]["epoch"] = 8
        result = snap.reproduce(minimal_payload(), published)
        assert not result.reproduced
        with pytest.raises(ex.ExportError) as excinfo:
            ex.build_export(
                snapshot_payload=minimal_payload(), reproduction=result,
                signature=snap.SignatureResult(True, "0x" + "aa" * 20, "0x" + "aa" * 20, "ok"),
                release_document={}, source_divergence={}, deployment_verification={},
                receipt_chains={}, admission={}, unverified=[])
        assert excinfo.value.code == "SNAPSHOT_NOT_REPRODUCED"

    def test_the_signing_domain_cannot_be_confused_with_an_eip712_digest(self):
        payload = minimal_payload()
        assert snap.signing_digest(payload) != keccak256(snap.canonical_bytes(payload))
        assert snap.SNAPSHOT_SIGNING_DOMAIN.startswith(b"\x19")

    def test_an_unsigned_snapshot_reports_transport_failure_not_content_failure(self):
        result = snap.verify_signature(minimal_payload(), None, "0x" + "aa" * 20)
        assert not result.valid and "no signature" in result.reason
        assert "transport authentication" in result.as_dict()["meaning"]


# --------------------------------------------------------------------------- #
# Release and export classification
# --------------------------------------------------------------------------- #
def release_document(**overrides):
    document = {
        "format": rel.RELEASE_FORMAT, "classification": "MAINNET_REHEARSAL", "chain_id": 8453,
        "network": "base",
        "addresses": {"registry": REGISTRY, "mining": MINING, "verifier": VERIFIER},
        "runtime_code_hashes": {"registry": "11" * 32, "mining": "22" * 32,
                                "verifier": "33" * 32},
        "deploy_block": 100,
        "source": {"repo": "https://github.com/botcoinmoney/botcoin-mining-rigs",
                   "commit": "cdb91d211e4620c6ecfd90b68d827d607033e1f1",
                   "publicly_fetchable": False},
    }
    document.update(overrides)
    return document


class TestClassification:
    def test_a_canonical_release_is_refused_by_name(self):
        with pytest.raises(rel.ReleaseError) as excinfo:
            rel.parse_release(release_document(classification="MAINNET_CANONICAL"))
        assert excinfo.value.code == "CLASSIFICATION_REFUSED"

    def test_a_canonical_export_cannot_be_minted_by_passing_a_flag(self):
        with pytest.raises(ex.ExportError) as excinfo:
            ex.build_export(
                snapshot_payload=minimal_payload(),
                reproduction=snap.reproduce(minimal_payload(), minimal_payload()),
                signature=None, release_document={}, source_divergence={},
                deployment_verification={}, receipt_chains={}, admission={}, unverified=[],
                classification="MAINNET_CANONICAL")
        assert excinfo.value.code == "CLASSIFICATION_REFUSED"

    def test_a_release_without_a_source_commit_is_refused(self):
        # Without it, a KNOWN divergence between the deployed bytecode and the interface
        # authority becomes an unknown one.
        document = release_document()
        document["source"] = {"repo": "x"}
        with pytest.raises(rel.ReleaseError) as excinfo:
            rel.parse_release(document)
        assert excinfo.value.code == "SOURCE_PIN_MISSING"

    def test_the_two_authorities_are_reported_separately(self):
        parsed = rel.parse_release(release_document())
        divergence = parsed.source_divergence()
        assert divergence["deployment_authority"] == "release_artifact"
        assert divergence["source_interface_authority"]["publicly_fetchable"] is False
        assert "does not compile anything" in divergence["note"]

    def test_the_export_carries_its_gaps_rather_than_omitting_them(self):
        export = ex.build_export(
            snapshot_payload=minimal_payload(),
            reproduction=snap.reproduce(minimal_payload(), minimal_payload()),
            signature=None, release_document=release_document(), source_divergence={},
            deployment_verification={}, receipt_chains={}, admission={"outcome": "BACKLOG"},
            unverified=[{"step": "deterministic_admission", "reason": "trees not present"}])
        assert export.document["classification"] == "MAINNET_REHEARSAL"
        assert export.unverified[0]["step"] == "deterministic_admission"
        assert len(export.root()) == 64
