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
import os
import subprocess
import sys

import pytest

from coretex_validator import abi
from coretex_validator import dispatch as dp
from coretex_validator import export as ex
from coretex_validator import frontier as fr
from coretex_validator import historical_law as hl
from coretex_validator import join as jn
from coretex_validator import publication as pub
from coretex_validator import receipt_chain as rc
from coretex_validator import release as rel
from coretex_validator import rig_events as rig
from coretex_validator import rig_receipt_binding as binding
from coretex_validator import snapshot as snap
from coretex_validator.keccak256 import keccak256, keccak256_hex

def _referenced_names(module) -> set:
    """Every identifier a module's CODE references — attributes and bare names, not prose.

    Substring searches over source cannot answer "does this module call X?", because a module
    that documents why it must never call X contains the string X. The AST can.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(module))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
    return names


# --------------------------------------------------------------------------- #
# Cross-tree file resolution — env override first, then candidate roots
# --------------------------------------------------------------------------- #
#: The coordinator checkouts this client is developed against, newest first. A HARDCODED ABSOLUTE
#: PATH IS NOT A GUARD (review M-10): the one that used to sit in this file pointed at
#: `/home/ubuntu/botcoin-coordinator-v5-p6`, a tree that does not exist on this host, so the tests
#: it guarded skipped silently forever and their assertions never ran. Resolution is now: an
#: explicit env override, then each candidate root in order, and only a genuinely absent file skips.
_COORDINATOR_ROOTS = (
    "/home/ubuntu/botcoin-coordinator-v5",
    "/home/ubuntu/botcoin-coordinator-v5-p6",
    "/home/ubuntu/botcoin-coordinator",
)


def _resolve_cross_tree(relative, env_var):
    """The first existing ``<root>/<relative>``, or ``None``. ``env_var`` wins outright."""
    import pathlib

    override = os.environ.get(env_var)
    if override:
        candidate = pathlib.Path(override)
        return candidate if candidate.is_file() else None
    for root in _COORDINATOR_ROOTS:
        candidate = pathlib.Path(root) / relative
        if candidate.is_file():
            return candidate
    return None


#: The published epoch-180 resolver snapshot — LEGACY-ERA evidence, never modified by this suite.
E180_SNAPSHOT_RELATIVE = "v5/resolver/evidence/mainnet-rehearsal-e180-20260804/snapshot.json"
#: The machine-generated receipt binding this package's hand transcription must agree with.
GENERATED_BINDING_RELATIVE = "v5/e2e/generated_rig_receipt_binding.py"

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
        word("11" * 32), word(f"{credits:x}"), word("21"),
        word(f"{9 * 32:x}"), word(f"{len(patch):x}"), padded.hex(),
    ])
    return {"address": address,
            "topics": ["0x" + rig.STATE_ADVANCED_TOPIC0, topic_uint(epoch), topic_uint(index),
                       topic_address(miner)],
            "data": "0x" + data, "blockNumber": hex(block), "logIndex": hex(log_index),
            "transactionHash": tx}


def legacy_v2_advance_log(*, address: str = REGISTRY):
    descriptor = (bytes([0x20]) + bytes.fromhex("7e" * 32) + bytes.fromhex("aa" * 32)
                  + bytes.fromhex("bb" * 32) + (1234).to_bytes(8, "big"))
    patch_hash = keccak256_hex(rig.TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL + descriptor)
    padded = descriptor + b"\x00" * ((32 - len(descriptor) % 32) % 32)
    data = "".join([
        word("aa" * 32), word("bb" * 32), word(patch_hash), word("dd" * 32),
        word("ee" * 32), word("11" * 32), word("22" * 32), word("64"), word("20"),
        word(f"{10 * 32:x}"), word(f"{len(descriptor):x}"), padded.hex(),
    ])
    return {"address": address,
            "topics": ["0x" + rig.LEGACY_V2_STATE_ADVANCED_TOPIC0, topic_uint(7),
                       topic_uint(0),
                       topic_address("0x00000000000000000000000000000000000000aa")],
            "data": "0x" + data, "blockNumber": "0x10", "logIndex": "0x0",
            "transactionHash": "0x" + "ab" * 32}


def epoch_context_log(*, address: str = VERIFIER, epoch: int = 7,
                      parent: str = "aa" * 32, context_root: str = "cc" * 32,
                      core_version: str = "ee" * 32, block: int = 15):
    return {
        "address": address,
        "topics": ["0x" + rig.EPOCH_CONTEXT_SET_TOPIC0, topic_uint(epoch)],
        "data": "0x" + "".join([word(parent), word(context_root), word(core_version)]),
        "blockNumber": hex(block), "logIndex": "0x0", "transactionHash": "0x" + "ac" * 32,
    }


# --------------------------------------------------------------------------- #
# The event surface
# --------------------------------------------------------------------------- #
class TestEventSurface:
    def test_descriptor_v3_topics_move_and_v2_stays_explicitly_legacy(self):
        assert rig.STATE_ADVANCED_TOPIC0 != dp.V4_STATE_ADVANCED_TOPIC0
        assert rig.EPOCH_FINALIZED_TOPIC0 != dp.V4_EPOCH_FINALIZED_TOPIC0
        assert rig.LEGACY_V2_STATE_ADVANCED_TOPIC0 == dp.V4_STATE_ADVANCED_TOPIC0
        assert rig.LEGACY_V2_STATE_ADVANCED_TOPIC0 not in rig.RIG_LOG_TOPICS

    def test_genuine_v2_requires_the_explicit_legacy_decoder(self):
        log = legacy_v2_advance_log()
        assert rig.decode(log, DEPLOYMENT) is None
        decoded = rig.decode_legacy_v2_state_advanced(log)
        assert decoded.transition_format_version == 0x20
        assert len(decoded.compact_patch_bytes) == 105
        assert decoded.corpus_root == "11" * 32
        assert decoded.active_frontier_root == "22" * 32
        scanned = rig.scan_legacy_v2([log], DEPLOYMENT)
        assert scanned.advances == [decoded]

    def test_descriptor_v3_epoch_context_event_decodes_exactly_three_pins(self):
        decoded = rig.decode_epoch_context_set(epoch_context_log())
        assert decoded.epoch == 7
        assert decoded.parent_state_root == "aa" * 32
        assert decoded.epoch_context_root == "cc" * 32
        assert decoded.core_version_hash == "ee" * 32
        assert rig.scan([epoch_context_log()], DEPLOYMENT).contexts == [decoded]

    def test_operational_state_begins_at_context_parent_not_constructor_genesis(self):
        # No constructor root is supplied anywhere: the deployed registry reads this value from
        # the verifier until transition 0 initializes its live-state cell.
        decoded = rig.scan([epoch_context_log(parent="aa" * 32, context_root="11" * 32),
                            advance_log(parent="aa" * 32)],
                           DEPLOYMENT)
        report = rig.context_parent_continuity(decoded)
        assert report["problems"] == []
        assert report["operational_context_parents"] == {"7": "aa" * 32}
        assert report["constructor_genesis_used_as_state_authority"] is False

    def test_first_advance_must_build_on_confirmed_context_parent(self):
        decoded = rig.scan([epoch_context_log(parent="99" * 32, context_root="11" * 32),
                            advance_log(parent="aa" * 32)],
                           DEPLOYMENT)
        report = rig.context_parent_continuity(decoded)
        assert any("confirmed context parent" in problem for problem in report["problems"])

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
        # coretex.transition-descriptor/v3: the LIVE label is "coretex-transition-descriptor-v3".
        # Both the RETIRED 4-word-patch label (this lane's own history) and the SUPERSEDED
        # memory-lane label give a DIFFERENT digest for every input, so a signer still on either
        # one is refused, never silently accepted.
        patch = b'{"x":1}'
        assert rig.TRANSITION_DESCRIPTOR_HASH_LABEL == b"coretex-transition-descriptor-v3"
        assert rig.patch_hash(patch) != keccak256_hex(
            rig.TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL + patch)
        assert rig.patch_hash(patch) != keccak256_hex(
            rig.TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL + patch)
        assert rig.patch_hash(patch) != keccak256_hex(
            rig.TRANSITION_DESCRIPTOR_RETIRED_LABEL + patch)
        # chain_first's own label now matches the live v3 rule (it used to be pinned to the
        # SUPERSEDED memory-lane label, which the finding above documents as always wrong).
        from coretex_validator import chain_first as cf
        assert cf.RIG_PATCH_HASH_LABEL == rig.TRANSITION_DESCRIPTOR_HASH_LABEL
        assert cf.RIG_PATCH_HASH_LABEL_SUPERSEDED == rig.TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL
        assert cf.RIG_PATCH_HASH_LABEL_RETIRED == rig.TRANSITION_DESCRIPTOR_RETIRED_LABEL

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
        epoch=epoch, parent_state_root="aa" * 32, epoch_context_root="11" * 32,
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
        assert law.enforced_pins() == {"epoch_context_root": "11" * 32,
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
            {"rulesVersion": 3, "epochContextRoot": "11" * 32,
             "coreVersionHash": "ee" * 32}, law)
        assert any("priced under rulesVersion 3" in p for p in problems)

    def test_an_unscheduled_policy_is_unchecked_not_accepted(self):
        decoded = rig.DecodedLogs([], [], [], [], [context(7)], [], [], [])
        law = hl.law_for_epoch(decoded, 7)
        problems = hl.check_receipt_against_law(
            {"rulesVersion": 1, "epochContextRoot": "11" * 32,
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

    def test_no_signature_can_rescue_a_failed_reproduction(self):
        """Now structurally true: build_export has no signature parameter to pass.

        This used to be an assertion about ORDERING — check reproduction first, then the
        signature, and never let the second excuse the first. The signature ceremony is removed,
        so the property is enforced by the function's shape rather than by its discipline: there
        is no argument through which a signature could be offered as compensation.
        """
        import inspect

        assert "signature" not in inspect.signature(ex.build_export).parameters

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
    def test_production_snapshot_requires_separately_authenticated_release_authority(self):
        from coretex_validator import resolver_snapshot as rsn

        payload = {k: {} for k in rsn.TOP_LEVEL_KEYS_V3}
        payload.update({"schema": rsn.SCHEMA_V3,
                        "classification": rsn.CLASSIFICATION_PRODUCTION,
                        "production_authority": True})
        with pytest.raises(rsn.ReproductionError) as excinfo:
            rsn.check_shape(payload)
        assert excinfo.value.code == "PRODUCTION_AUTHORITY_REQUIRED"
        rsn.check_shape(payload, production_authority=True)

    def test_a_canonical_release_is_refused_by_name(self):
        with pytest.raises(rel.ReleaseError) as excinfo:
            rel.parse_release(release_document(classification="MAINNET_CANONICAL"))
        assert excinfo.value.code == "CLASSIFICATION_REFUSED"

    def test_a_canonical_export_cannot_be_minted_by_passing_a_flag(self):
        with pytest.raises(ex.ExportError) as excinfo:
            ex.build_export(
                snapshot_payload=minimal_payload(),
                reproduction=snap.reproduce(minimal_payload(), minimal_payload()),
                release_document={}, source_divergence={},
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
            release_document=release_document(), source_divergence={},
            deployment_verification={}, receipt_chains={}, admission={"outcome": "BACKLOG"},
            unverified=[{"step": "deterministic_admission", "reason": "trees not present"}])
        assert export.document["classification"] == "MAINNET_REHEARSAL"
        assert export.unverified[0]["step"] == "deterministic_admission"
        assert len(export.root()) == 64


# --------------------------------------------------------------------------- #
# Lane separation: the collision, enforced in CODE and not only in the README
# --------------------------------------------------------------------------- #
V4_REGISTRY = "0x4444444444444444444444444444444444444444"


class TestLaneSeparationIsEnforced:
    """A V4 log must never enter the V5 stream, and a V5 log must never enter the V4 stream.

    The two lanes share topic0 AND wire format, so neither a topic filter nor a decode failure
    will ever separate them. Only the emitting address can, and these tests exist because that is
    the kind of property that is easy to state in a README and easy to lose in code.
    """

    def test_a_v4_log_at_a_v4_address_is_not_ingested_by_the_rig_lane(self):
        # Byte-identical to a rig advance except for who emitted it.
        decoded = rig.scan([advance_log(address=V4_REGISTRY)], DEPLOYMENT)
        assert decoded.advances == []
        assert decoded.ignored == 1              # counted, never silently dropped

    def test_a_rig_log_at_the_rig_address_is_ingested(self):
        decoded = rig.scan([advance_log(address=REGISTRY)], DEPLOYMENT)
        assert len(decoded.advances) == 1
        assert decoded.ignored == 0

    def test_the_same_log_bytes_route_differently_for_two_deployments(self):
        # The clinching demonstration: ONE log, TWO deployments, opposite verdicts. Nothing about
        # the log itself decides this.
        other = rig.RigDeployment(chain_id=8453, registry=V4_REGISTRY, mining=MINING,
                                  verifier=VERIFIER)
        log = advance_log(address=V4_REGISTRY)
        assert rig.route_rig_log(log, DEPLOYMENT).event is None
        assert rig.route_rig_log(log, other).event == "CoreTexStateAdvanced"

    def test_the_v5_scan_filters_by_address_at_the_rpc_layer_too(self):
        # Defence in depth: `route_rig_log` refuses a foreign log, but the scan should never have
        # retrieved one in the first place.
        import ast
        import inspect

        from coretex_validator import pipeline

        tree = ast.parse(inspect.getsource(pipeline.run))
        scoped = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "get_logs"
            and any(kw.arg == "addresses" for kw in node.keywords)
        ]
        assert scoped, (
            "the log scan must be address-scoped at the RPC layer; a topic-only filter would "
            "retrieve the other lane's history and rely entirely on the router to notice")

    def test_the_v4_decoder_is_not_reachable_from_the_rig_path(self):
        # dispatch.decode_v4_state_advanced still exists and still works — V4 replay is preserved.
        # What must not happen is the rig path CALLING it, because a rig advance decoded as a V4
        # one would carry V4's protocol meaning with rig field values.
        from coretex_validator import join as join_module
        from coretex_validator import pipeline

        for module in (rig, join_module, pipeline):
            assert "decode_v4_state_advanced" not in _referenced_names(module), module.__name__

    def test_the_staged_never_deployed_decoders_are_unreachable_from_the_client_path(self):
        """The ported staged rig decoders stay as history; nothing live may call them.

        `dispatch.decode_rig_state_advanced` and `chain_first.validate_rig_chain_first` decode the
        SUPERSEDED shape (rig-keyed, inline artifactHash, trailing bool) that no deployed contract
        emits, and `chain_first` hashes the patch under the RETIRED label. They are kept so the
        change is evidenced rather than erased — but a live path that reached them would refuse
        every real advance.

        Checked over the AST, not the source text: these names appear in PROSE all over this
        package (that is the point of documenting the finding), and a substring search would
        flag the documentation for describing the thing it is warning about.
        """
        from coretex_validator import join as join_module
        from coretex_validator import pipeline
        from coretex_validator import receipt_chain as receipt_module
        from coretex_validator import snapshot as snapshot_module

        staged = {"decode_rig_state_advanced", "decode_rig_screener_pass",
                  "decode_rig_epoch_context_set", "decode_rig_epoch_inherited",
                  "decode_rig_epoch_finalized", "validate_rig_chain_first",
                  "build_rig_pins_from_logs", "RIG_PATCH_HASH_LABEL"}
        for module in (rig, join_module, pipeline, receipt_module, snapshot_module):
            reached = staged & _referenced_names(module)
            assert not reached, f"{module.__name__} reaches the staged path via {sorted(reached)}"


# --------------------------------------------------------------------------- #
# The four reconciliation decisions
# --------------------------------------------------------------------------- #
class TestWideIntegers:
    """uint256/uint128 render as decimal STRINGS. A correctness fix, not a preference."""

    def test_two_to_the_53_and_one_more_are_distinguishable(self):
        from coretex_validator import canonical as cn

        # In any IEEE-754 reader these two are the SAME double. The canonical rendering keeps
        # them apart, which is the entire argument.
        assert cn.wide(2 ** 53) != cn.wide(2 ** 53 + 1)
        assert cn.wide(2 ** 53 + 1) == "9007199254740993"

    def test_a_uint256_at_the_top_of_its_range_survives_exactly(self):
        from coretex_validator import canonical as cn

        assert cn.wide(2 ** 256 - 1) == str(2 ** 256 - 1)
        with pytest.raises(cn.CanonicalizationError):
            cn.wide(2 ** 256)

    def test_narrow_refuses_rather_than_rounds_above_the_safe_bound(self):
        from coretex_validator import canonical as cn

        assert cn.narrow(2 ** 53 - 1) == 2 ** 53 - 1
        with pytest.raises(cn.CanonicalizationError) as excinfo:
            cn.narrow(2 ** 53)
        assert "wide()" in str(excinfo.value)

    def test_a_wide_value_survives_a_canonical_round_trip_as_a_string(self):
        from coretex_validator import canonical as cn

        document = {"credits_earned": cn.wide(2 ** 53 + 1)}
        assert cn.canonical_bytes(document) == b'{"credits_earned":"9007199254740993"}'


class TestRootSpelling:
    """0x for chain words, bare for content roots, one sanctioned crossing."""

    def test_chain_words_are_prefixed_and_content_roots_are_not(self):
        from coretex_validator import canonical as cn

        root = "ab" * 32
        assert cn.word(root) == "0x" + root
        assert cn.bare_root(root) == root
        with pytest.raises(cn.CanonicalizationError):
            cn.bare_root("0x" + root)          # the two spellings never become interchangeable

    def test_the_boundary_is_crossed_only_through_the_named_converters(self):
        from coretex_validator import canonical as cn

        root = "cd" * 32
        assert cn.root_from_word("0x" + root) == root
        assert cn.word_from_root(root) == "0x" + root

    def test_a_short_hex_string_is_refused_never_padded(self):
        from coretex_validator import canonical as cn

        # Guessing the padding side is how a root and a left-aligned label get confused.
        with pytest.raises(cn.CanonicalizationError):
            cn.word("0xdeadbeef")


class TestSupersededDeployment:
    def test_the_old_rehearsal_set_is_named_and_refused(self):
        from coretex_validator import rehearsal_deployment as rd

        match = rd.superseded_match({"mining": "0x7302bCaBa9a2f17447AEA5CEB3dC1593681758F6"})
        assert match is not None and match[0] == "2026-08-03"

    def test_the_live_set_is_not_flagged(self):
        from coretex_validator import rehearsal_deployment as rd

        assert rd.superseded_match(rd.LIVE_DEPLOYMENT) is None

    def test_the_transcribed_addresses_are_checked_against_the_operator_handoff(self):
        from coretex_validator import rehearsal_deployment as rd

        report = rd.check_against_handoff()
        if not report["checked"]:
            pytest.skip(report["reason"])
        assert report["chain_id"] == rd.REHEARSAL_CHAIN_ID
        assert report["deployment_kind"] == "ACCELERATED_DISPOSABLE_MAINNET_REHEARSAL"

    def test_the_operator_signer_coincidence_is_recorded_as_a_trap(self):
        from coretex_validator import rehearsal_deployment as rd

        record = rd.operator_signer_coincidence()
        assert record["equal_in_this_deployment"] and record["is_a_coincidence"]
        assert "coordinatorSigner()" in record["consequence"]

    def test_nothing_in_the_validation_path_imports_a_deployment_constant(self):
        # rehearsal_deployment is a safety net, not a source. The addresses a run uses come from
        # the release artifact, which is verified against chain bytecode.
        from coretex_validator import join as join_module
        from coretex_validator import pipeline
        from coretex_validator import snapshot as snapshot_module

        for module in (join_module, pipeline, snapshot_module):
            assert "LIVE_DEPLOYMENT" not in _referenced_names(module), module.__name__


class TestSignatureArtifactHasTwoFields:
    """payload_sha256 is IDENTITY; signing_digest is what the signature COVERS."""

    def _artifact(self, payload, **overrides):
        artifact = {"payload_sha256": snap.payload_hash(payload),
                    "signing_digest": "0x" + snap.signing_digest(payload).hex(),
                    "signature": "0x" + "11" * 65}
        artifact.update(overrides)
        return artifact

    def test_a_wrong_payload_identity_is_refused_before_any_key_is_touched(self):
        payload = minimal_payload()
        result = snap.verify_signature_artifact(
            payload, self._artifact(payload, payload_sha256="00" * 32), "0x" + "aa" * 20)
        assert not result.valid and "not about this payload" in result.reason

    def test_a_CORRECT_identity_with_a_WRONG_digest_is_still_refused(self):
        # The hole this second check closes: the identity matches, so an implementation that
        # checked only payload_sha256 would go on to verify against a digest nobody computed.
        payload = minimal_payload()
        artifact = self._artifact(payload, signing_digest="0x" + "22" * 32)
        assert artifact["payload_sha256"] == snap.payload_hash(payload)
        result = snap.verify_signature_artifact(payload, artifact, "0x" + "aa" * 20)
        assert not result.valid
        assert "digest nobody computed" in result.reason

    def test_the_two_fields_are_different_values_over_different_preimages(self):
        payload = minimal_payload()
        assert snap.payload_hash(payload) != snap.signing_digest(payload).hex()

    def test_a_signature_under_the_superseded_tag_is_DIAGNOSED_not_just_rejected(self):
        # A stale-tag signature and a forged one are different problems, and only one of them is
        # somebody re-signing. Saying which is the difference between a useful refusal and a
        # mysterious one.
        import subprocess

        payload = minimal_payload()
        key = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
        signer = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
        digest = snap.superseded_signing_digest(payload).hex()
        env = dict(os.environ)
        env["PATH"] = "/home/ubuntu/.foundry/bin:" + env.get("PATH", "")
        proc = subprocess.run(["cast", "wallet", "sign", "--no-hash", "--private-key", key,
                               "0x" + digest], capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            pytest.skip("cast is unavailable on this host")
        result = snap.verify_signature(payload, proc.stdout.strip(), signer)
        assert not result.valid
        assert "superseded domain tag" in result.reason


class TestSandboxImportIsolation:
    """The two path classes, separated STRUCTURALLY — an allow-list, not a scrub.

    ALLOWED: the pinned admission trees plus the verified interpreter's stdlib and site-packages.
    REFUSED: source tree, repository-relative entries, the working directory, PYTHONPATH
    injections and the user site directory — all ambient, all dependent on where the command was
    run from, all things that must not influence a deterministic replay.

    The direction of failure is the point. A blocklist can only remove what somebody remembered
    to name, and the previous one named the wrong thing. An allow-list fails toward REFUSING an
    import, which is the correct direction for a sandbox.
    """

    def _render(self, template):
        return template.format(v5="/PARENT", validator="/PARENT/coretex_validator",
                               coretex="/trees/coretex-memory", bench="/trees/benchmark-v2",
                               repo="/trees", isolation="/iso.py")

    def _templates(self):
        from coretex_validator import replay as replay_mod

        return (replay_mod._SCREEN_CHILD, replay_mod._SANDBOX_CHILD)      # noqa: SLF001

    def test_the_path_is_BUILT_not_filtered(self):
        for template in self._templates():
            rendered = self._render(template)
            assert "_allowed = " in rendered
            # The old blocklist form must be gone entirely, in both children.
            assert "for p in sys.path if" not in rendered

    def test_the_admission_trees_are_allowed_and_come_first(self):
        for template in self._templates():
            rendered = self._render(template)
            assert "_allowed = ['/trees/benchmark-v2', '/trees/coretex-memory']" in rendered

    def test_site_packages_of_the_verified_environment_is_allowed(self):
        # Without this the sandbox cannot import wasmtime, which was exactly the K2 defect.
        for template in self._templates():
            assert "_site.getsitepackages()" in self._render(template)

    def test_the_user_site_directory_is_NOT_allowed(self):
        # ~/.local is ambient host state — present on some machines, absent on others.
        for template in self._templates():
            assert "getusersitepackages" not in self._render(template)

    def test_source_tree_and_package_paths_are_not_in_the_allow_list(self):
        for template in self._templates():
            rendered = self._render(template)
            body = rendered.split("_allowed = ", 1)[1].split("sys.path[:]", 1)[0]
            assert "/PARENT/coretex_validator" not in body
            assert "'/PARENT'" not in body

    def test_the_dependency_preflight_names_the_dependency_and_fails_closed(self):
        from coretex_validator import replay as replay_mod

        rendered = self._render(replay_mod._SANDBOX_CHILD)                # noqa: SLF001
        assert "MISSING_DEPENDENCY" in rendered
        assert 'for _dependency in ("wasmtime",)' in rendered
        assert "raise SystemExit(97)" in rendered

    def test_a_missing_dependency_is_a_FAIL_not_a_BACKLOG(self):
        from coretex_validator import replay as replay_mod

        # The distinction the operator called out: "could not check" vs "your environment is
        # wrong". They must not be the same class, or one degrades into the other.
        assert not issubclass(replay_mod.SandboxDependencyError, replay_mod.SandboxUnavailable)
        error = replay_mod.SandboxDependencyError("wasmtime", "no module named wasmtime")
        assert "MISSING_DEPENDENCY[wasmtime]" in str(error)
        assert "ENVIRONMENT fault" in str(error)
        assert error.dependency == "wasmtime"
        assert error.remedy

    def test_the_pinned_range_is_recorded_and_used_in_the_remedy(self):
        from coretex_validator import replay as replay_mod

        assert replay_mod.PINNED_RUNTIME_DEPENDENCIES["wasmtime"] == ">=46.0.1,<47"


class TestResolverSchemaReproduction:
    """The published schema is the RESOLVER's per-epoch shape, and this package reproduces it."""

    def test_the_published_check_vocabulary_is_the_normative_step_numbers(self):
        # These strings go INSIDE the canonical bytes, so a lane that spelled them its own way
        # would produce a payload that could not reproduce however correct its logic was.
        assert jn.JOIN_STEPS == (
            "step1_advance_decoded", "step2_credit_event_joined", "step3_calldata_decoded",
            "step4_receipt_hash_bound", "step5_artifact_hash_bound_via_digest",
            "step6_calldata_bound_to_logs", "step7_coordinator_signature_verified",
            "step8_patch_hash_verified")

    def test_the_schema_has_exactly_twenty_three_top_level_keys(self):
        from coretex_validator import resolver_snapshot as rsn

        assert len(rsn.TOP_LEVEL_KEYS) == 23
        with pytest.raises(rsn.ReproductionError) as excinfo:
            rsn.check_shape({"schema": rsn.SCHEMA, "epoch": 1})
        assert excinfo.value.code == "SCHEMA_SHAPE_MISMATCH"

    def test_a_canonical_classification_is_refused_by_the_shape_check(self):
        from coretex_validator import resolver_snapshot as rsn

        payload = {k: None for k in rsn.TOP_LEVEL_KEYS}
        payload["schema"] = rsn.SCHEMA
        payload["classification"] = "MAINNET_CANONICAL"
        with pytest.raises(rsn.ReproductionError) as excinfo:
            rsn.check_shape(payload)
        assert excinfo.value.code == "CLASSIFICATION_REFUSED"

    def test_schema_constant_keys_are_named_so_they_cannot_pose_as_evidence(self):
        from coretex_validator import resolver_snapshot as rsn

        # Reproducing spec text proves the transcription, not the chain. The comparison report
        # keeps the two classes apart for exactly that reason.
        assert "derivation" in rsn.SCHEMA_CONSTANT_KEYS
        assert "canonicalization" in rsn.SCHEMA_CONSTANT_KEYS
        assert "transitions" in rsn.CHAIN_DERIVED_KEYS
        assert "state" in rsn.CHAIN_DERIVED_KEYS
        assert not set(rsn.SCHEMA_CONSTANT_KEYS) & set(rsn.CHAIN_DERIVED_KEYS)

    def test_wide_receipt_members_render_as_strings_and_narrow_ones_as_numbers(self):
        from coretex_validator import resolver_snapshot as rsn

        # The mixture inside ONE object is what a reader has to get right: rigId is a string,
        # epochId beside it is a number.
        assert "rigId" in rsn._WIDE_RECEIPT_MEMBERS            # noqa: SLF001
        assert "worldSeed" in rsn._WIDE_RECEIPT_MEMBERS        # noqa: SLF001
        assert "difficultyCountSnapshot" in rsn._WIDE_RECEIPT_MEMBERS   # noqa: SLF001
        assert "epochId" in rsn._NARROW_RECEIPT_MEMBERS        # noqa: SLF001
        assert not set(rsn._WIDE_RECEIPT_MEMBERS) & set(rsn._NARROW_RECEIPT_MEMBERS)  # noqa: SLF001

    def test_finalized_at_is_wide_because_it_is_a_uint256_timestamp(self):
        from coretex_validator import resolver_snapshot as rsn

        state = rsn.build_state(
            epoch=10,
            context={"active_frontier_root": "0x" + "aa" * 32,
                     "baseline_manifest_hash": "0x" + "bb" * 32, "configured": True,
                     "core_version_hash": "0x" + "cc" * 32, "corpus_root": "0x" + "dd" * 32,
                     "hidden_seed_commit": "0x" + "ee" * 32,
                     "parent_state_root": "0x" + "ff" * 32},
            header={"final_state_root": "0x" + "11" * 32},
            live_state_root="0x" + "11" * 32, transition_count=3, sealed=True, served=True,
            finalized_at=1785992019)
        # A decimal STRING, sitting beside transition_count which is a number. The easiest field
        # in the whole payload to get wrong.
        assert state["finalized_at"] == "1785992019"
        assert state["transition_count"] == 3

    def test_the_observation_omits_everything_that_depends_on_WHEN_it_ran(self):
        from coretex_validator import resolver_snapshot as rsn

        chain = rsn.build_chain(chain_id=31337, block_number=36, block_hash="0x" + "ab" * 32,
                                parent_hash="0x" + "cd" * 32, block_timestamp=1785992019,
                                required_confirmations=2)
        observation = chain["observation"]
        # Including any of these would make two honest resolutions of one block differ.
        for absent in ("head_number", "confirmations", "finalized_block_number"):
            assert absent not in observation
        assert observation["finality_policy"]["required_confirmations"] == 2


class TestCompactPatchIsBinaryNotJson:
    """HISTORY. The full validation set from the RETIRED RigCoreTexVerifier._validateCompactPatch
    (coretex-patch-hash-v1 era), kept because epoch-180-and-earlier advances are legacy-era
    history that must stay decodable (transition-descriptor/v2 spec §9.5) — never re-migrated,
    because ``decode_compact_patch`` is explicitly preserved as-is. See
    ``TestTransitionDescriptorV3`` below for the live model's equivalent adversarial breadth.

    Every negative control asserts its SPECIFIC refusal code. A control that only checked "it
    threw" would pass just as happily when the decoder rejects for the wrong reason — and a
    decoder that refused everything would satisfy the whole suite.
    """

    def _patch(self, *, patch_type=0xFF, word_count=1, score_delta=65500,
               parent="21" * 32, words=((2, "b3" * 32),), trailing=b""):
        raw = bytes([patch_type, word_count]) + score_delta.to_bytes(8, "big") \
            + bytes.fromhex(parent)
        for index, value in words:
            raw += (bytes([index]) if index < 128
                    else bytes([0x80 | (index & 0x7F), index >> 7]))
            raw += bytes.fromhex(value)
        return raw + trailing

    def _refusal(self, raw, **kwargs):
        with pytest.raises(rig.CompactPatchError) as excinfo:
            rig.decode_compact_patch(raw, **kwargs)
        return excinfo.value.code

    # ── POSITIVE FIXTURE: the real 75-byte epoch-180 patch, replayed as LEGACY-ERA history ──
    def test_the_real_epoch_180_patches_decode_to_documented_ground_truth(self):
        """THE LEGACY-ERA REPLAY, restored (review M-10).

        These two advances are read under the RETIRED rules — the ``coretex-patch-hash-v1`` label
        and the 42..178-byte word-diff layout — because that is what the deployed verifier enforced
        when they were mined. They are NOT re-read under v2 and MUST NOT be: their first byte,
        ``0xff``, is a permanently-burned descriptor version. The era is asserted here rather than
        implied, so "this does not reproduce under today's constants" reads as the era boundary it
        is instead of as a failed reproduction.

        This test used to resolve its evidence through a hardcoded
        ``/home/ubuntu/botcoin-coordinator-v5-p6/...`` path that does not exist on this host, so it
        skipped silently and asserted nothing at all.
        """
        evidence = _resolve_cross_tree(E180_SNAPSHOT_RELATIVE, "CORETEX_E180_SNAPSHOT")
        if evidence is None:
            pytest.skip("the published epoch-180 snapshot is not on this host "
                        f"(looked under {_COORDINATOR_ROOTS}; set CORETEX_E180_SNAPSHOT)")
        snapshot = json.loads(evidence.read_text(encoding="utf-8"))
        # The era, asserted before anything is decoded under it.
        assert snapshot["derivation"]["receipt_layout"]["typehash"] == (
            "0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b")
        assert snapshot["derivation"]["receipt_layout"]["source_commit"] == (
            "cdb91d211e4620c6ecfd90b68d827d607033e1f1")
        expected = {0: (65500, "2170c3de"), 1: (90600, "17e41e20")}
        for entry in snapshot["transitions"]["lineage"]:
            event = entry["registry_event"]
            raw = bytes.fromhex(event["compact_patch_bytes"][2:])
            patch = rig.decode_compact_patch(
                raw, parent_state_root=event["parent_state_root"],
                expected_patch_hash=event["patch_hash"],
                score_delta_ppm=(int(entry["receipt"]["scoreAfterPpm"])
                                 - int(entry["receipt"]["scoreBeforePpm"])))
            delta, parent_prefix = expected[entry["transition_index"]]
            assert len(raw) == 75
            assert patch.patch_type == 0xFF and patch.word_count == 1
            assert patch.score_delta_ppm == delta
            assert patch.parent_state_root.startswith(parent_prefix)
            # Word 2 is the candidate release root — the signed artifactHash.
            assert patch.words[0] == (2, entry["receipt"]["artifactHash"][2:])

    # ── NEGATIVE CONTROLS: each asserts WHICH refusal fired ───────────────────────────────
    def test_malformed_length(self):
        assert self._refusal(b"\xff\x01" + b"\x00" * 10) == rig.PATCH_LENGTH_INVALID
        assert self._refusal(self._patch(words=((2, "aa" * 32),) * 4) + b"\x00" * 200) \
            == rig.PATCH_LENGTH_INVALID

    def test_truncated_leb128(self):
        # A continuation bit with nothing after it.
        raw = bytes([0xFF, 1]) + (65500).to_bytes(8, "big") + bytes.fromhex("21" * 32) + b"\x82"
        assert self._refusal(raw) == rig.PATCH_INDEX_TRUNCATED

    def test_overlong_leb128(self):
        raw = (bytes([0xFF, 1]) + (65500).to_bytes(8, "big") + bytes.fromhex("21" * 32)
               + b"\x82\x81\x01" + bytes.fromhex("aa" * 32))
        assert self._refusal(raw) == rig.PATCH_INDEX_OVERLONG

    def test_redundant_leb128_encoding(self):
        # 0x82 0x00 and 0x02 both mean 2: one index with two spellings is one patch with two
        # hashes, which breaks the patchHash binding outright.
        raw = (bytes([0xFF, 1]) + (65500).to_bytes(8, "big") + bytes.fromhex("21" * 32)
               + b"\x82\x00" + bytes.fromhex("aa" * 32))
        assert self._refusal(raw) == rig.PATCH_INDEX_REDUNDANT

    def test_duplicate_index(self):
        assert self._refusal(
            self._patch(word_count=2, words=((2, "aa" * 32), (2, "bb" * 32)))) \
            == rig.PATCH_INDEX_DUPLICATE

    def test_reserved_index(self):
        assert self._refusal(self._patch(words=((999, "aa" * 32),))) == rig.PATCH_INDEX_RESERVED

    def test_index_outside_the_patch_type_window(self):
        assert self._refusal(self._patch(patch_type=0x06, words=((400, "aa" * 32),))) \
            == rig.PATCH_INDEX_OUT_OF_WINDOW

    def test_wrong_parent(self):
        assert self._refusal(self._patch(parent="21" * 32), parent_state_root="99" * 32) \
            == rig.PATCH_PARENT_MISMATCH

    def test_wrong_score_delta(self):
        assert self._refusal(self._patch(score_delta=65500), score_delta_ppm=90600) \
            == rig.PATCH_SCORE_DELTA_MISMATCH

    def test_trailing_bytes(self):
        assert self._refusal(self._patch(trailing=b"\x00")) == rig.PATCH_TRAILING_BYTES

    def test_json_substitution(self):
        # THE bug K1 was: canonical JSON handed to a decoder expecting the contract's struct.
        # It must be refused HERE with a structural code, not accepted and not crash elsewhere.
        payload = json.dumps({"target_profile": "doc.tool.v1",
                              "expected_prior_release_root": "aa" * 32,
                              "new_release_root": "bb" * 32,
                              "resulting_composition_root": "cc" * 32},
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
        assert self._refusal(payload) in {rig.PATCH_TYPE_UNKNOWN, rig.PATCH_LENGTH_INVALID,
                                          rig.PATCH_WORD_COUNT_INVALID}
        # ...and symmetrically, the real binary patch is not UTF-8, so the JSON parser can never
        # have been right for it. This is the whole of K1 in two assertions.
        from coretex_validator import frontier as frontier_mod

        with pytest.raises(Exception):
            frontier_mod.parse_transition_bytes(self._patch())

    def test_unknown_patch_type_and_word_count_bounds(self):
        assert self._refusal(self._patch(patch_type=0x08)) == rig.PATCH_TYPE_UNKNOWN
        assert self._refusal(self._patch(word_count=0)) == rig.PATCH_WORD_COUNT_INVALID
        assert self._refusal(self._patch(word_count=5)) == rig.PATCH_WORD_COUNT_INVALID

    def test_the_keccak_patch_hash_rule_is_part_of_the_validation_set(self):
        raw = self._patch()
        # Correct hash (the RETIRED label — this decoder is history) passes...
        retired_hash = rig.keccak256_hex(rig.TRANSITION_DESCRIPTOR_RETIRED_LABEL + raw)
        rig.decode_compact_patch(raw, expected_patch_hash=retired_hash)
        # ...a wrong one is refused BEFORE any field complaint, because a patch whose bytes hash
        # elsewhere is a different patch, not a malformed one.
        assert self._refusal(raw, expected_patch_hash="00" * 32) == rig.PATCH_HASH_MISMATCH

    def test_a_superseded_label_signature_is_diagnosed_by_name(self):
        raw = self._patch()
        stale = rig.keccak256_hex(rig.TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL + raw)
        with pytest.raises(rig.CompactPatchError) as excinfo:
            rig.decode_compact_patch(raw, expected_patch_hash=stale)
        assert excinfo.value.code == rig.PATCH_HASH_MISMATCH
        assert "superseded" in excinfo.value.message

    def test_the_live_v2_label_is_also_diagnosed_as_a_dead_label_here(self):
        # The RETIRED decoder's own hint only names the TWO labels it always checked
        # (coretex-patch-hash-v1's own family and the memory lane's). A receipt signed under the
        # LIVE v3 label and mistakenly fed to this HISTORY decoder is still just "wrong hash" —
        # recorded here so nobody mistakes silence for a promise the hint covers every label.
        raw = self._patch()
        live = rig.transition_descriptor_hash(raw)
        with pytest.raises(rig.CompactPatchError) as excinfo:
            rig.decode_compact_patch(raw, expected_patch_hash=live)
        assert excinfo.value.code == rig.PATCH_HASH_MISMATCH


class TestTransitionDescriptorV3:
    """coretex.transition-descriptor/v3 — the descriptor's own adversarial suite.

    Mirrors ``TestCompactPatchIsBinaryNotJson`` in shape (one method per refusal, each asserting
    the SPECIFIC code) but tests the LIVE model: a fixed 97-byte commitment plus a separately
    fetched, rehashed and replayed canonical patch artifact. See
    ``docs/CORETEX-TRANSITION-DESCRIPTOR-V2.md`` (botcoin-mining-rigs @
    ba4d5acfa7aa3042f39eb6e8e4d8e4007400090c) for the normative spec this decodes against.
    """

    PARENT = "aa" * 32
    NEW = "bb" * 32
    ARTIFACT_HASH = "cc" * 32
    DELTA = 5000

    def _raw(self, **overrides):
        kwargs = dict(patch_artifact_hash=self.ARTIFACT_HASH, parent_state_root=self.PARENT,
                     new_state_root=self.NEW)
        kwargs.update(overrides)
        return rig.encode_transition_descriptor(**kwargs)

    # ── THE FORMAT ──────────────────────────────────────────────────────────────────────────
    def test_encode_decode_round_trips_at_exactly_97_bytes(self):
        raw = self._raw()
        assert len(raw) == rig.TRANSITION_DESCRIPTOR_BYTES == 97
        assert raw[0] == rig.TRANSITION_DESCRIPTOR_VERSION == 0x21
        decoded = rig.decode_transition_descriptor(raw)
        assert decoded.version == 0x21
        assert decoded.patch_artifact_hash == self.ARTIFACT_HASH
        assert decoded.parent_state_root == self.PARENT
        assert decoded.new_state_root == self.NEW
        # Cross-checks against the "signed receipt" all pass together.
        digest = rig.transition_descriptor_hash(raw)
        again = rig.decode_transition_descriptor(
            raw, parent_state_root=self.PARENT, new_state_root=self.NEW,
            expected_patch_hash=digest, transition_format_version=0x21)
        assert again == decoded

    def test_length_is_the_format(self):
        raw = self._raw()
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw + b"\x00")
        assert excinfo.value.code == rig.DESCRIPTOR_LENGTH_INVALID
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw[:-1])
        assert excinfo.value.code == rig.DESCRIPTOR_LENGTH_INVALID
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(b"")
        assert excinfo.value.code == rig.DESCRIPTOR_LENGTH_INVALID

    # ── THE HASH RULE — checked after version and length ─────────────────────────────────────
    def test_hash_mismatch_is_refused_before_any_field_is_read(self):
        raw = self._raw()
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, expected_patch_hash="00" * 32)
        assert excinfo.value.code == rig.DESCRIPTOR_HASH_MISMATCH

    def test_legacy_first_bytes_are_refused_even_at_the_v3_length(self):
        # A LEGACY compact patch's first byte (patchType) is always in {0x01..0x07, 0xff}. All are
        # PERMANENTLY BURNED version values, so a coincidentally-105-byte legacy-shaped blob is
        # refused on the version byte, not silently misread as a v3 descriptor of some other kind.
        raw = self._raw()
        for burned_first_byte in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF):
            legacy_shaped = bytes([burned_first_byte]) + raw[1:]
            with pytest.raises(rig.TransitionDescriptorError) as excinfo:
                rig.decode_transition_descriptor(legacy_shaped)
            assert excinfo.value.code == rig.DESCRIPTOR_VERSION_UNSUPPORTED

    def test_every_burned_and_unassigned_version_byte_is_refused(self):
        raw = self._raw()
        for version in rig.TRANSITION_DESCRIPTOR_BURNED_VERSIONS:
            mutated = bytes([version]) + raw[1:]
            with pytest.raises(rig.TransitionDescriptorError) as excinfo:
                rig.decode_transition_descriptor(mutated)
            assert excinfo.value.code == rig.DESCRIPTOR_VERSION_UNSUPPORTED
        for version in (0x08, 0x1f, 0x15):
            assert version in rig.TRANSITION_DESCRIPTOR_UNASSIGNED_VERSIONS
            mutated = bytes([version]) + raw[1:]
            with pytest.raises(rig.TransitionDescriptorError) as excinfo:
                rig.decode_transition_descriptor(mutated)
            assert excinfo.value.code == rig.DESCRIPTOR_VERSION_UNSUPPORTED
        # A hypothetical successor version (reserved, not burned/unassigned) is ALSO refused: one
        # deployed verifier accepts exactly one version, compared for equality, never a range.
        mutated = bytes([0x22]) + raw[1:]
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(mutated)
        assert excinfo.value.code == rig.DESCRIPTOR_VERSION_UNSUPPORTED

    def test_the_retired_v2_version_is_named_before_length_or_hash(self):
        old = bytes([0x20]) + self._raw()[1:] + bytes(8)
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(
                old, expected_patch_hash=keccak256_hex(rig.TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL + old))
        assert excinfo.value.code == rig.DESCRIPTOR_VERSION_RETIRED

    def test_zero_artifact_hash_is_refused_both_at_encode_and_decode(self):
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            self._raw(patch_artifact_hash="0" * 64)
        assert excinfo.value.code == rig.DESCRIPTOR_ARTIFACT_HASH_ZERO
        raw = self._raw()
        zeroed = raw[:1] + bytes(32) + raw[33:]
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(zeroed)
        assert excinfo.value.code == rig.DESCRIPTOR_ARTIFACT_HASH_ZERO

    def test_parent_root_mismatch(self):
        raw = self._raw()
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, parent_state_root="99" * 32)
        assert excinfo.value.code == rig.DESCRIPTOR_PARENT_MISMATCH

    def test_new_root_mismatch_did_not_exist_under_the_retired_model(self):
        # The retired compact patch carried no resulting root at all, so this check is NEW.
        raw = self._raw()
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, new_state_root="99" * 32)
        assert excinfo.value.code == rig.DESCRIPTOR_NEW_ROOT_MISMATCH

    def test_score_delta_is_not_a_descriptor_field(self):
        raw = self._raw()
        assert len(raw) == 97
        assert raw[65:97] == bytes.fromhex(self.NEW)

    def test_signed_transition_format_version_must_be_the_descriptor_byte_zero_extended(self):
        raw = self._raw()
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, transition_format_version=1)
        assert excinfo.value.code == rig.DESCRIPTOR_FORMAT_VERSION_MISMATCH
        # The zero-extension itself is accepted.
        rig.decode_transition_descriptor(raw, transition_format_version=0x21)

    # ── SUPERSEDED LABELS — refused, never silently accepted ──────────────────────────────────
    def test_all_three_dead_labels_are_refused_and_named(self):
        raw = self._raw()
        v2 = rig.keccak256_hex(rig.TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL + raw)
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, expected_patch_hash=v2)
        assert excinfo.value.code == rig.DESCRIPTOR_HASH_MISMATCH
        assert "coretex-transition-descriptor-v2" in str(excinfo.value)

        retired = rig.keccak256_hex(rig.TRANSITION_DESCRIPTOR_RETIRED_LABEL + raw)
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, expected_patch_hash=retired)
        assert excinfo.value.code == rig.DESCRIPTOR_HASH_MISMATCH
        assert "coretex-patch-hash-v1" in str(excinfo.value)

        superseded = rig.keccak256_hex(rig.TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL + raw)
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, expected_patch_hash=superseded)
        assert excinfo.value.code == rig.DESCRIPTOR_HASH_MISMATCH
        assert "coretex-memory-transition-hash-v1" in str(excinfo.value)

        plain = rig.keccak256_hex(raw)
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.decode_transition_descriptor(raw, expected_patch_hash=plain)
        assert "PLAIN undomained keccak256" in str(excinfo.value)

    def test_the_four_labels_are_prefix_free(self):
        live = rig.TRANSITION_DESCRIPTOR_HASH_LABEL
        v2 = rig.TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL
        retired = rig.TRANSITION_DESCRIPTOR_RETIRED_LABEL
        superseded = rig.TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL
        assert len(live) == len(v2) == 32 and live != v2
        for a, b in ((live, v2), (live, retired), (live, superseded), (v2, retired),
                     (v2, superseded), (retired, superseded)):
            assert not a.startswith(b) and not b.startswith(a)

    # ── OUTCOME-1 (SCREENER) DISCIPLINE — the tightening the retired model did not have ────────
    def test_screener_pass_must_carry_an_empty_descriptor(self):
        raw = self._raw()
        with pytest.raises(rig.TransitionDescriptorError) as excinfo:
            rig.check_screener_descriptor(raw)
        assert excinfo.value.code == rig.DESCRIPTOR_UNEXPECTED
        rig.check_screener_descriptor(b"")   # empty is the only legal shape
        rig.check_screener_descriptor(None)  # None is treated as empty

    def test_screener_pass_must_sign_zero_scores_and_zero_format_version(self):
        for kwargs in ({"transition_format_version": 1}, {"score_before_ppm": 1},
                      {"score_after_ppm": 1}):
            with pytest.raises(rig.TransitionDescriptorError) as excinfo:
                rig.check_screener_descriptor(b"", **kwargs)
            assert excinfo.value.code == rig.DESCRIPTOR_UNEXPECTED
        rig.check_screener_descriptor(b"", transition_format_version=0, score_before_ppm=0,
                                      score_after_ppm=0)

    # ── H-2: the screener patchHash rule, which the FIRST cut of this tightening did not state ──
    def test_screener_pass_must_sign_a_ZERO_patch_hash(self):
        """Removing the descriptor BYTES without forbidding the WORD left a live defect.

        ``patchHash`` is a signed member; with an empty descriptor mandatory and a non-zero
        ``patchHash`` still demanded, the only descriptor-derived value an honest implementer could
        reach was the CONSTANT ``keccak256(LABEL ‖ "")``. A screener never moves the root, so the
        first screener burned ``coreTexPatchCredited[epoch][parent][thatConstant]`` and the second
        reverted ``DuplicateCoreTexPatch`` — killing the screener cap and the whole difficulty
        ramp, which exist to count many screeners between advances.
        """
        constant = rig.transition_descriptor_hash(b"")
        for spelling in (constant, f"0x{constant}", bytes.fromhex(constant), "11" * 32):
            with pytest.raises(rig.TransitionDescriptorError) as excinfo:
                rig.check_screener_descriptor(b"", patch_hash=spelling)
            assert excinfo.value.code == rig.SCREENER_PATCH_HASH_NONZERO
        # bytes32(0) — the one word that names no transition — in every spelling.
        for zero in ("0" * 64, f"0x{'0' * 64}", bytes(32)):
            rig.check_screener_descriptor(b"", patch_hash=zero)

    def test_the_screener_constant_is_exactly_the_value_the_review_computed(self):
        """Pinned so the hazard cannot be re-introduced silently: this is THE word every honest
        v2 implementer would have named, recomputed here with this repo's own keccak."""
        assert rig.transition_descriptor_hash(b"") == (
            "9382d3cfe879c5c069835615ecc625f1858991dd6a71f64dade11727b08e2964")

    def test_a_state_advance_must_sign_a_NON_ZERO_patch_hash(self):
        """The outcome-2 half. ``_validateCoreTexNonZero`` deliberately no longer states it
        outcome-independently — that is what forced a screener to name some word."""
        for zero in ("0" * 64, f"0x{'0' * 64}", bytes(32)):
            with pytest.raises(rig.TransitionDescriptorError) as excinfo:
                rig.check_state_advance_patch_hash(zero)
            assert excinfo.value.code == rig.STATE_ADVANCE_PATCH_HASH_ZERO
        rig.check_state_advance_patch_hash(rig.transition_descriptor_hash(b"\x21" * 97))

    def test_both_new_codes_are_in_the_declared_refusal_set(self):
        """``code`` IS THE CONTRACT: a refusal that is not in the declared set cannot be asserted
        on by a caller that only knows the vocabulary."""
        assert rig.SCREENER_PATCH_HASH_NONZERO in rig.DESCRIPTOR_REFUSALS
        assert rig.STATE_ADVANCE_PATCH_HASH_ZERO in rig.DESCRIPTOR_REFUSALS


# --------------------------------------------------------------------------- #
# L-1 / H-2 — the outcome-1 discipline is WIRED into the production screener path
# --------------------------------------------------------------------------- #
def _encode_receipt_calldata(values):
    """Encode ``submitCoreTexReceipt((...))`` calldata from a member dict.

    Hand-rolled rather than taken from :mod:`.join`: this is the counterpart to
    :func:`join.decode_submit_calldata`, and an encoder that shared its code would agree with it
    about a layout they were both wrong about.
    """
    comps = binding.CORETEX_RECEIPT_TUPLE_COMPONENTS
    head, tail = [], b""
    tail_base = 32 * len(comps)
    for component in comps:
        name, kind = component["name"], component["type"]
        value = values[name]
        if kind == "bytes":
            data = bytes(value)
            head.append((tail_base + len(tail)).to_bytes(32, "big"))
            tail += len(data).to_bytes(32, "big") + data + bytes((-len(data)) % 32)
        elif kind == "address":
            head.append(bytes(12) + bytes.fromhex(str(value).lower().removeprefix("0x")))
        elif kind == "bytes32":
            head.append(bytes.fromhex(str(value).lower().removeprefix("0x").rjust(64, "0")))
        else:
            head.append(int(value).to_bytes(32, "big"))
    body = (32).to_bytes(32, "big") + b"".join(head) + tail
    return "0x" + jn.SUBMIT_SELECTOR[2:] + body.hex()


class TestScreenerDisciplineIsWiredIntoTheProductionPath:
    """L-1: ``check_screener_descriptor`` encoded the v2 tightening and NOTHING but a test called
    it. The production screener branch checked the outcome, the receipt-hash binding and the
    signature, and never looked at ``compactPatchBytes``, ``transitionFormatVersion``, the scores
    or ``patchHash``. There was no acceptance hole — the chain enforces all of it — but a
    tightening a validator cannot OBSERVE is one it cannot report, and reporting is the job.
    """

    DOMAIN = bytes.fromhex("cd" * 32)
    TX = "0x" + "ab" * 32
    SIGNER = "0x" + "11" * 20

    def _receipt_values(self, **overrides):
        values = {
            "rigId": 7, "operator": self.SIGNER, "epochId": 9, "solveIndex": 3,
            "prevReceiptHash": "00" * 32, "outcome": jn.OUTCOME_SCREENER_PASS,
            "challengeId": "aa" * 32, "parentStateRoot": "bb" * 32, "newStateRoot": "bb" * 32,
            "epochContextRoot": "cc" * 32, "coreVersionHash": "ee" * 32,
            "evalReportHash": "ff" * 32,
            # THE RULE: outcome 1 credits no transition, so patchHash is bytes32(0).
            "patchHash": "00" * 32,
            "artifactHash": "12" * 32, "worldSeed": 1, "rulesVersion": 1,
            "workPolicyHash": "13" * 32, "workUnitsBps": 20000, "difficultyCountSnapshot": 0,
            "transitionFormatVersion": 0, "scoreBeforePpm": 0, "scoreAfterPpm": 0,
            "issuedAt": 1_800_000_000, "expiresAt": 1_800_000_600,
            "compactPatchBytes": b"", "signature": bytes(65),
        }
        values.update(overrides)
        return values

    def _join(self, **overrides):
        calldata = _encode_receipt_calldata(self._receipt_values(**overrides))
        receipt = jn.decode_submit_calldata(calldata)
        receipt_hash = receipt.receipt_hash(receipt.digest(self.DOMAIN))
        credit = rig.CoreTexCreditAccepted(
            epoch=9, rig_id=7, operator=self.SIGNER, solve_index=3, receipt_hash=receipt_hash,
            challenge_id="aa" * 32, work_units_bps=20000, credits_earned=1,
            provenance=dp.LogProvenance(transaction_hash=self.TX))
        decoded = rig.DecodedLogs(
            advances=[], coretex_credits=[credit], standard_credits=[], finalizations=[],
            contexts=[], commits=[], reveals=[], policies=[])
        return jn.join_all(decoded, calldata_for=lambda _tx: calldata,
                           domain_separator=self.DOMAIN, coordinator_signer=self.SIGNER,
                           verify_signature=False)

    def test_a_clean_screener_reports_the_discipline_step(self):
        result = self._join()
        assert result.unresolved == []
        assert len(result.screener_passes) == 1
        assert jn.STEP8_SCREENER_DISCIPLINE in result.screener_passes[0].checks

    @pytest.mark.parametrize("overrides,fragment", [
        ({"patchHash": "9382d3cfe879c5c069835615ecc625f1858991dd6a71f64dade11727b08e2964"},
         "MUST be bytes32(0)"),
        ({"compactPatchBytes": b"\x21" * 97}, "EMPTY compactPatchBytes"),
        ({"transitionFormatVersion": 0x21}, "transitionFormatVersion"),
        ({"scoreAfterPpm": 5}, "scoreAfterPpm"),
    ])
    def test_an_outcome_1_receipt_breaking_the_rule_is_UNRESOLVED_not_accepted(
            self, overrides, fragment):
        result = self._join(**overrides)
        assert result.screener_passes == []
        assert len(result.unresolved) == 1
        assert result.unresolved[0]["code"] == "JOIN_SCREENER_DISCIPLINE_VIOLATED"
        assert fragment in result.unresolved[0]["reason"]


@pytest.mark.skip(reason=(
    "retired descriptor-v2 transition artifacts are historical evidence only; "
    "the live V5 validator is closed over generalized transition-artifact/v3"))
class TestTransitionArtifactV2:
    """The canonical patch artifact (spec §5), scoped to the single-transition (T-1/T-2) shape
    this repo's :mod:`.frontier` already supports. See :mod:`.rig_events`'s section note on why
    T-3/T-4/T-5 multi-profile breadth is a documented gap rather than implemented here.
    """

    TRANSITION = fr.make_transition(
        target_profile="conv.pref.v1", expected_prior_release_root="ab" * 32,
        new_release_root="cd" * 32, resulting_composition_root="ef" * 32)

    def _artifact(self, **overrides):
        artifact = {
            "format": rig.TRANSITION_ARTIFACT_FORMAT,
            "parent_state_root": "aa" * 32,
            "new_state_root": "bb" * 32,
            "score_delta_ppm": 5000,
            "transition": self.TRANSITION,
        }
        artifact.update(overrides)
        return artifact

    def _descriptor(self, **overrides):
        artifact_hash = rig.transition_artifact_root(self._artifact())
        kwargs = dict(patch_artifact_hash=artifact_hash, parent_state_root="aa" * 32,
                     new_state_root="bb" * 32)
        kwargs.update(overrides)
        raw = rig.encode_transition_descriptor(**kwargs)
        return rig.decode_transition_descriptor(raw)

    def test_a_well_formed_artifact_validates_and_addresses_itself(self):
        artifact = self._artifact()
        validated = rig.validate_transition_artifact(artifact)
        assert validated["parent_state_root"] == "aa" * 32
        root = rig.transition_artifact_root(artifact)
        assert len(root) == 64
        # sha256, not keccak — a different digest for the same bytes.
        assert root != rig.transition_descriptor_hash(rig.transition_artifact_bytes(artifact))

    def test_unknown_field_is_refused_the_schema_is_closed(self):
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.validate_transition_artifact(self._artifact(extra_field="nope"))
        assert excinfo.value.code == rig.TRANSITION_ARTIFACT_MALFORMED

    def test_missing_field_is_refused(self):
        artifact = self._artifact()
        del artifact["score_delta_ppm"]
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.validate_transition_artifact(artifact)
        assert excinfo.value.code == rig.TRANSITION_ARTIFACT_MALFORMED

    def test_wrong_format_tag_is_refused(self):
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.validate_transition_artifact(self._artifact(format="coretex.something-else/v1"))
        assert excinfo.value.code == rig.TRANSITION_ARTIFACT_MALFORMED

    def test_score_delta_out_of_range_is_refused(self):
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.validate_transition_artifact(self._artifact(score_delta_ppm=0))
        assert excinfo.value.code == rig.TRANSITION_ARTIFACT_MALFORMED

    def test_an_invalid_frontier_transition_is_refused(self):
        broken = dict(self.TRANSITION)
        broken["new_release_root"] = broken["expected_prior_release_root"]  # no-op transition
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.validate_transition_artifact(self._artifact(transition=broken))
        assert excinfo.value.code == rig.TRANSITION_ARTIFACT_MALFORMED

    # ── THE DESCRIPTOR <-> ARTIFACT BINDING ────────────────────────────────────────────────────
    def test_a_bound_artifact_agrees_with_its_descriptor(self):
        descriptor = self._descriptor()
        document = rig.check_transition_artifact_binds_descriptor(
            self._artifact(), descriptor=descriptor, expected_score_delta_ppm=5000)
        assert document["new_state_root"] == descriptor.new_state_root

    def test_artifact_parent_mismatch_against_the_descriptor(self):
        descriptor = self._descriptor()
        substituted = self._artifact(parent_state_root="99" * 32)
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.check_transition_artifact_binds_descriptor(substituted, descriptor=descriptor)
        assert excinfo.value.code == rig.TRANSITION_PARENT_MISMATCH

    def test_artifact_new_root_mismatch_against_the_descriptor(self):
        descriptor = self._descriptor()
        substituted = self._artifact(new_state_root="99" * 32)
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.check_transition_artifact_binds_descriptor(substituted, descriptor=descriptor)
        assert excinfo.value.code == rig.TRANSITION_REPLAY_ROOT_MISMATCH

    def test_artifact_score_delta_mismatch_against_the_descriptor(self):
        descriptor = self._descriptor()
        substituted = self._artifact(score_delta_ppm=1)
        with pytest.raises(rig.TransitionArtifactError) as excinfo:
            rig.check_transition_artifact_binds_descriptor(
                substituted, descriptor=descriptor, expected_score_delta_ppm=5000)
        assert excinfo.value.code == rig.TRANSITION_SCORE_DELTA_MISMATCH

    # ── FAIL-CLOSED AVAILABILITY (spec §6.3): the fetch+rehash wiring pipeline.py/chain_first.py
    #    both use for the patchArtifactHash-addressed object, exactly as for any other artifact ──
    def test_an_unpublished_patch_artifact_is_a_typed_unavailable_refusal(self):
        store = pub.InMemoryCAS()
        descriptor = self._descriptor()
        with pytest.raises(pub.ObjectNotFoundError):
            pub.fetch_json(descriptor.patch_artifact_hash, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                           store=store)

    def test_a_substituted_patch_artifact_fails_read_back_before_it_reaches_the_binding_check(self):
        store = pub.InMemoryCAS()
        descriptor = self._descriptor()
        # A store that serves DIFFERENT bytes at the addressed root than what hashes to it.
        store.put(descriptor.patch_artifact_hash, b'{"not":"the artifact"}')
        with pytest.raises(pub.PublicationError):
            pub.fetch_json(descriptor.patch_artifact_hash, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                           store=store)

    def test_publish_fetch_rehash_bind_is_the_full_happy_path(self):
        store = pub.InMemoryCAS()
        artifact = self._artifact()
        published_root = pub.publish_and_read_back(artifact, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                                    store=store)
        descriptor = self._descriptor(patch_artifact_hash=published_root)
        fetched = pub.fetch_json(descriptor.patch_artifact_hash,
                                 hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
        document = rig.check_transition_artifact_binds_descriptor(fetched, descriptor=descriptor)
        assert document["transition"]["new_release_root"] == self.TRANSITION["new_release_root"]


class TestDescriptorV3GoldenVector:
    def test_the_committed_vector_rederives_every_cross_surface_pin(self):
        from pathlib import Path

        vector = json.loads((Path(__file__).parent / "fixtures" /
                             "rig-descriptor-v3-vector.json").read_text(encoding="utf-8"))
        descriptor = vector["descriptor"]
        raw = bytes.fromhex(descriptor["canonical_hex"])
        assert len(raw) == descriptor["bytes"] == binding.TRANSITION_DESCRIPTOR_BYTES
        assert raw[0] == descriptor["version"] == binding.TRANSITION_DESCRIPTOR_VERSION
        assert raw[1:33].hex() == descriptor["patch_artifact_hash"]
        assert raw[33:65].hex() == descriptor["parent_state_root"]
        assert raw[65:97].hex() == descriptor["new_state_root"]
        assert keccak256_hex(descriptor["hash_label"].encode() + raw) == descriptor["patch_hash"]
        decoded = rig.decode_transition_descriptor(
            raw, parent_state_root=descriptor["parent_state_root"],
            new_state_root=descriptor["new_state_root"],
            expected_patch_hash=descriptor["patch_hash"],
            transition_format_version=descriptor["version"])
        assert decoded.patch_artifact_hash == descriptor["patch_artifact_hash"]

        receipt = vector["receipt"]
        assert receipt["signed_members"] == len(binding.CORETEX_RECEIPT_TYPES[
            binding.CORETEX_RECEIPT_PRIMARY_TYPE])
        assert receipt["tuple_members"] == len(binding.CORETEX_RECEIPT_TUPLE_COMPONENTS)
        assert receipt["typehash"] == binding.CORETEX_RECEIPT_TYPEHASH
        assert receipt["submit_selector"] == binding.SUBMIT_CORETEX_RECEIPT_SELECTOR
        registry = vector["registry"]
        assert registry["submit_state_advance_selector"] == binding.SUBMIT_STATE_ADVANCE_SELECTOR
        assert registry["epoch_context_root_selector"] == next(
            item["selector"] for item in binding.CORETEX_REGISTRY_READS
            if item["signature"] == "epochContextRoot(uint64)")
        assert registry["state_advanced_topic0"][2:] == rig.STATE_ADVANCED_TOPIC0
        assert registry["epoch_finalized_topic0"][2:] == rig.EPOCH_FINALIZED_TOPIC0
        assert registry["epoch_context_set_topic0"][2:] == rig.EPOCH_CONTEXT_SET_TOPIC0


class TestRigReceiptTypehashV3:
    """The typehash pin — the context pair collapsed, RE-DERIVED and cross-checked, never transcribed
    once and trusted."""

    def test_the_typehash_is_rederived_from_the_member_list_and_matches_the_pin(self):
        derived = keccak256_hex(binding.CORETEX_RECEIPT_TYPEHASH_STRING.encode("utf-8"))
        assert "0x" + derived == binding.CORETEX_RECEIPT_TYPEHASH
        assert binding.CORETEX_RECEIPT_TYPEHASH == (
            "0xd21a4141318ac86ffd63faa82975263001e87a21ce5db2db3230837a90d2dab3")

    def test_the_typehash_differs_from_the_retired_one_and_the_retired_one_is_kept_nameable(self):
        assert binding.CORETEX_RECEIPT_TYPEHASH != binding.RETIRED_CORETEX_RECEIPT_TYPEHASH
        assert binding.RETIRED_CORETEX_RECEIPT_TYPEHASH == (
            "0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf")

    def test_member_19_is_transitionFormatVersion_and_member_9_is_epoch_context(self):
        assert binding.CORETEX_RECEIPT_TUPLE_COMPONENTS[9] == {
            "name": "epochContextRoot", "type": "bytes32"}
        assert binding.CORETEX_RECEIPT_TUPLE_COMPONENTS[19] == {
            "name": "transitionFormatVersion", "type": "uint16"}
        assert "stateWordCount" not in binding.CORETEX_RECEIPT_TYPEHASH_STRING
        assert "transitionFormatVersion" in binding.CORETEX_RECEIPT_TYPEHASH_STRING

    def test_the_selector_moves_when_the_tuple_loses_a_word(self):
        assert binding.SUBMIT_CORETEX_RECEIPT_SELECTOR == "0xed5daa91"
def _load_generated_binding():
    """Import ``generated_rig_receipt_binding.py`` from the coordinator tree, by absolute path."""
    import importlib.util

    path = _resolve_cross_tree(GENERATED_BINDING_RELATIVE, "CORETEX_GENERATED_RIG_BINDING")
    if path is None:
        return None
    spec = importlib.util.spec_from_file_location("_generated_rig_receipt_binding", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: Constants that are legitimately DIFFERENT between the two files, each with its reason. Anything
#: not listed here and present in both modules must be equal.
_PARITY_EXEMPT = {
    # The generated file's bundle hash moves with independent coordinator regeneration; this
    # package has no bundle.json to state a hash for. ABI/source provenance itself is compared.
    "BUNDLE_SHA256",
    # The client deliberately records the SUPERSEDED rehearsal pair (cross-referenced with
    # rehearsal_deployment.SUPERSEDED_DEPLOYMENTS); the generated file records the LIVE one plus a
    # "superseded" list. Two different true statements, not a drift.
    "EIP712_REHEARSAL_OBSERVED",
    # The client carries extra prose keys (burned/unassigned version renderings, empty-patch note).
    # The load-bearing keys are compared field by field below.
    "TRANSITION_DESCRIPTOR_LAYOUT",
}


class TestGeneratedBindingParity:
    """M-11. A hand-transcribed binding with no comparison test is a second source of truth by
    definition.

    ``rig_receipt_binding.py`` is a HAND TRANSCRIPTION of a file that is machine-generated on the
    coordinator side (``v5/e2e/generated_rig_receipt_binding.py``). The review diffed the two
    programmatically and found five divergences that no test in either repo could see — a string
    ``"0x20"`` where the generated file has the int ``32`` (so ``descriptor_bytes[0] == …`` is
    silently False forever), two absent constants the client kept private copies of, two names that
    do not exist in the generated file at all, and one shared NAME holding two unrelated VALUES.

    So the comparison exists now, and it is exhaustive rather than a list of the five: every shared
    module-level constant, with an explicit exemption table for the ones that are legitimately
    different. It SKIPS only when the generated file is genuinely not on this host.
    """

    @staticmethod
    def generated():
        """Not a fixture: a plain call, so the skip reason is attached to the test that needs it
        and no fixture caching sits between the file on disk and the comparison."""
        module = _load_generated_binding()
        if module is None:
            pytest.skip(
                "the coordinator's generated_rig_receipt_binding.py is not on this host (looked "
                f"under {_COORDINATOR_ROOTS} for {GENERATED_BINDING_RELATIVE}; set "
                "CORETEX_GENERATED_RIG_BINDING to point at it)")
        if getattr(module, "CORETEX_RECEIPT_TYPEHASH", None) != binding.CORETEX_RECEIPT_TYPEHASH:
            pytest.skip("the coordinator generated binding is still descriptor-v2; v3 parity "
                        "resumes once the interrupted coordinator migration regenerates it")
        return module

    def test_every_shared_module_level_constant_is_identical(self):
        generated = self.generated()
        shared = sorted(
            name for name in vars(generated)
            if name.isupper() and not name.startswith("_") and name not in _PARITY_EXEMPT
            and hasattr(binding, name))
        # A parity test that compared nothing would pass; assert it has real work to do.
        assert len(shared) >= 15, f"only {len(shared)} shared constants found: {shared}"
        mismatched = {name: (getattr(binding, name), getattr(generated, name))
                      for name in shared
                      if getattr(binding, name) != getattr(generated, name)}
        assert mismatched == {}, (
            "the client's hand-transcribed binding has drifted from the generated one: "
            f"{sorted(mismatched)}")

    def test_the_names_the_generated_file_declares_all_exist_here(self):
        """A name-keyed importer that works against one file and not the other is the divergence.

        ``COMPACT_PATCH_SUPERSEDED_LABEL`` was exactly that: the generated
        ``TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL`` under a different name (M-11.4).
        """
        generated = self.generated()
        missing = sorted(
            name for name in vars(generated)
            if name.isupper() and not name.startswith("_") and name not in _PARITY_EXEMPT
            and not hasattr(binding, name))
        assert missing == [], f"the generated binding declares names this file does not: {missing}"

    def test_the_retired_names_are_gone_and_the_live_ones_say_what_they_are(self):
        """M-11.3/M-11.4/M-11.5, pinned by name so a revert is loud."""
        for gone in ("COMPACT_PATCH_HASH_DOMAIN_LABEL", "COMPACT_PATCH_HASH_RULE",
                     "COMPACT_PATCH_SUPERSEDED_LABEL", "BUNDLE_SHA256"):
            assert not hasattr(binding, gone), f"{gone} names the wrong thing; it was renamed"
        assert binding.RETIRED_COMPACT_PATCH_HASH_DOMAIN_LABEL == "coretex-patch-hash-v1"
        assert "RETIRED" in binding.RETIRED_COMPACT_PATCH_HASH_RULE
        assert binding.COMPATIBILITY_LOCK_ROOT == (
            "307df364b165023b20ec1ea9ac699b8b39a5f340040be9a418b1a7d1d50b2c5a")
        assert binding.EIP712_REHEARSAL_OBSERVED["status"] == "SUPERSEDED"
        assert binding.EIP712_REHEARSAL_OBSERVED["superseded_on"] == "2026-08-04"

    def test_the_superseded_rehearsal_domain_agrees_with_the_deployment_module(self):
        """One module saying "observed" and another saying "dead" about one address is how an
        operator ends up signing against a domain separator no contract has."""
        from coretex_validator import rehearsal_deployment as rd

        dead = {entry["mining"] for entry in rd.SUPERSEDED_DEPLOYMENTS.values()}
        assert binding.EIP712_REHEARSAL_OBSERVED["verifying_contract"].lower() in dead

    # ── M-1: the 97 / 0x21 transcriptions, compared against the authority ─────────────────────
    def test_the_descriptor_length_and_version_equal_the_generated_values(self):
        generated = self.generated()
        assert binding.TRANSITION_DESCRIPTOR_BYTES == generated.TRANSITION_DESCRIPTOR_BYTES == 97
        assert binding.TRANSITION_DESCRIPTOR_VERSION == generated.TRANSITION_DESCRIPTOR_VERSION \
            == 33

    def test_the_layouts_load_bearing_fields_are_identical(self):
        generated = self.generated()
        mine, theirs = binding.TRANSITION_DESCRIPTOR_LAYOUT, generated.TRANSITION_DESCRIPTOR_LAYOUT
        assert mine["total_bytes"] == theirs["total_bytes"] == 97
        assert mine["version"] == theirs["version"] == 33
        assert isinstance(mine["version"], int) and not isinstance(mine["version"], bool)
        pick = lambda fields: [(f["offset"], f["size"], f["field"]) for f in fields]   # noqa: E731
        assert pick(mine["fields"]) == pick(theirs["fields"])
        assert sum(f["size"] for f in mine["fields"]) == 97

    def test_the_layout_version_is_comparable_to_a_descriptor_byte(self):
        """The whole point of M-11.1. Against the string ``"0x21"`` this is False for every input,
        which is a check that is not there rather than a check that fails."""
        descriptor = rig.encode_transition_descriptor(
            patch_artifact_hash="7e" * 32, parent_state_root="aa" * 32,
            new_state_root="bb" * 32)
        assert descriptor[0] == binding.TRANSITION_DESCRIPTOR_LAYOUT["version"]

    def test_rig_events_uses_the_bindings_constants_rather_than_its_own_copies(self):
        """M-11.2. The module that DECODES and the module that DESCRIBES must be one value, not
        two agreeing transcriptions — only the binding module can be compared to the generator."""
        assert rig.TRANSITION_DESCRIPTOR_BYTES is binding.TRANSITION_DESCRIPTOR_BYTES
        assert rig.TRANSITION_DESCRIPTOR_VERSION is binding.TRANSITION_DESCRIPTOR_VERSION

    def test_the_typehash_string_and_selectors_match_byte_for_byte(self):
        generated = self.generated()
        assert binding.CORETEX_RECEIPT_TYPEHASH_STRING == generated.CORETEX_RECEIPT_TYPEHASH_STRING
        assert binding.CORETEX_RECEIPT_TYPEHASH == generated.CORETEX_RECEIPT_TYPEHASH
        assert binding.SUBMIT_CORETEX_RECEIPT_SELECTOR == \
            generated.SUBMIT_CORETEX_RECEIPT_SELECTOR
        assert binding.SUBMIT_STATE_ADVANCE_SELECTOR == generated.SUBMIT_STATE_ADVANCE_SELECTOR

    def test_all_26_tuple_components_and_24_signed_members_match(self):
        generated = self.generated()
        assert binding.CORETEX_RECEIPT_TUPLE_COMPONENTS == \
            generated.CORETEX_RECEIPT_TUPLE_COMPONENTS
        assert len(binding.CORETEX_RECEIPT_TUPLE_COMPONENTS) == 26
        primary = binding.CORETEX_RECEIPT_PRIMARY_TYPE
        assert binding.CORETEX_RECEIPT_TYPES[primary] == generated.CORETEX_RECEIPT_TYPES[primary]
        assert len(binding.CORETEX_RECEIPT_TYPES[primary]) == 24

    def test_the_domain_labels_match(self):
        generated = self.generated()
        for name in ("TRANSITION_DESCRIPTOR_HASH_DOMAIN_LABEL", "TRANSITION_DESCRIPTOR_HASH_RULE",
                     "TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL",
                     "TRANSITION_DESCRIPTOR_RETIRED_LABEL",
                     "TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL",
                     "TRANSITION_DESCRIPTOR_SPEC"):
            assert getattr(binding, name) == getattr(generated, name), name


class TestNoNullReachesCanonicalBytes:
    """F7, enforced: every report dict must survive canonicalisation.

    This bug class has now cost two multi-minute chain runs — the expensive work completed and
    then the RESULT failed to serialise, which is the worst possible place to discover it. The
    canonical grammar refuses `null` by design, so any `as_dict()` that defaults an absent value
    to None is a landmine that only goes off at the end.
    """

    def test_signature_result_with_nothing_recovered_is_canonicalisable(self):
        from coretex_validator import canonical as cn

        result = snap.SignatureResult(False, None, None, "no signature was supplied")
        cn.canonical_bytes(result.as_dict())          # must not raise

    def test_reproduction_result_without_a_published_payload_is_canonicalisable(self):
        from coretex_validator import canonical as cn

        result = snap.reproduce(minimal_payload(), None)
        cn.canonical_bytes(result.as_dict())

    def test_ARBITRARY_nested_nulls_cannot_kill_an_export(self):
        """The CLASS, not another instance.

        The previous two tests here pinned the two shapes that had already failed. That is how
        this bug reached its third occurrence: each fix addressed the instance in front of it
        while the class — "a report dict assembled across a dozen call sites carries a None
        somebody defaulted" — went untested. This throws nulls at every level of the structures
        an export is built from.
        """
        from coretex_validator import canonical as cn

        payload = minimal_payload()
        export = ex.build_export(
            snapshot_payload=payload, reproduction=snap.reproduce(payload, dict(payload)),
            release_document=release_document(),
            source_divergence={"a": None, "b": {"c": None, "d": 1}},
            deployment_verification={"contracts": {"registry": {"match": True, "err": None}}},
            receipt_chains={1: {"ok": True, "chain_next_index": None}},
            admission={"outcome": "PASS", "code": None, "stage": None,
                       "checks": ["a", None], "nested": {"deep": {"deeper": None}}},
            unverified=[{"step": "x", "reason": None}])
        cn.canonical_bytes(export.document)           # must not raise
        # And the surviving values are untouched — the sweep drops nulls, not content.
        assert export.document["verification"]["deterministic_admission"]["outcome"] == "PASS"
        assert "code" not in export.document["verification"]["deterministic_admission"]

    def test_a_full_export_is_canonicalisable(self):
        from coretex_validator import canonical as cn

        payload = minimal_payload()
        export = ex.build_export(
            snapshot_payload=payload, reproduction=snap.reproduce(payload, dict(payload)),
            release_document=release_document(), source_divergence={},
            deployment_verification={}, receipt_chains={}, admission={"outcome": "PASS"},
            unverified=[])
        cn.canonical_bytes(export.document)


class TestSchemaV1V2AndV3:
    """Historical readers stay immutable while descriptor-v3 has an explicit schema boundary."""

    def _payload(self, schema, identity_key):
        from coretex_validator import resolver_snapshot as rsn

        keys = (rsn.TOP_LEVEL_KEYS_V1 if identity_key == "resolver" else rsn.TOP_LEVEL_KEYS_V2)
        payload = {k: {} for k in keys}
        payload["schema"] = schema
        payload["classification"] = rsn.CLASSIFICATION_REHEARSAL
        return payload

    def test_both_schemas_are_supported(self):
        from coretex_validator import resolver_snapshot as rsn

        assert rsn.SUPPORTED_SCHEMAS == (rsn.SCHEMA_V1, rsn.SCHEMA_V2, rsn.SCHEMA_V3)
        rsn.check_shape(self._payload(rsn.SCHEMA_V1, "resolver"))
        rsn.check_shape(self._payload(rsn.SCHEMA_V2, "authority"))
        rsn.check_shape(self._payload(rsn.SCHEMA_V3, "authority"))

    def test_the_versions_differ_in_exactly_one_key(self):
        from coretex_validator import resolver_snapshot as rsn

        assert len(rsn.TOP_LEVEL_KEYS_V1) == len(rsn.TOP_LEVEL_KEYS_V2) == 23
        assert set(rsn.TOP_LEVEL_KEYS_V1) ^ set(rsn.TOP_LEVEL_KEYS_V2) == {"resolver", "authority"}
        assert rsn.TOP_LEVEL_KEYS_V3 == rsn.TOP_LEVEL_KEYS_V2

    def test_a_v2_payload_wearing_the_v1_id_is_refused_on_SHAPE(self):
        # The bump exists because the shape changed. A document that claims v1 but carries v2's
        # shape is exactly what a reused id would have produced, and it must not parse.
        from coretex_validator import resolver_snapshot as rsn

        with pytest.raises(rsn.ReproductionError) as excinfo:
            rsn.check_shape(self._payload(rsn.SCHEMA_V1, "authority"))
        assert excinfo.value.code == "SCHEMA_SHAPE_MISMATCH"

    def test_an_unknown_schema_is_refused_not_guessed(self):
        from coretex_validator import resolver_snapshot as rsn

        with pytest.raises(rsn.ReproductionError) as excinfo:
            rsn.schema_of({"schema": "coretex.rig-state.resolver-snapshot/v4"})
        assert excinfo.value.code == "SCHEMA_UNSUPPORTED"
        assert "Refusing to guess" in excinfo.value.message

    def test_v3_state_context_and_sealed_header_are_closed_to_canonical_contract_cells(self):
        from coretex_validator import resolver_snapshot as rsn

        root = lambda byte: "0x" + byte * 64
        state = rsn.build_state_v3(
            epoch=181,
            context={"configured": True, "epoch": 181,
                     "parent_state_root": root("1"), "core_version_hash": root("2"),
                     "epoch_context_root": root("3"), "hidden_seed_commit": root("4")},
            live_state_root=root("5"), transition_count=2, sealed=True, served=True,
            header={"patch_set_root": root("6"), "score_root": root("7")}, finalized_at=9)
        assert set(state["context"]) == rsn._V3_CONTEXT_KEYS  # noqa: SLF001
        assert set(state["header"]) == {"patch_set_root", "score_root"}
        for retired in ("corpus_root", "active_frontier_root", "baseline_manifest_hash",
                        "final_state_root", "core_version_hash", "epoch_context_root"):
            assert retired not in state["header"]
        with pytest.raises(rsn.ReproductionError) as excinfo:
            rsn.build_state_v3(
                epoch=181,
                context={**state["context"], "corpus_root": root("8")},
                live_state_root=root("5"), transition_count=2, sealed=False, served=True)
        assert excinfo.value.code == "V3_CONTEXT_SHAPE_MISMATCH"

    def test_v3_derivation_pins_the_new_receipt_descriptor_and_selector(self):
        from coretex_validator import resolver_schema_constants as constants

        layout = constants.DERIVATION_V3["receipt_layout"]
        assert layout["transition_descriptor_bytes"] == 97
        assert layout["transition_descriptor_version"] == 33
        assert layout["signed_members"] == 24
        assert layout["tuple_members"] == 26
        assert layout["submit_selector"] == "0xed5daa91"
        assert layout["typehash"] == (
            "0xd21a4141318ac86ffd63faa82975263001e87a21ce5db2db3230837a90d2dab3")
        fields = constants.DERIVATION_V3["join_recipe"]["fields"]
        assert "epochContextRoot" in fields
        assert not {"corpusRoot", "activeFrontierRoot"} & set(fields)

    def test_epoch_context_is_a_separately_rehashed_closed_document(self):
        manifest = {
            "format": rig.EPOCH_CONTEXT_FORMAT, "epoch": 181,
            "corpus_root": "11" * 32, "active_frontier_root": "22" * 32,
            "baseline_manifest_hash": "33" * 32, "benchmark_law_root": "44" * 32,
            "runtime_abi_root": "55" * 32, "counter_resource_law_root": "66" * 32,
            "selection_law_root": "77" * 32,
            "admission_thresholds_ppm": {"minimum": 1},
            "seed_commitment": {"scheme": "keccak256-hidden-seed/v1",
                                "binding_rule": "keccak256(secret)",
                                "commitment_source": "mining.epochCommit(epochId)"},
        }
        encoded = fr.canonical_bytes(manifest)
        root = fr.sha256_hex(encoded)
        assert rig.verify_epoch_context_bytes(encoded, expected_root=root) == manifest
        with pytest.raises(rig.EpochContextError) as excinfo:
            rig.verify_epoch_context_bytes(encoded, expected_root="88" * 32)
        assert excinfo.value.code == rig.EPOCH_CONTEXT_ADDRESS_MISMATCH
        with pytest.raises(rig.EpochContextError) as excinfo:
            rig.validate_epoch_context({**manifest, "corpus_root_copy": "11" * 32})
        assert excinfo.value.code == rig.EPOCH_CONTEXT_MALFORMED

    def test_the_identity_block_is_a_schema_constant_in_both_versions(self):
        from coretex_validator import resolver_snapshot as rsn

        # Neither `resolver` nor `authority` is chain-derived, so neither may be counted as
        # evidence about a deployment.
        assert "resolver" in rsn.SCHEMA_CONSTANT_KEYS
        assert "authority" in rsn.SCHEMA_CONSTANT_KEYS
        assert "resolver" not in rsn.CHAIN_DERIVED_KEYS
        assert "authority" not in rsn.CHAIN_DERIVED_KEYS

    def test_adopted_blocks_are_reported_so_they_cannot_pose_as_evidence(self):
        from coretex_validator import resolver_snapshot as rsn

        result = rsn.compare({"a": 1}, {"a": 1})
        result.adopted_blocks = ["authority"]
        report = result.as_dict()
        assert report["adopted_blocks"] == ["authority"]
        assert "match by construction" in report["note"]

    def test_epoch_180_is_v1_and_stays_v1(self):
        from coretex_validator import resolver_snapshot as rsn

        evidence = _resolve_cross_tree(E180_SNAPSHOT_RELATIVE, "CORETEX_E180_SNAPSHOT")
        if evidence is None:
            pytest.skip("the published epoch-180 snapshot is not on this host "
                        f"(looked under {_COORDINATOR_ROOTS}; set CORETEX_E180_SNAPSHOT)")
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        # Historical evidence. The reproduction of 7087b32d… remains a true statement about it,
        # and chasing the new schema on this data would be a category error.
        assert payload["schema"] == rsn.SCHEMA_V1
        assert "resolver" in payload and "authority" not in payload
        rsn.check_shape(payload)

    def test_epoch_180_is_LEGACY_ERA_and_the_divergence_from_live_constants_is_PINNED(self):
        """M-10. The published payload is reproducible ONLY at client ``a4a18bc`` / rig
        ``cdb91d21``, under the RETIRED word-diff rules.

        ``resolver_snapshot.py`` embeds today's ``resolver_schema_constants`` into the RECONSTRUCTED
        payload and ``compare()`` is whole-document byte equality, so re-running the reproduction
        with current code yields a loud ``identical=False`` on ``derivation`` — a FALSE divergence
        on legacy-era history, which is the same "slander a valid mine" class the descriptor
        migration exists to remove.

        The constants are deliberately NOT forked. What is pinned instead is the DIVERGENCE: this
        test asserts the legacy-era values the published bytes actually carry AND that today's
        constants differ, so a future constants rewrite that quietly makes the two agree (or that
        edits the published evidence into agreement) is caught as the era confusion it would be.
        NOTHING HERE WRITES TO THE SNAPSHOT.
        """
        from coretex_validator import resolver_schema_constants as rsc

        evidence = _resolve_cross_tree(E180_SNAPSHOT_RELATIVE, "CORETEX_E180_SNAPSHOT")
        if evidence is None:
            pytest.skip("the published epoch-180 snapshot is not on this host "
                        f"(looked under {_COORDINATOR_ROOTS}; set CORETEX_E180_SNAPSHOT)")
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        layout = payload["derivation"]["receipt_layout"]
        recipe = payload["derivation"]["join_recipe"]["fields"]
        assert rsc.DERIVATION_V1 == payload["derivation"]

        # ── the LEGACY era, as the published bytes state it ──
        assert layout["typehash"] == (
            "0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b")
        assert layout["source_commit"] == "cdb91d211e4620c6ecfd90b68d827d607033e1f1"
        assert layout["compact_patch_hash_rule"] == (
            "keccak256(utf8('coretex-patch-hash-v1') || compactPatchBytes)")
        assert "transition_descriptor_hash_rule" not in layout
        assert "stateWordCount" in recipe and "transitionFormatVersion" not in recipe
        # Every real epoch-180 advance signed a word COUNT, not a format version.
        for step in payload["transitions"]["lineage"]:
            assert step["receipt"]["stateWordCount"] >= 1

        # ── and today's constants, which are the OTHER era ──
        live = rsc.DERIVATION["receipt_layout"]
        assert live["typehash"] == (
            "0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf")
        assert live["source_commit"] == "ba4d5acfa7aa3042f39eb6e8e4d8e4007400090c"
        assert "transition_descriptor_hash_rule" in live
        assert "compact_patch_hash_rule" not in live
        assert "transitionFormatVersion" in rsc.DERIVATION["join_recipe"]["fields"]
        assert "stateWordCount" not in rsc.DERIVATION["join_recipe"]["fields"]

        # ── therefore: the reproduction is ERA-BOUND, and that is the statement, not a bug ──
        assert layout["typehash"] != live["typehash"]
        assert layout["source_commit"] != live["source_commit"]


# --------------------------------------------------------------------------- #
# M-5 — "refuse, do not degrade": a substituted or non-canonical patch artifact
#       is a FAIL, not a BACKLOG
# --------------------------------------------------------------------------- #
class TestPatchArtifactFailuresAreClassified:
    """One ``except pub.PublicationError`` collapsed three facts into "try again later".

    ``fetch_json`` -> ``read_back`` recomputes the root and re-serialises the parsed document, so
    it distinguishes "nothing is served here" from "the wrong bytes are served here" from "these
    bytes were never canonical". Reporting all three as BACKLOG made a publisher serving the wrong
    bytes at the committed address indistinguishable from a publisher that is temporarily down —
    the exact opposite of spec §5.4's "disagreeing with the descriptor's ``newStateRoot`` is a
    PUBLICLY PROVABLE refutation", and it left two DECLARED refusal codes unraised anywhere in the
    package.
    """

    PARENT = "a1" * 32
    NEW = "b2" * 32
    RELEASE = "cd" * 32
    DELTA = 4321

    def _patch_artifact(self):
        return {
            "format": rig.TRANSITION_ARTIFACT_FORMAT,
            "parent_state_root": self.PARENT,
            "new_state_root": self.NEW,
            "score_delta_ppm": self.DELTA,
            "transition": fr.make_transition(
                target_profile="conv.pref.v1", expected_prior_release_root="ab" * 32,
                new_release_root=self.RELEASE, resulting_composition_root="ef" * 32),
        }

    def _eval_artifact(self):
        return {"frontier": {"parent_frontier_root": self.PARENT, "new_frontier_root": self.NEW,
                             "composition_root": "ef" * 32, "benchmark_law_root": "12" * 32,
                             "runtime_abi_root": "13" * 32},
                "counter_resource_law_root": "14" * 32}

    def _selected(self, patch_root):
        descriptor = rig.encode_transition_descriptor(
            patch_artifact_hash=patch_root, parent_state_root=self.PARENT,
            new_state_root=self.NEW)
        advance = rig.StateAdvanced(
            epoch=9, transition_index=0, miner="0x" + "11" * 20,
            parent_state_root=self.PARENT, new_state_root=self.NEW,
            patch_hash=rig.transition_descriptor_hash(descriptor),
            eval_report_hash=fr.sha256_hex(fr.canonical_bytes(self._eval_artifact())),
            core_version_hash="ee" * 32, epoch_context_root="cc" * 32,
            improvement_credits=1, transition_format_version=0x21,
            compact_patch_bytes=descriptor, provenance=dp.LogProvenance())

        class _Selected:
            pass

        selected = _Selected()
        selected.advance = advance
        selected.receipt = {"scoreBeforePpm": 0, "scoreAfterPpm": self.DELTA,
                            "artifactHash": self.RELEASE}
        return selected

    def _run(self, store):
        from coretex_validator import pipeline

        patch_root = fr.sha256_hex(fr.canonical_bytes(self._patch_artifact()))
        return pipeline._admit(self._selected(patch_root), None, store,
                               allow_test_doubles=False)[1], patch_root

    class _Serving(pub.ContentStore):
        """A store that serves the eval artifact honestly and does something SPECIFIC for the
        patch artifact's address."""

        def __init__(self, objects, behaviour=None):
            self.objects = dict(objects)
            self.behaviour = behaviour

        def put(self, root, data):
            self.objects[root] = data

        def get(self, root):
            if root in self.objects:
                return self.objects[root]
            if self.behaviour is not None:
                return self.behaviour(root)
            raise pub.ObjectNotFoundError(f"no object published at {root}")

        def has(self, root):
            return root in self.objects

    def _base_objects(self):
        artifact = self._eval_artifact()
        return {fr.sha256_hex(fr.canonical_bytes(artifact)): fr.canonical_bytes(artifact)}

    def test_an_unavailable_artifact_is_the_ONLY_backlog(self):
        report, _ = self._run(self._Serving(self._base_objects()))
        assert report["outcome"] == "BACKLOG"
        assert report["code"] == rig.TRANSITION_ARTIFACT_UNAVAILABLE
        assert "may become available" in report["reason"]

    def test_a_SUBSTITUTED_artifact_is_a_FAIL_with_the_address_mismatch_code(self):
        other = fr.canonical_bytes({"format": "something.else/v1"})

        def serve_wrong_bytes(_root):
            return other

        report, _ = self._run(self._Serving(self._base_objects(), serve_wrong_bytes))
        assert report["outcome"] == "FAIL"
        assert report["code"] == rig.TRANSITION_ARTIFACT_ADDRESS_MISMATCH
        assert "SUBSTITUTED" in report["reason"]

    def test_a_NON_CANONICAL_serialisation_is_a_FAIL_with_its_own_code(self):
        # Decodes fine, re-serialises differently: key order is not canonical.
        def serve_non_canonical(_root):
            return b'{"b": 1, "a": 2}'

        report, _ = self._run(self._Serving(self._base_objects(), serve_non_canonical))
        assert report["outcome"] == "FAIL"
        assert report["code"] == rig.TRANSITION_ARTIFACT_NOT_CANONICAL

    def test_an_unclassified_publication_failure_REFUSES_rather_than_backlogs(self):
        def raise_availability(root):
            raise pub.AvailabilityError(f"availability manifest is unusable for {root}")

        report, _ = self._run(self._Serving(self._base_objects(), raise_availability))
        assert report["outcome"] == "FAIL"
        assert report["code"] == rig.TRANSITION_ARTIFACT_MALFORMED

    def test_the_two_declared_codes_are_now_actually_raised_somewhere(self):
        """They were declared in ``OFFCHAIN_TRANSITION_REFUSALS`` and raised nowhere."""
        assert rig.TRANSITION_ARTIFACT_ADDRESS_MISMATCH in rig.OFFCHAIN_TRANSITION_REFUSALS
        assert rig.TRANSITION_ARTIFACT_NOT_CANONICAL in rig.OFFCHAIN_TRANSITION_REFUSALS
        assert rig.TRANSITION_ARTIFACT_UNAVAILABLE in rig.OFFCHAIN_TRANSITION_REFUSALS


# --------------------------------------------------------------------------- #
# L-7 — the mutual-unparseability claim, pinned in the direction the comment overstated
# --------------------------------------------------------------------------- #
def test_the_legacy_word_decoder_REFUSES_a_v3_descriptor_it_never_misreads_one():
    """``rig_events.py``'s HISTORY note used to claim the legacy decoder "would not even refuse
    [a v2 descriptor] outright — it would misread [it] as a same-length compact patch". It would
    not. 97 is inside the retired 42..178 window so the LENGTH check passes, and then ``0x21`` is
    not a key of ``PATCH_TYPE_WORD_RANGES`` so ``PATCH_TYPE_UNKNOWN`` fires before any word is
    parsed. The patch-type check is LOAD-BEARING and must not be loosened.
    """
    descriptor = rig.encode_transition_descriptor(
        patch_artifact_hash="7e" * 32, parent_state_root="aa" * 32,
        new_state_root="bb" * 32)
    assert len(descriptor) == 97
    assert rig.COMPACT_PATCH_HEADER_BYTES <= len(descriptor) <= rig.COMPACT_PATCH_MAX_BYTES
    assert rig.TRANSITION_DESCRIPTOR_VERSION not in rig.PATCH_TYPE_WORD_RANGES
    with pytest.raises(rig.CompactPatchError) as excinfo:
        rig.decode_compact_patch(descriptor)
    assert excinfo.value.code == rig.PATCH_TYPE_UNKNOWN


def test_the_documented_patch_type_table_is_the_whole_key_set():
    """L-7: the spec's historical table omitted ``0x07``, which the decoder accepts."""
    documented = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF}
    assert set(rig.PATCH_TYPE_WORD_RANGES) == documented
    assert set(int(k, 16) for k in
               binding.RETIRED_COMPACT_PATCH_LAYOUT["patch_type_word_ranges"]) == documented
    spec = pathlib_read_spec()
    assert "| `0x07` |" in spec, "specs/patch_format.md must list 0x07"
    # The document may NAME the non-existent constant only to say it does not exist; what it must
    # never do again is cite it as the authority for the length window.
    assert "COMPACT_PATCH_MIN/MAX_BYTES" not in spec
    assert "There is no `COMPACT_PATCH_MIN_BYTES` constant" in spec
    for real in ("COMPACT_PATCH_HEADER_BYTES", "COMPACT_PATCH_MAX_BYTES"):
        assert real in spec and hasattr(rig, real)


def pathlib_read_spec():
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[2] / "specs" / "patch_format.md"
    if not path.is_file():
        pytest.skip("source-only retired patch-format prose is not shipped in the clean wheel")
    return path.read_text(encoding="utf-8")
