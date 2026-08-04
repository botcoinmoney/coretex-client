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
from coretex_validator import receipt_chain as rc
from coretex_validator import release as rel
from coretex_validator import rig_events as rig
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
    """The full validation set from RigCoreTexVerifier._validateCompactPatch.

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

    # ── POSITIVE FIXTURE: the real 75-byte epoch-180 patch ────────────────────────────────
    def test_the_real_epoch_180_patches_decode_to_documented_ground_truth(self):
        import pathlib

        evidence = pathlib.Path("/home/ubuntu/botcoin-coordinator-v5-p6/v5/resolver/evidence"
                                "/mainnet-rehearsal-e180-20260804/snapshot.json")
        if not evidence.is_file():
            pytest.skip("the published epoch-180 snapshot is not on this host")
        snapshot = json.loads(evidence.read_text(encoding="utf-8"))
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
        # Correct hash passes...
        rig.decode_compact_patch(raw, expected_patch_hash=rig.patch_hash(raw))
        # ...a wrong one is refused BEFORE any field complaint, because a patch whose bytes hash
        # elsewhere is a different patch, not a malformed one.
        assert self._refusal(raw, expected_patch_hash="00" * 32) == rig.PATCH_HASH_MISMATCH

    def test_a_superseded_label_signature_is_diagnosed_by_name(self):
        raw = self._patch()
        stale = rig.keccak256_hex(rig.SUPERSEDED_PATCH_HASH_LABEL + raw)
        with pytest.raises(rig.CompactPatchError) as excinfo:
            rig.decode_compact_patch(raw, expected_patch_hash=stale)
        assert excinfo.value.code == rig.PATCH_HASH_MISMATCH
        assert "superseded" in excinfo.value.message


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
    """The full validation set from RigCoreTexVerifier._validateCompactPatch.

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

    # ── POSITIVE FIXTURE: the real 75-byte epoch-180 patch ────────────────────────────────
    def test_the_real_epoch_180_patches_decode_to_documented_ground_truth(self):
        import pathlib

        evidence = pathlib.Path("/home/ubuntu/botcoin-coordinator-v5-p6/v5/resolver/evidence"
                                "/mainnet-rehearsal-e180-20260804/snapshot.json")
        if not evidence.is_file():
            pytest.skip("the published epoch-180 snapshot is not on this host")
        snapshot = json.loads(evidence.read_text(encoding="utf-8"))
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
        # Correct hash passes...
        rig.decode_compact_patch(raw, expected_patch_hash=rig.patch_hash(raw))
        # ...a wrong one is refused BEFORE any field complaint, because a patch whose bytes hash
        # elsewhere is a different patch, not a malformed one.
        assert self._refusal(raw, expected_patch_hash="00" * 32) == rig.PATCH_HASH_MISMATCH

    def test_a_superseded_label_signature_is_diagnosed_by_name(self):
        raw = self._patch()
        stale = rig.keccak256_hex(rig.SUPERSEDED_PATCH_HASH_LABEL + raw)
        with pytest.raises(rig.CompactPatchError) as excinfo:
            rig.decode_compact_patch(raw, expected_patch_hash=stale)
        assert excinfo.value.code == rig.PATCH_HASH_MISMATCH
        assert "superseded" in excinfo.value.message


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

    def test_a_full_export_with_no_signature_checked_is_canonicalisable(self):
        from coretex_validator import canonical as cn

        payload = minimal_payload()
        export = ex.build_export(
            snapshot_payload=payload, reproduction=snap.reproduce(payload, dict(payload)),
            signature=snap.SignatureResult(False, None, None, "none checked"),
            release_document=release_document(), source_divergence={},
            deployment_verification={}, receipt_chains={}, admission={"outcome": "PASS"},
            unverified=[])
        cn.canonical_bytes(export.document)
