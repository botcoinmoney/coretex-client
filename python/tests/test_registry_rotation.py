# SPDX-License-Identifier: Apache-2.0
"""STEP F — registry-ROTATION continuity, enforced by refusal in the validator.

WHAT THIS SUITE IS GUARDING AGAINST, AND IT IS NOT ONLY "does the guard fire".

The failure mode that matters is a suite that passes because the rotation it describes is one
NOBODY COULD EVER PERFORM. Six negatives all refusing proves nothing on its own — a gate that
refuses everything refuses those six too. So every negative below is ONE MUTATION away from
:func:`legitimate_rotation`, which is asserted ACCEPTED first. If the accept ever breaks, every
negative becomes vacuous, and ``test_positive_legitimate_rotation_is_accepted`` fails loudly rather
than the suite staying green.

The other half is ``test_limitation_*``: the documented limitation must EXIST, NAME
``MINING_POLICY_ADMIN``, and be carried in every refusal and in the operator documents. That is a
test about honesty rather than behaviour — the whole point of this step is that continuity is a
CONVENTION, and a convention presented as a chain guarantee is worse than no convention.
"""
from __future__ import annotations

import dataclasses
import pathlib
from typing import Any, Dict, Optional

import pytest

from coretex_validator import release as rel
from coretex_validator import rotation as rot

INCUMBENT = "0x1000000000000000000000000000000000000007"
SUCCESSOR = "0x1000000000000000000000000000000000000017"
VERIFIER = "0x1000000000000000000000000000000000000006"
MINING = "0x1000000000000000000000000000000000000001"
CLOCK = MINING
SEALED_HEAD = "aa" * 32
REGISTRY_CODE_HASH = "bb" * 32
REGISTRY_CODE = b"\x60\x80registry-runtime"

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def legitimate_rotation(**overrides: Any) -> rot.RotationObservation:
    """A rotation an operator could ACTUALLY perform — the §6.3 ceremony, exactly.

    The incumbent served through epoch 163 and was RETIRED there (``CONFIG_ADMIN``), the handover
    epoch was FINALIZED, the successor was deployed with ``minAcceptedEpoch = 164`` and
    ``genesisStateRoot`` == the head 163 sealed (so its M-11 constructor passed), it was bound to
    the SAME verifier and epoch clock, it carries the audited bytecode, and ``setCoreTexRegistry``
    (``MINING_POLICY_ADMIN``) landed in a block whose preceding state had all three of the
    verifier's lock terms at zero.
    """
    incumbent = rot.IncumbentFacts(
        address=INCUMBENT, retired=True, service_ceiling_epoch=163, has_any_transition=True,
        handover_epoch_finalized=True, sealed_head=SEALED_HEAD, core_tex_verifier=VERIFIER,
        epoch_clock=CLOCK)
    successor = rot.SuccessorFacts(
        address=SUCCESSOR, predecessor_registry=INCUMBENT, min_accepted_epoch=164,
        genesis_state_root=SEALED_HEAD, code_hash=REGISTRY_CODE_HASH, core_tex_verifier=VERIFIER,
        epoch_clock=CLOCK)
    epoch = rot.RotationEpochFacts(rotation_block=900_000, epoch=164, total_credits=0,
                                   screener_passes=0, incumbent_transition_count=0)
    if "incumbent" in overrides:
        incumbent = dataclasses.replace(incumbent, **overrides.pop("incumbent"))
    if "successor" in overrides:
        successor = dataclasses.replace(successor, **overrides.pop("successor"))
    if "epoch" in overrides:
        epoch = dataclasses.replace(epoch, **overrides.pop("epoch"))
    base: Dict[str, Any] = {
        "approved_registry_code_hash": REGISTRY_CODE_HASH,
        "approved_release_path": "/artifacts/rig/release.json",
        "observation_block": 900_010,
    }
    base.update(overrides)
    return rot.RotationObservation(incumbent=incumbent, successor=successor, epoch=epoch, **base)


def refuses_with(observation: rot.RotationObservation, code: str) -> rot.RotationRefusal:
    """The one assertion shape every negative uses: exactly this code, and nothing else fired."""
    verdict = rot.evaluate_rotation_continuity(observation)
    assert not verdict.accepted, (
        f"expected a refusal, got an ACCEPT — the mutation for {code} is not being detected")
    assert verdict.codes == [code], (
        f"expected exactly [{code}], got {verdict.codes} — a negative that trips more than its own "
        "guard cannot mutation-kill that guard")
    return verdict.refusals[0]


# ── THE POSITIVE CASE FIRST. Everything below it is meaningless without it. ───────────────── #


def test_positive_legitimate_rotation_is_accepted() -> None:
    verdict = rot.evaluate_rotation_continuity(legitimate_rotation())
    assert verdict.accepted, (
        "the six conditions are supposed to be satisfiable by the documented ceremony; if this "
        "fails, every negative in this file is passing for the wrong reason")
    assert verdict.codes == []
    assert len(verdict.checks) == 6, "all six conditions report as PASSED, individually"
    report = rot.format_rotation_verdict(legitimate_rotation(), verdict)
    assert "ACCEPTED" in report
    # The accept is when the limitation matters MOST, so it travels with it.
    assert "MINING_POLICY_ADMIN" in report


def test_positive_degenerate_never_mined_predecessor_is_accepted() -> None:
    # RigCoreTexStateRegistry.sol:508-519 — a predecessor retired without ever mining hands across
    # its OWN GENESIS_STATE_ROOT, and there is no finalized handover epoch to read.
    verdict = rot.evaluate_rotation_continuity(legitimate_rotation(
        incumbent={"has_any_transition": False, "handover_epoch_finalized": False}))
    assert verdict.accepted
    assert "never mined" in "\n".join(verdict.checks)


# ── 1. PREDECESSOR ───────────────────────────────────────────────────────────────────────── #


def test_1_refuses_successor_of_a_different_lineage() -> None:
    other = "0x00000000000000000000000000000000000000ff"
    refusal = refuses_with(legitimate_rotation(successor={"predecessor_registry": other}),
                           rot.ROTATION_PREDECESSOR_NOT_INCUMBENT)
    assert refusal.expected == INCUMBENT
    assert refusal.observed == other
    # The distinction the ruling demanded, stated in the refusal itself.
    assert "constructor already PROVED" in refusal.reason
    assert "somebody else's lineage" in refusal.reason


def test_1_refuses_a_genesis_claim_on_a_lane_that_has_history() -> None:
    refusal = refuses_with(
        legitimate_rotation(successor={"predecessor_registry": rot.ZERO_ADDRESS}),
        rot.ROTATION_PREDECESSOR_NOT_INCUMBENT)
    assert "GENESIS deployment" in refusal.reason
    assert "refutes" in refusal.reason


# ── 2. CONTIGUITY ────────────────────────────────────────────────────────────────────────── #


def test_2_refuses_a_gap_above_the_sealed_ceiling() -> None:
    refusal = refuses_with(legitimate_rotation(successor={"min_accepted_epoch": 166}),
                           rot.ROTATION_EPOCH_FLOOR_NOT_CONTIGUOUS)
    assert refusal.expected == "164"
    assert refusal.observed == "166"
    assert "served by NEITHER registry" in refusal.reason


def test_2_refuses_an_overlap_with_the_sealed_window() -> None:
    refusal = refuses_with(legitimate_rotation(successor={"min_accepted_epoch": 162}),
                           rot.ROTATION_EPOCH_FLOOR_NOT_CONTIGUOUS)
    assert "claimed by BOTH registries" in refusal.reason


# ── 3. GENESIS == THE SEALED HEAD ────────────────────────────────────────────────────────── #


def test_3_refuses_a_genesis_root_that_is_not_the_sealed_head() -> None:
    wrong = "cc" * 32
    refusal = refuses_with(legitimate_rotation(successor={"genesis_state_root": wrong}),
                           rot.ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD)
    assert refusal.expected == SEALED_HEAD
    assert refusal.observed == wrong
    assert "fork the state lineage" in refusal.reason


def test_3_refuses_an_incumbent_that_was_never_retired() -> None:
    refusal = refuses_with(legitimate_rotation(incumbent={"retired": False}),
                           rot.ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD)
    assert refusal.checked == "incumbent.retired()"
    # The two-key point: retireAtEpoch is CONFIG_ADMIN, setCoreTexRegistry is MINING_POLICY_ADMIN.
    assert "CONFIG_ADMIN" in refusal.reason
    assert "single-signature" in refusal.reason


def test_3_refuses_a_handover_epoch_that_was_mined_but_never_finalized() -> None:
    refusal = refuses_with(legitimate_rotation(incumbent={"handover_epoch_finalized": False}),
                           rot.ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD)
    assert refusal.checked == "incumbent.epochFinalized(163)"
    assert "a head that can move" in refusal.reason


# ── 4. APPROVED BYTECODE ─────────────────────────────────────────────────────────────────── #


def test_4_refuses_bytecode_that_is_not_the_approved_pin() -> None:
    deployed = "dd" * 32
    refusal = refuses_with(legitimate_rotation(successor={"code_hash": deployed}),
                           rot.ROTATION_BYTECODE_NOT_APPROVED)
    assert refusal.expected == REGISTRY_CODE_HASH
    assert refusal.observed == deployed
    # The reason must say WHY the other five cannot catch this one.
    assert "passes checks 1-3 and is caught only here" in refusal.reason


def test_4_an_unpinned_registry_is_a_refusal_never_a_pass() -> None:
    refusal = refuses_with(legitimate_rotation(approved_registry_code_hash=None),
                           rot.ROTATION_BYTECODE_NOT_APPROVED)
    assert refusal.observed == "NOT PINNED"
    assert "never as a pass" in refusal.reason


# ── 5. SAME VERIFIER, SAME CLOCK ─────────────────────────────────────────────────────────── #


def test_5_refuses_a_successor_bound_to_a_different_verifier() -> None:
    refusal = refuses_with(
        legitimate_rotation(successor={"core_tex_verifier": "0x" + "aa" * 20}),
        rot.ROTATION_VERIFIER_OR_CLOCK_REBOUND)
    assert refusal.checked == "successor.coreTexVerifier()"
    assert "OnlyCoreTexVerifier" in refusal.reason


def test_5_refuses_a_successor_bound_to_a_different_epoch_clock() -> None:
    refusal = refuses_with(
        legitimate_rotation(successor={"epoch_clock": "0x" + "bb" * 20}),
        rot.ROTATION_VERIFIER_OR_CLOCK_REBOUND)
    assert refusal.checked == "successor.epochClock()"
    assert "quieter and worse" in refusal.reason


# ── 6. UNLOCKED EPOCH BOUNDARY ───────────────────────────────────────────────────────────── #


def test_6_refuses_a_rotation_under_live_mining_credits() -> None:
    refusal = refuses_with(legitimate_rotation(epoch={"total_credits": 4200}),
                           rot.ROTATION_EPOCH_LOCKED)
    assert "mining.totalCredits(164) == 4200" in refusal.observed
    assert "ActiveEpochHasCredits" in refusal.reason


def test_6_refuses_a_rotation_under_live_screener_passes() -> None:
    refusal = refuses_with(legitimate_rotation(epoch={"screener_passes": 3}),
                           rot.ROTATION_EPOCH_LOCKED)
    assert "qualifiedScreenerPassesSinceLastStateAdvance" in refusal.observed


def test_6_refuses_a_rotation_under_recorded_registry_transitions() -> None:
    refusal = refuses_with(legitimate_rotation(epoch={"incumbent_transition_count": 1}),
                           rot.ROTATION_EPOCH_LOCKED)
    assert "incumbent.transitionCount(164) == 1" in refusal.observed


# ── COLLECT-ALL AND THE CODE INVENTORY ───────────────────────────────────────────────────── #


def test_every_refusal_is_collected_not_fail_fast() -> None:
    verdict = rot.evaluate_rotation_continuity(legitimate_rotation(
        successor={"predecessor_registry": "0x" + "ff" * 20, "min_accepted_epoch": 999,
                   "genesis_state_root": "00" * 32, "code_hash": "ee" * 32,
                   "core_tex_verifier": "0x" + "aa" * 20},
        epoch={"total_credits": 1}))
    assert not verdict.accepted
    assert sorted(verdict.codes) == sorted(rot.ROTATION_CODES), (
        "an operator repairing a mis-staged rotation must see the whole list once")
    assert verdict.checks == []


def test_six_conditions_have_six_distinct_codes() -> None:
    assert len(set(rot.ROTATION_CODES)) == 6


def test_assert_rotation_continuity_raises_typed_and_returns_on_accept() -> None:
    with pytest.raises(rot.RotationError) as excinfo:
        rot.assert_rotation_continuity(legitimate_rotation(epoch={"total_credits": 9}))
    assert excinfo.value.code == rot.ROTATION_EPOCH_LOCKED
    assert "MINING_POLICY_ADMIN" in excinfo.value.message
    assert rot.assert_rotation_continuity(legitimate_rotation()).accepted


# ── THE LIMITATION. This is the test the whole step exists for. ──────────────────────────── #


def test_limitation_is_documented_and_names_the_role() -> None:
    limitation = rot.ROTATION_CONVENTION_LIMITATION
    assert limitation["role"] == "MINING_POLICY_ADMIN"
    assert limitation["status"] == "CONVENTION_NOT_CHAIN_ENFORCED"
    assert "setCoreTexRegistry" in limitation["entry_point"]
    assert "FROZEN" in limitation["not_enforced_by"]
    # The three claims the ruling required, each stated and each falsifiable by reading it:
    assert "CONVENTION, NOT A CHAIN GUARANTEE" in limitation["statement"]
    assert "MINING_POLICY_ADMIN retains the theoretical ability" in limitation["statement"]
    assert "separately audited change to RigCoreTexVerifier" in limitation["statement"]
    assert "separately audited" in limitation["would_require_to_close"]
    assert "CONVENTION" in rot.ROTATION_LIMITATION_LINE
    assert "MINING_POLICY_ADMIN" in rot.ROTATION_LIMITATION_LINE


def test_limitation_travels_with_every_refusal_and_with_the_accept() -> None:
    for mutation in (
        {"successor": {"predecessor_registry": "0x" + "ff" * 20}},
        {"successor": {"min_accepted_epoch": 999}},
        {"incumbent": {"retired": False}},
        {"approved_registry_code_hash": None},
        {"successor": {"epoch_clock": "0x" + "bb" * 20}},
        {"epoch": {"screener_passes": 1}},
    ):
        verdict = rot.evaluate_rotation_continuity(legitimate_rotation(**mutation))
        assert not verdict.accepted
        for refusal in verdict.refusals:
            assert "CONVENTION" in refusal.reason, (
                f"{refusal.code} does not tell the reader this is a convention, not a chain rule")
            assert "MINING_POLICY_ADMIN" in refusal.reason
    # And the ACCEPT carries it too — that is when it is most likely to be misread.
    accepted = rot.evaluate_rotation_continuity(legitimate_rotation()).as_dict()
    assert accepted["limitation"]["role"] == "MINING_POLICY_ADMIN"


def test_limitation_is_recorded_where_an_operator_reads() -> None:
    """Not only in the source. A limitation that lives in a comment is buried, not recorded."""
    for relative, patterns in {
        "python/coretex_validator/rotation.py": (
            "CONVENTION", "MINING_POLICY_ADMIN", "separately audited"),
        "docs/V5-RIG-VALIDATOR.md": (
            "MINING_POLICY_ADMIN", "separately audited", "convention"),
        "README.md": ("MINING_POLICY_ADMIN", "convention"),
    }.items():
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        for pattern in patterns:
            assert pattern.lower() in text.lower(), f"{relative} does not record: {pattern}"


# ── READING THE FACTS OFF CHAIN ──────────────────────────────────────────────────────────── #


class StubRpc:
    """A literal-answering RPC. The BLOCK is part of the key, deliberately.

    The whole point of condition 6 is that the lock terms are read at ``rotation_block - 1`` while
    the lineage facts are read at the observation block. A stub that ignored the block could not
    tell a correct reader from one that reads everything at ``"latest"``.
    """

    def __init__(self, answers: Dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list = []

    def eth_call(self, *, to: str, data: str, block: int) -> bytes:
        signature = self.answers["__selectors__"][data[:10]]
        arg = int(data[10:], 16) if len(data) > 10 else None
        key = f"{to.lower()}|{signature}|{arg}|{block}"
        self.calls.append(key)
        if key not in self.answers:
            raise KeyError(f"unstubbed read {key}")
        value = self.answers[key]
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, int):
            return value.to_bytes(32, "big")
        if isinstance(value, str) and value.startswith("0x"):
            return bytes.fromhex(value[2:].rjust(64, "0"))
        return bytes.fromhex(str(value).rjust(64, "0"))

    def code(self, address: str, *, block: int) -> bytes:
        self.calls.append(f"{address.lower()}|code|{block}")
        return self.answers[f"{address.lower()}|code|{block}"]


AT = 900_010
PRE = 899_999
SIGNATURES = (
    "retired()", "serviceCeilingEpoch()", "hasAnyTransition()", "coreTexVerifier()",
    "epochClock()", "GENESIS_STATE_ROOT()", "epochFinalized(uint64)", "liveStateRoot(uint64)",
    "PREDECESSOR_REGISTRY()", "MIN_ACCEPTED_EPOCH()", "currentEpoch()", "totalCredits(uint64)",
    "currentDifficultyCount(uint64)", "transitionCount(uint64)",
)


def chain_answers(**overrides: Any) -> Dict[str, Any]:
    from coretex_validator.rpc import selector
    answers: Dict[str, Any] = {
        "__selectors__": {selector(sig): sig for sig in SIGNATURES},
        f"{INCUMBENT}|retired()|None|{AT}": True,
        f"{INCUMBENT}|serviceCeilingEpoch()|None|{AT}": 163,
        f"{INCUMBENT}|hasAnyTransition()|None|{AT}": True,
        f"{INCUMBENT}|coreTexVerifier()|None|{AT}": VERIFIER,
        f"{INCUMBENT}|epochClock()|None|{AT}": CLOCK,
        f"{INCUMBENT}|GENESIS_STATE_ROOT()|None|{AT}": "ff" * 32,
        f"{INCUMBENT}|epochFinalized(uint64)|163|{AT}": True,
        f"{INCUMBENT}|liveStateRoot(uint64)|163|{AT}": SEALED_HEAD,
        f"{SUCCESSOR}|PREDECESSOR_REGISTRY()|None|{AT}": INCUMBENT,
        f"{SUCCESSOR}|MIN_ACCEPTED_EPOCH()|None|{AT}": 164,
        f"{SUCCESSOR}|GENESIS_STATE_ROOT()|None|{AT}": SEALED_HEAD,
        f"{SUCCESSOR}|coreTexVerifier()|None|{AT}": VERIFIER,
        f"{SUCCESSOR}|epochClock()|None|{AT}": CLOCK,
        f"{SUCCESSOR}|code|{AT}": REGISTRY_CODE,
        f"{MINING}|currentEpoch()|None|{PRE}": 164,
        f"{MINING}|totalCredits(uint64)|164|{PRE}": 0,
        f"{VERIFIER}|currentDifficultyCount(uint64)|164|{PRE}": 0,
        f"{INCUMBENT}|transitionCount(uint64)|164|{PRE}": 0,
    }
    answers.update(overrides)
    return answers


def _read(rpc: StubRpc, **kwargs: Any) -> rot.RotationObservation:
    from coretex_validator.keccak256 import keccak256_hex
    defaults = dict(incumbent_registry=INCUMBENT, successor_registry=SUCCESSOR, mining=MINING,
                    verifier=VERIFIER, rotation_block=900_000, observation_block=AT,
                    approved_registry_code_hash=keccak256_hex(REGISTRY_CODE),
                    approved_release_path="/artifacts/rig/release.json")
    defaults.update(kwargs)
    return rot.read_rotation_observation(rpc, **defaults)


def test_reader_pins_lock_terms_to_the_rotation_block_and_lineage_to_the_observation_block() -> None:
    rpc = StubRpc(chain_answers())
    observation = _read(rpc)
    assert observation.incumbent.sealed_head == SEALED_HEAD
    assert observation.successor.min_accepted_epoch == 164
    assert observation.epoch.epoch == 164
    lock_reads = [c for c in rpc.calls
                  if any(t in c for t in ("totalCredits", "currentDifficultyCount",
                                          "transitionCount", "currentEpoch"))]
    assert len(lock_reads) >= 4
    for call in lock_reads:
        assert call.endswith(f"|{PRE}"), call
    assert rot.evaluate_rotation_continuity(observation).accepted


def test_reader_never_invents_a_sealed_head_for_an_unretired_incumbent() -> None:
    answers = chain_answers(**{f"{INCUMBENT}|retired()|None|{AT}": False})
    del answers[f"{INCUMBENT}|epochFinalized(uint64)|163|{AT}"]
    del answers[f"{INCUMBENT}|liveStateRoot(uint64)|163|{AT}"]
    observation = _read(StubRpc(answers))
    assert observation.incumbent.retired is False
    verdict = rot.evaluate_rotation_continuity(observation)
    assert verdict.codes == [rot.ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD]


def test_reader_refuses_a_rotation_block_with_no_predecessor_block() -> None:
    with pytest.raises(rot.RotationError):
        _read(StubRpc(chain_answers()), rotation_block=0)


# ── THE DECLARATION, AND verify_deployment ───────────────────────────────────────────────── #


def release_document(rotation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from coretex_validator.keccak256 import keccak256_hex
    document: Dict[str, Any] = {
        "format": rel.RELEASE_FORMAT,
        "classification": rel.CLASSIFICATION_REHEARSAL,
        "chain_id": 31337,
        "network": "anvil",
        "addresses": {"registry": SUCCESSOR, "mining": MINING, "verifier": VERIFIER},
        "runtime_code_hashes": {"registry": keccak256_hex(REGISTRY_CODE),
                                "mining": "11" * 32, "verifier": "22" * 32},
        "deploy_block": 1,
        "source": {"repo": "botcoinmoney/botcoin-mining-rigs", "commit": "a" * 40},
    }
    if rotation is not None:
        document["registry_rotation"] = rotation
    return document


def test_declaration_absent_means_no_rotation_claimed() -> None:
    assert rel.parse_release(release_document()).registry_rotation is None


def test_declaration_parses_when_well_formed() -> None:
    parsed = rel.parse_release(release_document(
        {"predecessor_registry": INCUMBENT, "rotation_block": 900_000})).registry_rotation
    assert parsed == rot.RotationDeclaration(predecessor_registry=INCUMBENT,
                                             rotation_block=900_000)


@pytest.mark.parametrize("bad", [
    {"rotation_block": 900_000},
    {"predecessor_registry": INCUMBENT},
    {"predecessor_registry": INCUMBENT, "rotation_block": 0},
    {"predecessor_registry": SUCCESSOR, "rotation_block": 9},
    "not-an-object",
])
def test_declaration_malformed_is_refused_not_ignored(bad: Any) -> None:
    with pytest.raises(rot.RotationError):
        rel.parse_release(release_document(bad))


def _verify(rotation: Optional[Dict[str, Any]], answers: Dict[str, Any]):
    release = rel.parse_release(release_document(rotation))
    answers = dict(answers)
    answers[f"{SUCCESSOR}|code|{AT}"] = REGISTRY_CODE
    answers[f"{MINING}|code|{AT}"] = b"mining"
    answers[f"{VERIFIER}|code|{AT}"] = b"verifier"
    # verify_deployment reads the three contracts' code and the wiring first; stub those too.
    from coretex_validator.rpc import selector
    answers["__selectors__"] = dict(answers["__selectors__"])
    for sig in ("coreTexRegistry()", "mining()"):
        answers["__selectors__"][selector(sig)] = sig
    answers[f"{SUCCESSOR}|coreTexVerifier()|None|{AT}"] = VERIFIER
    answers[f"{VERIFIER}|coreTexRegistry()|None|{AT}"] = SUCCESSOR
    answers[f"{VERIFIER}|mining()|None|{AT}"] = MINING
    release = dataclasses.replace(
        release, runtime_code_hashes=dict(release.runtime_code_hashes))
    from coretex_validator.keccak256 import keccak256_hex
    release.runtime_code_hashes["mining"] = keccak256_hex(b"mining")
    release.runtime_code_hashes["verifier"] = keccak256_hex(b"verifier")
    return rel.verify_deployment(release, StubRpc(answers), block=AT)


def test_verify_deployment_reports_not_checked_when_no_rotation_is_declared() -> None:
    result = _verify(None, chain_answers())
    assert result.wiring["rotation"]["checked"] is False
    assert "THIS IS NOT A PASS" in result.wiring["rotation"]["reason"]
    assert result.wiring["rotation"]["limitation"]["role"] == "MINING_POLICY_ADMIN"
    assert result.ok


def test_verify_deployment_accepts_a_continuous_declared_rotation() -> None:
    result = _verify({"predecessor_registry": INCUMBENT, "rotation_block": 900_000},
                     chain_answers())
    assert result.wiring["rotation"]["checked"] is True
    assert result.wiring["rotation"]["accepted"] is True
    assert "MINING_POLICY_ADMIN" in result.wiring["rotation"]["summary"]
    assert result.ok, result.failures


def test_verify_deployment_fails_on_a_declared_rotation_that_breaks_continuity() -> None:
    answers = chain_answers(
        **{f"{SUCCESSOR}|PREDECESSOR_REGISTRY()|None|{AT}": "0x" + "ff" * 20})
    result = _verify({"predecessor_registry": INCUMBENT, "rotation_block": 900_000}, answers)
    assert not result.ok
    assert any(rot.ROTATION_PREDECESSOR_NOT_INCUMBENT in f for f in result.failures)
    assert result.wiring["rotation"]["accepted"] is False


def test_verify_deployment_fails_when_a_declared_rotation_cannot_be_read() -> None:
    answers = chain_answers()
    del answers[f"{SUCCESSOR}|PREDECESSOR_REGISTRY()|None|{AT}"]
    result = _verify({"predecessor_registry": INCUMBENT, "rotation_block": 900_000}, answers)
    assert not result.ok
    assert any("could not be read from the chain" in f for f in result.failures)
    assert result.wiring["rotation"]["checked"] is False
