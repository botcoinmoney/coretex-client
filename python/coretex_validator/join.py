# SPDX-License-Identifier: Apache-2.0
"""Step 4: reconstruct the exact CoreTex transition — the §7 resolver join.

This is a direct implementation of ``RIG-CORETEX-REGISTRY-DESIGN.md`` §7.2, which is NORMATIVE.
Three sources, joined and cryptographically closed:

    A. registry ``CoreTexStateAdvanced`` — the transition and the verbatim patch
    B. mining ``RigCoreTexCreditAccepted`` — rigId, solveIndex, receiptHash, challengeId, work
    C. transaction calldata ``submitCoreTexReceipt(CoreTexReceipt)`` — the full 27-member struct,
       and the only place ``artifactHash``, ``workPolicyHash`` and the signature exist

THE JOIN KEY IS ``(epoch, parentStateRoot, patchHash)`` — ALL THREE (§7.4). ``(epoch,
parentStateRoot)`` is NOT unique: the only self-referential rule is ``newStateRoot !=
parentStateRoot``, so the head may legally cycle ``P → A → P → C`` within one epoch and ``P``
occurs as a parent twice. Uniqueness comes entirely from the verifier's
``coreTexPatchCredited[epoch][parent][patchHash]`` guard. A resolver keyed on two of the three
silently collapses two real transitions into one — which is not a decode error, produces no
exception, and yields a shorter history that looks fine. :func:`index_advances` refuses to build a
two-part key at all, and :func:`assert_key_is_patch_keyed` proves on a real cycle that it matters.

``transitionIndex`` is a per-epoch ordering, dense and zero-based. It is used for ordering and
never as an identity, and never across epochs.

THE LOAD-BEARING STEP IS 4, NOT 7. Recomputing ``receiptHash`` from the calldata and requiring it
to equal the mining log's is what binds C to B — and because ``workPolicyHash`` and the EIP-712
``digest`` are both inside that preimage, one hash proves the policy the receipt was priced under
AND (via step 5) the ``artifactHash`` that no event and no registry parameter carries. The
signature check in step 7 authenticates the coordinator; it is not what makes the join sound.

SCREENER-ONLY WORK. There is no screener-pass EVENT on any deployed contract. Priced work that did
not move the root appears as a ``RigCoreTexCreditAccepted`` with NO advance in the same
transaction. :func:`join_transaction` returns those as :class:`ScreenerPass` rather than dropping
them, because "every priced receipt is accounted for" is the property that makes a credit total
checkable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import abi
from . import rig_events as rig
from . import rig_receipt_binding as binding
from .keccak256 import keccak256, keccak256_hex

#: ``submitCoreTexReceipt((...))``. Pinned by the generated binding AND recomputed here; a
#: disagreement means the tuple layout moved, which would silently mis-decode every field.
SUBMIT_SELECTOR = binding.SUBMIT_CORETEX_RECEIPT_SELECTOR
#: The raw registry mutator. An advance minted through it (the ``0xa2d87e1d`` fallback route) has
#: NO ``submitCoreTexReceipt`` calldata, so steps 3-7 are impossible for it. That is reported,
#: never silently treated as a join failure of the ordinary kind.
LEGACY_ADVANCE_SELECTOR = binding.SUBMIT_STATE_ADVANCE_SELECTOR

_TUPLE = binding.CORETEX_RECEIPT_TUPLE_COMPONENTS
_TYPEHASH = bytes.fromhex(binding.CORETEX_RECEIPT_TYPEHASH[2:])
#: The signed struct is the tuple MINUS its two trailing unsigned ``bytes`` members.
_SIGNED_MEMBERS = len(binding.CORETEX_RECEIPT_TYPES[binding.CORETEX_RECEIPT_PRIMARY_TYPE])

OUTCOME_SCREENER_PASS = 1
OUTCOME_STATE_ADVANCE = 2

#: THE PUBLISHED CHECK VOCABULARY, and it is published rather than internal because it goes INSIDE
#: the canonical snapshot bytes — so a lane that invented its own spelling would produce a payload
#: that could not reproduce, however correct its logic.
#:
#: The names carry the NORMATIVE step numbers from RIG-CORETEX-REGISTRY-DESIGN.md §7.2, which is
#: the right vocabulary for a public artifact: a reader can follow "step4_receipt_hash_bound"
#: straight to the paragraph that says what step 4 is and why it is the load-bearing one. This
#: package previously used descriptive names of its own (``receipt_hash_binds_calldata_to_credit``
#: and friends); they said the same things and reproduced nothing.
STEP1_ADVANCE_DECODED = "step1_advance_decoded"
STEP2_CREDIT_EVENT_JOINED = "step2_credit_event_joined"
STEP3_CALLDATA_DECODED = "step3_calldata_decoded"
STEP4_RECEIPT_HASH_BOUND = "step4_receipt_hash_bound"
STEP5_ARTIFACT_HASH_BOUND = "step5_artifact_hash_bound_via_digest"
STEP6_CALLDATA_BOUND_TO_LOGS = "step6_calldata_bound_to_logs"
STEP7_COORDINATOR_SIGNATURE = "step7_coordinator_signature_verified"
STEP8_PATCH_HASH_VERIFIED = "step8_patch_hash_verified"
#: The SCREENER-only counterpart of step 8. A screener has no advance and therefore no descriptor
#: to hash, so its step 8 is the OUTCOME-1 DISCIPLINE instead: empty ``compactPatchBytes``, a ZERO
#: ``patchHash``, and zero ``transitionFormatVersion``/``scoreBeforePpm``/``scoreAfterPpm``. Wired
#: here because the checker that encodes it was production-dead in this package — reachable only
#: from tests — which made the v2 tightening a thing the validator asserted and never observed
#: (review L-1, and the H-2 patchHash half).
STEP8_SCREENER_DISCIPLINE = "step8_screener_outcome1_discipline"

#: The eight, in order. A transition that reports fewer has not been fully joined.
JOIN_STEPS = (STEP1_ADVANCE_DECODED, STEP2_CREDIT_EVENT_JOINED, STEP3_CALLDATA_DECODED,
              STEP4_RECEIPT_HASH_BOUND, STEP5_ARTIFACT_HASH_BOUND, STEP6_CALLDATA_BOUND_TO_LOGS,
              STEP7_COORDINATOR_SIGNATURE, STEP8_PATCH_HASH_VERIFIED)


class JoinError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# Calldata decoding (source C)
# --------------------------------------------------------------------------- #
def _word(data: bytes, index: int, field_name: str) -> bytes:
    start = index * 32
    if len(data) < start + 32:
        raise JoinError("CALLDATA_DECODE_FAILURE",
                        f"{field_name}: calldata ends before word {index}")
    return data[start:start + 32]


def _uint(data: bytes, index: int, field_name: str, *, bits: int) -> int:
    raw = _word(data, index, field_name)
    value = int.from_bytes(raw, "big")
    if bits < 256 and value >> bits:
        raise JoinError("CALLDATA_DECODE_FAILURE",
                        f"{field_name}: uint{bits} has dirty high bits")
    return value


def _bytes_tail(data: bytes, head_index: int, field_name: str) -> bytes:
    offset = _uint(data, head_index, f"{field_name}.offset", bits=256)
    if offset % 32 or offset + 32 > len(data):
        raise JoinError("CALLDATA_DECODE_FAILURE",
                        f"{field_name}: tail offset {offset} is unaligned or out of range")
    length = int.from_bytes(data[offset:offset + 32], "big")
    start = offset + 32
    if start + length > len(data):
        raise JoinError("CALLDATA_DECODE_FAILURE",
                        f"{field_name}: declared length {length} overruns the calldata")
    padded = (length + 31) // 32 * 32
    if data[start + length:start + padded] != b"\x00" * (padded - length):
        raise JoinError("CALLDATA_DECODE_FAILURE", f"{field_name}: tail padding is non-zero")
    return data[start:start + length]


@dataclass(frozen=True)
class CoreTexReceipt:
    """The 27-member struct, decoded. Field names are the contract's, not prettified."""

    values: Dict[str, Any]

    def __getitem__(self, name: str) -> Any:
        return self.values[name]

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    # -- EIP-712 ------------------------------------------------------------ #
    def struct_hash(self) -> bytes:
        """``keccak256(typehash ‖ each SIGNED member, ABI-encoded)``.

        The two trailing ``bytes`` members (``compactPatchBytes``, ``signature``) are OUTSIDE the
        typehash. That is the reason the coordinator has to hash-bind the patch before signing:
        a miner can alter member 25 without invalidating the signature, and only ``patchHash`` —
        which IS signed — stops that from being a free edit.
        """
        words = [_TYPEHASH]
        for component in _TUPLE[:_SIGNED_MEMBERS]:
            name, kind = component["name"], component["type"]
            value = self.values[name]
            if kind == "address":
                words.append(abi.as_address(value, name))
            elif kind == "bytes32":
                words.append(abi.as_bytes32(value, name))
            elif kind.startswith("uint"):
                words.append(abi.as_uint(int(value), bits=int(kind[4:]), field=name))
            else:                                             # pragma: no cover - closed set
                raise JoinError("CALLDATA_DECODE_FAILURE", f"unsupported signed type {kind}")
        return keccak256(b"".join(words))

    def digest(self, domain_separator: bytes) -> bytes:
        return abi.eip712_digest(domain_separator, self.struct_hash())

    def receipt_hash(self, digest: bytes) -> str:
        """§7.2 step 4. NOTE THE ORDER: ``patchHash`` precedes ``evalReportHash``, which is NOT
        the struct order — transcribing the struct here instead of the preimage is a real and
        very quiet bug (``BotcoinMiningRigsV1.sol:432-449``)."""
        v = self.values
        parts = [
            abi.as_uint(int(v["rigId"]), bits=256, field="rigId"),
            abi.as_address(v["operator"], "operator"),
            abi.as_uint(int(v["epochId"]), bits=64, field="epochId"),
            abi.as_uint(int(v["solveIndex"]), bits=64, field="solveIndex"),
            abi.as_bytes32(v["prevReceiptHash"], "prevReceiptHash"),
            abi.as_uint(int(v["outcome"]), bits=8, field="outcome"),
            abi.as_bytes32(v["challengeId"], "challengeId"),
            abi.as_bytes32(v["parentStateRoot"], "parentStateRoot"),
            abi.as_bytes32(v["newStateRoot"], "newStateRoot"),
            abi.as_bytes32(v["patchHash"], "patchHash"),
            abi.as_bytes32(v["evalReportHash"], "evalReportHash"),
            abi.as_bytes32(v["workPolicyHash"], "workPolicyHash"),
            abi.as_uint(int(v["difficultyCountSnapshot"]), bits=256,
                        field="difficultyCountSnapshot"),
            bytes(digest),
        ]
        return keccak256_hex(b"".join(parts))


def decode_submit_calldata(calldata: str) -> CoreTexReceipt:
    """Decode ``submitCoreTexReceipt(CoreTexReceipt)`` calldata into the 27 members."""
    raw = calldata[2:] if calldata.startswith("0x") else calldata
    data = bytes.fromhex(raw)
    if len(data) < 4:
        raise JoinError("CALLDATA_DECODE_FAILURE", "calldata is shorter than a selector")
    found = "0x" + data[:4].hex()
    if found != SUBMIT_SELECTOR:
        if found == LEGACY_ADVANCE_SELECTOR:
            raise JoinError(
                "CALLDATA_LEGACY_ROUTE",
                f"this advance was minted through the raw registry mutator {found} "
                "(submitStateAdvance), not through submitCoreTexReceipt. There is no signed "
                "receipt in this transaction, so artifactHash / workPolicyHash / the signature "
                "are unrecoverable — the advance is real, its receipt is not in calldata")
        raise JoinError("CALLDATA_DECODE_FAILURE",
                        f"selector {found} is not submitCoreTexReceipt ({SUBMIT_SELECTOR})")
    body = data[4:]
    # A single tuple argument with dynamic members is itself encoded behind an offset.
    outer = int.from_bytes(_word(body, 0, "tuple.offset"), "big")
    if outer % 32 or outer >= len(body):
        raise JoinError("CALLDATA_DECODE_FAILURE", "the receipt tuple offset is unusable")
    tup = body[outer:]

    values: Dict[str, Any] = {}
    for index, component in enumerate(_TUPLE):
        name, kind = component["name"], component["type"]
        if kind == "bytes":
            values[name] = _bytes_tail(tup, index, name)
        elif kind == "address":
            word = _word(tup, index, name)
            if word[:12] != b"\x00" * 12:
                raise JoinError("CALLDATA_DECODE_FAILURE", f"{name}: address has dirty high bits")
            values[name] = "0x" + word[12:].hex()
        elif kind == "bytes32":
            values[name] = _word(tup, index, name).hex()
        elif kind.startswith("uint"):
            values[name] = _uint(tup, index, name, bits=int(kind[4:]))
        else:                                                 # pragma: no cover - closed set
            raise JoinError("CALLDATA_DECODE_FAILURE", f"unsupported member type {kind}")
    return CoreTexReceipt(values)


# --------------------------------------------------------------------------- #
# Indexing (step 1) — the §7.4 key
# --------------------------------------------------------------------------- #
def index_advances(advances: Sequence[rig.StateAdvanced]
                   ) -> Dict[Tuple[int, str, str], rig.StateAdvanced]:
    """Index by ``(epoch, parentStateRoot, patchHash)``. A collision here is a chain-level fault.

    The verifier's duplicate guard makes the triple unique on chain, so two advances sharing it
    cannot both be confirmed. Seeing that means the log set is corrupted or contains logs from two
    different registries — either way, continuing would mean picking one arbitrarily.
    """
    out: Dict[Tuple[int, str, str], rig.StateAdvanced] = {}
    for advance in advances:
        key = advance.join_key
        if key in out:
            raise JoinError(
                "JOIN_KEY_COLLISION",
                f"two advances share (epoch, parentStateRoot, patchHash) = {key}. The verifier's "
                "coreTexPatchCredited guard makes that impossible on one registry, so these logs "
                "are not one registry's history")
        out[key] = advance
    return out


def assert_key_is_patch_keyed(advances: Sequence[rig.StateAdvanced]) -> Dict[str, Any]:
    """Report whether this history actually CONTAINS a head cycle, and prove the key survives it.

    A resolver keyed on ``(epoch, parentStateRoot)`` is wrong always but only VISIBLY wrong when
    the head cycles. Reporting the cycle count is how a reader knows whether this particular
    dataset would have caught the mistake.
    """
    two_part: Dict[Tuple[int, str], List[str]] = {}
    for advance in advances:
        two_part.setdefault((advance.epoch, advance.parent_state_root), []).append(
            advance.patch_hash)
    collisions = {f"{epoch}:{parent}": patches
                  for (epoch, parent), patches in two_part.items() if len(patches) > 1}
    return {
        "advances": len(advances),
        "distinct_three_part_keys": len(index_advances(advances)),
        "two_part_key_collisions": collisions,
        "cycled": bool(collisions),
        "note": ("(epoch, parentStateRoot) collided for the listed parents; a two-part key would "
                 "have collapsed those transitions into one"
                 if collisions else
                 "this history contains no head cycle, so a two-part key would NOT have been "
                 "caught here. It is still wrong — see design §7.4"),
    }


# --------------------------------------------------------------------------- #
# The join (steps 2-8)
# --------------------------------------------------------------------------- #
@dataclass
class ScreenerPass:
    """Priced work that did not move the root. No advance, no registry log, still a real receipt."""

    credit: rig.CoreTexCreditAccepted
    receipt: Optional[CoreTexReceipt]
    checks: List[str] = field(default_factory=list)


@dataclass
class JoinedTransition:
    """One advance with everything the three sources contribute, and what was proved about it."""

    advance: rig.StateAdvanced
    credit: rig.CoreTexCreditAccepted
    receipt: CoreTexReceipt
    digest: bytes
    receipt_hash: str
    #: ``""`` when step 7 was skipped — never a plausible-looking address for "not checked".
    recovered_signer: str
    transaction_hash: str
    checks: List[str] = field(default_factory=list)

    @property
    def key(self) -> Tuple[int, str, str]:
        return self.advance.join_key

    def as_dict(self) -> Dict[str, Any]:
        return {
            "epoch": self.advance.epoch,
            "transition_index": self.advance.transition_index,
            "join_key": {"epoch": self.key[0], "parent_state_root": self.key[1],
                         "patch_hash": self.key[2]},
            "rig_id": self.credit.rig_id,
            "operator": self.credit.operator,
            "solve_index": self.credit.solve_index,
            "receipt_hash": self.receipt_hash,
            "challenge_id": self.credit.challenge_id,
            "work_units_bps": self.credit.work_units_bps,
            "credits_earned": self.credit.credits_earned,
            "parent_state_root": self.advance.parent_state_root,
            "new_state_root": self.advance.new_state_root,
            "patch_hash": self.advance.patch_hash,
            "eval_report_hash": self.advance.eval_report_hash,
            "artifact_hash": self.receipt["artifactHash"],
            "work_policy_hash": self.receipt["workPolicyHash"],
            "rules_version": self.receipt["rulesVersion"],
            "difficulty_count_snapshot": self.receipt["difficultyCountSnapshot"],
            "score_before_ppm": self.receipt["scoreBeforePpm"],
            "score_after_ppm": self.receipt["scoreAfterPpm"],
            "issued_at": self.receipt["issuedAt"],
            "expires_at": self.receipt["expiresAt"],
            "world_seed": self.receipt["worldSeed"],
            "compact_patch_bytes": self.advance.compact_patch_bytes.hex(),
            "transaction_hash": self.transaction_hash,
            "block_number": self.advance.provenance.block_number,
            "checks": list(self.checks),
        }


#: Every field C must agree with A on (§7.2 step 6). ``compactPatchBytes`` is compared as bytes.
#: ``transitionFormatVersion`` was ``stateWordCount`` under the retired word-diff model
#: (coretex.transition-descriptor/v2 §9.1) — same ABI slot, same topic0, renamed field.
_C_TO_A_FIELDS = (
    ("epochId", "epoch"), ("parentStateRoot", "parent_state_root"),
    ("newStateRoot", "new_state_root"), ("patchHash", "patch_hash"),
    ("evalReportHash", "eval_report_hash"), ("coreVersionHash", "core_version_hash"),
    ("corpusRoot", "corpus_root"), ("activeFrontierRoot", "active_frontier_root"),
    ("transitionFormatVersion", "transition_format_version"),
)


def join_advance(advance: rig.StateAdvanced, credit: rig.CoreTexCreditAccepted,
                 calldata: str, *, domain_separator: bytes,
                 coordinator_signer: str,
                 verify_signature: bool = True) -> JoinedTransition:
    """Steps 2-8 for ONE advance. Every step is a refusal, never a downgrade.

    ``verify_signature`` controls step 7 ONLY, and defaults to on. It exists because step 7 is
    the one step here that is not load-bearing for a CONFIRMED advance: ``mining`` already
    reverted anything the coordinator did not sign, so a transaction that is in a block has had
    its signature checked by the chain. Re-checking it is defence in depth against a forged or
    substituted log set, which is worth having — but a caller that only wants to REPRODUCE the
    unsigned snapshot can turn it off and never touch curve arithmetic. What cannot be turned off
    is step 4: that is what binds the calldata to the confirmed credit, and without it every
    field this join recovers is unattributed.
    """
    checks: List[str] = [STEP1_ADVANCE_DECODED]

    # 2. B cross-checks.
    if credit.epoch != advance.epoch:
        raise JoinError("JOIN_FIELD_MISMATCH",
                        f"credit epoch {credit.epoch} != advance epoch {advance.epoch}")
    if not abi.addresses_equal(credit.operator, advance.miner):
        raise JoinError("JOIN_FIELD_MISMATCH",
                        f"credit operator {credit.operator} != advance miner {advance.miner}")
    if credit.credits_earned != advance.improvement_credits:
        raise JoinError(
            "JOIN_FIELD_MISMATCH",
            f"creditsEarned {credit.credits_earned} != improvementCredits "
            f"{advance.improvement_credits}; the two contracts disagree about what was paid")
    checks.append(STEP2_CREDIT_EVENT_JOINED)

    # 3. C.
    receipt = decode_submit_calldata(calldata)
    checks.append(STEP3_CALLDATA_DECODED)

    # 5 (before 4, because 4 consumes the digest). artifactHash is member 15 of the SIGNED struct.
    digest = receipt.digest(domain_separator)

    # 4. THE load-bearing step.
    recomputed = receipt.receipt_hash(digest)
    if recomputed != credit.receipt_hash:
        raise JoinError(
            "JOIN_RECEIPT_HASH_MISMATCH",
            f"recomputed receiptHash {recomputed} != the mining log's {credit.receipt_hash}. This "
            "is the step that binds the calldata to the confirmed credit, so nothing downstream "
            "of it — artifactHash, workPolicyHash, the signature — can be relied on")
    # Step 4 proves workPolicyHash too (it is inside the preimage) and, via the digest it
    # consumes, artifactHash — signed member 15, which no event and no registry parameter carries.
    checks.append(STEP4_RECEIPT_HASH_BOUND)
    checks.append(STEP5_ARTIFACT_HASH_BOUND)

    # 6. C to A.
    for calldata_name, advance_name in _C_TO_A_FIELDS:
        want = getattr(advance, advance_name)
        got = receipt[calldata_name]
        if isinstance(want, int) or isinstance(got, int):
            if int(want) != int(got):
                raise JoinError("JOIN_FIELD_MISMATCH",
                                f"calldata {calldata_name}={got} != advance {advance_name}={want}")
        elif str(want) != str(got):
            raise JoinError("JOIN_FIELD_MISMATCH",
                            f"calldata {calldata_name}={got} != advance {advance_name}={want}")
    if not abi.addresses_equal(receipt["operator"], advance.miner):
        raise JoinError("JOIN_FIELD_MISMATCH", "calldata operator != advance miner")
    if bytes(receipt["compactPatchBytes"]) != bytes(advance.compact_patch_bytes):
        raise JoinError(
            "JOIN_FIELD_MISMATCH",
            "the calldata's compactPatchBytes differ from the ones the registry logged. Member 25 "
            "is UNSIGNED, so this is exactly the substitution patchHash exists to catch")
    checks.append(STEP6_CALLDATA_BOUND_TO_LOGS)

    # 7. The signature — coordinator authentication, AFTER the binding is already proved.
    recovered = ""
    if verify_signature:
        from . import secp256k1 as ec                                      # noqa: WPS433
        recovered = ec.ecrecover(digest, bytes(receipt["signature"]))
        if not abi.addresses_equal(recovered, coordinator_signer):
            raise JoinError(
                "JOIN_SIGNATURE_INVALID",
                f"ecrecover(digest, signature) = {recovered}, mining.coordinatorSigner() = "
                f"{coordinator_signer}")
        checks.append(STEP7_COORDINATOR_SIGNATURE)
    else:
        checks.append("step7_coordinator_signature_SKIPPED")

    # 8. The patch. The non-zero `patchHash` rule is checked FIRST and separately: it is the
    #    outcome-2 half of `_validateStateAdvanceReceipt`'s explicit rule (review H-2), and it
    #    refuses with the ROOT error rather than a hash-mismatch error that would misdescribe
    #    "this receipt commits to no transition at all" as "these bytes are the wrong bytes".
    try:
        rig.check_state_advance_patch_hash(advance.patch_hash)
    except rig.TransitionDescriptorError as exc:
        raise JoinError("JOIN_ADVANCE_PATCH_HASH_ZERO", exc.message) from exc
    rig.check_patch_hash(advance)
    checks.append(STEP8_PATCH_HASH_VERIFIED)

    if int(receipt["outcome"]) != OUTCOME_STATE_ADVANCE:
        raise JoinError("JOIN_FIELD_MISMATCH",
                        f"an advance's receipt must declare outcome {OUTCOME_STATE_ADVANCE} "
                        f"(state advance); this one declares {receipt['outcome']}")

    return JoinedTransition(
        advance=advance, credit=credit, receipt=receipt, digest=digest,
        receipt_hash=recomputed, recovered_signer=recovered,
        transaction_hash=str(advance.provenance.transaction_hash or ""), checks=checks)


@dataclass
class JoinResult:
    transitions: List[JoinedTransition]
    screener_passes: List[ScreenerPass]
    #: Advances the join could not complete, with the reason. NEVER dropped silently.
    unresolved: List[Dict[str, Any]]
    key_report: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {"transitions": [t.as_dict() for t in self.transitions],
                "screener_passes": [
                    {"epoch": s.credit.epoch, "rig_id": s.credit.rig_id,
                     "solve_index": s.credit.solve_index, "receipt_hash": s.credit.receipt_hash,
                     "credits_earned": s.credit.credits_earned,
                     "work_units_bps": s.credit.work_units_bps,
                     "transaction_hash": s.credit.provenance.transaction_hash,
                     "checks": list(s.checks)}
                    for s in self.screener_passes],
                "unresolved": list(self.unresolved),
                "join_key": self.key_report}


def join_all(decoded: rig.DecodedLogs, *, calldata_for, domain_separator: bytes,
             coordinator_signer: str, verify_signature: bool = True) -> JoinResult:
    """Join a whole scan. ``calldata_for(tx_hash) -> str`` supplies source C.

    Grouped BY TRANSACTION: A and B are always in the same one (mining calls the verifier
    directly and emits immediately after), and A always precedes B. Pairing across transactions
    would be inventing an association the chain does not make.
    """
    by_tx: Dict[str, Dict[str, List[Any]]] = {}
    for advance in decoded.advances:
        tx = str(advance.provenance.transaction_hash or "")
        by_tx.setdefault(tx, {"advances": [], "credits": []})["advances"].append(advance)
    for credit in decoded.coretex_credits:
        tx = str(credit.provenance.transaction_hash or "")
        by_tx.setdefault(tx, {"advances": [], "credits": []})["credits"].append(credit)

    transitions: List[JoinedTransition] = []
    screeners: List[ScreenerPass] = []
    unresolved: List[Dict[str, Any]] = []
    for tx, group in sorted(by_tx.items()):
        advances = group["advances"]
        credits = group["credits"]
        if advances and not credits:
            for advance in advances:
                unresolved.append({
                    "code": "JOIN_CREDIT_EVENT_MISSING", "transaction_hash": tx,
                    "epoch": advance.epoch, "patch_hash": advance.patch_hash,
                    "reason": ("no RigCoreTexCreditAccepted in the same transaction. Either this "
                               "advance came through the raw registry mutator, or the mining "
                               "address in this deployment is wrong")})
            continue
        if len(advances) > 1 or len(credits) > 1:
            unresolved.append({"code": "JOIN_AMBIGUOUS_TRANSACTION", "transaction_hash": tx,
                               "advances": len(advances), "credits": len(credits),
                               "reason": "more than one advance/credit pair in one transaction"})
            continue
        if credits and not advances:
            # Screener-only: priced work, no state movement, no registry log.
            credit = credits[0]
            receipt = None
            checks = ["screener_only_no_advance"]
            try:
                receipt = decode_submit_calldata(calldata_for(tx))
                digest = receipt.digest(domain_separator)
                if receipt.receipt_hash(digest) != credit.receipt_hash:
                    raise JoinError("JOIN_RECEIPT_HASH_MISMATCH",
                                    "screener receipt hash does not bind its credit")
                if verify_signature:
                    from . import secp256k1 as ec                          # noqa: WPS433
                    if not abi.addresses_equal(
                            ec.ecrecover(digest, bytes(receipt["signature"])),
                            coordinator_signer):
                        raise JoinError("JOIN_SIGNATURE_INVALID", "screener signature invalid")
                if int(receipt["outcome"]) != OUTCOME_SCREENER_PASS:
                    raise JoinError("JOIN_FIELD_MISMATCH",
                                    f"a credit with no advance must declare outcome "
                                    f"{OUTCOME_SCREENER_PASS}; it declares {receipt['outcome']}")
                # ── OUTCOME-1 DISCIPLINE, ACTUALLY RUN ────────────────────────────────────────
                #
                # `rig.check_screener_descriptor` encodes `_validateScreenerReceipt` exactly, and
                # until now nothing but a test ever called it: this branch checked the outcome,
                # the receipt-hash binding and the signature and never looked at
                # `compactPatchBytes`, `transitionFormatVersion`, the scores or `patchHash`
                # (review L-1). There is no acceptance hole either way — the chain enforces all of
                # it — but a tightening the validator cannot OBSERVE is a tightening this package
                # cannot report, and reporting is what a public validator is for. Wiring it changes
                # no verdict for a receipt the deployed verifier would have accepted: every
                # condition here is one `validateAndRecord` already reverts on.
                try:
                    rig.check_screener_descriptor(
                        receipt["compactPatchBytes"],
                        transition_format_version=int(receipt["transitionFormatVersion"]),
                        score_before_ppm=int(receipt["scoreBeforePpm"]),
                        score_after_ppm=int(receipt["scoreAfterPpm"]),
                        patch_hash=receipt["patchHash"])
                except rig.TransitionDescriptorError as exc:
                    raise JoinError("JOIN_SCREENER_DISCIPLINE_VIOLATED", exc.message) from exc
                checks += [STEP3_CALLDATA_DECODED, STEP4_RECEIPT_HASH_BOUND,
                           STEP7_COORDINATOR_SIGNATURE if verify_signature
                           else "step7_coordinator_signature_SKIPPED",
                           STEP8_SCREENER_DISCIPLINE]
            except JoinError as exc:
                unresolved.append({"code": exc.code, "transaction_hash": tx,
                                   "epoch": credit.epoch, "reason": exc.message})
                continue
            screeners.append(ScreenerPass(credit=credit, receipt=receipt, checks=checks))
            continue
        try:
            transitions.append(join_advance(
                advances[0], credits[0], calldata_for(tx),
                domain_separator=domain_separator, coordinator_signer=coordinator_signer,
                verify_signature=verify_signature))
        except JoinError as exc:
            unresolved.append({"code": exc.code, "transaction_hash": tx,
                               "epoch": advances[0].epoch,
                               "patch_hash": advances[0].patch_hash, "reason": exc.message})

    transitions.sort(key=lambda t: (t.advance.epoch, t.advance.transition_index))
    return JoinResult(transitions=transitions, screener_passes=screeners, unresolved=unresolved,
                      key_report=assert_key_is_patch_keyed(decoded.advances))


# --------------------------------------------------------------------------- #
# §7.5 — the sealed-header walk, with the fall-through rule
# --------------------------------------------------------------------------- #
@dataclass
class LineageStep:
    epoch: int
    sealed: bool
    served: bool
    final_root: str
    source: str
    flagged: bool = False
    note: str = ""


def walk_lineage(views, *, from_epoch: int, back_to: int) -> Tuple[List[LineageStep], List[str]]:
    """Validate epoch-to-epoch continuity backwards from ``from_epoch`` (design §7.5, NORMATIVE).

    ``getHeader(N)`` for an unsealed epoch returns a ZERO-FILLED STRUCT rather than reverting, so
    "no header" is read from ``epochFinalized(N)`` and never inferred from a zero root. Epochs
    that were never served are SKIPPED — they genuinely did not move the root, so skipping them is
    correct rather than a tolerance, and treating a header-less epoch as a fault would make an
    ordinary screener-only epoch look like a break.

    An unsealed-but-served ``M`` is compared against ``liveStateRoot(M)``, which is frozen once
    the epoch has ended (no receipt can target a past epoch) — sound, but FLAGGED, because it
    means the operator has not committed to that root on chain.
    """
    steps: List[LineageStep] = []
    problems: List[str] = []
    expected = views.epoch_parent_state_root(int(from_epoch))
    epoch = int(from_epoch) - 1
    while epoch >= int(back_to):
        # An epoch that never had a context cannot have been served, and the registry REVERTS
        # rather than answering for it (EpochContextNotSet). §7.5's zero-filled-struct rule is
        # about `getHeader` only; `liveStateRoot` and `epochParentStateRoot` do not share it. So
        # the walk asks first. Below the registry's first served epoch every epoch is like this,
        # which is the ordinary case, not an edge one.
        if not views.epoch_has_context(epoch):
            steps.append(LineageStep(epoch=epoch, sealed=False, served=False, final_root="",
                                     source="no_epoch_context",
                                     note="skipped: no epoch context was ever set, so this epoch "
                                          "could not have been served and the registry has "
                                          "nothing to report for it"))
            epoch -= 1
            continue
        served = views.transition_count(epoch) > 0
        sealed = views.epoch_finalized(epoch)
        if not served:
            steps.append(LineageStep(epoch=epoch, sealed=sealed, served=False,
                                     final_root=views.epoch_parent_state_root(epoch),
                                     source="never_advanced",
                                     note="skipped: no recorded transition, so it cannot have "
                                          "moved the root and can never be sealed"))
            epoch -= 1
            continue
        if sealed:
            final_root = views.header(epoch)["final_state_root"]
            source = "getHeader.finalStateRoot"
            flagged = False
            note = ""
        else:
            final_root = views.live_state_root(epoch)
            source = "liveStateRoot"
            flagged = True
            note = ("epoch is served but NOT sealed: the comparison is sound (a past epoch's live "
                    "root is frozen) but the operator has not committed to it on chain")
        step = LineageStep(epoch=epoch, sealed=sealed, served=True, final_root=final_root,
                           source=source, flagged=flagged, note=note)
        if final_root != expected:
            problems.append(
                f"continuity break: epoch {from_epoch}'s context parent is {expected}, but the "
                f"most recent SERVED epoch {epoch} ends at {final_root} ({source})")
        steps.append(step)
        return steps, problems
    steps.append(LineageStep(epoch=int(back_to) - 1, sealed=False, served=False,
                             final_root=expected, source="registry_genesis",
                             note="no served epoch at or above the registry's floor: this is the "
                                  "genesis of this registry's history, not a fault"))
    return steps, problems
