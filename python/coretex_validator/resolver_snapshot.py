# SPDX-License-Identifier: Apache-2.0
"""Reproduce the resolver's per-epoch snapshots (v1/v2 history and descriptor-v3 live state).

WHY THE RESOLVER'S SCHEMA AND NOT THIS PACKAGE'S
------------------------------------------------
This package first built a PER-TRANSITION document. It lost, and the reasoning is worth keeping
because it is not a matter of taste: the consumer is an isolated runtime agent performing PORTABLE
ACTIVATION. It needs the STATE at an epoch — the live root, the per-profile release roots, the
composed manifest, the law locks — not the story of one advance. A per-transition document
describes an EDGE; activation needs a NODE. Lineage still matters, but it belongs inside the epoch
snapshot as evidence, which is exactly where the resolver puts it.

So :mod:`.snapshot`'s own format is retired as a published shape and this module reproduces the
resolver's. The ORDERING discipline that module established survives unchanged and is the whole
point: reconstruct the unsigned payload from chain truth FIRST, compare bytes, and only then look
at a signature.

WHAT "REPRODUCE" MEANS HERE, PRECISELY
--------------------------------------
Every value in the payload falls into one of two classes, and they are not verified the same way:

* **Chain-derived** — ``chain``, ``contracts``, ``wiring``, ``epoch``, ``state``, ``transitions``,
  ``epoch_lineage``, ``profiles``, ``composition``, ``artifacts``, ``locks``, ``findings``, and the
  chain-backed half of ``migration``. These are read back from the chain, the logs, the
  transaction calldata and the content store, independently of the published payload. Reproducing
  them is what proves the snapshot true.
* **Schema-constant** — ``schema``, ``version``, ``protocol``, ``classification``,
  ``production_authority``, ``disclosure``, ``canonicalization``, ``derivation``, ``prior`` (when
  genesis), ``resolver`` (when unattributed). These are SPEC TEXT. They are identical in every
  snapshot of this schema and prove nothing about any chain; they are transcribed, and
  :data:`SCHEMA_CONSTANT_KEYS` names them so a report never presents "I copied the spec text
  correctly" as evidence about a deployment.

:func:`compare` reports per-key equality across both classes so the distinction stays visible.
Byte equality over the whole document is the acceptance criterion; per-key equality is how you
find out what went wrong when it fails.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import canonical as cn
from . import join as jn
from . import rig_events as rig

#: THE SIGNED ERA. Its payload carries a ``resolver`` key-identity block, because a snapshot of
#: that era named who signed it. Epoch 180's published snapshot is this schema and STAYS VALID:
#: it is historical evidence, and reproducing it remains a true statement about it. Reproduction
#: does not require checking the signature that happens to exist alongside it.
SCHEMA_V1 = "coretex.rig-state.resolver-snapshot/v1"
#: THE UNSIGNED ERA. Removing the signature changed the payload SHAPE — ``resolver`` became
#: ``authority`` — so the resolver bumped the version rather than reusing the id.
#:
#: That is the F8 defect this package raised when the two schemas first diverged, applied to
#: itself, and it is the right call: two documents with different shapes must not answer to one
#: name, or a validator cannot tell from the id alone what it is about to parse.
SCHEMA_V2 = "coretex.rig-state.resolver-snapshot/v2"
#: THE DESCRIPTOR-V3 ERA. It retains v2's unsigned ``authority`` envelope while changing the
#: chain-derived state, transition/event, receipt and derivation blocks to the canonical three-pin
#: contract. Reusing v2 would make two incompatible inner schemas answer to one identifier.
SCHEMA_V3 = "coretex.rig-state.resolver-snapshot/v3"

#: Both are accepted, and the set is widened DELIBERATELY. An unknown schema is refused rather
#: than guessed at — a validator that guesses is one that will eventually parse a v3 as a v2 and
#: report a confident, wrong answer.
SUPPORTED_SCHEMAS: Tuple[str, ...] = (SCHEMA_V1, SCHEMA_V2, SCHEMA_V3)

#: Retained for callers that predate the v2 cut. New code should name a version explicitly.
SCHEMA = SCHEMA_V1
SCHEMA_VERSION = 1
PROTOCOL_ID = "coretex.rig-state.v1"
SUPERSEDED_PROTOCOLS = ("coretex.memory-frontier.v1", "coretex.state.v4")
CLASSIFICATION_REHEARSAL = "MAINNET_REHEARSAL"
CLASSIFICATION_CANONICAL_FORBIDDEN = "MAINNET_CANONICAL"
CLASSIFICATION_PRODUCTION = "CANONICAL_PRODUCTION"

#: 23 top-level keys in BOTH versions. A payload with 22 or 24 is neither.
#:
#: The versions differ in exactly one key, and it is the one the signature removal touched:
#: v1's ``resolver`` (who signed this) becomes v2's ``authority`` (why you should believe it at
#: all — the cache-vs-authority statement, carried inside the canonical bytes rather than in a
#: README where it could be separated from the document it describes).
_COMMON_KEYS: Tuple[str, ...] = (
    "artifacts", "canonicalization", "chain", "classification", "composition", "contracts",
    "derivation", "disclosure", "epoch", "epoch_lineage", "findings", "locks", "migration",
    "prior", "production_authority", "profiles", "protocol", "schema", "state",
    "transitions", "version", "wiring")
TOP_LEVEL_KEYS_V1: Tuple[str, ...] = tuple(sorted(_COMMON_KEYS + ("resolver",)))
TOP_LEVEL_KEYS_V2: Tuple[str, ...] = tuple(sorted(_COMMON_KEYS + ("authority",)))
TOP_LEVEL_KEYS_V3: Tuple[str, ...] = TOP_LEVEL_KEYS_V2
KEYS_BY_SCHEMA: Dict[str, Tuple[str, ...]] = {SCHEMA_V1: TOP_LEVEL_KEYS_V1,
                                              SCHEMA_V2: TOP_LEVEL_KEYS_V2,
                                              SCHEMA_V3: TOP_LEVEL_KEYS_V3}

#: Retained for callers that predate the v2 cut.
TOP_LEVEL_KEYS: Tuple[str, ...] = TOP_LEVEL_KEYS_V1

#: Keys whose content is SPEC TEXT, identical in every snapshot of this schema.
#:
#: Named explicitly so a comparison report can never present "the constant blocks matched" as
#: evidence about a chain. Reproducing these proves the transcription is right and nothing else.
SCHEMA_CONSTANT_KEYS: Tuple[str, ...] = (
    "authority", "canonicalization", "classification", "derivation", "disclosure", "prior",
    "production_authority", "protocol", "resolver", "schema", "version")

#: Keys that are read back from the chain. These are what a reproduction actually proves.
CHAIN_DERIVED_KEYS: Tuple[str, ...] = tuple(
    k for k in _COMMON_KEYS if k not in SCHEMA_CONSTANT_KEYS)


class ReproductionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# Chain-derived blocks
# --------------------------------------------------------------------------- #
def build_chain(*, chain_id: int, block_number: int, block_hash: str, parent_hash: str,
                block_timestamp: int, required_confirmations: int,
                mode: str = "confirmation-depth") -> Dict[str, Any]:
    """The pinned observation.

    NOTE WHAT IS ABSENT: the head number, the confirmation count actually observed, and the
    endpoint's ``finalized`` block. All three are properties of WHEN the resolution ran rather
    than of the state it describes, and including them would make two honest resolutions of the
    same block produce different bytes — destroying the reproduction property for no information
    gained. The finality POLICY stays, because it says what "settled" meant.
    """
    return {
        "chain_id": cn.narrow(int(chain_id), "chain_id"),
        "observation": {
            "block_hash": cn.word(block_hash, "block_hash"),
            "block_number": cn.narrow(int(block_number), "block_number"),
            "block_timestamp": cn.narrow(int(block_timestamp), "block_timestamp"),
            "finality_policy": {"mode": mode,
                                "required_confirmations": cn.narrow(int(required_confirmations),
                                                                    "required_confirmations")},
            "parent_hash": cn.word(parent_hash, "parent_hash"),
        },
    }


def build_contracts(entries: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """``role -> {address, code_hash, code_size}`` for registry / verifier / mining."""
    out: Dict[str, Any] = {}
    for role in ("mining", "registry", "verifier"):
        if role not in entries:
            raise ReproductionError("CONTRACT_MISSING", f"no code identity for {role}")
        entry = entries[role]
        out[role] = {
            "address": cn.address(entry["address"], f"{role}.address"),
            "code_hash": cn.word(entry["code_hash"], f"{role}.code_hash"),
            "code_size": cn.narrow(int(entry["code_size"]), f"{role}.code_size"),
        }
    return out


def build_wiring(*, coordinator_signer: str, current_epoch: int, cutover_epoch: int,
                 domain_separator: Any, mining_core_tex_verifier: str,
                 registry_core_tex_verifier: str, registry_epoch_clock: str,
                 verifier_core_tex_registry: str, verifier_mining: str) -> Dict[str, Any]:
    """Every cross-link, read back rather than assumed.

    ``verifier_coreTexRegistry`` is the field that IDENTIFIES A REGISTRY, and it is why address +
    code hash is not enough: a successor deployed from the same source has an identical code hash
    and, once it has inherited the epoch contexts, answers every pin getter identically. Neither
    the code nor the state separates a live registry from a retired one. Only the binding does.
    """
    return {
        "coordinator_signer": cn.address(coordinator_signer, "coordinator_signer"),
        "current_epoch": cn.narrow(int(current_epoch), "current_epoch"),
        "cutover_epoch": cn.narrow(int(cutover_epoch), "cutover_epoch"),
        "domain_separator": cn.word(domain_separator, "domain_separator"),
        "mining_coreTexVerifier": cn.address(mining_core_tex_verifier, "mining_coreTexVerifier"),
        "registry_coreTexVerifier": cn.address(registry_core_tex_verifier,
                                               "registry_coreTexVerifier"),
        "registry_epochClock": cn.address(registry_epoch_clock, "registry_epochClock"),
        "verifier_coreTexRegistry": cn.address(verifier_core_tex_registry,
                                               "verifier_coreTexRegistry"),
        "verifier_mining": cn.address(verifier_mining, "verifier_mining"),
    }


def build_state(*, epoch: int, context: Mapping[str, Any],
                live_state_root: str, transition_count: int, sealed: bool, served: bool,
                header: Optional[Mapping[str, Any]] = None,
                finalized_at: Optional[int] = None) -> Dict[str, Any]:
    """The epoch's registry state and its delegated context.

    ``finalized_at`` is a ``uint256`` block timestamp and therefore renders as a DECIMAL STRING.
    It is the easiest field in the whole payload to get wrong, because every neighbouring integer
    is a JSON number.
    """
    block: Dict[str, Any] = {
        "context": {
            "active_frontier_root": cn.word(context["active_frontier_root"],
                                            "active_frontier_root"),
            "baseline_manifest_hash": cn.word(context["baseline_manifest_hash"],
                                              "baseline_manifest_hash"),
            "configured": bool(context["configured"]),
            "core_version_hash": cn.word(context["core_version_hash"], "core_version_hash"),
            "corpus_root": cn.word(context["corpus_root"], "corpus_root"),
            "epoch": cn.narrow(int(epoch), "context.epoch"),
            "hidden_seed_commit": cn.word(context["hidden_seed_commit"], "hidden_seed_commit"),
            "parent_state_root": cn.word(context["parent_state_root"], "parent_state_root"),
        },
        "epoch": cn.narrow(int(epoch), "epoch"),
        "live_state_root": cn.word(live_state_root, "live_state_root"),
        "sealed": bool(sealed),
        "served": bool(served),
        "transition_count": cn.narrow(int(transition_count), "transition_count"),
    }
    # A HEADER EXISTS ONLY FOR A SEALED EPOCH, and an unsealed one must not carry a zero-filled
    # stand-in. `getHeader` returns zeros rather than reverting (§7.5), so emitting the struct
    # unconditionally would put eight zero roots into the payload and make "never sealed"
    # indistinguishable from "sealed at the zero root" — which D2 forbids and which is therefore a
    # state that cannot exist. Epoch 180 is the live case: still current, so unsealed, and its
    # final root comes from liveStateRoot.
    if sealed:
        if header is None or finalized_at is None:
            raise ReproductionError("SEALED_WITHOUT_HEADER",
                                    "a sealed epoch must carry its header and finalizedAt")
        block["finalized_at"] = cn.wide(int(finalized_at), "finalized_at")
        block["header"] = {name: cn.word(header[name], name) for name in sorted(header)}
    return block


_V3_CONTEXT_KEYS = frozenset({
    "configured", "epoch", "parent_state_root", "core_version_hash", "epoch_context_root",
    "hidden_seed_commit",
})
_V3_HEADER_KEYS = frozenset({"patch_set_root", "score_root"})


def build_state_v3(*, epoch: int, context: Mapping[str, Any],
                   live_state_root: str, transition_count: int, sealed: bool, served: bool,
                   header: Optional[Mapping[str, Any]] = None,
                   finalized_at: Optional[int] = None) -> Dict[str, Any]:
    """The descriptor-v3 registry state, without flattening the addressed epoch manifest.

    ``state.context`` mirrors the canonical contract's six cells exactly. Corpus, active-frontier,
    baseline, selection and threshold values are fields of the separately content-addressed
    ``epochContextRoot`` document and are deliberately absent here. A sealed header contains only
    closing evidence roots; final state and the epoch/core/context pins remain their canonical
    accessors rather than duplicate header cells.
    """
    supplied = set(context)
    if supplied != _V3_CONTEXT_KEYS:
        raise ReproductionError(
            "V3_CONTEXT_SHAPE_MISMATCH",
            f"descriptor-v3 state.context has exactly {sorted(_V3_CONTEXT_KEYS)}; "
            f"missing={sorted(_V3_CONTEXT_KEYS - supplied)}, "
            f"unexpected={sorted(supplied - _V3_CONTEXT_KEYS)}")
    block: Dict[str, Any] = {
        "context": {
            "configured": bool(context["configured"]),
            "core_version_hash": cn.word(context["core_version_hash"], "core_version_hash"),
            "epoch": cn.narrow(int(context["epoch"]), "context.epoch"),
            "epoch_context_root": cn.word(context["epoch_context_root"],
                                           "epoch_context_root"),
            "hidden_seed_commit": cn.word(context["hidden_seed_commit"],
                                           "hidden_seed_commit"),
            "parent_state_root": cn.word(context["parent_state_root"], "parent_state_root"),
        },
        "epoch": cn.narrow(int(epoch), "epoch"),
        "live_state_root": cn.word(live_state_root, "live_state_root"),
        "sealed": bool(sealed),
        "served": bool(served),
        "transition_count": cn.narrow(int(transition_count), "transition_count"),
    }
    if int(context["epoch"]) != int(epoch):
        raise ReproductionError(
            "V3_CONTEXT_EPOCH_MISMATCH",
            f"state epoch {epoch} != context epoch {context['epoch']}")
    if sealed:
        if header is None or finalized_at is None:
            raise ReproductionError("SEALED_WITHOUT_HEADER",
                                    "a sealed epoch must carry its header and finalizedAt")
        supplied_header = set(header)
        if supplied_header != _V3_HEADER_KEYS:
            raise ReproductionError(
                "V3_HEADER_SHAPE_MISMATCH",
                f"descriptor-v3 sealed header has exactly {sorted(_V3_HEADER_KEYS)}; "
                f"missing={sorted(_V3_HEADER_KEYS - supplied_header)}, "
                f"unexpected={sorted(supplied_header - _V3_HEADER_KEYS)}")
        block["finalized_at"] = cn.wide(int(finalized_at), "finalized_at")
        block["header"] = {name: cn.word(header[name], name) for name in sorted(_V3_HEADER_KEYS)}
    elif header is not None or finalized_at is not None:
        raise ReproductionError(
            "UNSEALED_WITH_HEADER",
            "an unsealed descriptor-v3 epoch must not carry header/finalizedAt stand-ins")
    return block


def build_transition(transition: jn.JoinedTransition) -> Dict[str, Any]:
    """One legacy v1/v2 joined transition, in the historical resolver spelling.

    Every wide field — ``rigId``, ``workUnitsBps``, ``difficultyCountSnapshot``, ``worldSeed``,
    ``improvement_credits``, ``credits_earned`` — renders as a decimal string. They sit beside
    narrow fields that render as numbers, in the same object, which is exactly the mixture a
    reader has to get right.
    """
    advance = transition.advance
    credit = transition.credit
    receipt = transition.receipt
    values = receipt.values
    return {
        "block_number": cn.narrow(int(advance.provenance.block_number or 0), "block_number"),
        "checks": list(transition.checks),
        "coordinator_signer": cn.address(transition.recovered_signer or "", "coordinator_signer"),
        "eip712_digest": cn.word(transition.digest, "eip712_digest"),
        "key": {
            "epoch": cn.narrow(advance.epoch, "key.epoch"),
            "parent_state_root": cn.word(advance.parent_state_root, "key.parent_state_root"),
            "patch_hash": cn.word(advance.patch_hash, "key.patch_hash"),
        },
        "log_index": cn.narrow(int(advance.provenance.log_index or 0), "log_index"),
        "mining_event": {
            "challenge_id": cn.word(credit.challenge_id, "challenge_id"),
            "credits_earned": cn.wide(credit.credits_earned, "credits_earned"),
            "epoch": cn.narrow(credit.epoch, "mining_event.epoch"),
            "operator": cn.address(credit.operator, "operator"),
            "receipt_hash": cn.word(credit.receipt_hash, "receipt_hash"),
            "rig_id": cn.wide(credit.rig_id, "rig_id"),
            "solve_index": cn.narrow(credit.solve_index, "solve_index"),
            "work_units_bps": cn.wide(credit.work_units_bps, "work_units_bps"),
        },
        "receipt": _receipt_block(values),
        "receipt_hash": cn.word(transition.receipt_hash, "receipt_hash"),
        "registry_event": {
            "active_frontier_root": cn.word(advance.active_frontier_root, "active_frontier_root"),
            "compact_patch_bytes": cn.hexdata(advance.compact_patch_bytes, "compact_patch_bytes"),
            "core_version_hash": cn.word(advance.core_version_hash, "core_version_hash"),
            "corpus_root": cn.word(advance.corpus_root, "corpus_root"),
            "epoch": cn.narrow(advance.epoch, "registry_event.epoch"),
            "eval_report_hash": cn.word(advance.eval_report_hash, "eval_report_hash"),
            "improvement_credits": cn.wide(advance.improvement_credits, "improvement_credits"),
            "miner": cn.address(advance.miner, "miner"),
            "new_state_root": cn.word(advance.new_state_root, "new_state_root"),
            "parent_state_root": cn.word(advance.parent_state_root, "parent_state_root"),
            "patch_hash": cn.word(advance.patch_hash, "patch_hash"),
            "transition_index": cn.narrow(advance.transition_index, "transition_index"),
            "transition_format_version": cn.narrow(advance.transition_format_version,
                                                    "transition_format_version"),
        },
        "transaction_hash": cn.word(advance.provenance.transaction_hash or "",
                                    "transaction_hash"),
        "transition_index": cn.narrow(advance.transition_index, "transition_index"),
    }


def build_transition_v3(transition: jn.JoinedTransition) -> Dict[str, Any]:
    """One descriptor-v3 transition using the canonical event and 24-field receipt."""
    advance = transition.advance
    credit = transition.credit
    values = transition.receipt.values
    return {
        "block_number": cn.narrow(int(advance.provenance.block_number or 0), "block_number"),
        "checks": list(transition.checks),
        "coordinator_signer": cn.address(transition.recovered_signer or "",
                                          "coordinator_signer"),
        "eip712_digest": cn.word(transition.digest, "eip712_digest"),
        "key": {
            "epoch": cn.narrow(advance.epoch, "key.epoch"),
            "parent_state_root": cn.word(advance.parent_state_root, "key.parent_state_root"),
            "patch_hash": cn.word(advance.patch_hash, "key.patch_hash"),
        },
        "log_index": cn.narrow(int(advance.provenance.log_index or 0), "log_index"),
        "mining_event": {
            "challenge_id": cn.word(credit.challenge_id, "challenge_id"),
            "credits_earned": cn.wide(credit.credits_earned, "credits_earned"),
            "epoch": cn.narrow(credit.epoch, "mining_event.epoch"),
            "operator": cn.address(credit.operator, "operator"),
            "receipt_hash": cn.word(credit.receipt_hash, "receipt_hash"),
            "rig_id": cn.wide(credit.rig_id, "rig_id"),
            "solve_index": cn.narrow(credit.solve_index, "solve_index"),
            "work_units_bps": cn.wide(credit.work_units_bps, "work_units_bps"),
        },
        "receipt": _receipt_block_v3(values),
        "receipt_hash": cn.word(transition.receipt_hash, "receipt_hash"),
        "registry_event": {
            "compact_patch_bytes": cn.hexdata(advance.compact_patch_bytes,
                                               "compact_patch_bytes"),
            "core_version_hash": cn.word(advance.core_version_hash, "core_version_hash"),
            "epoch": cn.narrow(advance.epoch, "registry_event.epoch"),
            "epoch_context_root": cn.word(advance.epoch_context_root, "epoch_context_root"),
            "eval_report_hash": cn.word(advance.eval_report_hash, "eval_report_hash"),
            "improvement_credits": cn.wide(advance.improvement_credits,
                                            "improvement_credits"),
            "miner": cn.address(advance.miner, "miner"),
            "new_state_root": cn.word(advance.new_state_root, "new_state_root"),
            "parent_state_root": cn.word(advance.parent_state_root, "parent_state_root"),
            "patch_hash": cn.word(advance.patch_hash, "patch_hash"),
            "transition_index": cn.narrow(advance.transition_index, "transition_index"),
            "transition_format_version": cn.narrow(advance.transition_format_version,
                                                    "transition_format_version"),
        },
        "transaction_hash": cn.word(advance.provenance.transaction_hash or "",
                                    "transaction_hash"),
        "transition_index": cn.narrow(advance.transition_index, "transition_index"),
    }


def build_transition_v1(transition: jn.JoinedTransition) -> Dict[str, Any]:
    """Immutable stateWordCount-era rendering used by signed resolver-snapshot/v1 history."""
    values = dict(transition.receipt.values)
    values["transitionFormatVersion"] = values.pop("stateWordCount")
    projected = jn.JoinedTransition(
        advance=transition.advance, credit=transition.credit,
        receipt=jn.CoreTexReceipt(values), digest=transition.digest,
        receipt_hash=transition.receipt_hash, recovered_signer=transition.recovered_signer,
        transaction_hash=transition.transaction_hash, checks=list(transition.checks))
    block = build_transition(projected)
    block["receipt"]["stateWordCount"] = block["receipt"].pop("transitionFormatVersion")
    block["registry_event"]["word_count"] = block["registry_event"].pop(
        "transition_format_version")
    return block


#: Which receipt members are wide (decimal strings) and which are narrow (JSON numbers).
_WIDE_RECEIPT_MEMBERS = ("rigId", "workUnitsBps", "difficultyCountSnapshot", "worldSeed")
_NARROW_RECEIPT_MEMBERS = ("epochId", "solveIndex", "outcome", "rulesVersion",
                           "transitionFormatVersion", "scoreBeforePpm", "scoreAfterPpm",
                           "issuedAt", "expiresAt")
_WORD_RECEIPT_MEMBERS_V2 = (
    "prevReceiptHash", "challengeId", "parentStateRoot", "newStateRoot", "corpusRoot",
    "activeFrontierRoot", "coreVersionHash", "evalReportHash", "patchHash", "artifactHash",
    "workPolicyHash")
_WORD_RECEIPT_MEMBERS_V3 = (
    "prevReceiptHash", "challengeId", "parentStateRoot", "newStateRoot", "epochContextRoot",
    "coreVersionHash", "evalReportHash", "patchHash", "artifactHash", "workPolicyHash")
# Retained for old callers and snapshot tests that introspect the historical layout.
_WORD_RECEIPT_MEMBERS = _WORD_RECEIPT_MEMBERS_V2


def _receipt_block(values: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in _WIDE_RECEIPT_MEMBERS:
        out[name] = cn.wide(int(values[name]), name)
    for name in _NARROW_RECEIPT_MEMBERS:
        out[name] = cn.narrow(int(values[name]), name)
    for name in _WORD_RECEIPT_MEMBERS_V2:
        out[name] = cn.word(values[name], name)
    out["operator"] = cn.address(values["operator"], "operator")
    out["compactPatchBytes"] = cn.hexdata(values["compactPatchBytes"], "compactPatchBytes")
    out["signature"] = cn.hexdata(values["signature"], "signature")
    return out


def _receipt_block_v3(values: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in _WIDE_RECEIPT_MEMBERS:
        out[name] = cn.wide(int(values[name]), name)
    for name in _NARROW_RECEIPT_MEMBERS:
        out[name] = cn.narrow(int(values[name]), name)
    for name in _WORD_RECEIPT_MEMBERS_V3:
        out[name] = cn.word(values[name], name)
    out["operator"] = cn.address(values["operator"], "operator")
    out["compactPatchBytes"] = cn.hexdata(values["compactPatchBytes"], "compactPatchBytes")
    out["signature"] = cn.hexdata(values["signature"], "signature")
    return out


def build_transitions(transitions: Sequence[jn.JoinedTransition]) -> Dict[str, Any]:
    return {
        "count": cn.narrow(len(transitions), "transitions.count"),
        "lineage": [build_transition(t) for t in transitions],
        # Spelled out rather than concatenated so a reader can SEE that patchHash is in it.
        "primary_key": ["epoch", "parentStateRoot", "patchHash"],
    }


def build_transitions_v3(transitions: Sequence[jn.JoinedTransition]) -> Dict[str, Any]:
    return {
        "count": cn.narrow(len(transitions), "transitions.count"),
        "lineage": [build_transition_v3(t) for t in transitions],
        "primary_key": ["epoch", "parentStateRoot", "patchHash"],
    }


def build_transitions_v1(transitions: Sequence[jn.JoinedTransition]) -> Dict[str, Any]:
    return {
        "count": cn.narrow(len(transitions), "transitions.count"),
        "lineage": [build_transition_v1(t) for t in transitions],
        "primary_key": ["epoch", "parentStateRoot", "patchHash"],
    }


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #
@dataclass
class KeyComparison:
    key: str
    equal: bool
    kind: str                      # "chain-derived" | "schema-constant"
    reproduced_bytes: int
    published_bytes: int
    detail: str = ""


@dataclass
class ComparisonResult:
    """Per-key and whole-document equality. Both, because they answer different questions."""

    identical: bool
    reproduced_sha256: str
    published_sha256: str
    reproduced_length: int
    published_length: int
    keys: List[KeyComparison] = field(default_factory=list)
    missing_keys: List[str] = field(default_factory=list)
    unexpected_keys: List[str] = field(default_factory=list)
    #: Blocks taken from the published payload rather than derived. They match by construction,
    #: so a report that did not name them would be counting them as evidence.
    adopted_blocks: List[str] = field(default_factory=list)

    @property
    def chain_derived_equal(self) -> List[str]:
        return [k.key for k in self.keys if k.equal and k.kind == "chain-derived"]

    @property
    def chain_derived_unequal(self) -> List[str]:
        return [k.key for k in self.keys if not k.equal and k.kind == "chain-derived"]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "identical": self.identical,
            "reproduced_sha256": self.reproduced_sha256,
            "published_sha256": self.published_sha256,
            "reproduced_length": self.reproduced_length,
            "published_length": self.published_length,
            "missing_keys": list(self.missing_keys),
            "unexpected_keys": list(self.unexpected_keys),
            "chain_derived": {
                "equal": self.chain_derived_equal,
                "unequal": self.chain_derived_unequal,
            },
            "schema_constant": {
                "equal": [k.key for k in self.keys if k.equal and k.kind == "schema-constant"],
                "unequal": [k.key for k in self.keys
                            if not k.equal and k.kind == "schema-constant"],
            },
            "keys": [{"key": k.key, "equal": k.equal, "kind": k.kind,
                      "reproduced_bytes": k.reproduced_bytes,
                      "published_bytes": k.published_bytes,
                      "detail": k.detail} for k in self.keys],
            "adopted_blocks": list(self.adopted_blocks),
            "note": ("schema-constant keys are SPEC TEXT and identical in every snapshot of this "
                     "schema; reproducing them proves the transcription is right and says nothing "
                     "about any chain. The chain-derived keys are what a reproduction proves. "
                     "`adopted_blocks` were taken from the published payload and therefore match "
                     "by construction — they are not evidence of anything"),
        }


def compare(reproduced: Mapping[str, Any], published: Mapping[str, Any]) -> ComparisonResult:
    """Whole-document byte equality, plus a per-key breakdown for when it fails."""
    reproduced_bytes = cn.canonical_bytes(reproduced)
    published_bytes = cn.canonical_bytes(published)
    result = ComparisonResult(
        identical=reproduced_bytes == published_bytes,
        reproduced_sha256=cn.sha256_hex(reproduced_bytes),
        published_sha256=cn.sha256_hex(published_bytes),
        reproduced_length=len(reproduced_bytes),
        published_length=len(published_bytes))
    result.missing_keys = sorted(set(published) - set(reproduced))
    result.unexpected_keys = sorted(set(reproduced) - set(published))
    for key in sorted(set(reproduced) & set(published)):
        left = cn.canonical_bytes({key: reproduced[key]})
        right = cn.canonical_bytes({key: published[key]})
        kind = "schema-constant" if key in SCHEMA_CONSTANT_KEYS else "chain-derived"
        detail = ""
        if left != right and isinstance(reproduced[key], Mapping) \
                and isinstance(published[key], Mapping):
            differing = sorted(k for k in set(reproduced[key]) | set(published[key])
                               if reproduced[key].get(k) != published[key].get(k))
            detail = "differing sub-keys: " + ", ".join(differing[:12])
        result.keys.append(KeyComparison(key=key, equal=left == right, kind=kind,
                                         reproduced_bytes=len(left) - len(key) - 5,
                                         published_bytes=len(right) - len(key) - 5,
                                         detail=detail))
    return result


def schema_of(payload: Mapping[str, Any]) -> str:
    """The declared schema id, refused unless this package actually implements it.

    Discriminating on the DECLARED id — rather than sniffing for a ``resolver`` or ``authority``
    key — is the whole point. A document that says what it is can be refused cleanly when it is
    something we do not implement; a document we guess at will eventually be guessed wrong, and a
    confident wrong answer is worse than a refusal.
    """
    declared = payload.get("schema")
    if declared not in SUPPORTED_SCHEMAS:
        raise ReproductionError(
            "SCHEMA_UNSUPPORTED",
            f"this package implements {list(SUPPORTED_SCHEMAS)}; the payload declares "
            f"{declared!r}. Refusing to guess which of them it resembles")
    return str(declared)


def check_shape(payload: Mapping[str, Any], *, production_authority: bool = False) -> None:
    """Refuse a document that is not a schema this package implements, before comparing anything."""
    declared = schema_of(payload)
    expected = KEYS_BY_SCHEMA[declared]
    observed = tuple(sorted(payload))
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        raise ReproductionError(
            "SCHEMA_SHAPE_MISMATCH",
            f"{declared} has exactly {len(expected)} top-level keys; missing={missing}, "
            f"unexpected={extra}")
    if payload.get("classification") == CLASSIFICATION_CANONICAL_FORBIDDEN:
        raise ReproductionError(
            "CLASSIFICATION_REFUSED",
            "MAINNET_CANONICAL is not a classification this package will process")
    if payload.get("classification") == CLASSIFICATION_PRODUCTION:
        if not production_authority or payload.get("production_authority") is not True:
            raise ReproductionError(
                "PRODUCTION_AUTHORITY_REQUIRED",
                "CANONICAL_PRODUCTION requires a separately authenticated canonical release")
    elif payload.get("classification") != CLASSIFICATION_REHEARSAL:
        raise ReproductionError("CLASSIFICATION_UNKNOWN",
                                f"unsupported classification {payload.get('classification')!r}")


# --------------------------------------------------------------------------- #
# The remaining chain-derived blocks
# --------------------------------------------------------------------------- #
def build_epoch_lineage(*, epoch: int, steps: Sequence[Mapping[str, Any]],
                        continuous: bool, terminates_at: int,
                        findings: Sequence[str] = (),
                        rule: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """The §7.5 backwards walk, including the epochs it fell THROUGH.

    Header-less epochs are in the record, not omitted from it. An epoch that was never armed
    reports ``context_set: false`` and ``final_root_source: "none (EpochContextNotSet)"`` — and
    that string is load-bearing: it says the walk ASKED and got a refusal, as distinct from a walk
    that never looked. On the real chain every epoch below 180 is like this, because 180 is that
    registry's genesis.
    """
    out: List[Dict[str, Any]] = []
    for step in steps:
        entry: Dict[str, Any] = {
            "context_set": bool(step["context_set"]),
            "epoch": cn.narrow(int(step["epoch"]), "lineage.epoch"),
            "final_root_source": str(step["final_root_source"]),
            "sealed": bool(step["sealed"]),
            "served": bool(step["served"]),
            "transition_count": cn.narrow(int(step["transition_count"]), "transition_count"),
            "uncommitted": bool(step["uncommitted"]),
        }
        # Present only when the epoch actually has one. An unarmed epoch has no roots, and
        # emitting a zero would be inventing a value the chain refused to give.
        if step.get("context_parent") is not None:
            entry["context_parent"] = cn.word(step["context_parent"], "context_parent")
        if step.get("final_root") is not None:
            entry["final_root"] = cn.word(step["final_root"], "final_root")
        out.append(entry)
    return {
        "continuous": bool(continuous),
        "epoch": cn.narrow(int(epoch), "epoch_lineage.epoch"),
        "epochs": out,
        "findings": sorted(str(f) for f in findings),
        # THE WALK PUBLISHES THE RULE IT APPLIED. A lineage record that showed only its
        # conclusions would be unauditable: a reader could not tell a fall-through from a missed
        # epoch, nor learn that continuity is asserted OFF chain and that this walk is the
        # mitigation rather than an on-chain guarantee.
        "rule": dict(rule or LINEAGE_RULE),
        "terminates_at": cn.narrow(int(terminates_at), "terminates_at"),
    }


#: The §7.5 walk, stated inside the payload so a reader need not fetch the design document.
LINEAGE_RULE: Dict[str, str] = {
    "fall_through": ("unserved epochs are SKIPPED, not treated as breaks: a screener-only epoch "
                     "can never be sealed (D3) and is a permanent, ordinary gap in the header "
                     "chain"),
    "final_root": ("sealed ? getHeader(N).finalStateRoot : served ? liveStateRoot(N) : "
                   "epochParentStateRoot(N)"),
    "on_chain_enforcement": ("NONE — epoch-to-epoch continuity is asserted by the "
                             "CORETEX_CONTEXT_OPERATOR, not derived on chain (design §11 gap 1). "
                             "This walk is the off-chain mitigation the design names"),
    "sealed": "epochFinalized(N)",
    "served": "transitionCount(N) > 0",
    "specification": "RIG-CORETEX-REGISTRY-DESIGN.md §7.5 (normative)",
}

LINEAGE_RULE_V3: Dict[str, str] = {
    "fall_through": ("unserved epochs are SKIPPED, not treated as breaks: a screener-only epoch "
                     "can never be sealed (D3) and is a permanent, ordinary gap in the header "
                     "chain"),
    "final_root": ("served ? liveStateRoot(N) : epochParentStateRoot(N); when sealed, "
                   "epochFinalized freezes liveStateRoot and getHeader stores only "
                   "patchSetRoot/scoreRoot"),
    "on_chain_enforcement": ("NONE — epoch-to-epoch continuity is asserted by the "
                             "CORETEX_CONTEXT_OPERATOR, not derived on chain (design §11 gap 1). "
                             "This walk is the off-chain mitigation the design names"),
    "sealed": "epochFinalized(N)",
    "served": "transitionCount(N) > 0",
    "specification": "RIG-CORETEX-REGISTRY-DESIGN.md §7.5 (normative)",
}


def build_migration(*, registry: str, registry_code_hash: str, verifier_bound_registry: str,
                    epoch_clock: str, cutover_epoch: int, lineage_floor_epoch: int,
                    log_window_from_block: int) -> Dict[str, Any]:
    """Which generation of the lane this is, and the collision a reader must know about."""
    return {
        "cutover_epoch": cn.narrow(int(cutover_epoch), "cutover_epoch"),
        "lineage_floor_epoch": cn.narrow(int(lineage_floor_epoch), "lineage_floor_epoch"),
        "log_window_from_block": cn.narrow(int(log_window_from_block), "log_window_from_block"),
        "protocol": PROTOCOL_ID,
        "registry_generation": {
            "epoch_clock": cn.address(epoch_clock, "epoch_clock"),
            "registry": cn.address(registry, "registry"),
            "registry_code_hash": cn.word(registry_code_hash, "registry_code_hash"),
            # The field that separates a live registry from a retired one. Address and code hash
            # cannot: a successor from the same source shares the hash and, once it has inherited
            # the contexts, answers every pin getter identically.
            "verifier_bound_registry": cn.address(verifier_bound_registry,
                                                  "verifier_bound_registry"),
        },
        "supersedes": list(SUPERSEDED_PROTOCOLS),
        "topic0_collision": {
            "note": ("this event shares topic0 with the retired coretex.state.v4 advance, by "
                     "design (ABI compatibility with the shipped reference). Logs MUST be "
                     "filtered by emitting address; a topic0 filter splices the two lanes' "
                     "histories"),
            "registry_state_advanced": cn.word(rig.LEGACY_V2_STATE_ADVANCED_TOPIC0,
                                               "registry_state_advanced"),
        },
    }


def build_migration_v3(*, registry: str, registry_code_hash: str,
                       verifier_bound_registry: str, epoch_clock: str, cutover_epoch: int,
                       lineage_floor_epoch: int, log_window_from_block: int) -> Dict[str, Any]:
    """Descriptor-v3 generation identity. Its advance topic no longer collides with legacy v2."""
    return {
        "cutover_epoch": cn.narrow(int(cutover_epoch), "cutover_epoch"),
        "lineage_floor_epoch": cn.narrow(int(lineage_floor_epoch), "lineage_floor_epoch"),
        "log_window_from_block": cn.narrow(int(log_window_from_block), "log_window_from_block"),
        "protocol": rig.PROTOCOL_RIG_EXACT,
        "registry_generation": {
            "epoch_clock": cn.address(epoch_clock, "epoch_clock"),
            "registry": cn.address(registry, "registry"),
            "registry_code_hash": cn.word(registry_code_hash, "registry_code_hash"),
            "verifier_bound_registry": cn.address(verifier_bound_registry,
                                                  "verifier_bound_registry"),
        },
        "supersedes": list(SUPERSEDED_PROTOCOLS),
        "topic0_collision": {
            "collides": False,
            "note": ("descriptor v3's epochContextRoot changed the live event ABI, so its "
                     "topic0 is distinct from retired coretex.state.v4. Logs are still filtered "
                     "by emitting address because a topic identifies a type, not an authorized "
                     "registry"),
            "registry_state_advanced": cn.word(rig.STATE_ADVANCED_TOPIC0,
                                               "registry_state_advanced"),
            "retired_v4_state_advanced": cn.word(rig.LEGACY_V2_STATE_ADVANCED_TOPIC0,
                                                  "retired_v4_state_advanced"),
        },
    }


def build_profiles(manifest: Mapping[str, Any]) -> Dict[str, str]:
    """Per-profile release roots from the head frontier manifest — the activation payload."""
    return {pid: cn.bare_root(root, f"profiles[{pid}]")
            for pid, root in sorted(manifest["profiles"].items())}


def build_composition(manifest: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "artifact_format": str(manifest["format"]),
        "composed_manifest_root": cn.bare_root(manifest["default_composition_root"],
                                               "composed_manifest_root"),
        "composition_artifact_format": "benchmark-v2/g8-deployment-signed/v1",
        "default_composition_root": cn.bare_root(manifest["default_composition_root"],
                                                 "default_composition_root"),
        "manifest_epoch": cn.narrow(int(manifest["epoch"]), "manifest_epoch"),
        # BARE, not 0x. It is a content-addressed frontier root read out of a fetched manifest,
        # never a chain word — nothing put it in a bytes32. Rendering it as a word was this
        # package's own slip while adopting the two-spelling rule, and it is exactly the confusion
        # `root_from_word` exists to make impossible at the one place the boundary is real.
        "manifest_parent_frontier_root": cn.bare_root(manifest["parent_frontier_root"],
                                                      "manifest_parent_frontier_root"),
    }


def build_artifacts(entries: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """The content-addressed index, sorted by root.

    ``hash_rule`` is per-object and is NOT a formality. Candidate bundles and composition
    manifests use ``sha256-signed-manifest-body`` — the hash covers the manifest body with its own
    attestation fields removed — while frontier manifests use ``sha256-frontier-canonical-json``.
    Rehashing a signed manifest under the frontier rule produces a mismatch and reports a TAMPER
    THAT IS NOT THERE, which is worse than not checking: it burns an operator's trust in the
    check. Found on real data.
    """
    out = []
    for entry in entries:
        item: Dict[str, Any] = {
            "chain_binding": str(entry["chain_binding"]),
            "chain_word": cn.word(entry["chain_word"], "chain_word"),
            "hash_rule": str(entry["hash_rule"]),
            "kind": str(entry["kind"]),
            "location": str(entry.get("location", "")),
            "resolved": bool(entry["resolved"]),
            "root": cn.bare_root(entry["root"], "root"),
        }
        # A RESOLVED entry says where the bytes came from and how many there were; an UNRESOLVED
        # one says why it was not fetched. They carry different fields because they are different
        # claims — "I have these bytes and rehashed them" versus "the chain commits to this root
        # and I recorded the commitment". Giving an unfetched object a `size` would be inventing
        # a measurement, and giving a fetched one an excuse `note` would be pretending it was not.
        if item["resolved"]:
            item["size"] = cn.narrow(int(entry["size"]), "size")
        else:
            item["note"] = str(entry["note"])
        out.append(item)
    return sorted(out, key=lambda item: (item["kind"], item["root"]))


def build_transition_artifact_ref_v3(advance: rig.StateAdvanced) -> Dict[str, Any]:
    """The unresolved artifact named by an authenticated descriptor-v3 event payload."""
    descriptor = rig.decode_transition_descriptor(
        advance.compact_patch_bytes,
        parent_state_root=advance.parent_state_root,
        new_state_root=advance.new_state_root,
        expected_patch_hash=advance.patch_hash,
        transition_format_version=advance.transition_format_version)
    index = advance.transition_index
    return {
        "chain_binding": (
            f"registry log compactPatchBytes descriptor of transition {index}; the event's "
            "patchHash authenticates those bytes under keccak256(abi.encodePacked("
            "\"coretex-transition-descriptor-v3\", compactPatchBytes)), and "
            "descriptor.patchArtifactHash names this artifact"),
        "chain_word": cn.word(advance.patch_hash, "patchHash"),
        "hash_rule": "sha256-frontier-canonical-json",
        "kind": "coretex.transition-artifact/v3",
        "location": "",
        "resolved": False,
        "note": ("commitment decoded from the authenticated descriptor; transition artifacts "
                 "are fetched by the validator, not here"),
        "root": descriptor.patch_artifact_hash,
    }


# --------------------------------------------------------------------------- #
# Locks: what the runtime record binds, and what it only claims
# --------------------------------------------------------------------------- #
#: Locks the frontier manifest itself carries. These are addressed by ``newStateRoot``, which the
#: registry event carries and the EIP-712 digest signs — so they are CHAIN-BOUND.
MANIFEST_LOCKS = ("benchmark_law_root", "runtime_abi_root")

#: Locks that exist only inside the runtime-integration record. They are chain-bound only when
#: that record is itself addressed by the epoch's ``coreVersionHash``.
TRANSITIVE_LOCKS = ("counter_resource_law_root", "counter_root", "evaluation_law_root",
                    "renderer_root", "runtime_artifact_root", "scorer_root")


def build_locks(manifest: Mapping[str, Any], runtime_record: Optional[Mapping[str, Any]], *,
                core_version_hash: str,
                record_root: Optional[str] = None) -> Tuple[Dict[str, Any], List[str]]:
    """The law locks, and the DISPUTE when two committed artifacts disagree.

    A dispute is not an error to resolve — it is a fact to publish. Two artifacts that a chain has
    committed to can disagree, and when they do the honest output says so, names both values, and
    DOWNGRADES everything that rests on the losing one. Silently preferring either would produce a
    snapshot that reproduces cleanly and asserts something no chain attests.

    The rule: the chain-addressed frontier manifest WINS, because it is addressed by a root the
    registry event carries and the receipt digest signs. The runtime-integration record is
    supplied out of band and is chain-bound only if ``coreVersionHash`` addresses it. When they
    disagree on a lock they share, every lock bound ONLY through that record becomes ``disputed``
    — not merely the one that differs, because the record's credibility is what was damaged.
    """
    locks: Dict[str, Any] = {}
    findings: List[str] = []
    record = runtime_record or {}
    claimed = record_locks(record) if record else {}
    chain_bound = bool(record_root) and cn.word(record_root, "record_root") == cn.word(
        core_version_hash, "core_version_hash")

    disputes: List[Dict[str, str]] = []
    for name in MANIFEST_LOCKS:
        value = manifest.get(name)
        if value is None:
            continue
        entry: Dict[str, Any] = {"binding": "manifest",
                                 "root": cn.bare_root(value, name)}
        claimed_value = claimed.get(name)
        if claimed_value is not None:
            claimed_root = cn.bare_root(claimed_value, f"{name}.record")
            if claimed_root != entry["root"]:
                entry["disputed_by_runtime_record"] = claimed_root
                disputes.append({"chain_addressed_manifest": entry["root"], "lock": name,
                                 "runtime_integration_record": claimed_root})
            else:
                entry["also_in_runtime_record"] = True
        locks[name] = entry

    disputed = bool(disputes)
    for name in TRANSITIVE_LOCKS:
        value = claimed.get(name)
        if value is None:
            continue
        locks[name] = {"binding": "disputed" if disputed else
                                  ("transitive" if not chain_bound else "chain-bound"),
                       "root": cn.bare_root(value, name)}

    for dispute in disputes:
        findings.append(
            f"LOCK DISPUTE on {dispute['lock']}: the chain-addressed frontier manifest says "
            f"{dispute['chain_addressed_manifest']} and the supplied runtime-integration record "
            f"says {dispute['runtime_integration_record']}. The manifest wins and is what is "
            "published; every lock bound only through that record is downgraded to `disputed` and "
            "must not be relied on for this chain")
    if not chain_bound:
        findings.append(
            "the runtime-integration record is NOT chain-bound for this epoch, so every lock "
            "marked `transitive` or `disputed` — the scorer, counter, counter-resource-law and "
            "renderer roots — is not attested by this chain")

    block: Dict[str, Any] = {
        "binding_note": (
            "`manifest` locks are addressed by newStateRoot, which the registry event carries and "
            "the EIP-712 digest signs. `transitive` locks live only in the runtime-integration "
            "record; they are chain-bound ONLY when runtime_record_chain_bound is true. "
            "`disputed` means the record disagrees with the chain-addressed manifest on a lock "
            "they share, so NOTHING bound only through that record may be relied on. The rig "
            "registry pins six values and the counter-resource law is not among them"),
        "locks": locks,
        "runtime_record_chain_bound": chain_bound,
    }
    if disputes:
        block["dispute_resolution"] = (
            "the chain-addressed frontier manifest WINS and is what is published; the "
            "runtime-integration record's value is recorded as disputed_by_runtime_record")
        block["disputes"] = sorted(disputes, key=lambda d: d["lock"])
    if record_root is not None:
        block["runtime_record_root"] = cn.bare_root(record_root, "runtime_record_root")
    return block, findings


# Descriptor-v3's ``coreVersionHash`` is the address of ONE compatibility-lock document.  Keep
# this schema transcription local to the independent client: importing the coordinator's
# implementation would make a clean installed-wheel replay depend on a private source checkout.
COMPATIBILITY_LOCK_SCHEMA = "coretex.compatibility-lock/v1"
COMPATIBILITY_LOCK_HASH_RULE = "compatibility-lock-root"
COMPATIBILITY_LOCK_DOMAIN = b"\x19" + COMPATIBILITY_LOCK_SCHEMA.encode("utf-8") + b"\n"
COMPATIBILITY_LOCK_ROOT_RULES: Dict[str, str] = {
    "benchmark_law_root": "sha256-bytes",
    "counter_resource_law_root": "sha256-frontier-canonical-json",
    "counter_root": "sha256-benchmark-canonical-json",
    "evaluation_law_root": "sha256-benchmark-canonical-json",
    "evaluation_law_scorer_root": "sha256-benchmark-canonical-json",
    "miner_module_abi_root": "sha256-frontier-canonical-json",
    "renderer_root": "sha256-benchmark-canonical-json",
    "runtime_artifact_root": "sha256-file-tree",
    "runtime_protocol_abi_root": "sha256-frontier-canonical-json",
    "runtime_wheel_root": "sha256-bytes",
}
COMPATIBILITY_LOCK_LITERAL_NAMES = (
    "input_envelope_schema", "module_manifest_schema", "store_schema",
    "transition_descriptor_schema")
COMPATIBILITY_LOCK_NAMES = tuple(sorted(
    tuple(COMPATIBILITY_LOCK_ROOT_RULES) + COMPATIBILITY_LOCK_LITERAL_NAMES))
COMPATIBILITY_LOCK_NON_LOCK_IDENTITIES = (
    "portability_runtime_config_root", "portability_support_scope_root")


def _lock_closed(mapping: Any, allowed: Sequence[str], where: str) -> Mapping[str, Any]:
    if not isinstance(mapping, Mapping):
        raise ReproductionError(
            "COMPATIBILITY_LOCK_MALFORMED",
            f"{where} must be an object, got {type(mapping).__name__}")
    keys = set(mapping)
    missing = sorted(set(allowed) - keys)
    unknown = sorted(keys - set(allowed))
    if missing or unknown:
        raise ReproductionError(
            "COMPATIBILITY_LOCK_MALFORMED",
            f"{where} is closed: missing={missing}, unexpected={unknown}")
    return mapping


def validate_compatibility_lock(document: Mapping[str, Any], *,
                                expected_root: str) -> str:
    """Strictly validate and re-address ``coretex.compatibility-lock/v1``.

    The root is deliberately not a SHA-256 CAS root: it is the domain-separated keccak256 of the
    canonical body with ``lock_root`` removed.  Both the self-declared root and the chain's
    ``coreVersionHash`` must equal that recomputation.
    """
    from .keccak256 import keccak256_hex

    doc = _lock_closed(document, ("format", "legacy_aliases", "lock_root", "locks"),
                       "compatibility lock")
    if doc["format"] != COMPATIBILITY_LOCK_SCHEMA:
        raise ReproductionError(
            "COMPATIBILITY_LOCK_SCHEMA_MISMATCH",
            f"format {doc['format']!r} is not {COMPATIBILITY_LOCK_SCHEMA!r}")
    locks = _lock_closed(doc["locks"], COMPATIBILITY_LOCK_NAMES,
                         "compatibility lock.locks")
    for name, hash_rule in COMPATIBILITY_LOCK_ROOT_RULES.items():
        entry = _lock_closed(locks[name], ("hash_rule", "kind", "root"),
                             f"compatibility lock.locks.{name}")
        if entry["kind"] != "root" or entry["hash_rule"] != hash_rule:
            raise ReproductionError(
                "COMPATIBILITY_LOCK_MALFORMED",
                f"locks.{name} must be kind='root' with hash_rule={hash_rule!r}")
        try:
            cn.bare_root(entry["root"], f"locks.{name}.root")
        except ValueError as exc:
            raise ReproductionError("COMPATIBILITY_LOCK_MALFORMED", str(exc)) from exc
    for name in COMPATIBILITY_LOCK_LITERAL_NAMES:
        entry = _lock_closed(locks[name], ("kind", "schema", "version"),
                             f"compatibility lock.locks.{name}")
        if entry["kind"] != "literal" or not isinstance(entry["schema"], str) \
                or not entry["schema"]:
            raise ReproductionError(
                "COMPATIBILITY_LOCK_MALFORMED",
                f"locks.{name} must be a literal with a non-empty schema")
        version = entry["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise ReproductionError(
                "COMPATIBILITY_LOCK_MALFORMED",
                f"locks.{name}.version must be a non-negative integer")

    aliases = doc["legacy_aliases"]
    if not isinstance(aliases, list):
        raise ReproductionError(
            "COMPATIBILITY_LOCK_MALFORMED", "compatibility lock.legacy_aliases must be an array")
    seen = set()
    identities = set(COMPATIBILITY_LOCK_NAMES) | set(COMPATIBILITY_LOCK_NON_LOCK_IDENTITIES)
    for index, raw_alias in enumerate(aliases):
        alias = _lock_closed(raw_alias, ("artifact", "field", "resolves_to"),
                             f"compatibility lock.legacy_aliases[{index}]")
        for field_name in ("artifact", "field", "resolves_to"):
            if not isinstance(alias[field_name], str) or not alias[field_name]:
                raise ReproductionError(
                    "COMPATIBILITY_LOCK_MALFORMED",
                    f"legacy_aliases[{index}].{field_name} must be a non-empty string")
        if alias["resolves_to"] not in identities:
            raise ReproductionError(
                "COMPATIBILITY_LOCK_MALFORMED",
                f"legacy_aliases[{index}].resolves_to names no compatibility-lock identity")
        key = (alias["artifact"], alias["field"])
        if key in seen:
            raise ReproductionError(
                "COMPATIBILITY_LOCK_MALFORMED", f"legacy_aliases repeats {key!r}")
        seen.add(key)

    try:
        recorded = cn.bare_root(doc["lock_root"], "compatibility lock.lock_root")
        expected = cn.root_from_word(expected_root, "state.context.core_version_hash")
        body = {key: value for key, value in doc.items() if key != "lock_root"}
        computed = keccak256_hex(COMPATIBILITY_LOCK_DOMAIN + cn.canonical_bytes(body))
    except ValueError as exc:
        raise ReproductionError("COMPATIBILITY_LOCK_MALFORMED", str(exc)) from exc
    if recorded != computed or expected != computed:
        raise ReproductionError(
            "COMPATIBILITY_LOCK_ROOT_MISMATCH",
            f"recorded={recorded}, chain={expected}, recomputed={computed}")
    return computed


def verify_compatibility_lock_bytes(data: bytes, *, expected_root: str) -> Dict[str, Any]:
    """Parse canonical served bytes, then validate and re-address the compatibility lock."""
    from . import frontier as fr

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ReproductionError(
            "COMPATIBILITY_LOCK_MALFORMED",
            f"compatibility-lock CAS returned {type(data).__name__}, not bytes")
    served = bytes(data)
    try:
        document = fr.parse_json(served.decode("utf-8"))
        canonical = cn.canonical_bytes(document)
    except (UnicodeDecodeError, fr.FrontierError) as exc:
        raise ReproductionError("COMPATIBILITY_LOCK_MALFORMED", str(exc)) from exc
    if served != canonical:
        raise ReproductionError(
            "COMPATIBILITY_LOCK_NON_CANONICAL",
            "served compatibility-lock bytes decode but are not the canonical byte string")
    validate_compatibility_lock(document, expected_root=expected_root)
    return dict(document)


def build_locks_v3(state_manifest: Mapping[str, Any],
                   compatibility_lock: Mapping[str, Any],
                   runtime_record: Optional[Mapping[str, Any]] = None, *,
                   core_version_hash: str,
                   record_root: Optional[str] = None) -> Tuple[Dict[str, Any], List[str]]:
    """Descriptor-v3 locks from the chain-addressed compatibility-lock document alone.

    ``runtime_record`` and ``record_root`` remain accepted only to avoid breaking callers that
    share a v1/v2 call shape.  They are intentionally not read: an out-of-band runtime record can
    neither add nor dispute a v3 chain lock.
    """
    del runtime_record, record_root
    lock_root = validate_compatibility_lock(
        compatibility_lock, expected_root=core_version_hash)
    source_locks = compatibility_lock["locks"]
    locks = {name: {**dict(source_locks[name]), "binding": "chain"}
             for name in COMPATIBILITY_LOCK_NAMES}

    benchmark = state_manifest.get("benchmark_law_root")
    if benchmark is None:
        raise ReproductionError(
            "V3_MANIFEST_BENCHMARK_LOCK_MISSING",
            "descriptor-v3 frontier manifest has no benchmark_law_root to cross-check")
    benchmark_root = cn.bare_root(benchmark, "state_manifest.benchmark_law_root")
    locked_benchmark = source_locks["benchmark_law_root"]["root"]
    if benchmark_root != locked_benchmark:
        raise ReproductionError(
            "V3_MANIFEST_BENCHMARK_LOCK_MISMATCH",
            f"manifest benchmark_law_root={benchmark_root}, compatibility lock={locked_benchmark}")
    cross_checked: List[Dict[str, str]] = [{
        "manifest_field": "benchmark_law_root",
        "resolves_to": "benchmark_law_root",
        "root": benchmark_root,
    }]

    findings: List[str] = []
    non_lock_identities: List[Dict[str, Any]] = []
    explicit = "compatibility_lock_root" in state_manifest
    if explicit:
        declared_lock = cn.bare_root(
            state_manifest["compatibility_lock_root"],
            "state_manifest.compatibility_lock_root")
        if declared_lock != lock_root:
            raise ReproductionError(
                "V3_MANIFEST_COMPATIBILITY_LOCK_MISMATCH",
                f"manifest compatibility_lock_root={declared_lock}, chain lock={lock_root}")
        runtime_abi = state_manifest.get("runtime_abi_root")
        if runtime_abi is None:
            raise ReproductionError(
                "V3_MANIFEST_RUNTIME_ABI_LOCK_MISSING",
                "an explicit compatibility-lock manifest must carry runtime_abi_root")
        runtime_root = cn.bare_root(runtime_abi, "state_manifest.runtime_abi_root")
        miner_abi_root = source_locks["miner_module_abi_root"]["root"]
        if runtime_root != miner_abi_root:
            raise ReproductionError(
                "V3_MANIFEST_RUNTIME_ABI_LOCK_MISMATCH",
                f"manifest runtime_abi_root={runtime_root}, miner_module_abi_root={miner_abi_root}")
        cross_checked.append({"manifest_field": "runtime_abi_root",
                              "resolves_to": "miner_module_abi_root",
                              "root": runtime_root})
        binding_note = (
            "every lock is `chain`-bound: the compatibility-lock document is content-addressed "
            "by its OWN lock root, the epoch context's coreVersionHash IS that root, and the "
            "served bytes are re-addressed on arrival. There is one authoritative document, so "
            "there is no second source to dispute with and no transitive contagion to spread. "
            "The explicit frontier manifest's compatibility_lock_root and runtime_abi_root are "
            "cross-checked against that authoritative document")
    else:
        runtime_abi = state_manifest.get("runtime_abi_root")
        if runtime_abi is None:
            raise ReproductionError(
                "V3_MANIFEST_RUNTIME_IDENTITY_MISSING",
                "legacy fieldless descriptor-v3 manifest has no runtime_abi_root identity")
        runtime_root = cn.bare_root(runtime_abi, "state_manifest.runtime_abi_root")
        non_lock_identities.append({
            "binding": "chain-addressed-manifest",
            "identity": "portability_support_scope_root",
            "kind": "declared-not-locked",
            "manifest_field": "runtime_abi_root",
            "not_compared_to_lock": "miner_module_abi_root",
            "root": runtime_root,
        })
        findings.append(
            f"legacy fieldless descriptor-v3 manifest runtime_abi_root {runtime_root} is recorded "
            "as portability_support_scope_root (declared-not-locked) and was NOT compared with "
            "the authoritative miner_module_abi_root compatibility lock")
        binding_note = (
            "every lock is `chain`-bound: the compatibility-lock document is content-addressed "
            "by its OWN lock root, the epoch context's coreVersionHash IS that root, and the "
            "served bytes are re-addressed on arrival. There is one authoritative document, so "
            "there is no second source to dispute with and no transitive contagion to spread. "
            "The values the chain-addressed frontier manifest also carries are cross-checked "
            "under the manifest generation's declared rules, never by matching an ambiguous "
            "field name. This legacy fieldless descriptor-v3 manifest's runtime_abi_root is "
            "recorded as the declared-not-locked portability_support_scope_root; it is "
            "deliberately not compared with the authoritative miner_module_abi_root lock")

    block: Dict[str, Any] = {
        "binding_note": binding_note,
        "compatibility_lock_root": lock_root,
        "cross_checked_against_manifest": cross_checked,
        "lock_schema": COMPATIBILITY_LOCK_SCHEMA,
        "locks": locks,
        "runtime_record_chain_bound": True,
    }
    if non_lock_identities:
        block["legacy_manifest_non_lock_identities"] = non_lock_identities
    return block, findings


#: Where each lock lives inside a ``coretex.runtime-integrated-pre-rig/v1`` record.
#:
#: The record states several of these more than once — ``abi_root`` appears under
#: ``identities.abi``, ``evaluation_law.runtime_identity`` and ``runtime_config.runtime_identity``
#: — so a reader that grabbed the first path it found could pick up a stale copy without noticing.
#: ``identities`` is the canonical block and is the only one consulted.
RUNTIME_RECORD_LOCK_PATHS: Dict[str, Tuple[str, ...]] = {
    "benchmark_law_root": ("identities", "law", "benchmark_law_root"),
    "counter_resource_law_root": ("identities", "counter", "counter_resource_law_root"),
    "counter_root": ("identities", "counter", "root"),
    "evaluation_law_root": ("identities", "law", "evaluation_law_root"),
    "renderer_root": ("identities", "renderer", "root"),
    "runtime_abi_root": ("identities", "abi", "root"),
    "runtime_artifact_root": ("identities", "runtime", "artifact_root"),
    "scorer_root": ("identities", "scorer", "root"),
}


def record_locks(runtime_record: Mapping[str, Any]) -> Dict[str, str]:
    """Flatten a runtime-integration record's ``identities`` block into ``lock -> root``."""
    out: Dict[str, str] = {}
    for name, path in RUNTIME_RECORD_LOCK_PATHS.items():
        node: Any = runtime_record
        for step in path:
            if not isinstance(node, Mapping) or step not in node:
                node = None
                break
            node = node[step]
        if isinstance(node, str):
            out[name] = node
    return out


def record_root_of(runtime_record: Mapping[str, Any]) -> Optional[str]:
    """The record's SELF-DECLARED root.

    Not recomputed, and that is the point rather than a shortcut: the value is a claim the record
    makes about itself, and whether it is TRUE is decided by comparing it to the epoch's
    ``coreVersionHash`` — which is what :func:`build_locks` does through
    ``runtime_record_chain_bound``. Recomputing a hash over the file's own bytes would answer a
    different and much less interesting question (whether the file was pretty-printed).
    """
    value = runtime_record.get("record_root")
    return cn.bare_root(value, "record_root") if isinstance(value, str) else None


# --------------------------------------------------------------------------- #
# The entry point a clean installation runs
# --------------------------------------------------------------------------- #
def reproduce_from_chain(published: Mapping[str, Any], *, rpc_url: str,
                         store_dir: str, runtime_record: Optional[Mapping[str, Any]] = None,
                         chunk_blocks: int = 2000,
                         min_interval: float = 0.7,
                         production_authority: bool = False) -> Tuple[Dict[str, Any], ComparisonResult]:
    """Rebuild a published snapshot from chain truth, and compare. NO KEY IS TOUCHED.

    Everything the rebuild needs that is not on the chain is read from the PUBLISHED payload's own
    self-describing fields — the addresses, the observation block, the epoch, the log window, the
    lineage floor. That is not circular: those fields select WHAT TO READ, and every value that
    ends up in the reconstruction is read back from the chain, the logs, the calldata or a
    content-addressed object that was rehashed on arrival. A published field that lied about the
    observation block would simply make the reconstruction describe a different block and fail to
    match — which is the correct outcome.

    The signature is not consulted here and this function takes no signer. Verify it separately
    with :func:`snapshot.verify_signature_artifact`, and only after this has returned identical.
    """
    from . import join as jn_mod
    from . import publication as pub_mod
    from . import resolver_schema_constants as constants
    from . import rig_events as rig_mod
    from .keccak256 import keccak256_hex as _kh
    from .rpc import JsonRpc, RigViews, selector as _sel, _encode_uint as _enc

    check_shape(published, production_authority=production_authority)
    declared_schema = schema_of(published)
    descriptor_v3 = declared_schema == SCHEMA_V3
    chain_id = int(published["chain"]["chain_id"])
    block = int(published["chain"]["observation"]["block_number"])
    epoch = int(published["epoch"])
    registry = published["contracts"]["registry"]["address"]
    mining = published["contracts"]["mining"]["address"]
    verifier = published["contracts"]["verifier"]["address"]
    from_block = int(published["migration"]["log_window_from_block"])
    floor = int(published["migration"]["lineage_floor_epoch"])
    policy = published["chain"]["observation"]["finality_policy"]

    rpc = JsonRpc(rpc_url, chunk_blocks=chunk_blocks, min_interval=min_interval)
    rpc.assert_chain(chain_id)
    deployment = rig_mod.RigDeployment(chain_id=chain_id, registry=registry, mining=mining,
                                       verifier=verifier)
    views = RigViews(rpc, deployment, block=block)

    def addr(to: str, sig: str) -> str:
        return "0x" + rpc.eth_call(to=to, data=_sel(sig), block=block)[-20:].hex()

    def uint(to: str, sig: str, arg: Optional[int] = None) -> int:
        data = _sel(sig) + (_enc(arg) if arg is not None else "")
        return int.from_bytes(rpc.eth_call(to=to, data=data, block=block), "big")

    def wordcall(to: str, sig: str, arg: Optional[int] = None) -> str:
        data = _sel(sig) + (_enc(arg) if arg is not None else "")
        return "0x" + rpc.eth_call(to=to, data=data, block=block)[:32].hex()

    built: Dict[str, Any] = {
        "schema": declared_schema,
        "version": cn.narrow(3 if descriptor_v3 else int(published["version"]), "version"),
        "protocol": rig_mod.PROTOCOL_RIG_EXACT if descriptor_v3 else PROTOCOL_ID,
        "classification": (CLASSIFICATION_PRODUCTION if production_authority
                           else CLASSIFICATION_REHEARSAL),
        "production_authority": bool(production_authority),
        "disclosure": (published["disclosure"] if production_authority else
                       (constants.DISCLOSURE_V3 if descriptor_v3 else constants.DISCLOSURE)),
        "canonicalization": constants.CANONICALIZATION,
        "derivation": (constants.DERIVATION_V3 if descriptor_v3 else
                       (constants.DERIVATION_V1 if declared_schema == SCHEMA_V1
                        else constants.DERIVATION_V2)),
        "prior": constants.PRIOR,
        "epoch": cn.narrow(epoch, "epoch"),
    }
    # THE ONE KEY THAT DIFFERS BETWEEN THE VERSIONS, and both are ADOPTED from the published
    # payload rather than generated here.
    #
    # For v1's `resolver`, adoption is forced: a key id names WHO claimed the resolution, and no
    # chain can say that. It lives inside the bytes precisely so that substituting a signer
    # changes them.
    #
    # For v2's `authority`, adoption is a STATED LIMITATION rather than a necessity. It is a
    # schema constant — the same cache-vs-authority statement in every v2 snapshot — so it
    # belongs in `resolver_schema_constants` alongside `derivation` and `canonicalization`,
    # transcribed from a real published artifact. No v2 artifact exists yet to transcribe from,
    # and inventing prose that has to match byte-for-byte is how this package already lost a run
    # (the `checks` vocabulary). So it is adopted until a v2 snapshot is published, and
    # `adopted_blocks` in the comparison says so rather than letting a reader assume it was
    # independently derived.
    identity_key = "resolver" if declared_schema == SCHEMA_V1 else "authority"
    built[identity_key] = published[identity_key]

    header_block = rpc.call("eth_getBlockByNumber", [hex(block), False])
    built["chain"] = build_chain(
        chain_id=chain_id, block_number=block, block_hash=header_block["hash"],
        parent_hash=header_block["parentHash"],
        block_timestamp=int(header_block["timestamp"], 16),
        required_confirmations=int(policy["required_confirmations"]), mode=str(policy["mode"]))

    identities = {}
    for role, address in (("registry", registry), ("verifier", verifier), ("mining", mining)):
        code = rpc.code(address, block=block)
        identities[role] = {"address": address, "code_hash": "0x" + _kh(code),
                            "code_size": len(code)}
    built["contracts"] = build_contracts(identities)

    built["wiring"] = build_wiring(
        coordinator_signer=addr(mining, "coordinatorSigner()"),
        current_epoch=uint(mining, "currentEpoch()"), cutover_epoch=uint(mining, "cutoverEpoch()"),
        domain_separator=rpc.eth_call(to=mining, data=_sel("DOMAIN_SEPARATOR()"), block=block)[:32],
        mining_core_tex_verifier=addr(mining, "coreTexVerifier()"),
        registry_core_tex_verifier=addr(registry, "coreTexVerifier()"),
        registry_epoch_clock=addr(registry, "epochClock()"),
        verifier_core_tex_registry=addr(verifier, "coreTexRegistry()"),
        verifier_mining=addr(verifier, "mining()"))

    context = {"configured": views.epoch_has_context(epoch), "epoch": epoch}
    context_getters = (
        (("parent_state_root", "epochParentStateRoot(uint64)"),
         ("core_version_hash", "epochCoreVersionHash(uint64)"),
         ("epoch_context_root", "epochContextRoot(uint64)"),
         ("hidden_seed_commit", "epochHiddenSeedCommit(uint64)"))
        if descriptor_v3 else
        (("parent_state_root", "epochParentStateRoot(uint64)"),
         ("corpus_root", "epochCorpusRoot(uint64)"),
         ("active_frontier_root", "epochActiveFrontierRoot(uint64)"),
         ("baseline_manifest_hash", "epochBaselineManifestHash(uint64)"),
         ("core_version_hash", "epochCoreVersionHash(uint64)"),
         ("hidden_seed_commit", "epochHiddenSeedCommit(uint64)")))
    for name, sig in context_getters:
        context[name] = wordcall(registry, sig, epoch)
    sealed = views.epoch_finalized(epoch)
    count = views.transition_count(epoch)
    observed_header = (views.header(epoch) if descriptor_v3 else views.legacy_v2_header(epoch))
    state_builder = build_state_v3 if descriptor_v3 else build_state
    built["state"] = state_builder(
        epoch=epoch, context=context,
        live_state_root=wordcall(registry, "liveStateRoot(uint64)", epoch),
        transition_count=count, sealed=sealed, served=count > 0,
        header=({k: "0x" + v for k, v in observed_header.items()} if sealed else None),
        finalized_at=(uint(registry, "finalizedAt(uint64)", epoch) if sealed else None))

    logs = rpc.get_logs(addresses=list(deployment.addresses), topics=[], from_block=from_block,
                        to_block=block)
    decoded = (rig_mod.scan(logs, deployment) if descriptor_v3
               else rig_mod.scan_legacy_v2(logs, deployment))
    cache: Dict[str, str] = {}

    def calldata_for(tx: str) -> str:
        if tx not in cache:
            cache[tx] = str(rpc.transaction(tx).get("input", ""))
        return cache[tx]

    joiner = (jn_mod.join_all if descriptor_v3 else
              (jn_mod.join_all_legacy_v1 if declared_schema == SCHEMA_V1
               else jn_mod.join_all_legacy_v2))
    joined = joiner(
        decoded, calldata_for=calldata_for,
        domain_separator=bytes.fromhex(built["wiring"]["domain_separator"][2:]),
        coordinator_signer=built["wiring"]["coordinator_signer"])
    selected = [t for t in joined.transitions if t.advance.epoch == epoch]
    built["transitions"] = (
        build_transitions_v3(selected) if descriptor_v3 else
        (build_transitions_v1(selected) if declared_schema == SCHEMA_V1
         else build_transitions(selected)))

    steps = []
    walk = epoch
    while walk >= floor:
        has_context = views.epoch_has_context(walk)
        served = views.transition_count(walk)
        is_sealed = views.epoch_finalized(walk)
        step: Dict[str, Any] = {"context_set": has_context, "epoch": walk, "sealed": is_sealed,
                                "served": served > 0, "transition_count": served,
                                "uncommitted": False}
        if not has_context:
            # The real chain does revert here — F9 is live below this registry's genesis.
            step["final_root_source"] = "none (EpochContextNotSet)"
        else:
            step["context_parent"] = wordcall(registry, "epochParentStateRoot(uint64)", walk)
            if is_sealed:
                if descriptor_v3:
                    step["final_root_source"] = "liveStateRoot (frozen by epochFinalized)"
                    step["final_root"] = wordcall(registry, "liveStateRoot(uint64)", walk)
                else:
                    step["final_root_source"] = "getHeader.finalStateRoot"
                    step["final_root"] = "0x" + views.legacy_v2_header(walk)["final_state_root"]
            else:
                step["final_root_source"] = "liveStateRoot"
                step["final_root"] = wordcall(registry, "liveStateRoot(uint64)", walk)
        steps.append(step)
        walk -= 1
    built["epoch_lineage"] = build_epoch_lineage(
        epoch=epoch, steps=steps, continuous=True, terminates_at=floor, findings=[],
        rule=LINEAGE_RULE_V3 if descriptor_v3 else LINEAGE_RULE)

    migration_builder = build_migration_v3 if descriptor_v3 else build_migration
    built["migration"] = migration_builder(
        registry=registry, registry_code_hash=built["contracts"]["registry"]["code_hash"],
        verifier_bound_registry=built["wiring"]["verifier_coreTexRegistry"],
        epoch_clock=built["wiring"]["registry_epochClock"],
        cutover_epoch=built["wiring"]["cutover_epoch"], lineage_floor_epoch=floor,
        log_window_from_block=from_block)

    store = pub_mod.FilesystemCAS(store_dir)
    epoch_context_manifest = None
    epoch_context_root = None
    epoch_context_bytes_len = None
    compatibility_lock = None
    compatibility_lock_root = None
    if descriptor_v3:
        epoch_context_root = cn.root_from_word(
            built["state"]["context"]["epoch_context_root"], "epoch_context_root")
        # Fetch the addressed admission context independently of the state manifest and rehash the
        # exact served canonical bytes before any of its fields can inform derived presentation.
        epoch_context_manifest = pub_mod.fetch_json(
            epoch_context_root, hash_rule=pub_mod.HASH_RULE_FRONTIER_JSON, store=store)
        rig_mod.validate_epoch_context(epoch_context_manifest)
        served_context = store.get(epoch_context_root)
        rig_mod.verify_epoch_context_bytes(served_context, expected_root=epoch_context_root)
        epoch_context_bytes_len = len(served_context)
        compatibility_lock_root = cn.root_from_word(
            built["state"]["context"]["core_version_hash"], "core_version_hash")
        # Unlike the ordinary SHA-256 CAS families, a compatibility lock addresses its canonical
        # BODY under a domain-separated keccak rule. Fetch by the chain word first, then verify
        # the exact served bytes and both copies of the root before any lock value is consumed.
        compatibility_lock = verify_compatibility_lock_bytes(
            store.get(compatibility_lock_root),
            expected_root=built["state"]["context"]["core_version_hash"])
    head_root = built["state"]["live_state_root"][2:]
    manifest = pub_mod.fetch_json(head_root, hash_rule=pub_mod.HASH_RULE_FRONTIER_JSON,
                                  store=store)
    built["profiles"] = build_profiles(manifest)
    built["composition"] = build_composition(manifest)

    if descriptor_v3:
        locks_block, lock_findings = build_locks_v3(
            manifest, compatibility_lock or {},
            core_version_hash=built["state"]["context"]["core_version_hash"])
    else:
        record_root = record_root_of(runtime_record) if runtime_record else None
        locks_block, lock_findings = build_locks(
            manifest, runtime_record,
            core_version_hash=built["state"]["context"]["core_version_hash"],
            record_root=record_root)
    built["locks"] = locks_block
    built["findings"] = sorted(set(lock_findings))

    refs: List[Dict[str, Any]] = []
    for item in selected:
        index = item.advance.transition_index
        artifact_ordinal = 14 if descriptor_v3 else 15
        refs.append({"chain_binding": (f"receipt.artifactHash of transition {index} — signed "
                                       f"member {artifact_ordinal}, bound by the EIP-712 digest inside the "
                                       "receiptHash preimage"),
                     "chain_word": cn.word(item.receipt["artifactHash"], "artifactHash"),
                     # SIGNED-MANIFEST-BODY, not frontier-JSON. Rehashing a signed manifest under
                     # the frontier rule reports a tamper that is not there — worse than not
                     # checking, because it burns an operator's trust in the check.
                     "hash_rule": pub_mod.HASH_RULE_SIGNED_MANIFEST_BODY,
                     "kind": "candidate-release", "location": "", "resolved": False,
                     "note": ("commitment recorded; candidate bundles are not fetched by the "
                              "resolver"),
                     "root": cn.root_from_word(item.receipt["artifactHash"], "artifactHash")})
        refs.append({"chain_binding": f"registry log evalReportHash of transition {index}",
                     "chain_word": cn.word(item.advance.eval_report_hash, "evalReportHash"),
                     "hash_rule": pub_mod.HASH_RULE_FRONTIER_JSON,
                     "kind": ("coretex.memory-eval-artifact.v2" if descriptor_v3 else
                              "coretex.memory-eval-artifact.v1"),
                     "location": "", "resolved": False,
                     "note": ("commitment recorded; eval artifacts are fetched by the validator, "
                              "not here"),
                     "root": cn.root_from_word(item.advance.eval_report_hash, "evalReportHash")})
        if descriptor_v3:
            refs.append(build_transition_artifact_ref_v3(item.advance))
    refs.append({"chain_binding": "registry.liveStateRoot(epoch) — the confirmed head",
                 "chain_word": built["state"]["live_state_root"],
                 "hash_rule": pub_mod.HASH_RULE_FRONTIER_JSON,
                 "kind": "coretex.memory-frontier.v1", "location": f"cas://{head_root}",
                 "resolved": True, "root": head_root, "size": len(store.get(head_root))})
    if descriptor_v3 and epoch_context_root is not None:
        refs.append({
            "chain_binding": "registry.epochContextRoot(epoch) — the epoch admission context",
            "chain_word": built["state"]["context"]["epoch_context_root"],
            "hash_rule": pub_mod.HASH_RULE_FRONTIER_JSON,
            "kind": rig_mod.EPOCH_CONTEXT_FORMAT,
            "location": f"cas://{epoch_context_root}",
            "resolved": True,
            "root": epoch_context_root,
            "size": int(epoch_context_bytes_len or 0),
        })
    if descriptor_v3 and compatibility_lock_root is not None:
        refs.append({
            "chain_binding": "epoch context coreVersionHash — the lock root IS the address",
            "chain_word": built["state"]["context"]["core_version_hash"],
            "hash_rule": COMPATIBILITY_LOCK_HASH_RULE,
            "kind": COMPATIBILITY_LOCK_SCHEMA,
            "location": "",
            "resolved": False,
            "note": "fetched and re-addressed; see locks.cross_checked_against_manifest",
            "root": compatibility_lock_root,
        })
    if not descriptor_v3 and record_root is not None:
        refs.append({"chain_binding": ("epoch context coreVersionHash (bound only if the two are "
                                       "equal)"),
                     "chain_word": built["state"]["context"]["core_version_hash"],
                     "hash_rule": pub_mod.HASH_RULE_FRONTIER_JSON,
                     "kind": "coretex.runtime-integrated-pre-rig/v1", "location": "",
                     "resolved": False,
                     "note": "supplied out of band; see locks.runtime_record_chain_bound",
                     "root": record_root})
    built["artifacts"] = build_artifacts(refs)
    comparison = compare(built, published)
    comparison.adopted_blocks = ([identity_key, "disclosure"] if production_authority
                                 else [identity_key])
    return built, comparison
