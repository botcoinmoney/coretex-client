# SPDX-License-Identifier: Apache-2.0
"""Reproduce the resolver's per-epoch snapshot — ``coretex.rig-state.resolver-snapshot/v1``.

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

SCHEMA = "coretex.rig-state.resolver-snapshot/v1"
SCHEMA_VERSION = 1
PROTOCOL_ID = "coretex.rig-state.v1"
SUPERSEDED_PROTOCOLS = ("coretex.memory-frontier.v1", "coretex.state.v4")
CLASSIFICATION_REHEARSAL = "MAINNET_REHEARSAL"
CLASSIFICATION_CANONICAL_FORBIDDEN = "MAINNET_CANONICAL"

#: The 23 top-level keys. Fixed: a payload with 22 or 24 is not this schema.
TOP_LEVEL_KEYS: Tuple[str, ...] = (
    "artifacts", "canonicalization", "chain", "classification", "composition", "contracts",
    "derivation", "disclosure", "epoch", "epoch_lineage", "findings", "locks", "migration",
    "prior", "production_authority", "profiles", "protocol", "resolver", "schema", "state",
    "transitions", "version", "wiring")

#: Keys whose content is SPEC TEXT, identical in every snapshot of this schema.
#:
#: Named explicitly so a comparison report can never present "the constant blocks matched" as
#: evidence about a chain. Reproducing these proves the transcription is right and nothing else.
SCHEMA_CONSTANT_KEYS: Tuple[str, ...] = (
    "canonicalization", "classification", "derivation", "disclosure", "prior",
    "production_authority", "protocol", "resolver", "schema", "version")

#: Keys that are read back from the chain. These are what a reproduction actually proves.
CHAIN_DERIVED_KEYS: Tuple[str, ...] = tuple(
    k for k in TOP_LEVEL_KEYS if k not in SCHEMA_CONSTANT_KEYS)


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


def build_transition(transition: jn.JoinedTransition) -> Dict[str, Any]:
    """One joined transition, in the resolver's spelling.

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
            "word_count": cn.narrow(advance.word_count, "word_count"),
        },
        "transaction_hash": cn.word(advance.provenance.transaction_hash or "",
                                    "transaction_hash"),
        "transition_index": cn.narrow(advance.transition_index, "transition_index"),
    }


#: Which receipt members are wide (decimal strings) and which are narrow (JSON numbers).
_WIDE_RECEIPT_MEMBERS = ("rigId", "workUnitsBps", "difficultyCountSnapshot", "worldSeed")
_NARROW_RECEIPT_MEMBERS = ("epochId", "solveIndex", "outcome", "rulesVersion", "stateWordCount",
                           "scoreBeforePpm", "scoreAfterPpm", "issuedAt", "expiresAt")
_WORD_RECEIPT_MEMBERS = ("prevReceiptHash", "challengeId", "parentStateRoot", "newStateRoot",
                         "corpusRoot", "activeFrontierRoot", "coreVersionHash", "evalReportHash",
                         "patchHash", "artifactHash", "workPolicyHash")


def _receipt_block(values: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name in _WIDE_RECEIPT_MEMBERS:
        out[name] = cn.wide(int(values[name]), name)
    for name in _NARROW_RECEIPT_MEMBERS:
        out[name] = cn.narrow(int(values[name]), name)
    for name in _WORD_RECEIPT_MEMBERS:
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
            "note": ("schema-constant keys are SPEC TEXT and identical in every snapshot of this "
                     "schema; reproducing them proves the transcription is right and says nothing "
                     "about any chain. The chain-derived keys are what a reproduction proves"),
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


def check_shape(payload: Mapping[str, Any]) -> None:
    """Refuse a document that is not this schema before comparing anything."""
    if payload.get("schema") != SCHEMA:
        raise ReproductionError("SCHEMA_MISMATCH",
                                f"expected {SCHEMA!r}, got {payload.get('schema')!r}")
    if payload.get("classification") == CLASSIFICATION_CANONICAL_FORBIDDEN:
        raise ReproductionError(
            "CLASSIFICATION_REFUSED",
            "MAINNET_CANONICAL is not a classification this package will process")
    observed = tuple(sorted(payload))
    if observed != TOP_LEVEL_KEYS:
        missing = sorted(set(TOP_LEVEL_KEYS) - set(observed))
        extra = sorted(set(observed) - set(TOP_LEVEL_KEYS))
        raise ReproductionError(
            "SCHEMA_SHAPE_MISMATCH",
            f"this schema has exactly {len(TOP_LEVEL_KEYS)} top-level keys; missing={missing}, "
            f"unexpected={extra}")


# --------------------------------------------------------------------------- #
# The remaining chain-derived blocks
# --------------------------------------------------------------------------- #
def build_epoch_lineage(*, epoch: int, steps: Sequence[Mapping[str, Any]],
                        continuous: bool, terminates_at: int,
                        findings: Sequence[str] = ()) -> Dict[str, Any]:
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
        "rule": LINEAGE_RULE,
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
            "registry_state_advanced": cn.word(rig.STATE_ADVANCED_TOPIC0,
                                               "registry_state_advanced"),
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
        out.append({
            "chain_binding": str(entry["chain_binding"]),
            "chain_word": cn.word(entry["chain_word"], "chain_word"),
            "hash_rule": str(entry["hash_rule"]),
            "kind": str(entry["kind"]),
            "location": str(entry.get("location", "")),
            "note": str(entry["note"]),
            "resolved": bool(entry["resolved"]),
            "root": cn.bare_root(entry["root"], "root"),
        })
    return sorted(out, key=lambda item: (item["kind"], item["root"]))


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
    record_locks = record.get("locks", record)
    chain_bound = bool(record_root) and cn.word(record_root, "record_root") == cn.word(
        core_version_hash, "core_version_hash")

    disputes: List[Dict[str, str]] = []
    for name in MANIFEST_LOCKS:
        value = manifest.get(name)
        if value is None:
            continue
        entry: Dict[str, Any] = {"binding": "manifest",
                                 "root": cn.bare_root(value, name)}
        claimed = record_locks.get(name)
        if claimed is not None:
            claimed_root = cn.bare_root(claimed, f"{name}.record")
            if claimed_root != entry["root"]:
                entry["disputed_by_runtime_record"] = claimed_root
                disputes.append({"chain_addressed_manifest": entry["root"], "lock": name,
                                 "runtime_integration_record": claimed_root})
            else:
                entry["also_in_runtime_record"] = True
        locks[name] = entry

    disputed = bool(disputes)
    for name in TRANSITIVE_LOCKS:
        value = record_locks.get(name)
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
