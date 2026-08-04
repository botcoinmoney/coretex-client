# SPDX-License-Identifier: Apache-2.0
"""Step 7: reproduce the resolver snapshot — the UNSIGNED payload first, the signature after.

THE ORDER IS THE WHOLE POINT AND IT IS ENFORCED, NOT ADVISED.

A resolver publishes a snapshot: a description of a confirmed CoreTex transition, signed so that
consumers can tell it came from the resolver. The tempting implementation is "check the signature,
then trust the payload". That makes the resolver an authority — and the protocol's entire claim is
that it is not one. So:

1. :func:`build_unsigned` reconstructs the payload from the chain, the logs, the calldata and the
   fetched artifacts, **without ever reading the published payload**;
2. :func:`reproduce` compares the reconstruction to the published payload **byte for byte**, over
   canonical bytes, before any key is consulted;
3. :func:`verify_signature` is a SEPARATE call, and its result is labelled TRANSPORT
   AUTHENTICATION. It answers "did the resolver send this?", never "is this true?".

A snapshot that reproduces byte-for-byte is true whether or not it was signed. A snapshot that is
signed but does not reproduce is a correctly-transmitted false statement, and the signature makes
it worse rather than better. :func:`reproduce` therefore refuses to accept a
``signature_valid=True`` as compensation for a mismatch, and there is no parameter that lets a
caller ask it to.

CANONICAL BYTES. The payload is canonicalised by :func:`frontier.canonical_bytes` — the same
authority the frontier manifests use — so "byte for byte" means something reproducible across
implementations rather than "the same after my JSON library got through with it". Floats are
refused by that canonicaliser, which is why every measurement in a snapshot is an integer.

WHAT IS DELIBERATELY EXCLUDED FROM THE UNSIGNED PAYLOAD. Anything the resolver observed but a
third party cannot re-derive: wall-clock time of publication, the resolver's own request counts,
endpoint identity. Including them would make the payload unreproducible on purpose, which is the
easiest way to quietly retire this check.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from . import join as jn
from . import historical_law as hl
from . import abi
from . import rig_events as rig
from .keccak256 import keccak256

SNAPSHOT_FORMAT = "coretex.rig-resolver-snapshot/v1"
#: The classification every snapshot this package produces carries. See :mod:`.export`.
CLASSIFICATION_REHEARSAL = "MAINNET_REHEARSAL"


class SnapshotError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ChainObservation:
    """The pinned chain state a snapshot is ABOUT. Every field is read at one block."""

    chain_id: int
    block_number: int
    block_hash: str
    registry: str
    mining: str
    verifier: str
    live_state_root: str
    transition_count: int
    epoch_finalized: bool
    coordinator_signer: str


def build_unsigned(*, transition: jn.JoinedTransition, law: hl.EpochLaw,
                   observation: ChainObservation,
                   artifact_roots: Mapping[str, str],
                   lineage: Sequence[jn.LineageStep] = ()) -> Dict[str, Any]:
    """The canonical UNSIGNED payload, from chain-derived facts only.

    Every value here is either read from a confirmed log, read from the pinned block's state,
    decoded from the transaction calldata, or the hash of a fetched artifact. Nothing is copied
    from a published snapshot and nothing is supplied by an operator.
    """
    receipt = transition.receipt
    advance = transition.advance
    credit = transition.credit
    payload: Dict[str, Any] = {
        "format": SNAPSHOT_FORMAT,
        "classification": CLASSIFICATION_REHEARSAL,
        "chain": {
            "chain_id": observation.chain_id,
            "block_number": observation.block_number,
            "block_hash": observation.block_hash,
        },
        "deployment": {
            "registry": observation.registry.lower(),
            "mining": observation.mining.lower(),
            "verifier": observation.verifier.lower(),
            "coordinator_signer": observation.coordinator_signer.lower(),
        },
        "epoch": {
            "epoch": advance.epoch,
            "live_state_root": observation.live_state_root,
            "transition_count": observation.transition_count,
            "finalized": observation.epoch_finalized,
            "law": law.as_dict(),
        },
        # The §7.4 key, spelled out rather than concatenated: a reader must be able to see that
        # patchHash is in it.
        "join_key": {
            "epoch": advance.epoch,
            "parent_state_root": advance.parent_state_root,
            "patch_hash": advance.patch_hash,
        },
        "transition": {
            "transition_index": advance.transition_index,
            "parent_state_root": advance.parent_state_root,
            "new_state_root": advance.new_state_root,
            "patch_hash": advance.patch_hash,
            "eval_report_hash": advance.eval_report_hash,
            "core_version_hash": advance.core_version_hash,
            "corpus_root": advance.corpus_root,
            "active_frontier_root": advance.active_frontier_root,
            "improvement_credits": advance.improvement_credits,
            "word_count": advance.word_count,
            "compact_patch_bytes_hex": advance.compact_patch_bytes.hex(),
            "miner": advance.miner.lower(),
        },
        "receipt": {
            "rig_id": credit.rig_id,
            "operator": credit.operator.lower(),
            "solve_index": credit.solve_index,
            "receipt_hash": transition.receipt_hash,
            "challenge_id": credit.challenge_id,
            "work_units_bps": credit.work_units_bps,
            "credits_earned": credit.credits_earned,
            "artifact_hash": receipt["artifactHash"],
            "work_policy_hash": receipt["workPolicyHash"],
            "rules_version": int(receipt["rulesVersion"]),
            "world_seed": int(receipt["worldSeed"]),
            "difficulty_count_snapshot": int(receipt["difficultyCountSnapshot"]),
            "score_before_ppm": int(receipt["scoreBeforePpm"]),
            "score_after_ppm": int(receipt["scoreAfterPpm"]),
            "issued_at": int(receipt["issuedAt"]),
            "expires_at": int(receipt["expiresAt"]),
            "prev_receipt_hash": receipt["prevReceiptHash"],
            "outcome": int(receipt["outcome"]),
        },
        "artifacts": {name: root for name, root in sorted(dict(artifact_roots).items())},
        # Same omit-never-null rule as elsewhere: a feed that did not report a block number is
        # not a snapshot of block `null`.
        "provenance": {key: value for key, value in (
            ("transaction_hash", str(advance.provenance.transaction_hash or "").lower() or None),
            ("block_number", advance.provenance.block_number),
            ("log_index", advance.provenance.log_index)) if value is not None},
        "checks": sorted(set(transition.checks)),
    }
    if lineage:
        payload["lineage"] = [
            {"epoch": step.epoch, "served": step.served, "sealed": step.sealed,
             "final_state_root": step.final_root, "source": step.source, "flagged": step.flagged}
            for step in lineage]
    # Canonicalising here (rather than at comparison time) fails fast on a value the canonical
    # form cannot represent — a float that crept in, a non-string key — at the point it was
    # introduced instead of three modules later.
    fr.canonical_bytes(payload)
    return payload


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """The bytes that ARE the payload. There is no other spelling of it."""
    return fr.canonical_bytes(payload)


def payload_hash(payload: Mapping[str, Any]) -> str:
    return fr.sha256_hex(canonical_bytes(payload))


@dataclass
class ReproductionResult:
    """Whether the published payload is the one the chain implies. Signature-independent."""

    reproduced: bool
    reconstructed_hash: str
    published_hash: Optional[str]
    #: Field paths that differ, deepest-first. Empty when ``reproduced``.
    differences: List[str]
    byte_length: int

    def as_dict(self) -> Dict[str, Any]:
        return {"reproduced": self.reproduced,
                "reconstructed_sha256": self.reconstructed_hash,
                "published_sha256": self.published_hash,
                "byte_length": self.byte_length,
                "differences": list(self.differences)}


def _diff(a: Any, b: Any, path: str, out: List[str]) -> None:
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                out.append(f"{path}.{key}: absent in reconstruction, published {b[key]!r}")
            elif key not in b:
                out.append(f"{path}.{key}: reconstructed {a[key]!r}, absent in published")
            else:
                _diff(a[key], b[key], f"{path}.{key}", out)
        return
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: {len(a)} entries reconstructed, {len(b)} published")
        for index, (left, right) in enumerate(zip(a, b)):
            _diff(left, right, f"{path}[{index}]", out)
        return
    if a != b:
        out.append(f"{path}: reconstructed {a!r}, published {b!r}")


def reproduce(reconstructed: Mapping[str, Any],
              published: Optional[Mapping[str, Any]]) -> ReproductionResult:
    """Compare BEFORE any signature check. A mismatch is never excused by a valid signature."""
    reconstructed_bytes = canonical_bytes(reconstructed)
    reconstructed_hash = fr.sha256_hex(reconstructed_bytes)
    if published is None:
        return ReproductionResult(
            reproduced=False, reconstructed_hash=reconstructed_hash, published_hash=None,
            differences=["no published snapshot was supplied, so there is nothing to reproduce; "
                         "the reconstruction stands on its own but proves no agreement"],
            byte_length=len(reconstructed_bytes))
    published_bytes = canonical_bytes(published)
    published_hash = fr.sha256_hex(published_bytes)
    if reconstructed_bytes == published_bytes:
        return ReproductionResult(True, reconstructed_hash, published_hash, [],
                                  len(reconstructed_bytes))
    differences: List[str] = []
    _diff(dict(reconstructed), dict(published), "$", differences)
    return ReproductionResult(False, reconstructed_hash, published_hash, differences,
                              len(reconstructed_bytes))


#: The domain the resolver signs over. Prefixed so a resolver signature can never be replayed as
#: an EIP-712 receipt signature or an ``eth_sign`` message: different prefix, different digest.
SNAPSHOT_SIGNING_DOMAIN = b"\x19coretex.rig-resolver-snapshot/v1\n"


def signing_digest(payload: Mapping[str, Any]) -> bytes:
    """``keccak256(domain ‖ canonical payload bytes)``."""
    return keccak256(SNAPSHOT_SIGNING_DOMAIN + canonical_bytes(payload))


@dataclass
class SignatureResult:
    """TRANSPORT AUTHENTICATION ONLY. Read the class name before using the boolean."""

    valid: bool
    recovered_signer: Optional[str]
    expected_signer: Optional[str]
    reason: str

    def as_dict(self) -> Dict[str, Any]:
        return {"meaning": ("transport authentication: whether the resolver sent this payload. "
                            "It says NOTHING about whether the payload is true — that is what "
                            "byte-for-byte reproduction against the chain establishes"),
                "valid": self.valid, "recovered_signer": self.recovered_signer,
                "expected_signer": self.expected_signer, "reason": self.reason}


def verify_signature(payload: Mapping[str, Any], signature: Optional[str],
                     expected_signer: Optional[str]) -> SignatureResult:
    """Verify the resolver's signature over the UNSIGNED payload, separately from everything else."""
    if not signature:
        return SignatureResult(False, None, expected_signer,
                               "the snapshot carries no signature")
    if not expected_signer:
        return SignatureResult(False, None, None,
                               "no expected resolver signer is configured, so a recovered address "
                               "could not be checked against anything")
    # THE ONLY PLACE THIS PACKAGE'S CURVE CODE IS REACHED FROM A SNAPSHOT, and it is imported
    # HERE rather than at module scope so that importing :mod:`.snapshot` — or calling
    # :func:`build_unsigned`, :func:`canonical_bytes` or :func:`reproduce` — never loads
    # :mod:`.secp256k1` at all. Reproduction is an arithmetic-free, key-free operation: it
    # rebuilds bytes from chain facts and compares them. Keeping the curve off that path is what
    # makes "the payload is true whether or not it was signed" a property of the code and not
    # only of the docstring; ``test_reproduction_never_loads_curve_code`` asserts it.
    from . import secp256k1 as ec                                          # noqa: WPS433

    raw = signature[2:] if str(signature).startswith("0x") else str(signature)
    try:
        recovered = ec.ecrecover(signing_digest(payload), bytes.fromhex(raw))
    except (ValueError, ec.SignatureError) as exc:
        return SignatureResult(False, None, expected_signer, str(exc))
    if not abi.addresses_equal(recovered, expected_signer):
        return SignatureResult(False, recovered, expected_signer,
                               "the signature recovers a different address")
    return SignatureResult(True, recovered, expected_signer, "signed by the expected resolver")
