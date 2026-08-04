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

#: THE CANONICALISATION RULE, WHICH IS THE PART THAT MUST NOT DIVERGE.
#:
#: "Byte-for-byte" only means anything if both sides spell bytes the same way. Both this package
#: and the resolver lane serialise with :func:`frontier.canonical_bytes` and address the result
#: with ``sha256`` — key-sorted, separator-tight, floats refused, ``null`` refused. A schema can be
#: extended; this rule cannot be changed without invalidating every prior comparison.
CANONICALIZATION_RULE = "frontier-canonical-json/sha256"

#: Schemas whose payloads this package can BUILD, and therefore reproduce.
SUPPORTED_SCHEMAS = (SNAPSHOT_FORMAT,)

#: The resolver lane's own schema. KNOWN, and deliberately NOT claimed as supported.
#:
#: The Phase 6 resolver publishes ``coretex.rig-state.resolver-snapshot/v1``, a richer document
#: (profiles, composition, locks, migration, prior-snapshot linkage, a resolver key identity, and
#: embedded join-recipe / receipt-layout records). This package derives most of those parts but
#: does not yet assemble that shape, and guessing at a field set that is still in flight is the
#: fastest way to produce a "reproduction" that fails for schema reasons and gets explained away.
#:
#: So a payload in this schema is REFUSED with a precise reason rather than diffed into noise.
#: The canonicalisation rule above is already shared, so landing support is a builder, not a
#: re-think. Tracked as F8 in docs/V5-RIG-VALIDATOR.md.
RESOLVER_SCHEMA = "coretex.rig-state.resolver-snapshot/v1"


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
    if published is not None:
        # A schema this package cannot BUILD cannot be reproduced by it, and a field-by-field diff
        # between two different document shapes is noise that reads like a finding. Say the true
        # thing instead.
        published_schema = published.get("schema") or published.get("format")
        if published_schema is not None and published_schema not in SUPPORTED_SCHEMAS:
            known = (" This is the resolver lane's own schema; this package derives the parts but "
                     "does not yet assemble that shape (F8)."
                     if published_schema == RESOLVER_SCHEMA else "")
            return ReproductionResult(
                reproduced=False, reconstructed_hash=reconstructed_hash,
                published_hash=fr.sha256_hex(canonical_bytes(published)),
                differences=[f"SCHEMA_UNSUPPORTED: the published payload is "
                             f"{published_schema!r}; this package builds "
                             f"{list(SUPPORTED_SCHEMAS)!r}.{known} Refusing to report a "
                             f"field-level diff between two different document shapes"],
                byte_length=len(reconstructed_bytes))
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


#: THE SIGNING DIGEST DOMAIN. ``keccak256(0x19 ‖ tag ‖ 0x0a ‖ canonical_bytes)``.
#:
#: The leading ``0x19`` is the byte EIP-191 reserves for "this is signed data, not a transaction",
#: and the tag that follows is none of the envelopes a contract will accept — not
#: ``\x19Ethereum Signed Message:\n``, not ``\x19\x01`` (EIP-712). So a resolver attestation is
#: STRUCTURALLY incapable of being replayed into the rig lane's ``submitCoreTexReceipt`` signature
#: slot or into a personal-sign flow. A bare ``sha256`` of the payload has no such property: it is
#: just 32 bytes, and 32 bytes will happily serve as somebody else's digest.
#:
#: THE TAG NAMES THE PUBLISHED SCHEMA, WHICH IS NOT THIS PACKAGE'S. This construction was authored
#: here and its tag originally spelled this package's own schema id
#: (``coretex.rig-resolver-snapshot/v1``). When the two snapshot schemas were reconciled, the
#: RESOLVER's per-epoch schema won — see :mod:`.resolver_snapshot` — which left the tag naming a
#: schema nobody publishes. It was aligned before any real signature existed.
#:
#: The timing is the whole argument, because the general rule points the other way: a domain tag
#: works whatever it says, and changing one unilaterally breaks the agreement it encodes. But the
#: tag is baked into every signature ever made under it. With zero real snapshots in existence the
#: correction cost one line on each side; one published rehearsal snapshot later it would have
#: invalidated verification of that snapshot and every one before the change — a migration, not an
#: edit. A wart that is free today and expensive tomorrow gets fixed today.
#:
#: BOTH LANES MUST SPELL THIS IDENTICALLY. Changing it on one side silently invalidates every
#: signature the other side can verify.
SNAPSHOT_SIGNING_DOMAIN = b"\x19coretex.rig-state.resolver-snapshot/v1\n"

#: What the tag used to say. Recorded so a future reader does not have to wonder whether the
#: mismatch was deliberate, and so a stale signature can be DIAGNOSED rather than merely rejected.
SUPERSEDED_SIGNING_DOMAIN = b"\x19coretex.rig-resolver-snapshot/v1\n"


def signing_digest(payload: Mapping[str, Any]) -> bytes:
    """``keccak256(domain ‖ canonical payload bytes)``."""
    return keccak256(SNAPSHOT_SIGNING_DOMAIN + canonical_bytes(payload))


def superseded_signing_digest(payload: Mapping[str, Any]) -> bytes:
    """The digest under the RETIRED tag. For diagnosis only — never for acceptance.

    A signature made before the tag was aligned recovers a valid address under this digest and a
    wrong one under the live digest. Being able to say "this was signed under the superseded
    domain" is the difference between a useful refusal and a mysterious one.
    """
    return keccak256(SUPERSEDED_SIGNING_DOMAIN + canonical_bytes(payload))


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


#: The two published fields of a detached signature artifact, and why BOTH are checked.
#:
#: ``payload_sha256`` is IDENTITY: what a snapshot is addressed by, compared by and reproduced
#: against. ``signing_digest`` is what the signature actually COVERS. They are different values
#: over different preimages — the digest includes the domain tag — and treating one as a proxy for
#: the other is a real hole: an artifact naming a CORRECT ``payload_sha256`` beside a WRONG
#: ``signing_digest`` would satisfy the identity check and then be verified against a digest
#: nobody computed. That is precisely the "the hash matched" substitution this design exists to
#: prevent, so :func:`verify_signature_artifact` recomputes both from the payload and refuses on
#: either mismatch, BEFORE it recovers a key.
SIGNATURE_ARTIFACT_FIELDS = ("payload_sha256", "signing_digest")


def verify_signature_artifact(payload: Mapping[str, Any], artifact: Mapping[str, Any],
                              expected_signer: Optional[str]) -> SignatureResult:
    """Verify a DETACHED signature artifact against a payload. Both published fields are checked.

    The order is deliberate and is the same order the payload itself is verified in: everything
    that can be recomputed from the bytes is recomputed FIRST, and only then is a key recovered.
    A caller that skipped straight to :func:`verify_signature` would be authenticating a digest
    the artifact asserted rather than one the payload produces.
    """
    if not isinstance(artifact, Mapping):
        return SignatureResult(False, None, expected_signer,
                               "the signature artifact is not an object")
    computed_identity = payload_hash(payload)
    claimed_identity = str(artifact.get("payload_sha256") or "")
    if claimed_identity != computed_identity:
        return SignatureResult(
            False, None, expected_signer,
            f"the artifact claims payload_sha256 {claimed_identity!r}, these bytes hash to "
            f"{computed_identity}. The artifact is not about this payload")
    computed_digest = "0x" + signing_digest(payload).hex()
    claimed_digest = str(artifact.get("signing_digest") or "").lower()
    if claimed_digest != computed_digest:
        return SignatureResult(
            False, None, expected_signer,
            f"the artifact names signing_digest {claimed_digest!r}, but these bytes sign under "
            f"{computed_digest}. The payload identity matched, which is exactly why this second "
            "check exists: without it the signature would be verified against a digest nobody "
            "computed from the payload")
    return verify_signature(payload, artifact.get("signature"), expected_signer)


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
        # Before saying "wrong signer", check whether it is the RIGHT signer under the retired
        # domain tag. A stale-tag signature and a forged one are different problems and only one
        # of them is somebody re-signing.
        try:
            stale = ec.ecrecover(superseded_signing_digest(payload), bytes.fromhex(raw))
        except (ValueError, ec.SignatureError):             # pragma: no cover - defensive
            stale = ""
        if stale and abi.addresses_equal(stale, expected_signer):
            return SignatureResult(
                False, recovered, expected_signer,
                "the expected signer DID sign these bytes, but under the superseded domain tag "
                f"{SUPERSEDED_SIGNING_DOMAIN!r}. The payload is unaffected; the signature needs "
                "re-issuing under the published schema's tag")
        return SignatureResult(False, recovered, expected_signer,
                               "the signature recovers a different address")
    return SignatureResult(True, recovered, expected_signer, "signed by the expected resolver")
