# SPDX-License-Identifier: UNLICENSED
"""Chain-first, content-addressed validator admission envelope.

This is deliberately a thin trust wrapper around :func:`replay.replay_advance`.  The deterministic
replay remains the consensus implementation.  This wrapper closes the production-dispatch gap:
all chain state is captured first, every public dependency is fetched by its committed root and
rehashed, signed manifests and candidate-bound receipts are verified, and only then may replay
execute candidate code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from . import publication as pub

from . import dispatch as dp
from . import replay as rp
from . import rig_events as rig

CHAIN_FIRST_FORMAT = "coretex.memory-frontier.v5/chain-first-validator/v1"


class ChainFirstError(Exception):
    """A deterministic pre-execution validator refusal with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ArtifactCommitment:
    kind: str
    root: str
    hash_rule: str
    media_type: str
    size: int
    signature_required: bool = False
    expected_fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CanonicalSnapshot:
    chain_id: int
    block_number: int
    block_hash: str
    finalized_block: int
    epoch: int
    incumbent_root: str
    runtime_root: str
    law_root: str
    counter_root: str
    scorer_root: str
    deterministic_receipt_root: str
    fresh_selection_root: str
    supported_historical_laws: Tuple[str, ...]
    artifacts: Tuple[ArtifactCommitment, ...]


class CanonicalChainSource:
    def snapshot(self, event: dp.FrontierAdvanced) -> CanonicalSnapshot:
        raise NotImplementedError

    def pins(self, epoch: int) -> dp.EpochPins:
        raise NotImplementedError


ManifestSignatureVerifier = Callable[[str, Mapping[str, Any], str], bool]
ReceiptSignatureVerifier = Callable[[Mapping[str, Any]], bool]


def _required(document: Mapping[str, Any], field_name: str) -> Any:
    if field_name not in document:
        raise ChainFirstError("MALFORMED_ARTIFACT", f"required field {field_name!r} is absent")
    return document[field_name]


def _fetch(commitment: ArtifactCommitment, store: pub.ContentStore) -> Tuple[bytes, Any]:
    try:
        data = pub.read_back(commitment.root, hash_rule=commitment.hash_rule, store=store,
                             expected_bytes_len=commitment.size)
    except pub.ObjectNotFoundError as exc:
        raise ChainFirstError("MISSING_ARTIFACT", f"{commitment.kind}: {exc}") from exc
    except pub.PublicationError as exc:
        raise ChainFirstError("ARTIFACT_INTEGRITY_FAILURE",
                              f"{commitment.kind}: {exc}") from exc
    if not commitment.media_type:
        raise ChainFirstError("MALFORMED_ARTIFACT",
                              f"{commitment.kind}: committed media type is absent")
    document: Any = data
    if "json" in commitment.media_type:
        try:
            document = fr.parse_json(data.decode("utf-8"))
        except (UnicodeDecodeError, fr.FrontierError) as exc:
            raise ChainFirstError("MALFORMED_ARTIFACT",
                                  f"{commitment.kind}: invalid JSON: {exc}") from exc
    return data, document


def _verify_receipt_bindings(receipt: Mapping[str, Any], *, event: dp.FrontierAdvanced,
                             snapshot: CanonicalSnapshot, now: int, max_ttl: int,
                             verifier: ReceiptSignatureVerifier) -> None:
    if verifier(receipt) is not True:
        raise ChainFirstError("RECEIPT_SIGNATURE_INVALID",
                              "candidate-bound receipt signature did not verify")
    expected = {
        "epoch": event.epoch,
        "parent_root": event.parent_frontier_root,
        "candidate_artifact_root": event.candidate_release_root,
        "candidate_manifest_root": event.composition_root,
        "runtime_root": snapshot.runtime_root,
        "law_root": snapshot.law_root,
        "counter_root": snapshot.counter_root,
        "scorer_root": snapshot.scorer_root,
        "deterministic_receipt_root": snapshot.deterministic_receipt_root,
        "fresh_selection_root": snapshot.fresh_selection_root,
        "transition_root": fr.sha256_hex(event.transition_bytes),
        "proposed_new_root": event.new_frontier_root,
    }
    for name, value in expected.items():
        if _required(receipt, name) != value:
            raise ChainFirstError(
                f"{name.upper()}_SUBSTITUTION",
                f"candidate-bound receipt {name}={receipt.get(name)!r}, chain/candidate requires "
                f"{value!r}",
            )
    expires_at = _required(receipt, "expires_at")
    issued_at = _required(receipt, "issued_at")
    evaluated_at = _required(receipt, "evaluated_at")
    chain_observed_at = _required(receipt, "chain_observed_at")
    if any(not isinstance(value, int) or isinstance(value, bool)
           for value in (expires_at, issued_at, evaluated_at, chain_observed_at)):
        raise ChainFirstError("MALFORMED_RECEIPT",
                              "issued/evaluated/chain-observed/expires timestamps must be integers")
    if expires_at <= now:
        raise ChainFirstError("EXPIRED_RECEIPT", f"receipt expired at {expires_at}, now is {now}")
    if not (evaluated_at <= chain_observed_at <= issued_at < expires_at):
        raise ChainFirstError(
            "RECEIPT_TIME_BINDING_INVALID",
            "receipt must be issued after evaluation and the fresh chain observation",
        )
    if expires_at - issued_at > max_ttl:
        raise ChainFirstError("RECEIPT_TTL_TOO_LONG",
                              f"receipt TTL exceeds the configured maximum {max_ttl}s")
    # These roots are resolved through the chain-selected public artifact graph. They are
    # mandatory and non-zero so a candidate/canary join cannot silently omit them.
    for name in ("deterministic_receipt_root", "fresh_selection_root"):
        try:
            fr.check_root(_required(receipt, name), name)
        except fr.FrontierError as exc:
            raise ChainFirstError("MALFORMED_RECEIPT", str(exc)) from exc


# --------------------------------------------------------------------------- #
# The RIG receipt shape
# --------------------------------------------------------------------------- #
#: The eleven signed rig-receipt fields a confirmed ``RigCoreTexStateAdvanced`` independently
#: asserts. Left = the receipt's ABI member name, right = the event attribute it must equal.
#:
#: These are the fields where a substitution would otherwise be invisible: the log and the receipt
#: are two independent publications of the same claim, so anything present in BOTH must agree or
#: one of them is lying. Fields the event does NOT carry (``solveIndex``, ``prevReceiptHash``,
#: ``workUnitsBps``, ``difficultyCountSnapshot``, the scores, the times) are checked elsewhere —
#: by the contract, or by the receipt-chain reconstruction — and are deliberately absent here
#: rather than checked against a value copied out of the receipt itself.
RIG_RECEIPT_EVENT_BINDINGS: Tuple[Tuple[str, str], ...] = (
    ("epochId", "epoch"),
    ("rigId", "rig_id"),
    ("parentStateRoot", "parent_state_root"),
    ("newStateRoot", "new_state_root"),
    ("corpusRoot", "corpus_root"),
    ("activeFrontierRoot", "active_frontier_root"),
    ("coreVersionHash", "core_version_hash"),
    ("workPolicyHash", "work_policy_hash"),
    ("evalReportHash", "eval_report_hash"),
    ("patchHash", "patch_hash"),
    ("artifactHash", "artifact_hash"),
)

#: The two signable outcomes. 0 and >2 revert for every epoch, so a confirmed event can never
#: carry one — seeing one means the log is not what it claims to be.
RIG_OUTCOME_SCREENER_PASS = 1
RIG_OUTCOME_STATE_ADVANCE = 2

#: Recomputes ``(struct_hash, digest, on_chain_receipt_hash)`` for a rig receipt mapping.
#:
#: INJECTED, never imported. ``v5/e2e`` owns the ABI encoders and is a HARNESS; a validator that
#: imported its test harness would invert the dependency and make the consensus path depend on
#: something that may be absent in a validator-only deployment. The e2e lane supplies this
#: adapter; a validator without one gets the field-binding checks and says so.
RigReceiptHasher = Callable[[Mapping[str, Any]], Mapping[str, str]]


_BARE_ROOT_LEN = 64


def _same_root_spelling(value: str, expected: str) -> str:
    """Render ``value`` in ``expected``'s spelling when both are the same 32-byte root.

    Deliberately conservative: it only touches values where BOTH sides are 32-byte roots, so a
    genuinely different string is still compared verbatim and a substitution still fails.
    """
    normalised = value.strip().lower().removeprefix("0x")
    if len(normalised) != _BARE_ROOT_LEN or len(expected) != _BARE_ROOT_LEN:
        return value
    try:
        int(normalised, 16)
        int(expected, 16)
    except ValueError:
        return value
    return normalised


def verify_rig_receipt_bindings(receipt: Mapping[str, Any], *, event: dp.RigStateAdvanced,
                                now: int, max_ttl: int,
                                hasher: Optional[RigReceiptHasher] = None,
                                expected_digest: Optional[str] = None,
                                expected_receipt_hash: Optional[str] = None) -> Dict[str, Any]:
    """Verify a signed rig receipt against the confirmed advance that published it.

    Deliberately SEPARATE from :func:`_verify_receipt_bindings` rather than a widened version of
    it. The two receipts share no field names, no actor key (``rigId`` vs a candidate-bound
    ``miner``) and no time model, and a single function that accepted either would be one
    ``if`` away from checking a rig receipt with the memory-frontier lane's rules and passing.

    The OUTCOME is checked against the event KIND, which is the one cross-check neither the log
    nor the receipt can make alone: a ``RigCoreTexStateAdvanced`` is by construction an
    ``outcome == 2`` that moved the root, so a receipt claiming a screener pass alongside it is
    a receipt for different work than the chain recorded.
    """
    checks: List[str] = []
    for member, attribute in RIG_RECEIPT_EVENT_BINDINGS:
        value = _required(receipt, member)
        expected = getattr(event, attribute)
        if isinstance(expected, int) and not isinstance(value, int):
            # A uint256 rigId is routinely carried as a decimal string in JSON; compare as ints
            # rather than rejecting the only lossless spelling JSON has for it.
            try:
                value = int(str(value), 10)
            except ValueError:
                raise ChainFirstError(
                    "MALFORMED_RIG_RECEIPT",
                    f"rig receipt {member}={receipt.get(member)!r} is not an integer") from None
        elif isinstance(expected, str) and isinstance(value, str):
            # ONE VALUE, TWO SPELLINGS. A decoded log carries roots BARE (this lane's rendering);
            # the coordinator's signed envelope carries them `0x`-prefixed (the chain rendering).
            # `0x1c457ea7…` and `1c457ea7…` are the same 32 bytes, and comparing them literally
            # rejects a receipt that binds exactly what the chain confirmed. Normalised for the
            # same reason `rigId` is compared as an integer: a spelling difference between two
            # lanes is not a substitution. Anything that is not root-shaped is compared verbatim.
            value = _same_root_spelling(value, expected)
        if value != expected:
            raise ChainFirstError(
                f"RIG_{member.upper()}_SUBSTITUTION",
                f"rig receipt {member}={receipt.get(member)!r}, the confirmed "
                f"RigCoreTexStateAdvanced asserts {expected!r}")
    checks.append("rig_event_bindings")

    outcome = _required(receipt, "outcome")
    if outcome not in (RIG_OUTCOME_SCREENER_PASS, RIG_OUTCOME_STATE_ADVANCE):
        raise ChainFirstError("RIG_OUTCOME_INVALID",
                              f"rig receipt outcome={outcome!r} is not a signable outcome")
    if outcome != RIG_OUTCOME_STATE_ADVANCE:
        raise ChainFirstError(
            "RIG_OUTCOME_MISMATCH",
            f"rig receipt claims outcome={outcome} but a confirmed RigCoreTexStateAdvanced is a "
            "state advance; a screener pass emits RigCoreTexScreenerPassRecorded and writes no "
            "state")
    if event.new_state_root == event.parent_state_root:
        raise ChainFirstError("RIG_NO_OP_ADVANCE",
                              "the confirmed advance does not move the state root")
    # ``transitionFormatVersion`` (was ``stateWordCount`` — coretex.transition-descriptor/v2
    # §9.1). On a state advance it is no longer a count with a lower bound; it is the FIXED
    # zero-extension of the 105-byte descriptor's version byte, so it must equal that constant
    # exactly, not merely be non-zero.
    version = _required(receipt, "transitionFormatVersion")
    if (not isinstance(version, int) or isinstance(version, bool)
            or version != rig.TRANSITION_DESCRIPTOR_VERSION):
        raise ChainFirstError(
            "RIG_TRANSITION_FORMAT_VERSION_INVALID",
            f"transitionFormatVersion={version!r}; a state advance signs the zero-extension of "
            f"the descriptor version byte, 0x{rig.TRANSITION_DESCRIPTOR_VERSION:02x}")
    checks.append("rig_outcome")

    issued_at = _required(receipt, "issuedAt")
    expires_at = _required(receipt, "expiresAt")
    if any(not isinstance(v, int) or isinstance(v, bool) for v in (issued_at, expires_at)):
        raise ChainFirstError("MALFORMED_RIG_RECEIPT",
                              "issuedAt/expiresAt must be integers")
    if issued_at >= expires_at:
        raise ChainFirstError("RIG_RECEIPT_TIME_BINDING_INVALID",
                              f"issuedAt {issued_at} is not before expiresAt {expires_at}")
    if expires_at - issued_at > max_ttl:
        raise ChainFirstError("RIG_RECEIPT_TTL_TOO_LONG",
                              f"rig receipt TTL exceeds the configured maximum {max_ttl}s")
    if issued_at > now:
        raise ChainFirstError("RIG_RECEIPT_TIME_BINDING_INVALID",
                              f"rig receipt is issued at {issued_at}, in the future of {now}")
    checks.append("rig_receipt_window")

    computed: Dict[str, str] = {}
    if hasher is not None:
        computed = dict(hasher(receipt))
        for name, expected in (("digest", expected_digest),
                               ("on_chain_receipt_hash", expected_receipt_hash)):
            if expected is None:
                continue
            got = computed.get(name)
            if got is None:
                raise ChainFirstError("RIG_RECEIPT_HASH_UNAVAILABLE",
                                      f"the configured hasher produced no {name}")
            if got.lower().removeprefix("0x") != str(expected).lower().removeprefix("0x"):
                raise ChainFirstError(f"RIG_{name.upper()}_MISMATCH",
                                      f"recomputed {name} {got} != the chain's {expected}")
        checks.append("rig_receipt_hashes")
    return {"checks": tuple(checks), "computed": computed,
            "hashes_verified": hasher is not None}


# --------------------------------------------------------------------------- #
# The RIG chain-first envelope (§10)
# --------------------------------------------------------------------------- #
#: The FOUR law pins the registry re-checks word for word inside ``_recordStateAdvance``, keyed by
#: the confirmed event's attribute name. ``baseline_manifest_hash`` and ``hidden_seed_commit`` are
#: absent because the ADVANCE path does not carry them — they are checked at finalization, where
#: the log does assert them — and "checked" is not a thing you can do to a value the log never
#: published.
RIG_ENFORCED_PIN_FIELDS: Tuple[str, ...] = (
    "corpus_root", "active_frontier_root", "core_version_hash", "work_policy_hash")

#: The labelled ``patchHash`` rule the coordinator lane signs (Q-10, still open). Duplicated here
#: as a LITERAL rather than imported from ``e2e`` on purpose: a validator must not depend on the
#: proof harness (see :data:`RigReceiptHasher`). The two are asserted equal by the rig scenario.
#:
#: MIGRATION NOTE (transition-descriptor v2). This used to be
#: ``b"coretex-memory-transition-hash-v1"`` — the V5 MEMORY lane's domain, which
#: :mod:`.rig_events` independently flags as wrong for this lane ("the staged check does not
#: merely differ in style: it refuses every real advance"). It is now the LIVE v2 label, AND — the
#: half that was missed the first time (review M-9) — it is applied to the LIVE v2 PREIMAGE: the
#: 105 descriptor bytes, never the canonical-JSON transition object. The label and the preimage are
#: one rule; migrating either alone produces a check that cannot pass.
#:
#: Note the scope limit this envelope inherited from :class:`dispatch.RigStateAdvanced` (the
#: STAGED, never-deployed rig-registry design this function's ``event`` parameter is typed against,
#: per :mod:`.rig_events`'s module docstring): that event carries no ``compactPatchBytes`` at all,
#: so the descriptor must be handed to :func:`validate_rig_chain_first` beside the event, and an
#: absent descriptor is a typed REFUSAL rather than a skipped check. Unifying the two event shapes
#: is a bigger change than this migration and is out of scope here.
RIG_PATCH_HASH_LABEL = b"coretex-transition-descriptor-v2"
#: The label this constant WAS (kept nameable, never accepted).
RIG_PATCH_HASH_LABEL_SUPERSEDED = b"coretex-memory-transition-hash-v1"
#: This lane's own retired 4-word compact-patch label (kept nameable, never accepted).
RIG_PATCH_HASH_LABEL_RETIRED = b"coretex-patch-hash-v1"


@dataclass(frozen=True)
class RigCanonicalSnapshot:
    """Everything a rig validator reads from the chain BEFORE any candidate code can execute.

    ``pins`` is READ INDEPENDENTLY from the registry (or reconstructed from confirmed context and
    commit logs by :func:`dispatch.build_rig_pins_from_logs`) — never copied out of the event it is
    used to check. A snapshot that repeated the event's own four roots back at it would agree with
    itself by construction and catch nothing.

    ``counter_resource_law_root`` IS NOT A CHAIN PIN IN THE RIG LANE, and that is a finding rather
    than an omission. The rig registry pins six values and the counter-resource law is not among
    them, so the resource half of the Pareto rule is bound only TRANSITIVELY, inside the bytes
    ``evalReportHash`` addresses. The caller therefore supplies the value it expects (from the
    signed release artifact / operator policy) and this envelope REFUSES an artifact that
    disagrees, instead of adopting whatever the artifact happens to say.
    """

    chain_id: int
    block_number: int
    block_hash: str
    finalized_block: int
    epoch: int
    #: ``registry.liveStateRoot(epoch)`` at the observed block.
    live_state_root: str
    transition_count: int
    epoch_finalized: bool
    #: The registry that emitted the event, and the verifier that is bound to it. Both are read
    #: back so a rotated-in registry cannot be mistaken for the one the receipt was signed against.
    registry_address: str
    verifier_registry_address: str
    pins: dp.RigEpochPins
    counter_resource_law_root: str
    scorer_root: str
    deterministic_receipt_root: str
    fresh_selection_root: str
    supported_historical_laws: Tuple[str, ...]
    artifacts: Tuple[ArtifactCommitment, ...]


class RigCanonicalChainSource:
    def snapshot(self, event: "dp.RigStateAdvanced") -> RigCanonicalSnapshot:
        raise NotImplementedError


def _keccak_patch(descriptor_bytes: bytes) -> str:
    """``keccak256(utf8(LABEL) ++ the 105 DESCRIPTOR bytes)`` — the LABELLED rule, never plain
    keccak, and never over anything but the descriptor.

    THE PREIMAGE IS PART OF THE RULE. Under ``coretex.transition-descriptor/v2`` ``patchHash`` is
    ``keccak256(label ‖ compactPatchBytes)`` where ``compactPatchBytes`` is the fixed 105-byte
    descriptor. It is NOT the canonical-JSON transition object: that was approximately right under
    the retired model, where the patch committed the input side of the edit, and it is simply a
    different value now. Applying the LIVE label to the RETIRED preimage is the same class of
    defect as applying a dead label to the live preimage, and it is the more dangerous one because
    the label makes the site look migrated.
    """
    # Imported lazily so `chain_first` keeps its stdlib-plus-v5-law dependency profile.
    from .keccak256 import keccak256_hex                                    # noqa: WPS433
    return keccak256_hex(RIG_PATCH_HASH_LABEL + bytes(descriptor_bytes))


def _keccak_patch_dead_label_hint(descriptor_bytes: bytes, expected: str) -> str:
    """Name the dead label a mismatched patch hash DOES correspond to, if it is one — the
    "superseded label" idiom :mod:`.rig_events` uses, mirrored here for the same reason."""
    from .keccak256 import keccak256_hex                                    # noqa: WPS433
    for label in (RIG_PATCH_HASH_LABEL_RETIRED, RIG_PATCH_HASH_LABEL_SUPERSEDED):
        if keccak256_hex(label + bytes(descriptor_bytes)) == expected:
            return f" (it DOES match the DEAD label {label.decode('utf-8')!r})"
    return ""


def validate_rig_chain_first(
        event: "dp.RigStateAdvanced", *, chain: RigCanonicalChainSource,
        store: pub.ContentStore, manifest_verifier: ManifestSignatureVerifier,
        deterministic_receipt_verifier: ReceiptSignatureVerifier,
        rig_receipt: Mapping[str, Any],
        now: int,
        compact_patch_bytes: Optional[bytes] = None,
        rig_receipt_hasher: Optional[RigReceiptHasher] = None,
        expected_digest: Optional[str] = None,
        expected_receipt_hash: Optional[str] = None,
        local_state: Optional[Mapping[str, Any]] = None,
        canary: Optional[Mapping[str, Any]] = None,
        canary_verifier: Optional[ReceiptSignatureVerifier] = None,
        max_receipt_ttl: int = 3600,
        replay_kwargs: Optional[Mapping[str, Any]] = None) -> ChainFirstResult:
    """Chain-first admission for one confirmed ``RigCoreTexStateAdvanced``.

    DELIBERATELY A SEPARATE FUNCTION from :func:`validate_chain_first`, for the reason
    :func:`verify_rig_receipt_bindings` gives: the two lanes share no receipt shape, no actor key
    and no artifact graph. The rig event carries NO ``transitionBytes`` and NO
    ``compositionRoot``, so the candidate's edit and its composition are FETCHED by hash rather
    than read out of the log — and the ONE thing that makes that safe is the ``patchHash`` binding
    checked below.

    The order is the point, and it is the same order the memory lane uses:

      1. the chain snapshot, including the epoch's pins read INDEPENDENTLY of the event;
      2. the four law pins the registry enforces, re-checked here against the pins a validator
         read for itself — this is the check a substituted registry cannot survive;
      3. local coordinator state DEMOTED (a disagreement is a refusal, never a tie-break);
      4. every public dependency fetched by its committed root and REHASHED;
      5. the fetched eval artifact joined to the event: parent, new root, candidate release root,
         and ``keccak256(LABEL ++ compactPatchBytes) == event.patchHash`` over the SUPPLIED
         105-byte transition descriptor, followed by the descriptor's own layout/parent/new-root
         decode. The staged event shape carries no descriptor, so a caller that supplies none is
         REFUSED (``RIG_TRANSITION_DESCRIPTOR_UNAVAILABLE``) rather than checked against the
         canonical-JSON transition, which is a different value under v2 — see M-9 in
         ``docs/coretex-v5/ADVERSARIAL-REVIEW-DESCRIPTOR-V2-20260806.md``;
      6. the coordinator-signed rig receipt verified against the confirmed advance;
      7. committed canary evidence verified (never re-run);
      8. ONLY THEN the deterministic replay, over a projection of the event that carries the
         transition bytes the artifact supplied and nothing the artifact merely asserted.

    THE ROUTE IS REPORTED ON EVERY OUTCOME, INCLUDING REFUSALS. ``ChainFirstResult.via_legacy_route``
    /``.route`` carry the confirmed advance's H-11 flag out of here whether the admission passed or
    failed, because "which route minted this advance?" is a property of the LOG and does not
    depend on whether the validator went on to like the rest of it. Stamped in one place
    (:func:`_rig_result`) so no return path can be the one that drops it.
    """
    checks: List[str] = []

    def _rig_result(*args: Any, **kwargs: Any) -> ChainFirstResult:
        return ChainFirstResult(*args, via_legacy_route=event.via_legacy_route,
                                route=event.route, **kwargs)

    # Recorded, never enforced: the registry accepts BOTH routes, so refusing a legacy-route
    # advance here would be this lane inventing a consensus rule the chain does not have. Only
    # claimed when the flag was actually decoded from a log — a reconstructed event (``None``) has
    # no route to vouch for and must not appear to have had one checked.
    if event.via_legacy_route is not None:
        checks.append("rig_route_provenance")

    try:
        snapshot = chain.snapshot(event)
        fr.check_root(snapshot.live_state_root, "snapshot.live_state_root")
        if snapshot.epoch != event.epoch:
            raise ChainFirstError(
                "WRONG_EPOCH", f"chain epoch {snapshot.epoch} != advance epoch {event.epoch}")
        # ── Is this advance CONFIRMED, and is it the head or history? ──
        #
        # "Adjacent to the live root" is the right question for a validator watching the tip and
        # the WRONG one for a validator replaying an epoch that has since advanced further or been
        # sealed: transition 0 of a three-transition epoch is adjacent to nothing the registry
        # currently reports, and refusing it would make historical replay impossible — which is the
        # one thing a public validator exists to do.
        #
        # The property that holds for BOTH is the transition INDEX: the registry's
        # `transitionCount` is monotone within an epoch and never decreases, so an index at or
        # beyond it names an advance the chain does not confirm happened.
        if event.transition_index >= snapshot.transition_count:
            raise ChainFirstError(
                "RIG_TRANSITION_UNCONFIRMED",
                f"the advance claims transition index {event.transition_index} but the registry "
                f"reports only {snapshot.transition_count} transition(s) for epoch {event.epoch}; "
                "the chain does not confirm this advance happened")
        is_head = event.transition_index == snapshot.transition_count - 1
        if is_head and snapshot.live_state_root != event.new_state_root:
            raise ChainFirstError(
                "PARENT_ROOT_SUBSTITUTION",
                f"this advance is the epoch's LAST confirmed transition, so the registry's live "
                f"state root must be its `newStateRoot` {event.new_state_root} — it is "
                f"{snapshot.live_state_root}")
        checks.append("rig_head_or_history")
        if snapshot.registry_address.lower() != snapshot.verifier_registry_address.lower():
            raise ChainFirstError(
                "REGISTRY_SUBSTITUTION",
                f"the advance was emitted by registry {snapshot.registry_address} but the bound "
                f"verifier now resolves to {snapshot.verifier_registry_address}; a rotation "
                "happened and this advance's epoch may no longer be this registry's to own")
        checks.append("rig_chain_snapshot")

        pins = snapshot.pins
        if pins.epoch != event.epoch:
            raise ChainFirstError("CHAIN_SNAPSHOT_INCONSISTENT",
                                  f"pins are for epoch {pins.epoch}, the advance is epoch "
                                  f"{event.epoch}")
        enforced = pins.enforced_pins()
        for name in RIG_ENFORCED_PIN_FIELDS:
            if getattr(event, name) != enforced[name]:
                raise ChainFirstError(
                    f"RIG_{name.upper()}_SUBSTITUTION",
                    f"the advance carries {name}={getattr(event, name)} but epoch {event.epoch}'s "
                    f"independently-read registry pin is {enforced[name]}")
        checks.append("rig_epoch_pins")

        if local_state is not None:
            for name, chain_value in (
                    ("epoch", snapshot.epoch),
                    ("state_root", snapshot.live_state_root),
                    ("transition_count", snapshot.transition_count),
                    ("epoch_finalized", snapshot.epoch_finalized)):
                if name in local_state and local_state[name] != chain_value:
                    raise ChainFirstError(
                        "CHAIN_DATABASE_DISAGREEMENT",
                        f"local {name}={local_state[name]!r} conflicts with chain {chain_value!r}")
        checks.append("local_state_demoted")

        fetched: Dict[str, Any] = {}
        required_roots = {
            "eval_artifact": event.eval_report_hash,
            "candidate_manifest": event.artifact_hash,
        }
        seen: set = set()
        for commitment in snapshot.artifacts:
            fr.check_root(commitment.root, f"{commitment.kind}.root")
            _data, document = _fetch(commitment, store)
            fetched[commitment.kind] = document
            if commitment.kind in required_roots:
                seen.add(commitment.kind)
                if commitment.root != required_roots[commitment.kind]:
                    raise ChainFirstError(
                        f"{commitment.kind.upper()}_SUBSTITUTION",
                        f"{commitment.kind} root {commitment.root} != the confirmed advance's "
                        f"{required_roots[commitment.kind]}")
            if commitment.signature_required:
                if not isinstance(document, Mapping):
                    raise ChainFirstError("MALFORMED_ARTIFACT",
                                          f"{commitment.kind}: signed manifest is not an object")
                if manifest_verifier(commitment.kind, document, commitment.root) is not True:
                    raise ChainFirstError("MANIFEST_SIGNATURE_INVALID",
                                          f"{commitment.kind}: signature did not verify")
        missing = set(required_roots) - seen
        if missing:
            raise ChainFirstError(
                "MISSING_ARTIFACT",
                f"chain dispatch omitted required rig artifacts: {sorted(missing)}")
        checks.append("artifacts_rehashed")

        artifact = fetched.get("eval_artifact")
        if not isinstance(artifact, Mapping):
            raise ChainFirstError("MALFORMED_ARTIFACT",
                                  "the eval artifact is not a JSON object")
        front = artifact.get("frontier")
        candidate = artifact.get("candidate")
        if not isinstance(front, Mapping) or not isinstance(candidate, Mapping):
            raise ChainFirstError("MALFORMED_ARTIFACT",
                                  "the eval artifact carries no frontier/candidate block")
        for name, artifact_value, event_value in (
                ("parent_state_root", front.get("parent_frontier_root"), event.parent_state_root),
                ("new_state_root", front.get("new_frontier_root"), event.new_state_root),
                ("artifact_hash", candidate.get("release_root"), event.artifact_hash)):
            if artifact_value != event_value:
                raise ChainFirstError(
                    f"RIG_{name.upper()}_SUBSTITUTION",
                    f"the fetched eval artifact says {name}={artifact_value!r}, the confirmed "
                    f"advance says {event_value!r}")
        try:
            transition_bytes = fr.canonical_bytes(front["transition"])
        except (KeyError, TypeError, fr.FrontierError) as exc:
            raise ChainFirstError("MALFORMED_ARTIFACT",
                                  f"the eval artifact's transition is unusable: {exc}") from exc
        # ── THE DESCRIPTOR BINDING, repointed at the descriptor bytes (M-9) ───────────────────
        #
        # WHAT THIS USED TO BE AND WHY IT WAS WRONG. It hashed the LIVE v2 label over
        # `fr.canonical_bytes(front["transition"])` — the canonical-JSON transition object. Under
        # v2 `patchHash = keccak256(label ‖ the 105 descriptor bytes)`, so that comparison can
        # NEVER match a genuine advance: it was the right label on the wrong preimage, the mirror
        # image of the incident this lane already had once (the wrong label on the right bytes),
        # and worse than an obviously stale check because the corrected label made the site LOOK
        # migrated. Left in place it would have false-FAILed every valid v2 advance the day the
        # staged and deployed event shapes were unified — "slander a valid mine", the exact
        # failure class this migration exists to remove.
        #
        # WHERE THE BYTES COME FROM. `dispatch.RigStateAdvanced` is the STAGED, never-deployed
        # rig-registry event shape (topic0 `7a35edec…`); it carries no `compactPatchBytes` member
        # at all, so the descriptor cannot be recovered from the event and must be supplied by the
        # caller alongside it. The DEPLOYED event (`rig_events.StateAdvanced`, topic0 `2f0a8989…`)
        # does carry them, and `pipeline.py`'s join decodes them in full against the real log.
        #
        # FAIL CLOSED WHEN THEY ARE ABSENT. "The bytes the rule is defined over were not supplied"
        # is not a reason to admit the advance, and it is emphatically not a reason to fall back
        # to a preimage the rule does not name. A caller that cannot produce the descriptor gets a
        # typed refusal saying so.
        if compact_patch_bytes is None:
            raise ChainFirstError(
                "RIG_TRANSITION_DESCRIPTOR_UNAVAILABLE",
                "under coretex.transition-descriptor/v2 patchHash is keccak256(LABEL ++ the 105 "
                "DESCRIPTOR bytes), and this envelope's event type (the STAGED "
                "RigCoreTexStateAdvanced shape) carries no compactPatchBytes, so the descriptor "
                "must be supplied by the caller. It was not. This is a REFUSAL and not a skipped "
                "check: hashing the label over the eval artifact's canonical transition instead — "
                "which is what stood here before — is a DIFFERENT value for every input and would "
                "have refused every valid advance")
        descriptor_bytes = bytes(compact_patch_bytes)
        computed_patch = _keccak_patch(descriptor_bytes)
        if computed_patch != event.patch_hash:
            raise ChainFirstError(
                "RIG_PATCH_HASH_MISMATCH",
                f"keccak256(LABEL ++ compactPatchBytes) over the supplied 105-byte transition "
                f"descriptor is {computed_patch}, the confirmed advance asserts "
                f"{event.patch_hash}"
                f"{_keccak_patch_dead_label_hint(descriptor_bytes, event.patch_hash)}. THIS is "
                "the check that makes fetching the edit by hash safe; without it the rig lane's "
                "log carries no edit at all")
        try:
            rig.decode_transition_descriptor(
                descriptor_bytes,
                parent_state_root=event.parent_state_root,
                new_state_root=event.new_state_root,
                expected_patch_hash=event.patch_hash)
        except rig.TransitionDescriptorError as exc:
            raise ChainFirstError(exc.code, exc.message) from exc
        checks.append("rig_transition_descriptor")
        if artifact.get("counter_resource_law_root") != snapshot.counter_resource_law_root:
            raise ChainFirstError(
                "COUNTER_PACKAGE_SUBSTITUTION",
                f"the artifact binds counter law {artifact.get('counter_resource_law_root')!r} but "
                f"policy expects {snapshot.counter_resource_law_root!r}. NOTE: the rig registry "
                "pins no counter-resource law, so this value has no on-chain pin to compare "
                "against and the expectation is operator policy carried in the release artifact")
        checks.append("rig_artifact_join")

        receipt_report = verify_rig_receipt_bindings(
            rig_receipt, event=event, now=now, max_ttl=max_receipt_ttl,
            hasher=rig_receipt_hasher, expected_digest=expected_digest,
            expected_receipt_hash=expected_receipt_hash)
        checks.extend(receipt_report["checks"])

        canary_report = None
        if canary is not None:
            if canary_verifier is None:
                raise ChainFirstError("CANARY_SIGNATURE_INVALID",
                                      "committed canary has no configured signature verifier")
            if canary_verifier(canary) is not True:
                raise ChainFirstError("CANARY_SIGNATURE_INVALID",
                                      "canary signature did not verify")
            for name, expected in (("incumbent_root", event.parent_state_root),
                                   ("proposed_new_root", event.new_state_root),
                                   ("candidate_artifact_root", event.artifact_hash)):
                if _required(canary, name) != expected:
                    raise ChainFirstError(
                        "CANARY_CANDIDATE_MISMATCH",
                        f"canary {name}={canary.get(name)!r} does not bind this confirmed advance "
                        f"({expected!r})")
            canary_report = {"present": True, "verified": True, "model_rerun": False,
                             "consensus_critical": False,
                             "transcript_root": canary.get("transcript_root")}
            checks.append("canary_evidence")

        # 8. the deterministic replay, over a PROJECTION whose every field is either the confirmed
        #    event's or was just proved to hash to one of the confirmed event's.
        projected = dp.FrontierAdvanced(
            epoch=event.epoch,
            transition_index=event.transition_index,
            miner="0x" + f"{event.rig_id:040x}"[-40:],
            parent_frontier_root=event.parent_state_root,
            new_frontier_root=event.new_state_root,
            candidate_release_root=event.artifact_hash,
            composition_root=str(front.get("composition_root")),
            eval_report_hash=event.eval_report_hash,
            benchmark_law_root=str(front.get("benchmark_law_root")),
            runtime_abi_root=str(front.get("runtime_abi_root")),
            transition_bytes=transition_bytes,
            provenance=event.provenance)
        kwargs = dict(replay_kwargs or {})
        kwargs["signature_verifier"] = deterministic_receipt_verifier
        kwargs["pins"] = dp.pins_from_mapping({event.epoch: dp.EpochPins(
            epoch=event.epoch,
            runtime_abi_root=projected.runtime_abi_root,
            benchmark_law_root=projected.benchmark_law_root,
            counter_resource_law_root=snapshot.counter_resource_law_root,
            entropy_commitment=pins.entropy_commitment,
            revealed_secret=pins.revealed_secret)})
        replayed = rp.replay_advance(projected, store=store, **kwargs)
        if not replayed.ok:
            return _rig_result(False, replayed.code, tuple(checks), replayed, canary_report,
                               replayed.reason)
        checks.append("deterministic_replay")
        return _rig_result(True, "PASS", tuple(checks), replayed, canary_report)
    except ChainFirstError as exc:
        return _rig_result(False, exc.code, tuple(checks), reason=str(exc))
    except (fr.FrontierError, dp.DispatchError) as exc:
        return _rig_result(False, "MALFORMED_CHAIN_STATE", tuple(checks), reason=str(exc))


def _verify_canary(canary: Mapping[str, Any], receipt: Mapping[str, Any], *, now: int,
                   store: pub.ContentStore,
                   verifier: ReceiptSignatureVerifier) -> Dict[str, Any]:
    """Verify committed canary evidence only. Never invokes a model and never changes replay."""
    if verifier(canary) is not True:
        raise ChainFirstError("CANARY_SIGNATURE_INVALID", "canary signature did not verify")
    bindings = {
        "candidate_artifact_root": receipt["candidate_artifact_root"],
        "candidate_manifest_root": receipt["candidate_manifest_root"],
        "deterministic_receipt_root": receipt["deterministic_receipt_root"],
        "fresh_selection_root": receipt["fresh_selection_root"],
        "runtime_root": receipt["runtime_root"],
        "law_root": receipt["law_root"],
        "scorer_root": receipt["scorer_root"],
        "epoch": receipt["epoch"],
        "transition_root": receipt["transition_root"],
        "incumbent_root": receipt["parent_root"],
        "counter_root": receipt["counter_root"],
    }
    for name, value in bindings.items():
        if _required(canary, name) != value:
            raise ChainFirstError("CANARY_CANDIDATE_MISMATCH",
                                  f"canary {name} does not bind this candidate")
    transcript_root = _required(canary, "transcript_root")
    for identity in ("renderer_root", "prompt_root", "model_root", "configuration_root"):
        try:
            fr.check_root(_required(canary, identity), identity)
        except fr.FrontierError as exc:
            raise ChainFirstError("CANARY_IDENTITY_MALFORMED", str(exc)) from exc
    for field_name in ("provider_input_tokens", "provider_output_tokens", "cost_usd_micros",
                       "issued_at", "expires_at"):
        value = _required(canary, field_name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ChainFirstError("CANARY_ACCOUNTING_MALFORMED",
                                  f"{field_name} must be a non-negative integer")
    if canary["expires_at"] <= now or canary["issued_at"] >= canary["expires_at"]:
        raise ChainFirstError("CANARY_EXPIRED", "canary evidence is expired or has invalid time order")
    verdict = _required(canary, "verdict")
    if verdict not in ("PASS", "FAIL", "INCONCLUSIVE"):
        raise ChainFirstError("CANARY_VERDICT_MALFORMED", f"unsupported verdict {verdict!r}")
    proposed_root = _required(canary, "proposed_new_root")
    if proposed_root != receipt.get("proposed_new_root"):
        raise ChainFirstError("CANARY_CANDIDATE_MISMATCH",
                              "canary proposed root does not bind the candidate transition")
    try:
        pub.read_back(transcript_root, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    except pub.PublicationError as exc:
        raise ChainFirstError("TRANSCRIPT_SUBSTITUTION", str(exc)) from exc
    return {"present": True, "verified": True, "model_rerun": False,
            "consensus_critical": False, "transcript_root": transcript_root}


@dataclass
class ChainFirstResult:
    ok: bool
    code: str
    checks: Sequence[str]
    replay: Optional[rp.ReplayResult] = None
    canary: Optional[Mapping[str, Any]] = None
    reason: str = ""
    #: THE H-11 OBSERVABLE, carried out of the rig path. ``True`` = the admitted advance was minted
    #: through the raw ``0xa2d87e1d`` fallback shim, whose calldata word order is still unverified
    #: (Q-2); ``False`` = the typed ``submitStateAdvance``; ``None`` = not a rig result, or the
    #: event was reconstructed rather than decoded from a confirmed log.
    #:
    #: An admission is NOT refused on this. The registry accepts both routes, so refusing here
    #: would be this lane inventing a consensus rule the chain does not have. It is REPORTED, which
    #: is the whole point of H-11: an operator must be able to see, forever and without re-deriving
    #: it, which advances came through the unverified route.
    via_legacy_route: Optional[bool] = None
    #: ``"legacy-0xa2d87e1d"`` / ``"typed-submitStateAdvance"`` / ``"unobserved"``, or ``""`` when
    #: this is not a rig result at all.
    route: str = ""


def validate_chain_first(
        event: dp.FrontierAdvanced, *, chain: CanonicalChainSource,
        store: pub.ContentStore, manifest_verifier: ManifestSignatureVerifier,
        deterministic_receipt_verifier: ReceiptSignatureVerifier,
        candidate_receipt: Mapping[str, Any],
        candidate_receipt_verifier: ReceiptSignatureVerifier,
        now: int, local_state: Optional[Mapping[str, Any]] = None,
        canary: Optional[Mapping[str, Any]] = None,
        canary_verifier: Optional[ReceiptSignatureVerifier] = None,
        max_receipt_ttl: int = 3600,
        replay_kwargs: Optional[Mapping[str, Any]] = None) -> ChainFirstResult:
    checks = []
    try:
        snapshot = chain.snapshot(event)
        fr.check_root(snapshot.incumbent_root, "snapshot.incumbent_root")
        if snapshot.epoch != event.epoch:
            raise ChainFirstError("WRONG_EPOCH",
                                  f"chain epoch {snapshot.epoch} != candidate epoch {event.epoch}")
        if snapshot.incumbent_root not in (event.parent_frontier_root, event.new_frontier_root):
            raise ChainFirstError(
                "PARENT_ROOT_SUBSTITUTION",
                "event is not adjacent to the canonical chain frontier at the observed block",
            )
        if snapshot.law_root not in snapshot.supported_historical_laws:
            raise ChainFirstError("UNSUPPORTED_HISTORICAL_LAW",
                                  f"law {snapshot.law_root} is not in the chain policy's replay set")
        checks.append("chain_snapshot")

        if local_state is not None:
            for name, chain_value in (
                    ("epoch", snapshot.epoch), ("frontier_root", snapshot.incumbent_root),
                    ("runtime_root", snapshot.runtime_root), ("law_root", snapshot.law_root)):
                if name in local_state and local_state[name] != chain_value:
                    raise ChainFirstError(
                        "CHAIN_DATABASE_DISAGREEMENT",
                        f"local {name}={local_state[name]!r} conflicts with chain {chain_value!r}",
                    )
        checks.append("local_state_demoted")

        fetched: Dict[str, Any] = {}
        required_manifests = {
            "candidate_manifest": event.candidate_release_root,
            "composition_manifest": event.composition_root,
        }
        saw_manifests = set()
        required_identity_roots = {
            "runtime_package": snapshot.runtime_root,
            "law_package": snapshot.law_root,
            "counter_package": snapshot.counter_root,
            "scorer_package": snapshot.scorer_root,
            "eval_artifact": event.eval_report_hash,
        }
        saw_identity_artifacts = set()
        for commitment in snapshot.artifacts:
            fr.check_root(commitment.root, f"{commitment.kind}.root")
            _data, document = _fetch(commitment, store)
            fetched[commitment.kind] = document
            if commitment.kind in required_identity_roots:
                saw_identity_artifacts.add(commitment.kind)
                selected = (commitment.root if commitment.kind == "eval_artifact"
                            else document.get("identity_root")
                            if isinstance(document, Mapping) else None)
                if selected != required_identity_roots[commitment.kind]:
                    raise ChainFirstError(
                        f"{commitment.kind.upper()}_SUBSTITUTION",
                        f"{commitment.kind} selected identity {selected} does not match the "
                        f"chain-selected root {required_identity_roots[commitment.kind]}",
                    )
            must_be_signed = (
                commitment.kind.endswith("_manifest")
                or (commitment.kind in required_identity_roots
                    and commitment.kind != "eval_artifact")
            )
            if must_be_signed:
                if not isinstance(document, Mapping):
                    raise ChainFirstError("MALFORMED_ARTIFACT",
                                          f"{commitment.kind}: signed manifest is not an object")
                if manifest_verifier(commitment.kind, document, commitment.root) is not True:
                    raise ChainFirstError("MANIFEST_SIGNATURE_INVALID",
                                          f"{commitment.kind}: signature did not verify")
                for name, expected in commitment.expected_fields.items():
                    if document.get(name) != expected:
                        raise ChainFirstError(
                            "MANIFEST_IDENTITY_MISMATCH",
                            f"{commitment.kind}.{name}={document.get(name)!r}, expected {expected!r}",
                        )
            if commitment.kind == "candidate_manifest":
                saw_manifests.add(commitment.kind)
            if commitment.kind == "composition_manifest":
                saw_manifests.add(commitment.kind)
            if commitment.kind in required_manifests:
                if commitment.root != required_manifests[commitment.kind]:
                    raise ChainFirstError(
                        f"{commitment.kind.upper()}_SUBSTITUTION",
                        f"{commitment.kind} root does not match the chain event",
                    )
        missing_manifests = set(required_manifests) - saw_manifests
        if missing_manifests:
            raise ChainFirstError("MISSING_ARTIFACT",
                                  f"chain dispatch omitted signed manifests: {sorted(missing_manifests)}")
        missing_identities = set(required_identity_roots) - saw_identity_artifacts
        if missing_identities:
            raise ChainFirstError(
                "MISSING_ARTIFACT",
                f"chain dispatch omitted public replay packages: {sorted(missing_identities)}",
            )
        for descriptor_kind in ("runtime_package", "law_package", "counter_package",
                                "scorer_package"):
            descriptor = fetched[descriptor_kind]
            payload_kind = descriptor_kind.replace("_package", "_payload")
            payload_root = descriptor.get("payload_root") if isinstance(descriptor, Mapping) else None
            try:
                fr.check_root(payload_root, f"{descriptor_kind}.payload_root")
            except fr.FrontierError as exc:
                raise ChainFirstError("MALFORMED_ARTIFACT", str(exc)) from exc
            payload_commitment = next(
                (item for item in snapshot.artifacts if item.kind == payload_kind), None)
            if payload_commitment is None or payload_commitment.root != payload_root:
                raise ChainFirstError(
                    f"{descriptor_kind.upper()}_SUBSTITUTION",
                    f"signed {descriptor_kind} does not resolve to the fetched {payload_kind}",
                )
        checks.extend(("artifacts_rehashed", "manifest_signatures"))

        # The join roots are derived from the fetched, rehashed deterministic artifact. They are
        # never accepted merely because a chain adapter repeated the same caller-supplied values
        # into both the snapshot and candidate receipt.
        evaluation = fetched.get("eval_artifact")
        if not isinstance(evaluation, Mapping):
            raise ChainFirstError(
                "MISSING_ARTIFACT",
                "chain dispatch omitted the deterministic eval_artifact needed for receipt replay",
            )
        artifact_receipt = evaluation.get("receipt")
        artifact_selection = evaluation.get("selection")
        if not isinstance(artifact_receipt, Mapping) or not isinstance(artifact_selection, Mapping):
            raise ChainFirstError(
                "MALFORMED_ARTIFACT",
                "eval_artifact must contain receipt and fresh-selection objects",
            )
        deterministic_root = artifact_receipt.get("receipt_hash")
        try:
            fr.check_root(deterministic_root, "eval_artifact.receipt.receipt_hash")
            fresh_root = hashlib.sha256(
                pub.benchmark_canonical_bytes(artifact_selection)).hexdigest()
        except (fr.FrontierError, TypeError, ValueError) as exc:
            raise ChainFirstError("MALFORMED_ARTIFACT", str(exc)) from exc
        if snapshot.deterministic_receipt_root != deterministic_root:
            raise ChainFirstError(
                "CHAIN_SNAPSHOT_INCONSISTENT",
                "snapshot deterministic receipt root disagrees with the fetched eval artifact",
            )
        if snapshot.fresh_selection_root != fresh_root:
            raise ChainFirstError(
                "CHAIN_SNAPSHOT_INCONSISTENT",
                "snapshot fresh-selection root disagrees with the fetched eval artifact",
            )
        checks.append("deterministic_artifact_join")

        pins = chain.pins(event.epoch)
        if (pins.runtime_abi_root != snapshot.runtime_root
                or pins.benchmark_law_root != snapshot.law_root
                or pins.counter_resource_law_root != snapshot.counter_root):
            raise ChainFirstError("CHAIN_SNAPSHOT_INCONSISTENT",
                                  "independent chain pins disagree with the canonical snapshot")
        _verify_receipt_bindings(candidate_receipt, event=event, snapshot=snapshot, now=now,
                                 max_ttl=max_receipt_ttl,
                                 verifier=candidate_receipt_verifier)
        checks.append("candidate_receipt")

        canary_report = None
        if canary is not None:
            if canary_verifier is None:
                raise ChainFirstError("CANARY_SIGNATURE_INVALID",
                                      "committed canary has no configured signature verifier")
            canary_report = _verify_canary(canary, candidate_receipt, now=now, store=store,
                                           verifier=canary_verifier)
            checks.append("canary_evidence")

        # Signature verification is mandatory: the optional low-level replay hook is always
        # populated here, and candidate execution cannot precede this point.
        kwargs = dict(replay_kwargs or {})
        kwargs["signature_verifier"] = deterministic_receipt_verifier
        kwargs["pins"] = dp.pins_from_mapping({event.epoch: pins})
        replayed = rp.replay_advance(event, store=store, **kwargs)
        if not replayed.ok:
            return ChainFirstResult(False, replayed.code, tuple(checks), replayed, canary_report,
                                    replayed.reason)
        checks.append("deterministic_replay")
        return ChainFirstResult(True, "PASS", tuple(checks), replayed, canary_report)
    except ChainFirstError as exc:
        return ChainFirstResult(False, exc.code, tuple(checks), reason=str(exc))
    except (fr.FrontierError, dp.DispatchError) as exc:
        return ChainFirstResult(False, "MALFORMED_CHAIN_STATE", tuple(checks), reason=str(exc))
