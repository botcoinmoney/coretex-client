# SPDX-License-Identifier: Apache-2.0
"""Build and verify the one public fixed-suite evaluation artifact.

The on-chain ``evalReportHash`` addresses ``coretex.memory-eval-artifact.v3``. Validation is
content-addressed and fail-closed: reproduce the frontier transition, bind the exact public parent,
verify canonical-suite membership and the stored parent vector, recompute the componentwise
non-regression result, and bind the unsigned deterministic Benchmark-v2 report. Epoch secrets and
openings never enter this module; the report's entropy-named fields are fixed public receipt-format
constants and select nothing.
"""
from __future__ import annotations

import decimal
import hashlib
import json
import os
from typing import Any, Dict, Mapping, Optional, Tuple

from . import canonical_suite as cs
from . import frontier as fr
from . import parent_execution as parent_exec
from . import publication as pub

# --------------------------------------------------------------------------- #
# Identity constants
# --------------------------------------------------------------------------- #
#: THE GENESIS FIXED-SUITE LAW (Benchmark-v2 law ``dominance-fixed-suite.v1``). The artifact
#: records an evaluation whose CASES ARE LAW, not a draw: it carries the complete ``suite`` block
#: and additionally binds the three things the
#: componentwise rule decides against — the exact parent's STORED qualifying vector (the
#: determinism witness), the law-bound constructor-genesis FLOOR, and the DOMINANCE report itself.
#:
#: The only shipped evaluation artifact family.
ARTIFACT_FORMAT = "coretex.memory-eval-artifact.v3"

#: The Benchmark-v2 law id a v3 artifact's evaluation report must be bound to. Stated here so the
#: artifact layer refuses a mismatched pairing instead of inferring one.
FIXED_SUITE_LAW_ID = "benchmark-v2-law/dominance-fixed-suite.v1"
FIXED_MEASUREMENT_POLICY = "final-render-trusted-hostwork.v4"
#: The decision engine that law names. Mirrors ``benchmark-v2/frontier/dominance.ENGINE_ID``.
DOMINANCE_ENGINE_ID = "dominance.componentwise.v1"

COUNTER_RESOURCE_LAW_FORMAT = "coretex.counter-resource-law.v1"
FIXED_CAP_RESOURCE_NORMALIZER = "fixed_product_cap_c"
SATURATING_RESOURCE_OVERFLOW_POLICY = "saturate_at_resource_ppm_max"

#: THE EVALUATION REPORT — the deterministic Benchmark-v2 result this artifact addresses. V5 does
#: not mint a new family; ``benchmark-v2/validator/receipt.py`` owns this shape, and it is
#: canonical and content-addressed on its own (:func:`eval_report_root`).
EVAL_REPORT_FORMAT = "benchmark-v2/receipt/v1"
RECEIPT_BODY_FORMAT = EVAL_REPORT_FORMAT

SELECTION_LABELS = ("gate", "confirm")

#: Fixed-point scale for every measured quantity in the artifact.
MICRO = 1_000_000
#: uint32 ceiling — the receipt's ppm fields are ``uint32`` on-chain.
MAX_UINT32 = 2 ** 32 - 1
#: uint64 ceiling — epoch and byte counters.
MAX_UINT64 = 2 ** 64 - 1

#: The committed counter-resource law document shipped with this lane.
COUNTER_RESOURCE_LAW_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "COUNTER_RESOURCE_LAW.v1.json")

#: Availability names a broadcastable receipt REQUIRES (spec §9). ``eval_report`` replaced
#: ``receipt_wrapper``: what a validator must be able to fetch is the deterministic RESULT, which
#: is canonical and content-addressed on its own.
REQUIRED_AVAILABILITY = ("candidate_bundle", "composition_manifest", "counter_resource_law",
                         "eval_report", "parent_frontier_manifest")
#: What an evaluation JOB is handed and must publish before the artifact exists. The candidate
#: module itself is transported separately from the JSON objects and is added by the worker after
#: it has rehashed the exact decoded bytes against the candidate bundle's source provenance.
SUPPLIED_AVAILABILITY = REQUIRED_AVAILABILITY
#: Extra objects required by the rig lane. ``candidate_module`` is the submitted executable
#: miner bytes. ``candidate_adapter_module`` is the same bytes under the coordinator availability
#: kind name (there is no adapter wrapper; both kinds address ``module.py``). Publishing one
#: without the other still fails the coordinator's required-kind set.
#: ``transition_artifact`` is the complete state-transition document minted by the worker after
#: evaluation.
CANDIDATE_MODULE_AVAILABILITY_KIND = "candidate_module"
CANDIDATE_ADAPTER_MODULE_AVAILABILITY_KIND = "candidate_adapter_module"
RESULTING_FRONTIER_AVAILABILITY_KIND = "resulting_frontier_manifest"
#:
#: ``transition_artifact`` is the COMPLETE canonical patch artifact the descriptor's
#: ``patchArtifactHash`` addresses — the document that, with the parent state, reproduces
#: ``newStateRoot`` by pure replay. The chain COMMITS it and never fetches it, so if it is not
#: servable the advance still confirms, the credits are still paid, and every validator carries a
#: backlog entry whose replay fails PERMANENTLY. Spec §6.3 makes publishing-and-reading-it-back a
#: PRE-SIGN requirement, and ``coretex-memory-frontier-lane.ts``'s
#: ``CORETEX_MEMORY_REQUIRED_ARTIFACT_KINDS`` has required a record for it since the descriptor
#: landed — but NOTHING IN THIS REPO PRODUCED ONE. The only place the string occurred was inside
#: the TypeScript test doubles, so the coordinator's requirement was unsatisfiable by its own
#: named port implementation and the stack was fail-closed by accident rather than by design.
#:
#: IT IS RIG-SCOPED, not universal, and the distinction is real rather than a convenience: the
#: transition descriptor is a RIG-protocol member. An artifact with no ``rig_receipt`` block mints
#: no descriptor, addresses no patch artifact, and has nothing to publish — requiring one of it
#: would be requiring a document that does not exist. So the rig set applies exactly when a rig
#: receipt is about to be signed, which is the same condition ``require_rig_receipt`` already
#: expresses.
RIG_REQUIRED_AVAILABILITY = REQUIRED_AVAILABILITY + (
    CANDIDATE_MODULE_AVAILABILITY_KIND, CANDIDATE_ADAPTER_MODULE_AVAILABILITY_KIND,
    RESULTING_FRONTIER_AVAILABILITY_KIND,
    "transition_artifact")
#: The kind name, stated once. Must equal ``validator/chain_first.RIG_TRANSITION_ARTIFACT_KIND``
#: and the TypeScript lane's member of ``CORETEX_MEMORY_REQUIRED_ARTIFACT_KINDS``.
TRANSITION_ARTIFACT_AVAILABILITY_KIND = "transition_artifact"
#: ``rig_receipt`` remains optional at artifact construction; the refusal lives in verification:
#: :func:`verify_artifact` with ``require_rig_receipt=True`` (which the rig pre-sign gate always
#: passes) refuses an artifact that is about to be bound to a rig receipt but carries none of the
#: eight fields such a descriptor-v3 receipt signs.
OPTIONAL_ARTIFACT_FIELDS: Tuple[str, ...] = ("rig_receipt",)

CANDIDATE_FIELDS = ("candidate_hash", "prior_release_root", "release_root", "target_profile")
FRONTIER_FIELDS = ("benchmark_law_root", "composition_root", "new_frontier_root",
                   "parent_frontier_root", "runtime_abi_root", "transition",
                   "transition_bytes_len", "transition_id_sha256")
# --------------------------------------------------------------------------- #
# Current fixed-suite closed schemas
# --------------------------------------------------------------------------- #
ARTIFACT_FIELDS: Tuple[str, ...] = (
    "admission_projection", "availability", "candidate", "counter_resource_law_root",
    "determinism_witness", "dominance",
    "epoch", "format", "frontier", "genesis_floor", "measurements", "receipt", "replay_inputs",
    "resource_accounting", "suite", "verdict",
)

#: The law-bound exam this evaluation was scored on. ``suite_root`` is the sha256 of the suite
#: document's exact on-disk bytes — the same value ``evaluation_law``'s fixed identities bind — so
#: an artifact naming a different exam than the law it cites is a mismatch, not a variation.
SUITE_FIELDS = ("cases", "counts", "format", "law_id", "profile_id", "scales", "suite_root",
                "suite_version")
#: One suite case. ``suite_index`` is the case's ordinal inside its partition; there is no
#: ``derivation_index`` because there is no walk.
SUITE_CASE_FIELDS = ("instance_hash", "instance_id", "profile_id", "scale", "seed", "suite_index")

#: One ABSOLUTE VECTOR (LAW §3A.2) — the DETERMINISTIC subset, and only it. ``latency_micro`` /
#: ``compute_micro`` / ``host_profile`` are host-dependent telemetry: they are measured, projected
#: and bound in ``measurements`` exactly as before, and they are NEVER witness or floor inputs,
#: because a stored vector that depended on them could not be reproduced on another host.
VECTOR_FIELDS = ("composite_micro", "envelope_logical_durable_storage_bytes",
                 "envelope_rendered_cost_micro", "envelope_work_fuel",
                 "logical_durable_storage_bytes", "objectives_micro",
                 "rendered_cost_micro", "suite_block_id", "work_fuel")

#: The exact parent's STORED qualifying vector, carried into the job and bound here. Genesis
#: references resolve to the sealed public baseline; later parents resolve to their accepting
#: fixed-suite artifact.
DETERMINISM_WITNESS_FIELDS = ("law_id", "partitions", "profile_id", "release_root", "source_kind",
                              "source_root", "suite_root", "witness_root")
WITNESS_SOURCE_KINDS = ("genesis", "prior_accept")
GENESIS_BASELINE_FORMAT = "coretex.genesis-baseline/v1"
GENESIS_BASELINE_FIELDS = ("baseline_root", "format", "law_id", "profiles", "suite_root")
GENESIS_BASELINE_PROFILE_FIELDS = ("law_id", "partitions", "profile_id", "release_root",
                                   "stored_vector_root", "suite_root")

#: The law-bound constructor-genesis floor, as it was resolved for this decision.
GENESIS_FLOOR_FIELDS = ("partitions", "source", "status", "suite_root")

#: The componentwise decision, DERIVED from the evaluation report's bound verdicts — never
#: restated. ``partitions.<label>.incumbent_vector`` is the parent arm's RECOMPUTED vector; the
#: determinism witness holds the STORED one, and their equality is the witness check.
DOMINANCE_FIELDS = ("admit", "engine", "partitions")
DOMINANCE_PARTITION_FIELDS = ("admit", "candidate_vector",
                              "composite_after_ppm",
                              "composite_before_ppm", "composite_gain_ppm", "floor_regressions",
                              "hard", "hard_ok", "incumbent_vector",
                              "regressed_objectives",
                              "regressed_resource_axes")
DOMINANCE_PARTITION_ADMIT_FIELDS = DOMINANCE_PARTITION_FIELDS + (
    "admission_gain_ppm", "progress_class")
ADMISSION_PROJECTION_FIELDS = ("score_before_ppm",)
ADMISSION_PROJECTION_ADMIT_FIELDS = ("class", "score_after_ppm", "score_before_ppm")
PROGRESS_CLASSES = ("quality", "efficiency")
MEASUREMENT_FIELDS = ("branches", "micro_scale", "policy")
SIDE_FIELDS = ("composite_micro", "compute_micro", "corpus_supported", "events_scanned",
               "hook_compute_fuel", "hook_fuel", "host_profile", "latency_micro",
               "logical_durable_storage_bytes", "objectives_micro", "rendered_cost_micro",
               "storage_bytes", "store_events", "store_ops", "work_fuel")
RECEIPT_FIELDS = ("code_roots", "eval_report_root", "measurement_policy", "outputs_hash")
REPLAY_INPUT_FIELDS = ("candidate_declaration_id", "candidate_exec", "candidate_manifest_hash",
                       "candidate_module_bytes", "incumbent", "parent_manifest")
#: ``candidate_module_bytes`` is the UTF-8 length of the submitted miner module — NON-CONSENSUS
#: TELEMETRY, and the schema says so by construction: nothing compares it, no rule reads it, no
#: floor bounds it. It is reported because module footprint is the one place a
#: candidate can carry per-case specialization WITHOUT paying `logical_durable_storage_bytes` (the
#: logical meter charges sanctioned durable tables only; modules are bounded solely by the 256 KiB
#: `MAX_ARTIFACT_BYTES` admission cap). Metering it into a protected axis would be unsatisfiable —
#: constructor genesis executes a builtin and therefore has no module bytes, so making this a
#: no-regression axis would make every submitted module inadmissible. The law instead applies the
#: hard artifact cap and reports the size for review. It re-derives from the
#: bound report body, so it can be recomputed rather than believed.
REFERENCE_INCUMBENT_FIELDS = ("candidate_hash", "exec", "id", "protocol", "release_root")
CANDIDATE_INCUMBENT_FIELDS = ("candidate_hash", "exec", "id", "module_sha256", "release_root")
RESOURCE_ACCOUNTING_FIELDS = ("branch", "resource_after_ppm", "resource_before_ppm",
                              "utility_after_ppm", "utility_before_ppm")
VERDICT_FIELDS = ("admit", "consensus_critical", "decision_hash", "verdict")
COUNTER_LAW_FIELDS = ("branch", "format", "resource_axes", "resource_normalizer",
                      "resource_overflow_policy", "resource_ppm_max", "utility_axis",
                      "utility_ppm_max")
RESOURCE_AXIS_FIELDS = ("id", "integer_axis", "source", "unit", "weight_ppm")

# --------------------------------------------------------------------------- #
# The RIG-PROTOCOL receipt fields (V5 rig-keyed integration, step 6)
# --------------------------------------------------------------------------- #
#: The NINE signed ``RigCoreTexReceipt`` fields that no other part of the artifact carries.
#:
#: The descriptor-v3 rig receipt signs 24 fields. Sixteen of them the artifact already determines (the state
#: roots, ``evalReportHash``, the ppm scores) or the chain does (``rigId``, ``operator``,
#: ``epochId``, ``solveIndex``, ``prevReceiptHash``, ``workUnitsBps``,
#: ``difficultyCountSnapshot``, ``issuedAt``, ``expiresAt``, ``patchHash``, ``artifactHash``).
#: These eight are the remainder: values only the EVALUATOR can know. They live here, inside the
#: bytes ``evalReportHash`` addresses, so they are hashed and signed rather than merely asserted
#: by whichever process happened to build the calldata — the ruling
#: ``RIG-CORETEX-REGISTRY-DESIGN.md`` §5.1 made for the ``uint16`` slot at signed member 20, which
#: applies equally to the other eight.
#:
#: THAT SLOT IS NOW ``transition_format_version``, not ``state_word_count``
#: (``coretex.transition-descriptor/v3`` §9.1). It is the only word-model field in the signed
#: struct and the only one the retirement moves; the typehash moves with it, so every receipt
#: signed under the old one is unverifiable here and vice versa, and there is NO dual-accept window.
RIG_RECEIPT_FIELDS = ("challenge_id", "core_version_hash", "epoch_context_root", "outcome",
                      "rules_version", "transition_format_version", "work_policy_hash",
                      "world_seed")

#: ``outcome`` values the rig verifier prices. 0 and anything above 2 revert for EVERY epoch, so
#: an artifact may not even claim them.
RIG_OUTCOME_SCREENER_PASS = 1
RIG_OUTCOME_STATE_ADVANCE = 2
RIG_SIGNABLE_OUTCOMES: Tuple[int, ...] = (RIG_OUTCOME_SCREENER_PASS, RIG_OUTCOME_STATE_ADVANCE)

#: ``uint128`` — ``worldSeed``'s deployed ABI width. CoreTex reserves the member as zero.
MAX_UINT128 = 2 ** 128 - 1
RIG_CORETEX_RESERVED_WORLD_SEED = 0
#: ``uint16`` — ``transitionFormatVersion``'s signed width.
MAX_UINT16 = 2 ** 16 - 1

#: ``RIG_TRANSITION_FORMAT_VERSION`` is what the slot carries instead. The signed member is a
#: ``uint16`` while the descriptor's version is ONE byte; the receipt's value is the zero-extension
#: and the verifier requires exact equality, so the upper byte MUST be zero. THE DESCRIPTOR BYTE IS
#: THE AUTHORITY; the signed member is the binding.
RIG_TRANSITION_FORMAT_VERSION = 0x21
#: A screener pass advances no state, so it carries an EMPTY descriptor and signs zero here — and
#: zero is not a version, it is the absence of one.
RIG_SCREENER_TRANSITION_FORMAT_VERSION = 0

#: The camelCase spelling of each field, for the TypeScript coordinator.
#: ``coretex-memory-v5-worker-client.ts::decodeEvaluation`` reads every rig field through
#: ``pick(e, "<snake_case>", "<camelCase>")``, accepting both "only because the Python artifact
#: and the JS coordinator spell them differently". :func:`rig_receipt_projection` emits BOTH so
#: neither side has to guess which spelling the other chose.
RIG_RECEIPT_CAMEL_CASE: Dict[str, str] = {
    "challenge_id": "challengeId",
    "core_version_hash": "coreVersionHash",
    "epoch_context_root": "epochContextRoot",
    "outcome": "outcome",
    "rules_version": "rulesVersion",
    "transition_format_version": "transitionFormatVersion",
    "work_policy_hash": "workPolicyHash",
    "world_seed": "worldSeed",
}
#: The four that are 32-byte roots on chain.
RIG_RECEIPT_ROOT_FIELDS = ("challenge_id", "core_version_hash", "epoch_context_root",
                           "work_policy_hash")

#: ABI-wide fields rendered as decimal strings by :func:`rig_receipt_projection`. CoreTex permits
#: only zero for ``world_seed``, but preserving the string wire type keeps the deployed uint128
#: member unambiguous across Python and JavaScript. ``outcome`` (uint8), ``rules_version`` (uint32)
#: and ``transition_format_version`` (uint16) stay numbers.
RIG_RECEIPT_WIDE_UINT_FIELDS = ("world_seed",)

# --------------------------------------------------------------------------- #
# Typed errors — one class per fail-closed reason (frontier.py discipline)
# --------------------------------------------------------------------------- #
class EvalArtifactError(Exception):
    """Base class for every eval-artifact failure."""


class ArtifactSchemaError(EvalArtifactError):
    """Wrong/absent ``format``, a missing required field, or an unknown closed-schema field."""


class ArtifactTypeError(EvalArtifactError):
    """A field is present with the wrong type (including explicit ``null`` and bool-as-int)."""


class ArtifactValueError(EvalArtifactError):
    """Right type, illegal value (bad root, out-of-range integer, unknown enum member)."""


class MeasurementPrecisionError(EvalArtifactError):
    """A measured value is not exactly representable at 6 decimal places, so it cannot enter the
    artifact as an exact micro-integer. Refused rather than rounded."""


class BindingMismatchError(EvalArtifactError):
    """A bound value does not equal the value it claims to describe. Base of the specific
    mismatches below, so a caller may catch the family."""


class ParentRootMismatchError(BindingMismatchError):
    """The artifact's parent frontier root is not the confirmed live root it must extend."""


class NewRootMismatchError(BindingMismatchError):
    """The artifact's proposed new frontier root is not the one the transition produces."""


class ReleaseRootMismatchError(BindingMismatchError):
    """Candidate release root disagrees between the artifact, the transition and the caller."""


class CompositionRootMismatchError(BindingMismatchError):
    """Composition root disagrees between the artifact, the transition and the caller."""


class EpochPinMismatchError(BindingMismatchError):
    """A benchmark-law / runtime-ABI / counter-resource-law pin does not match."""


class SuiteMembershipError(BindingMismatchError):
    """The artifact's cases are not the immutable canonical suite's exact cases."""

    code = "SUITE_MEMBERSHIP_MISMATCH"


class DeterminismWitnessMismatchError(BindingMismatchError):
    """The re-executed parent arm did not reproduce the parent's STORED qualifying vector.

    Refusal code ``DETERMINISM_WITNESS_MISMATCH``. LAW §3A.3: this is an ENVIRONMENT-DRIFT
    DETECTOR and it fails closed. It never makes a candidate pass and it never adjusts a number —
    if the same parent bytes on the same fixed cases no longer produce the same vector, the thing
    that changed is the evaluator, and no admission computed on this run means anything.
    """

    code = "DETERMINISM_WITNESS_MISMATCH"


class WitnessSourceMismatchError(DeterminismWitnessMismatchError):
    """The object ``determinism_witness.source_root`` names does not carry the stored vector.

    Refusal code ``DETERMINISM_WITNESS_SOURCE_MISMATCH``. The witness is self-addressing, so
    nobody can restate it in transport — but self-addressing only proves the document is internally
    whole. It says nothing about whether the vector inside it was ever MEASURED by the sealed genesis baseline
    or EARNED by a prior accepting artifact. Resolving ``source_root`` against the published object
    is what turns "this document says the parent scored X" into "the genesis baseline or prior accept published
    X for this exact release".
    """

    code = "DETERMINISM_WITNESS_SOURCE_MISMATCH"


class WitnessSourceUnavailableError(EvalArtifactError):
    """``determinism_witness.source_root`` names an object that is not published here.

    Refusal code ``DETERMINISM_WITNESS_SOURCE_UNAVAILABLE``. Distinct from a MISMATCH on purpose:
    an object that cannot be fetched is UNPROVEN (a public validator records a backlog entry and
    retries), while an object that is fetched and disagrees is a refusal that never becomes a pass.
    """

    code = "DETERMINISM_WITNESS_SOURCE_UNAVAILABLE"


class GenesisFloorPendingError(EvalArtifactError):
    """The law-bound constructor-genesis floor is not resolved.

    Refusal code ``GENESIS_FLOOR_PENDING``. LAW §3A.3: a pending floor is a REFUSAL, never a
    skipped check — an admission is not computable without one.
    """

    code = "GENESIS_FLOOR_PENDING"


class ReceiptBindingError(BindingMismatchError):
    """The artifact and the addressed deterministic evaluation report disagree."""


class VerdictMismatchError(BindingMismatchError):
    """The bound verdict is not the receipt's deterministic decision."""


class RenderedCostMismatchError(BindingMismatchError):
    """A bound consumer-visible rendered cost is not the receipt's measured value."""


class ResourceAccountingError(BindingMismatchError):
    """Utility/resource ppm do not recompute from the receipt under the pinned counter law."""


class TransitionIdentityMismatchError(BindingMismatchError):
    """The canonical frontier-transition content id is wrong."""


class RigReceiptFieldsMissingError(EvalArtifactError):
    """An artifact about to be bound to a RIG receipt carries no ``rig_receipt`` block.

    Deliberately NOT a :class:`BindingMismatchError`: nothing mismatched. The artifact simply
    cannot supply eight of the twenty-four fields the coordinator is about to sign, so signing
    would mean inventing them — and an invented receipt field is one no validator can reproduce
    from the evidence ``evalReportHash`` addresses.
    """


class RigReceiptFieldError(BindingMismatchError):
    """The ``rig_receipt`` block is present but not signable as it stands."""


class ReceiptUnavailableError(EvalArtifactError):
    """Verification needs the addressed report and was given neither it nor a public store."""


class CounterResourceLawError(EvalArtifactError):
    """The counter-resource law document is malformed or unavailable."""


class PreSignError(EvalArtifactError):
    """The pre-sign gate refused to produce a broadcastable receipt."""


# --------------------------------------------------------------------------- #
# Small typed helpers
# --------------------------------------------------------------------------- #
def _check_closed(document: Any, required: Tuple[str, ...], family: str,
                  optional: Tuple[str, ...] = ()) -> Dict[str, Any]:
    if not isinstance(document, dict):
        raise ArtifactSchemaError(f"{family} must be a JSON object, got "
                                  f"{type(document).__name__}")
    missing = [f for f in required if f not in document]
    if missing:
        raise ArtifactSchemaError(f"{family} missing required field(s): {missing}")
    unknown = sorted(set(document) - set(required) - set(optional))
    if unknown:
        raise ArtifactSchemaError(
            f"{family} carries unknown field(s) {unknown}; the schema is CLOSED so nothing can "
            "ride along inside an addressed root that a validator cannot interpret")
    return document


def _check_int(value: Any, field: str, *, minimum: int = 0,
               maximum: int = MAX_UINT64) -> int:
    if value is None:
        raise ArtifactTypeError(f"{field} is null; an integer must be present")
    if isinstance(value, bool):
        raise ArtifactTypeError(
            f"{field} is a bool; bool is an int subclass in Python and would serialize as "
            "true/false — refused")
    if not isinstance(value, int):
        raise ArtifactTypeError(f"{field} must be an integer, got {type(value).__name__}")
    if value < minimum or value > maximum:
        raise ArtifactValueError(f"{field}={value} out of range [{minimum}, {maximum}]")
    return value


def _check_str(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if value is None:
        raise ArtifactTypeError(f"{field} is null; a string must be present")
    if not isinstance(value, str):
        raise ArtifactTypeError(f"{field} must be a string, got {type(value).__name__}")
    if not value and not allow_empty:
        raise ArtifactValueError(f"{field} must not be empty")
    return value


def _check_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ArtifactTypeError(f"{field} must be a bool, got {type(value).__name__}")
    return value


def _require(condition: bool, error: type, message: str) -> None:
    if not condition:
        raise error(message)


def project_incumbent(incumbent: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and project one of the two exact public parent identities."""
    if not isinstance(incumbent, dict):
        raise ReceiptBindingError("receipt incumbent must be an object")
    incumbent_exec = _check_str(incumbent.get("exec"), "receipt incumbent.exec")
    fields = (REFERENCE_INCUMBENT_FIELDS if incumbent_exec == "reference"
              else CANDIDATE_INCUMBENT_FIELDS if incumbent_exec == "candidate_module"
              else None)
    if fields is None or set(incumbent) != set(fields):
        raise ReceiptBindingError(
            "receipt incumbent must be exactly the builtin-reference identity or the "
            "candidate-module identity")
    incumbent_id = _check_str(incumbent["id"], "receipt incumbent.id")
    candidate_hash = incumbent.get("candidate_hash")
    if incumbent_exec == "reference":
        if candidate_hash not in (None, fr.ZERO_ROOT):
            raise ReceiptBindingError(
                "builtin reference incumbent candidate_hash must be null/zero")
        candidate_hash = fr.ZERO_ROOT
        if incumbent_id != "reference-runtime" or incumbent.get("protocol") != "rrm1":
            raise ReceiptBindingError(
                "builtin reference incumbent must identify reference-runtime/rrm1")
    else:
        fr.check_root(candidate_hash, "receipt incumbent.candidate_hash")
    release_root = fr.check_root(incumbent["release_root"], "receipt incumbent.release_root")
    projected = {
        "candidate_hash": candidate_hash,
        "exec": incumbent_exec,
        "id": incumbent_id,
        "release_root": release_root,
    }
    if incumbent_exec == "reference":
        projected["protocol"] = "rrm1"
    else:
        projected["module_sha256"] = fr.check_root(
            incumbent["module_sha256"], "receipt incumbent.module_sha256")
    return projected


def to_micro(value: Any, field: str) -> int:
    """EXACT micro-unit integer for a measured quantity. Never rounds.

    Benchmark-v2 rounds every measured float to 6 decimal places
    (``round(x, 6)``), so every legitimate value converts exactly. ``Decimal(repr(x))`` is the
    decimal ``json.dumps`` would emit for ``x`` (both use ``float.__repr__``), so this reads the
    receipt's own serialized value rather than a re-derived approximation of it.

    A value with more than 6 significant decimal places is a :class:`MeasurementPrecisionError`,
    not a rounding opportunity: silently rounding would let two different measurements produce one
    artifact, which is exactly the collision the canonical rule exists to prevent.
    """
    if value is None:
        raise ArtifactTypeError(f"{field} is null; a measurement must be present")
    if isinstance(value, bool):
        raise ArtifactTypeError(f"{field} is a bool, not a measurement")
    if isinstance(value, int):
        return value * MICRO
    if not isinstance(value, float):
        raise ArtifactTypeError(
            f"{field} must be a number, got {type(value).__name__}")
    if value != value or value in (float("inf"), float("-inf")):
        raise MeasurementPrecisionError(f"{field}={value!r} is not a finite measurement")
    scaled = decimal.Decimal(repr(value)) * MICRO
    if scaled != scaled.to_integral_value():
        raise MeasurementPrecisionError(
            f"{field}={value!r} is not exactly representable at 6 decimal places "
            f"(x10^6 = {scaled}); refused rather than rounded")
    return int(scaled)


def eval_report_root(report: Mapping[str, Any]) -> str:
    """THE CONTENT ADDRESS OF THE EVALUATION REPORT — ``sha256`` over its canonical bytes.

    The whole of v2's replacement for a signature, in one line. The report is canonical (one
    document spells to exactly one byte string) and content-addressed (that byte string has exactly
    one name), so "which result was this" is answered by rehashing the bytes rather than by asking
    who signed them. Identical rule to :func:`receipt_body_hash`, which is what v1's
    ``receipt_hash`` already was — so nothing about the report's identity changed when the wrapper
    around it stopped being opened.
    """
    return receipt_body_hash(report)


def receipt_body_hash(body: Mapping[str, Any]) -> str:
    """``sha256`` over the Benchmark-v2 canonical bytes of a receipt body.

    Byte-identical to ``benchmark-v2/frontier/_canon.py::hash_obj``, which is what
    ``signing.signed_wrapper`` puts in ``receipt_hash``. Reproduced here (rather than imported)
    so the V5 lane stays stdlib-only and importable without ``benchmark-v2`` on the path;
    ``tests/test_eval_artifact.py`` asserts byte-identity against the real module by file path.
    """
    return fr.sha256_hex(pub.benchmark_canonical_bytes(body))


# --------------------------------------------------------------------------- #
# Canonical bytes + the on-chain evalReportHash
# --------------------------------------------------------------------------- #
def artifact_canonical_bytes(artifact: Mapping[str, Any]) -> bytes:
    """The artifact's canonical bytes — the V5-A rule, unchanged (spec §3)."""
    return fr.canonical_bytes(artifact)


def eval_report_hash(artifact: Mapping[str, Any]) -> str:
    """``sha256`` over the artifact's canonical bytes = the on-chain ``evalReportHash``.

    The artifact is VALIDATED first: an invalid artifact has no hash (it is not addressable),
    rather than a hash nobody can reproduce. Same discipline as ``frontier.frontier_root``.
    """
    validate_artifact(artifact)
    return fr.sha256_hex(artifact_canonical_bytes(artifact))


# --------------------------------------------------------------------------- #
# The counter-resource law (spec §8)
# --------------------------------------------------------------------------- #
def load_counter_resource_law(path: str = COUNTER_RESOURCE_LAW_PATH) -> Dict[str, Any]:
    """Read + validate the committed law document."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise CounterResourceLawError(f"cannot read counter-resource law {path}: {exc}") from exc
    return validate_counter_resource_law(fr.parse_json(text))


def validate_counter_resource_law(law: Any) -> Dict[str, Any]:
    """Fail-closed structural validation of a ``coretex.counter-resource-law.v1`` document."""
    _check_closed(law, COUNTER_LAW_FIELDS, COUNTER_RESOURCE_LAW_FORMAT)
    if law["format"] != COUNTER_RESOURCE_LAW_FORMAT:
        raise CounterResourceLawError(
            f"format {law['format']!r} is not {COUNTER_RESOURCE_LAW_FORMAT!r}")
    if law["branch"] not in SELECTION_LABELS:
        raise CounterResourceLawError(
            f"branch {law['branch']!r} must be one of {SELECTION_LABELS}")
    if law["resource_normalizer"] != FIXED_CAP_RESOURCE_NORMALIZER:
        raise CounterResourceLawError(
            f"resource_normalizer {law['resource_normalizer']!r} is not the fixed-cap "
            f"normalizer {FIXED_CAP_RESOURCE_NORMALIZER!r}")
    if law["resource_overflow_policy"] != SATURATING_RESOURCE_OVERFLOW_POLICY:
        raise CounterResourceLawError(
            f"resource_overflow_policy {law['resource_overflow_policy']!r} is not the "
            f"non-admission telemetry policy {SATURATING_RESOURCE_OVERFLOW_POLICY!r}")
    _check_int(law["resource_ppm_max"], "resource_ppm_max", minimum=1, maximum=MAX_UINT32)
    _check_int(law["utility_ppm_max"], "utility_ppm_max", minimum=1, maximum=MAX_UINT32)
    util = _check_closed(law["utility_axis"], ("scale_max", "source"), "utility_axis")
    _check_str(util["source"], "utility_axis.source")
    _check_int(util["scale_max"], "utility_axis.scale_max", minimum=1)
    axes = law["resource_axes"]
    if not isinstance(axes, list) or not axes:
        raise CounterResourceLawError("resource_axes must be a non-empty array")
    total = 0
    seen = set()
    for i, axis in enumerate(axes):
        _check_closed(axis, RESOURCE_AXIS_FIELDS, f"resource_axes[{i}]")
        _check_str(axis["id"], f"resource_axes[{i}].id")
        _check_str(axis["source"], f"resource_axes[{i}].source")
        _check_str(axis["unit"], f"resource_axes[{i}].unit")
        _check_bool(axis["integer_axis"], f"resource_axes[{i}].integer_axis")
        total += _check_int(axis["weight_ppm"], f"resource_axes[{i}].weight_ppm",
                            minimum=0, maximum=MICRO)
        if axis["id"] in seen:
            raise CounterResourceLawError(f"duplicate resource axis id {axis['id']!r}")
        seen.add(axis["id"])
    if total != MICRO:
        raise CounterResourceLawError(
            f"resource axis weights sum to {total} ppm, not {MICRO}; a side exactly at fixed "
            "product cap C must evaluate to exactly 1_000_000 ppm")
    return law


def counter_resource_law_root(law: Mapping[str, Any]) -> str:
    """``sha256`` over the law's V5-A canonical bytes — the on-chain ``counterResourceLawRoot``."""
    validate_counter_resource_law(law)
    return fr.sha256_hex(fr.canonical_bytes(law))


def _axis_micro(side: Mapping[str, Any], axis: Mapping[str, Any], where: str) -> int:
    """The micro-unit value of one resource axis on one measured side of the artifact."""
    source = axis["source"]
    if source == "rendered_cost":
        return _check_int(side["rendered_cost_micro"], f"{where}.rendered_cost_micro")
    if source.startswith("resource."):
        key = source.split(".", 1)[1]
        if key not in side:
            raise CounterResourceLawError(
                f"{where} carries no resource axis {key!r} required by the pinned law")
        return _check_int(side[key], f"{where}.{key}") * MICRO
    raise CounterResourceLawError(f"unknown resource axis source {source!r}")


def _axis_cap_micro(fixed_cap: Mapping[str, Any], axis: Mapping[str, Any]) -> int:
    """The positive fixed-product cap ``C`` for one resource axis, in micro units.

    ``fixed_cap`` is one law-validated absolute vector.  The artifact layer separately proves
    that the parent and candidate both carry this canonical ``C``; using it here keeps aggregate
    accounting descriptive.  In particular, a zero measured parent axis is a valid reading, not
    a missing denominator that can strand the lineage.
    """
    source = axis["source"]
    if source == "rendered_cost":
        key = "envelope_rendered_cost_micro"
        scale = 1
    elif source.startswith("resource."):
        key = f"envelope_{source.split('.', 1)[1]}"
        scale = MICRO
    else:
        raise CounterResourceLawError(f"unknown resource axis source {source!r}")
    if key not in fixed_cap:
        raise CounterResourceLawError(
            f"fixed product cap carries no {key!r} required by resource axis {axis['id']!r}")
    value = _check_int(fixed_cap[key], f"fixed_cap.{key}") * scale
    if value <= 0:
        raise CounterResourceLawError(
            f"fixed product cap {key!r} is {value}; every metered cap axis must be positive")
    return value


def _canonical_fixed_cap_for_accounting(*, profile_id: str, branch: str,
                                        candidate_vector: Mapping[str, Any],
                                        incumbent_vector: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate both serialized envelopes and return law-owned ``C`` for this partition."""
    if branch not in SELECTION_LABELS:
        raise CounterResourceLawError(
            f"counter-resource branch {branch!r} must be one of {SELECTION_LABELS}")
    candidate_vector = _validate_vector(
        candidate_vector, f"counter_resource.{branch}.candidate_vector", profile_id)
    incumbent_vector = _validate_vector(
        incumbent_vector, f"counter_resource.{branch}.incumbent_vector", profile_id)
    canonical = cs.genesis_floor_vector(profile_id, branch)
    for side, vector in (("candidate", candidate_vector), ("incumbent", incumbent_vector)):
        if vector["suite_block_id"] != canonical["suite_block_id"]:
            raise ResourceAccountingError(
                f"{side} suite_block_id {vector['suite_block_id']} is not canonical block "
                f"{canonical['suite_block_id']} for {profile_id!r}/{branch}")
        for axis, _resource_key, cap_key in cs.PRODUCT_CAP_VECTOR_FIELDS:
            if vector[cap_key] != canonical[cap_key]:
                raise ResourceAccountingError(
                    f"{side} {cap_key}={vector[cap_key]} does not equal canonical fixed product "
                    f"cap C={canonical[cap_key]} for {profile_id!r}/{branch} ({axis})")
    return canonical


def evaluate_counter_resource_law(law: Mapping[str, Any], candidate: Mapping[str, Any],
                                  incumbent: Mapping[str, Any],
                                  *, profile_id: str,
                                  candidate_vector: Mapping[str, Any],
                                  incumbent_vector: Mapping[str, Any]) -> Dict[str, int]:
    """Recompute ``{utility_before_ppm, utility_after_ppm, resource_before_ppm,
    resource_after_ppm}`` from two measured sides. EXACT integer arithmetic throughout.

    utility:  ``utility_ppm = composite_micro // scale_max`` — a composite of ``scale_max``
              is exactly 1_000_000 ppm and 0 is exactly 0.
    resource: ``resource_ppm = SUM_axes ( weight_ppm * side_micro[axis] ) // C_micro[axis]``
              — a per-axis floor against the positive fixed product cap ``C``.  Both sides use
              the same denominator, so zero measurements are representable and every cap-valid
              side is in ``[0, 1_000_000]``. Values above the uint32 receipt representation are
              deterministically saturated at ``resource_ppm_max``; the exact raw measurements
              remain in the artifact, and dominance rejects every side above ``C``. The aggregate
              is bound non-admission telemetry; raw ``R`` versus exact-parent ``R`` remains the
              efficiency predicate.

    §17.236 records these ppm values on-chain but does NOT rank them there; the Pareto/resource
    trade-off stays off-chain under this pinned law, bound through ``evalReportHash`` +
    ``counterResourceLawRoot``. This function is that law, executable, and it needs nothing but
    the artifact — no coordinator-private state.
    """
    validate_counter_resource_law(law)
    fixed_cap = _canonical_fixed_cap_for_accounting(
        profile_id=profile_id, branch=law["branch"], candidate_vector=candidate_vector,
        incumbent_vector=incumbent_vector)
    scale_max = law["utility_axis"]["scale_max"]
    out = {
        "utility_before_ppm": _check_int(incumbent["composite_micro"],
                                         "incumbent.composite_micro") // scale_max,
        "utility_after_ppm": _check_int(candidate["composite_micro"],
                                        "candidate.composite_micro") // scale_max,
    }
    for name, side in (("resource_before_ppm", incumbent), ("resource_after_ppm", candidate)):
        total = 0
        for axis in law["resource_axes"]:
            base = _axis_cap_micro(fixed_cap, axis)
            total += (axis["weight_ppm"] * _axis_micro(side, axis, name)) // base
        out[name] = min(total, law["resource_ppm_max"])
    for key, value in out.items():
        limit = law["utility_ppm_max"] if key.startswith("utility") else law["resource_ppm_max"]
        if value > limit:
            raise ResourceAccountingError(
                f"{key}={value} exceeds the pinned ceiling {limit}")
    return out


# --------------------------------------------------------------------------- #
# Measurement projection (spec §8.1)
# --------------------------------------------------------------------------- #
def project_side(side: Mapping[str, Any], where: str) -> Dict[str, Any]:
    """Project one current measured side into exact integer artifact fields."""
    if not isinstance(side, dict):
        raise ArtifactTypeError(f"{where} must be an object, got {type(side).__name__}")
    for key in ("composite", "rendered_cost", "latency_ms", "compute_ms", "storage_bytes",
                "logical_durable_storage_bytes", "corpus_supported", "objectives", "resource"):
        if key not in side:
            raise ReceiptBindingError(f"{where} carries no {key!r}")
    resource = side["resource"]
    if not isinstance(resource, dict):
        raise ArtifactTypeError(f"{where}.resource must be an object")
    objectives = side["objectives"]
    if not isinstance(objectives, dict) or not objectives:
        raise ArtifactTypeError(f"{where}.objectives must be a non-empty object")
    storage = _check_int(resource.get("storage_bytes"), f"{where}.resource.storage_bytes")
    logical = _check_int(resource.get("logical_durable_storage_bytes"),
                         f"{where}.resource.logical_durable_storage_bytes")
    if _check_int(side["storage_bytes"], f"{where}.storage_bytes") != storage:
        raise ReceiptBindingError(f"{where}: storage_bytes disagrees with the resource block")
    if _check_int(side["logical_durable_storage_bytes"],
                  f"{where}.logical_durable_storage_bytes") != logical:
        raise ReceiptBindingError(
            f"{where}: logical_durable_storage_bytes disagrees with the resource block")
    return {
        "composite_micro": to_micro(side["composite"], f"{where}.composite"),
        "compute_micro": to_micro(side["compute_ms"], f"{where}.compute_ms"),
        "corpus_supported": _check_int(side["corpus_supported"], f"{where}.corpus_supported"),
        "events_scanned": _check_int(resource["events_scanned"],
                                     f"{where}.resource.events_scanned"),
        "hook_compute_fuel": _check_int(resource.get("hook_compute_fuel", 0),
                                        f"{where}.resource.hook_compute_fuel"),
        "hook_fuel": _check_int(resource.get("hook_fuel", 0),
                                f"{where}.resource.hook_fuel"),
        "host_profile": _check_str(resource["host_profile"], f"{where}.resource.host_profile"),
        "latency_micro": to_micro(side["latency_ms"], f"{where}.latency_ms"),
        "logical_durable_storage_bytes": logical,
        "objectives_micro": {
            name: to_micro(objectives[name], f"{where}.objectives[{name!r}]")
            for name in sorted(objectives)},
        "rendered_cost_micro": to_micro(side["rendered_cost"], f"{where}.rendered_cost"),
        "storage_bytes": storage,
        "store_events": _check_int(resource["store_events"], f"{where}.resource.store_events"),
        "store_ops": _check_int(resource["store_ops"], f"{where}.resource.store_ops"),
        "work_fuel": _check_int(resource["work_fuel"], f"{where}.resource.work_fuel"),
    }


def candidate_module_bytes(receipt_body: Mapping[str, Any]) -> int:
    """UTF-8 byte length of the directly submitted candidate module."""
    candidate = receipt_body.get("candidate")
    module = candidate.get("module") if isinstance(candidate, Mapping) else None
    source = module.get("source") if isinstance(module, Mapping) else None
    if not isinstance(source, str) or not source:
        raise ReceiptBindingError("candidate.module.source must be non-empty UTF-8 text")
    return len(source.encode("utf-8"))


def project_measurements(receipt_body: Mapping[str, Any]) -> Dict[str, Any]:
    """Project the current fixed-suite report's exact measured values."""
    descriptor = receipt_body.get("evaluation_law")
    if not isinstance(descriptor, Mapping) \
            or descriptor.get("law_id") != FIXED_SUITE_LAW_ID:
        raise ReceiptBindingError("evaluation report is not bound to the current fixed-suite law")
    policy = _check_str(receipt_body.get("measurement_policy"), "measurement_policy")
    if policy != FIXED_MEASUREMENT_POLICY \
            or descriptor.get("measurement_policy") != FIXED_MEASUREMENT_POLICY:
        raise ReceiptBindingError(
            f"current fixed-suite reports require measurement policy {FIXED_MEASUREMENT_POLICY!r}")
    scores = receipt_body.get("scores")
    if not isinstance(scores, dict):
        raise ReceiptBindingError("evaluation report carries no scores object")
    branches = {}
    for branch in SELECTION_LABELS:
        pair = scores.get(branch)
        if not isinstance(pair, dict) or set(pair) != {"candidate", "incumbent"}:
            raise ReceiptBindingError(
                f"evaluation report scores[{branch!r}] must be {{candidate, incumbent}}")
        branches[branch] = {
            "candidate": project_side(pair["candidate"], f"scores[{branch}].candidate"),
            "incumbent": project_side(pair["incumbent"], f"scores[{branch}].incumbent"),
        }
    return {"branches": branches, "micro_scale": MICRO, "policy": policy}


# --------------------------------------------------------------------------- #
# Selection re-derivation (spec §7.2)
# --------------------------------------------------------------------------- #
def artifact_law(artifact: Any) -> str:
    """Refuse every artifact family except the one public fixed-suite format."""
    if not isinstance(artifact, Mapping) or artifact.get("format") != ARTIFACT_FORMAT:
        observed = artifact.get("format") if isinstance(artifact, Mapping) else None
        raise ArtifactSchemaError(
            f"eval artifact format {observed!r} is unsupported; expected {ARTIFACT_FORMAT!r}")
    return FIXED_SUITE_LAW_ID


def validate_artifact(artifact: Any) -> Dict[str, Any]:
    """Fail-closed structural validation of the one public fixed-suite artifact."""
    artifact_law(artifact)
    _check_closed(artifact, ARTIFACT_FIELDS, ARTIFACT_FORMAT, OPTIONAL_ARTIFACT_FIELDS)
    fr.check_epoch(artifact["epoch"])
    fr.check_root(artifact["counter_resource_law_root"], "counter_resource_law_root")

    cand = _check_closed(artifact["candidate"], CANDIDATE_FIELDS, "candidate")
    fr.check_root(cand["candidate_hash"], "candidate.candidate_hash")
    fr.check_root(cand["release_root"], "candidate.release_root")
    fr.check_root(cand["prior_release_root"], "candidate.prior_release_root")
    fr.check_profile_id(cand["target_profile"], "candidate.target_profile")

    front = _check_closed(artifact["frontier"], FRONTIER_FIELDS, "frontier")
    for field in ("benchmark_law_root", "composition_root", "new_frontier_root",
                  "parent_frontier_root", "runtime_abi_root", "transition_id_sha256"):
        fr.check_root(front[field], f"frontier.{field}")
    fr.validate_transition(front["transition"])
    _check_int(front["transition_bytes_len"], "frontier.transition_bytes_len", minimum=1,
               maximum=fr.MAX_TRANSITION_BYTES)

    _validate_fixed_suite_blocks(artifact)
    _validate_measurements_block(artifact)
    _validate_receipt_block(artifact)
    _validate_replay_inputs_block(artifact)
    _validate_accounting_and_verdict(artifact)
    pub.validate_availability(artifact["availability"])

    if "rig_receipt" in artifact:
        validate_rig_receipt_block(artifact["rig_receipt"])

    fr.canonical_bytes(artifact)     # fail closed before anyone addresses it
    return artifact



# --------------------------------------------------------------------------- #
# Fixed-suite artifact blocks.
# --------------------------------------------------------------------------- #
def _validate_measurements_block(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    side_fields = SIDE_FIELDS
    integer_fields = ("composite_micro", "compute_micro", "corpus_supported",
                      "events_scanned", "hook_compute_fuel", "hook_fuel", "latency_micro",
                      "rendered_cost_micro", "storage_bytes", "store_events", "store_ops",
                      "work_fuel", "logical_durable_storage_bytes")
    meas = _check_closed(artifact["measurements"], MEASUREMENT_FIELDS, "measurements")
    _check_str(meas["policy"], "measurements.policy")
    if meas["micro_scale"] != MICRO:
        raise ArtifactValueError(
            f"measurements.micro_scale must be {MICRO}, got {meas['micro_scale']!r}")
    _check_closed(meas["branches"], SELECTION_LABELS, "measurements.branches")
    for label in SELECTION_LABELS:
        pair = _check_closed(meas["branches"][label], ("candidate", "incumbent"),
                             f"measurements.branches[{label!r}]")
        for side_name in ("candidate", "incumbent"):
            where = f"measurements.branches[{label!r}].{side_name}"
            side = _check_closed(pair[side_name], side_fields, where)
            for field in integer_fields:
                _check_int(side[field], f"{where}.{field}")
            _check_str(side["host_profile"], f"{where}.host_profile")
            objectives = side["objectives_micro"]
            if not isinstance(objectives, dict) or not objectives:
                raise ArtifactTypeError(f"{where}.objectives_micro must be a non-empty object")
            for name, value in objectives.items():
                _check_str(name, f"{where}.objectives_micro key")
                _check_int(value, f"{where}.objectives_micro[{name!r}]")
    return meas


def _validate_receipt_block(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    rec = _check_closed(artifact["receipt"], RECEIPT_FIELDS, "receipt")
    for field in ("eval_report_root", "outputs_hash"):
        fr.check_root(rec[field], f"receipt.{field}")
    _check_str(rec["measurement_policy"], "receipt.measurement_policy")
    roots = rec["code_roots"]
    if not isinstance(roots, dict) or not roots:
        raise ArtifactTypeError("receipt.code_roots must be a non-empty object")
    for tree, digest in roots.items():
        _check_str(tree, "receipt.code_roots key")
        fr.check_root(digest, f"receipt.code_roots[{tree!r}]")
    return rec


def _validate_replay_inputs_block(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    replay = _check_closed(artifact["replay_inputs"], REPLAY_INPUT_FIELDS,
                           "replay_inputs")
    _check_int(replay["candidate_module_bytes"], "replay_inputs.candidate_module_bytes",
               minimum=0)
    fr.validate_manifest(replay["parent_manifest"])
    fr.check_root(replay["candidate_manifest_hash"], "replay_inputs.candidate_manifest_hash")
    fr.check_root(replay["candidate_declaration_id"], "replay_inputs.candidate_declaration_id")
    _check_str(replay["candidate_exec"], "replay_inputs.candidate_exec")
    inc = project_incumbent(replay["incumbent"])
    if dict(replay["incumbent"]) != inc:
        raise ReceiptBindingError(
            "replay_inputs.incumbent must use the canonical public projection")
    return replay


def _validate_accounting_and_verdict(artifact: Mapping[str, Any]) -> None:
    acct = _check_closed(artifact["resource_accounting"], RESOURCE_ACCOUNTING_FIELDS,
                         "resource_accounting")
    if acct["branch"] not in SELECTION_LABELS:
        raise ArtifactValueError(
            f"resource_accounting.branch must be one of {SELECTION_LABELS}")
    for field in ("resource_after_ppm", "resource_before_ppm", "utility_after_ppm",
                  "utility_before_ppm"):
        _check_int(acct[field], f"resource_accounting.{field}", maximum=MAX_UINT32)

    verdict = _check_closed(artifact["verdict"], VERDICT_FIELDS, "verdict")
    _check_bool(verdict["admit"], "verdict.admit")
    fr.check_root(verdict["decision_hash"], "verdict.decision_hash")
    if verdict["verdict"] not in ("ADMIT", "REJECT"):
        raise ArtifactValueError(
            f"verdict.verdict must be 'ADMIT' or 'REJECT', got {verdict['verdict']!r}")
    if verdict["verdict"] != ("ADMIT" if verdict["admit"] else "REJECT"):
        raise VerdictMismatchError(
            f"verdict.verdict {verdict['verdict']!r} does not agree with admit="
            f"{verdict['admit']!r}")
    if _check_bool(verdict["consensus_critical"], "verdict.consensus_critical") is not True:
        raise ArtifactValueError(
            "verdict.consensus_critical MUST be true: the deterministic Benchmark-v2 result is "
            "the SOLE mining admission and state-advance law (§17.236)")


def declared_objectives(profile_id: str) -> Tuple[str, ...]:
    """The profile's FULL declared objective vocabulary, from the law-bound suite document.

    One resolver, so "which objectives does this law protect" is answered in exactly one place on
    the V5 side (:mod:`canonical_suite`, the mirror of the benchmark loader) rather than inferred
    from whatever a document happens to carry.
    """
    try:
        return tuple(cs.protected_quality_objectives(profile_id))
    except cs.CanonicalSuiteError as exc:
        raise SuiteMembershipError(
            f"this law tree's canonical suite declares no protected objective vocabulary for "
            f"profile {profile_id!r}: {exc}") from exc


def _validate_vector(vector: Any, where: str, profile_id: str) -> Dict[str, Any]:
    """One ABSOLUTE VECTOR (LAW §3A.2), closed and exact-integer.

    ``profile_id`` binds the vector to the profile's full protected objective vocabulary. A
    missing or extra objective is malformed, never silently unprotected.
    """
    vec = _check_closed(vector, VECTOR_FIELDS, where)
    for field in ("composite_micro", "logical_durable_storage_bytes", "rendered_cost_micro",
                  "work_fuel", "envelope_logical_durable_storage_bytes",
                  "envelope_rendered_cost_micro", "envelope_work_fuel"):
        _check_int(vec[field], f"{where}.{field}")
    _check_int(vec["suite_block_id"], f"{where}.suite_block_id")
    objectives = vec["objectives_micro"]
    if not isinstance(objectives, dict) or not objectives:
        raise ArtifactTypeError(f"{where}.objectives_micro must be a non-empty object")
    for name, value in objectives.items():
        _check_str(name, f"{where}.objectives_micro key")
        _check_int(value, f"{where}.objectives_micro[{name!r}]")
    declared = sorted(declared_objectives(profile_id))
    if sorted(objectives) != declared:
        raise ArtifactSchemaError(
            f"{where}.objectives_micro covers {sorted(objectives)}; the law protects "
            f"{declared} for {profile_id!r}. A missing objective is malformed, not unprotected")
    return vec


def validate_parent_stored_vector(
        parent_stored_vector: Any, *, expected_profile_id: str,
        expected_release_root: str, expected_law_id: str = FIXED_SUITE_LAW_ID,
        expected_suite_root: Optional[str] = None) -> Dict[str, Any]:
    """Validate the complete, self-addressed exact-parent witness used by an evaluation.

    This is deliberately usable *before* candidate scoring.  Artifact validation performs the
    same checks later, but an evaluator must not spend a fixed-suite run before discovering that
    its parent witness is missing a partition, belongs to another profile/release, names another
    law/suite, or is not self-addressed.  The returned document is detached from caller mutation.
    """
    expected_suite_root = expected_suite_root or cs.suite_root()
    witness = _check_closed(dict(parent_stored_vector)
                            if isinstance(parent_stored_vector, Mapping)
                            else parent_stored_vector,
                            DETERMINISM_WITNESS_FIELDS, "parent_stored_vector")
    if witness["law_id"] != expected_law_id:
        raise ArtifactSchemaError(
            f"parent_stored_vector.law_id {witness['law_id']!r} is not the evaluation law "
            f"{expected_law_id!r}")
    if witness["suite_root"] != expected_suite_root:
        raise ArtifactSchemaError(
            "parent_stored_vector.suite_root is not the canonical suite root for this evaluation")
    if witness["profile_id"] != expected_profile_id:
        raise ArtifactSchemaError(
            f"parent_stored_vector.profile_id {witness['profile_id']!r} is not the target profile "
            f"{expected_profile_id!r}")
    if witness["release_root"] != expected_release_root:
        raise DeterminismWitnessMismatchError(
            f"parent_stored_vector.release_root {witness['release_root']!r} is not the exact "
            f"parent release {expected_release_root!r}")
    if witness["source_kind"] not in WITNESS_SOURCE_KINDS:
        raise ArtifactValueError(
            f"parent_stored_vector.source_kind must be one of {list(WITNESS_SOURCE_KINDS)}")
    for field in ("release_root", "source_root", "witness_root"):
        fr.check_root(witness[field], f"parent_stored_vector.{field}")
    _check_closed(witness["partitions"], SELECTION_LABELS,
                  "parent_stored_vector.partitions")
    for label in SELECTION_LABELS:
        vector = _validate_vector(witness["partitions"][label],
                                  f"parent_stored_vector.partitions[{label!r}]",
                                  expected_profile_id)
        canonical = cs.genesis_floor_vector(expected_profile_id, label)
        if vector["suite_block_id"] != canonical["suite_block_id"]:
            raise ArtifactSchemaError(
                f"parent_stored_vector.partitions[{label!r}].suite_block_id is "
                f"{vector['suite_block_id']}, but the active canonical suite block is "
                f"{canonical['suite_block_id']}")
        for _axis, _measured_key, cap_key in cs.PRODUCT_CAP_VECTOR_FIELDS:
            if vector[cap_key] != canonical[cap_key]:
                raise ArtifactSchemaError(
                    f"parent_stored_vector.partitions[{label!r}].{cap_key} is "
                    f"{vector[cap_key]}, but the canonical fixed product cap C is "
                    f"{canonical[cap_key]}; parent E must equal C")
    recomputed = witness_root(witness)
    if witness["witness_root"] != recomputed:
        raise ArtifactSchemaError(
            f"parent_stored_vector.witness_root {witness['witness_root']} is not the sha256 of "
            f"its canonical body {recomputed}")
    # Canonical JSON is also the simplest deep copy of this JSON-only law object.
    return json.loads(fr.canonical_bytes(witness).decode("utf-8"))


def _validate_fixed_suite_blocks(artifact: Mapping[str, Any]) -> None:
    """The four blocks required by the current v3 fixed-suite format."""
    profile_id = artifact["candidate"]["target_profile"]

    if artifact["verdict"]["admit"]:
        proj = _check_closed(artifact["admission_projection"], ADMISSION_PROJECTION_ADMIT_FIELDS,
                             "admission_projection")
        _check_int(proj["score_before_ppm"], "admission_projection.score_before_ppm",
                   maximum=MAX_UINT32)
        if proj["score_before_ppm"] != 0:
            raise ArtifactValueError(
                "admission_projection.score_before_ppm must be 0 (transition-local receipt pair)")
        if proj["class"] not in PROGRESS_CLASSES:
            raise ArtifactValueError(
                f"admission_projection.class must be one of {PROGRESS_CLASSES} on an ADMIT")
        _check_int(proj["score_after_ppm"], "admission_projection.score_after_ppm",
                   minimum=1, maximum=1_000_000)
    else:
        proj = _check_closed(artifact["admission_projection"], ADMISSION_PROJECTION_FIELDS,
                             "admission_projection")
        _check_int(proj["score_before_ppm"], "admission_projection.score_before_ppm",
                   maximum=MAX_UINT32)
        if proj["score_before_ppm"] != 0:
            raise ArtifactValueError(
                "admission_projection.score_before_ppm must be 0 (transition-local receipt pair)")

    suite = _check_closed(artifact["suite"], SUITE_FIELDS, "suite")
    if suite["format"] != cs.SUITE_FORMAT:
        raise ArtifactSchemaError(
            f"suite.format {suite['format']!r} is not {cs.SUITE_FORMAT!r}")
    if suite["law_id"] != FIXED_SUITE_LAW_ID:
        raise ArtifactSchemaError(
            f"suite.law_id {suite['law_id']!r} is not the fixed-suite law "
            f"{FIXED_SUITE_LAW_ID!r}; a v3 artifact records an evaluation under that law and no "
            "other")
    fr.check_root(suite["suite_root"], "suite.suite_root")
    _check_str(suite["suite_version"], "suite.suite_version")
    fr.check_profile_id(suite["profile_id"], "suite.profile_id")
    if suite["profile_id"] != profile_id:
        raise ArtifactSchemaError(
            f"suite.profile_id {suite['profile_id']!r} != the target profile {profile_id!r}")
    scales = suite["scales"]
    if not isinstance(scales, list) or not scales or \
            not all(isinstance(s, str) and s for s in scales):
        raise ArtifactTypeError("suite.scales must be a non-empty array of strings")
    _check_closed(suite["counts"], SELECTION_LABELS, "suite.counts")
    _check_closed(suite["cases"], SELECTION_LABELS, "suite.cases")
    seen = set()
    for label in SELECTION_LABELS:
        _check_int(suite["counts"][label], f"suite.counts[{label!r}]", minimum=1)
        cases = suite["cases"][label]
        if not isinstance(cases, list) or len(cases) != suite["counts"][label]:
            raise ArtifactSchemaError(
                f"suite.cases[{label!r}] does not hold suite.counts[{label!r}] cases")
        for i, case in enumerate(cases):
            where = f"suite.cases[{label!r}][{i}]"
            _check_closed(case, SUITE_CASE_FIELDS, where)
            if _check_int(case["suite_index"], f"{where}.suite_index") != i:
                raise ArtifactSchemaError(
                    f"{where}.suite_index is {case['suite_index']}, the case sits at {i}")
            _check_int(case["seed"], f"{where}.seed", maximum=2 ** 31 - 1)
            _check_str(case["scale"], f"{where}.scale")
            _check_str(case["instance_id"], f"{where}.instance_id")
            fr.check_profile_id(case["profile_id"], f"{where}.profile_id")
            fr.check_root(case["instance_hash"], f"{where}.instance_hash")
            if case["profile_id"] != profile_id:
                raise ArtifactSchemaError(f"{where}.profile_id != the target profile")
            if case["instance_id"] in seen:
                raise ArtifactSchemaError(
                    f"{where} repeats instance {case['instance_id']!r}; the partitions are "
                    "disjoint by construction")
            seen.add(case["instance_id"])

    witness = validate_parent_stored_vector(
        artifact["determinism_witness"], expected_profile_id=profile_id,
        expected_release_root=artifact["candidate"]["prior_release_root"],
        expected_law_id=FIXED_SUITE_LAW_ID, expected_suite_root=suite["suite_root"])

    floor = _check_closed(artifact["genesis_floor"], GENESIS_FLOOR_FIELDS, "genesis_floor")
    if floor["status"] != "resolved":
        raise ArtifactValueError(
            "genesis_floor.status must be 'resolved': LAW §3A.3 makes a pending floor a REFUSAL, "
            "never a skipped check, so no admission artifact can carry one")
    if floor["suite_root"] != suite["suite_root"]:
        raise ArtifactSchemaError("genesis_floor.suite_root != suite.suite_root")
    _check_str(floor["source"], "genesis_floor.source")
    _check_closed(floor["partitions"], SELECTION_LABELS, "genesis_floor.partitions")
    for label in SELECTION_LABELS:
        _validate_vector(floor["partitions"][label], f"genesis_floor.partitions[{label!r}]",
                         profile_id)

    dom = _check_closed(artifact["dominance"], DOMINANCE_FIELDS, "dominance")
    _check_str(dom["engine"], "dominance.engine")
    if dom["engine"] != DOMINANCE_ENGINE_ID:
        raise ArtifactSchemaError(
            f"dominance.engine {dom['engine']!r} is not {DOMINANCE_ENGINE_ID!r}")
    _check_bool(dom["admit"], "dominance.admit")
    _check_closed(dom["partitions"], SELECTION_LABELS, "dominance.partitions")
    for label in SELECTION_LABELS:
        where = f"dominance.partitions[{label!r}]"
        peek = dom["partitions"][label]
        if not isinstance(peek, dict):
            raise ArtifactSchemaError(f"{where} must be a JSON object")
        part_admit = bool(peek.get("admit"))
        fields = DOMINANCE_PARTITION_ADMIT_FIELDS if part_admit else DOMINANCE_PARTITION_FIELDS
        part = _check_closed(peek, fields, where)
        _check_bool(part["admit"], f"{where}.admit")
        _check_bool(part["hard_ok"], f"{where}.hard_ok")
        hard = part["hard"]
        if not isinstance(hard, dict) or not hard:
            raise ArtifactTypeError(f"{where}.hard must be a non-empty object")
        for name, value in hard.items():
            _check_str(name, f"{where}.hard key")
            _check_bool(value, f"{where}.hard[{name!r}]")
        # THE CLOSED EIGHT-NAME VOCABULARY. This used to accept any non-empty map whose values
        # rolled up consistently with ``hard_ok``, which is exactly the forgery a compromised
        # minter reaches for: drop the gates that failed and state the rest true. The names are
        # the law's, not the report's — a missing gate is a REFUSAL, never an unchecked one.
        if tuple(sorted(hard)) != cs.HARD_GATE_VOCABULARY:
            unknown = sorted(set(hard) - set(cs.HARD_GATE_VOCABULARY))
            missing = sorted(set(cs.HARD_GATE_VOCABULARY) - set(hard))
            raise ArtifactSchemaError(
                f"{where}.hard names {sorted(hard)}; this law's hard-gate vocabulary is the "
                f"closed set {list(cs.HARD_GATE_VOCABULARY)} (unknown={unknown}, "
                f"missing={missing})")
        for field in ("composite_after_ppm", "composite_before_ppm"):
            _check_int(part[field], f"{where}.{field}", maximum=MAX_UINT32)
        gain = part["composite_gain_ppm"]
        if not isinstance(gain, int) or isinstance(gain, bool):
            raise ArtifactTypeError(f"{where}.composite_gain_ppm must be an integer")
        if gain != part["composite_after_ppm"] - part["composite_before_ppm"]:
            raise ArtifactValueError(
                f"{where}.composite_gain_ppm is not after - before")
        if part["admit"]:
            progress_class = part["progress_class"]
            gain_ppm = part["admission_gain_ppm"]
            if progress_class not in PROGRESS_CLASSES:
                raise ArtifactValueError(
                    f"{where}.progress_class must be one of {PROGRESS_CLASSES} on admit")
            _check_int(gain_ppm, f"{where}.admission_gain_ppm", minimum=1, maximum=1_000_000)
        for field in ("floor_regressions", "regressed_objectives", "regressed_resource_axes"):
            names = part[field]
            if not isinstance(names, list) or names != sorted(names) or \
                    not all(isinstance(n, str) and n for n in names):
                raise ArtifactTypeError(
                    f"{where}.{field} must be a sorted array of names")
        _validate_vector(part["candidate_vector"], f"{where}.candidate_vector", profile_id)
        _validate_vector(part["incumbent_vector"], f"{where}.incumbent_vector", profile_id)
        # ``hard_ok`` is a PROJECTION of ``hard``, never a second statement of it. Recomputed
        # here, at the schema layer, so an artifact that flips a gate to false and leaves the
        # rollup true is malformed rather than merely inconsistent-once-verified.
        if part["hard_ok"] != all(hard.values()):
            raise VerdictMismatchError(
                f"{where}.hard_ok is {part['hard_ok']}, the bound hard-gate map evaluates to "
                f"{all(hard.values())} (failing: "
                f"{sorted(name for name, ok in hard.items() if not ok)})")
        if part["admit"] and (part["regressed_objectives"] or part["regressed_resource_axes"]
                              or part["floor_regressions"] or not part["hard_ok"]):
            raise VerdictMismatchError(
                f"{where} claims admit with a recorded regression or a failed hard gate")
        # THE DETERMINISM WITNESS, as an ARTIFACT-LEVEL binding (LAW §3A.3). The incumbent vector
        # in the dominance block is the parent arm RE-EXECUTED in this job; the witness carries the
        # vector STORED for that exact release by its genesis baseline or prior accept. Their
        # equality IS the witness check, and it is decidable from the artifact alone — so it holds
        # for a reader who has the document and not the evaluation report.
        if part["incumbent_vector"] != witness["partitions"][label]:
            differing = sorted(
                k for k in set(part["incumbent_vector"]) | set(witness["partitions"][label])
                if part["incumbent_vector"].get(k) != witness["partitions"][label].get(k))
            raise DeterminismWitnessMismatchError(
                f"{where}.incumbent_vector is not determinism_witness.partitions[{label!r}]; the "
                f"re-executed parent arm and the stored vector for release "
                f"{witness['release_root']} differ on {differing}. This is an environment-drift "
                "detector and it fails closed")
    if dom["admit"] != all(dom["partitions"][label]["admit"] for label in SELECTION_LABELS):
        raise VerdictMismatchError(
            "dominance.admit is not gate_admit AND confirm_admit")
    if dom["admit"] != artifact["verdict"]["admit"]:
        raise VerdictMismatchError(
            "dominance.admit disagrees with the artifact verdict; the componentwise decision IS "
            "the verdict")


def witness_root(witness: Mapping[str, Any]) -> str:
    """``sha256`` over the determinism-witness body, ``witness_root`` itself excluded.

    Self-addressing so the stored parent vector is a content-addressed object the coordinator can
    carry, cache and re-present without a second registry: whoever hands it over cannot restate it.
    """
    body = {k: v for k, v in witness.items() if k != "witness_root"}
    return fr.sha256_hex(fr.canonical_bytes(body))

def validate_rig_receipt_block(block: Any) -> Dict[str, Any]:
    """Structural validation of the OPTIONAL ``rig_receipt`` block, at the SIGNED widths.

    Every field is range-checked at the width the on-chain struct declares, here, where the
    artifact is still addressable — not at calldata-encoding time, where an over-wide value is an
    ``AbiError`` on a document a validator has already accepted.

    Three semantic rules are enforced beyond the widths, from
    ``RIG-CORETEX-REGISTRY-DESIGN.md`` §5.1:

      * ``outcome`` must be 1 or 2. 0 and >2 revert for every epoch, so an artifact may not claim
        one even as an intention.
      * ``world_seed`` is a deployed-ABI compatibility member reserved as zero by CoreTex. It has
        no suite-selection, admission, challenge or credit semantics.
      * ``transition_format_version`` is ZERO for a screener pass — outcome 1 advances no state,
        so it carries an EMPTY descriptor and signs zero for the version and both scores — and
        exactly :data:`RIG_TRANSITION_FORMAT_VERSION` for a state advance. It is an OPAQUE
        enumerated tag compared for equality, never a range and never arithmetic.
    """
    rig = _check_closed(block, RIG_RECEIPT_FIELDS, "rig_receipt")
    for field in RIG_RECEIPT_ROOT_FIELDS:
        fr.check_root(rig[field], f"rig_receipt.{field}")
    outcome = _check_int(rig["outcome"], "rig_receipt.outcome", maximum=255)
    if outcome not in RIG_SIGNABLE_OUTCOMES:
        raise RigReceiptFieldError(
            f"rig_receipt.outcome={outcome} is not signable; the verifier prices only "
            f"{list(RIG_SIGNABLE_OUTCOMES)} and every other value reverts for every epoch")
    world_seed = _check_int(rig["world_seed"], "rig_receipt.world_seed", maximum=MAX_UINT128)
    if world_seed != RIG_CORETEX_RESERVED_WORLD_SEED:
        raise RigReceiptFieldError(
            f"rig_receipt.world_seed={world_seed}, but CoreTex reserves this deployed-ABI "
            f"member as {RIG_CORETEX_RESERVED_WORLD_SEED}; it has no evaluation or randomness "
            "semantics")
    _check_int(rig["rules_version"], "rig_receipt.rules_version", maximum=MAX_UINT32)
    version = _check_int(rig["transition_format_version"],
                         "rig_receipt.transition_format_version", maximum=MAX_UINT16)
    if outcome == RIG_OUTCOME_SCREENER_PASS and version != RIG_SCREENER_TRANSITION_FORMAT_VERSION:
        raise RigReceiptFieldError(
            f"rig_receipt.transition_format_version={version} but outcome={outcome} is a SCREENER "
            "PASS: priced work that did not move the root carries an EMPTY transition descriptor "
            f"and signs {RIG_SCREENER_TRANSITION_FORMAT_VERSION} here. A non-empty descriptor on "
            "outcome 1 reverts UnexpectedTransitionDescriptor")
    if outcome == RIG_OUTCOME_STATE_ADVANCE and version != RIG_TRANSITION_FORMAT_VERSION:
        raise RigReceiptFieldError(
            f"rig_receipt.transition_format_version={version} is not "
            f"0x{RIG_TRANSITION_FORMAT_VERSION:02x}. The deployed verifier accepts exactly that "
            "opaque descriptor tag")
    return rig


def rig_receipt_fields(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The eight evaluator-supplied receipt fields, or :class:`RigReceiptFieldsMissingError`.

    The artifact is VALIDATED first, for the same reason :func:`eval_report_hash` validates: an
    invalid artifact has no fields anyone may sign.
    """
    validate_artifact(artifact)
    if "rig_receipt" not in artifact:
        raise RigReceiptFieldsMissingError(
            "this artifact carries no 'rig_receipt' block, so it cannot supply outcome, "
            f"{', '.join(f for f in RIG_RECEIPT_FIELDS if f != 'outcome')}. A rig receipt signs "
            "all eight; the coordinator does not invent them.")
    return validate_rig_receipt_block(artifact["rig_receipt"])


def rig_receipt_projection(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The eight fields in BOTH spellings, for the coordinator's worker-result decoder.

    ``coretex-memory-v5-worker-client.ts`` reads each rig field as
    ``pick(e, "<snake_case>", "<camelCase>")``. Emitting both means neither lane has to guess
    which the other chose, and a rename on either side fails loudly at the closed-field check
    rather than silently defaulting a signed field to zero.

    Roots are emitted BARE (no ``0x``), exactly as every other root in this artifact lane, because
    the TypeScript side re-prefixes with ``0x`` after ``bareRoot()`` strips whatever it was given.

    ``world_seed`` is emitted as the exact decimal string ``"0"``. The artifact keeps integer zero
    because it is hashed into ``evalReportHash``; this projection preserves the established uint128
    wire type at the Python/JavaScript boundary without assigning the ABI member any CoreTex
    semantics.
    """
    rig = rig_receipt_fields(artifact)
    out: Dict[str, Any] = {}
    for field in RIG_RECEIPT_FIELDS:
        value = rig[field]
        if field in RIG_RECEIPT_WIDE_UINT_FIELDS:
            value = str(int(value))
        out[field] = value
        camel = RIG_RECEIPT_CAMEL_CASE[field]
        if camel != field:
            out[camel] = value
    return out


def deterministic_verdict(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The artifact's verdict, read from deterministic fixed-suite evidence."""
    validate_artifact(artifact)
    verdict = artifact["verdict"]
    return {"admit": verdict["admit"], "verdict": verdict["verdict"],
            "decision_hash": verdict["decision_hash"],
            "authority": "benchmark-v2 deterministic receipt decision",
            "consensus_critical": True}


# --------------------------------------------------------------------------- #
# Fixed-suite membership and stored-vector provenance
# --------------------------------------------------------------------------- #
def suite_block_for(profile_id: str, report_selection: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the suite block from the sealed law and prove the report used those exact cases."""
    expected = cs.suite_cases(profile_id)
    hashes = cs.suite_case_hashes(profile_id)
    cases: Dict[str, Any] = {}
    for label in SELECTION_LABELS:
        bound = report_selection.get(label)
        wanted = expected[label]
        if not isinstance(bound, list) or len(bound) != len(wanted):
            raise SuiteMembershipError(
                f"report selection[{label!r}] is not the complete canonical partition")
        rows = []
        for index, (case, suite_case) in enumerate(zip(bound, wanted)):
            if not isinstance(case, Mapping):
                raise SuiteMembershipError(
                    f"report selection[{label!r}][{index}] is not an object")
            for field in ("instance_id", "profile_id", "scale", "seed", "suite_index"):
                if case.get(field) != suite_case[field]:
                    raise SuiteMembershipError(
                        f"report selection[{label!r}][{index}].{field} is not the "
                        "canonical-suite value")
            instance_hash = hashes[suite_case["instance_id"]]
            if case.get("instance_hash") != instance_hash:
                raise SuiteMembershipError(
                    f"report selection[{label!r}][{index}].instance_hash is not the "
                    "suite-bound instance hash")
            rows.append(dict(suite_case, instance_hash=instance_hash))
        cases[label] = rows
    return {
        "cases": cases,
        "counts": {label: len(cases[label]) for label in SELECTION_LABELS},
        "format": cs.SUITE_FORMAT,
        "law_id": FIXED_SUITE_LAW_ID,
        "profile_id": profile_id,
        "scales": cs.suite_scales(profile_id),
        "suite_root": cs.suite_root(),
        "suite_version": cs.suite_version(),
    }


def genesis_floor_block_for(profile_id: str) -> Dict[str, Any]:
    """Project the constructor-genesis floor sealed into the canonical suite."""
    try:
        partitions = {label: cs.genesis_floor_vector(profile_id, label)
                      for label in SELECTION_LABELS}
    except cs.GenesisFloorPendingError as exc:
        raise GenesisFloorPendingError(str(exc)) from exc
    source = cs.genesis_floor_authority().get("source")
    return {
        "partitions": partitions,
        "source": source if isinstance(source, str) else json.dumps(source, sort_keys=True),
        "status": "resolved",
        "suite_root": cs.suite_root(),
    }


def build_determinism_witness(*, profile_id: str, release_root: str, source_kind: str,
                              source_root: str, partitions: Mapping[str, Any]
                              ) -> Dict[str, Any]:
    """Build the self-addressing stored vector transported to an evaluation job."""
    if source_kind not in WITNESS_SOURCE_KINDS:
        raise ArtifactValueError(
            f"source_kind must be one of {list(WITNESS_SOURCE_KINDS)}, got {source_kind!r}")
    body = {
        "law_id": FIXED_SUITE_LAW_ID,
        "partitions": {label: dict(partitions[label]) for label in SELECTION_LABELS},
        "profile_id": profile_id,
        "release_root": release_root,
        "source_kind": source_kind,
        "source_root": source_root,
        "suite_root": cs.suite_root(),
    }
    return dict(body, witness_root=witness_root(body))


def _genesis_baseline_root(document: Mapping[str, Any]) -> str:
    """Root rule for ``coretex.genesis-baseline/v1``: omit only ``baseline_root``."""
    body = {key: value for key, value in document.items() if key != "baseline_root"}
    return fr.sha256_hex(fr.canonical_bytes(body))


def _validate_genesis_baseline(document: Any, expected_root: str) -> Dict[str, Any]:
    doc = _check_closed(document, GENESIS_BASELINE_FIELDS, GENESIS_BASELINE_FORMAT)
    if doc["format"] != GENESIS_BASELINE_FORMAT:
        raise ArtifactSchemaError(
            f"genesis baseline format {doc['format']!r} is unsupported")
    if doc["law_id"] != FIXED_SUITE_LAW_ID:
        raise ArtifactSchemaError("genesis baseline law_id is not the fixed-suite law")
    for field in ("baseline_root", "suite_root"):
        fr.check_root(doc[field], f"genesis_baseline.{field}")
    computed = _genesis_baseline_root(doc)
    if doc["baseline_root"] != computed or computed != expected_root:
        raise ArtifactSchemaError(
            f"genesis baseline addresses {computed}, not its declared/requested root")
    profiles = doc["profiles"]
    if not isinstance(profiles, dict) or set(profiles) != set(fr.PROFILE_IDS):
        raise ArtifactSchemaError(
            "genesis baseline profiles must be exactly the public profile set")
    floor_authority = cs.genesis_floor_authority()
    source = floor_authority.get("source")
    source_profiles = source.get("profiles") if isinstance(source, Mapping) else None
    if not isinstance(source_profiles, Mapping) or set(source_profiles) != set(fr.PROFILE_IDS):
        raise ArtifactSchemaError(
            "the canonical-suite genesis authority does not bind every public profile release")
    for profile_id in fr.PROFILE_IDS:
        row = _check_closed(profiles[profile_id], GENESIS_BASELINE_PROFILE_FIELDS,
                            f"genesis_baseline.profiles[{profile_id!r}]")
        if row["law_id"] != FIXED_SUITE_LAW_ID or row["profile_id"] != profile_id:
            raise ArtifactSchemaError(
                f"genesis baseline profile {profile_id!r} has mismatched law/profile identity")
        for field in ("release_root", "stored_vector_root", "suite_root"):
            fr.check_root(row[field], f"genesis_baseline.profiles[{profile_id!r}].{field}")
        if row["suite_root"] != doc["suite_root"]:
            raise ArtifactSchemaError(
                f"genesis baseline profile {profile_id!r} names a different suite")
        expected_release = source_profiles[profile_id].get("release_root") \
            if isinstance(source_profiles[profile_id], Mapping) else None
        if row["release_root"] != expected_release:
            raise ArtifactSchemaError(
                f"genesis baseline profile {profile_id!r} release_root is not the sealed "
                "genesis reference release")
        _check_closed(row["partitions"], SELECTION_LABELS,
                      f"genesis_baseline.profiles[{profile_id!r}].partitions")
        for label in SELECTION_LABELS:
            _validate_vector(row["partitions"][label],
                             f"genesis_baseline.profiles[{profile_id!r}].partitions[{label!r}]",
                             profile_id)
            if row["partitions"][label] != cs.genesis_floor_vector(profile_id, label):
                raise ArtifactSchemaError(
                    f"genesis baseline profile {profile_id!r} partition {label!r} is not the "
                    "sealed constructor-genesis vector")
        vector_body = {key: value for key, value in row.items()
                       if key != "stored_vector_root"}
        if row["stored_vector_root"] != fr.sha256_hex(fr.canonical_bytes(vector_body)):
            raise ArtifactSchemaError(
                f"genesis baseline profile {profile_id!r} stored_vector_root is not its body root")
    return doc


def resolve_determinism_witness_source(artifact: Mapping[str, Any], *,
                                       store: pub.ContentStore) -> Dict[str, Any]:
    """Resolve a witness to the sealed genesis baseline or an accepting public artifact."""
    witness = artifact["determinism_witness"]
    kind = witness["source_kind"]
    root = witness["source_root"]
    try:
        if kind == "genesis":
            raw = store.get(root)
            try:
                source = _validate_genesis_baseline(
                    fr.parse_json(raw.decode("utf-8")), root)
            except (UnicodeError, fr.FrontierError, EvalArtifactError) as exc:
                raise WitnessSourceMismatchError(
                    f"the object at genesis source_root {root} is not the sealed baseline: "
                    f"{exc}") from exc
            row = source["profiles"].get(witness["profile_id"])
            if not isinstance(row, Mapping):
                raise WitnessSourceMismatchError(
                    f"genesis baseline {root} has no profile {witness['profile_id']!r}")
            for field in ("law_id", "suite_root", "profile_id", "release_root"):
                if row[field] != witness[field]:
                    raise WitnessSourceMismatchError(
                        f"genesis baseline {root} records {field}={row[field]!r}; witness "
                        f"claims {witness[field]!r}")
            source_partitions = row["partitions"]
            detail: Any = {"stored_vector_root": row["stored_vector_root"]}
        else:
            try:
                prior = pub.fetch_json(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
                validate_artifact(prior)
            except (pub.PublicationError, EvalArtifactError) as exc:
                raise WitnessSourceMismatchError(
                    f"the object at prior_accept source_root {root} is not a current eval "
                    f"artifact: {exc}") from exc
            if eval_report_hash(prior) != root or prior["verdict"]["admit"] is not True:
                raise WitnessSourceMismatchError(
                    f"artifact {root} is not a content-addressed accepting artifact")
            for actual, wanted, field in (
                    (prior["suite"]["suite_root"], witness["suite_root"], "suite_root"),
                    (prior["candidate"]["target_profile"], witness["profile_id"], "profile_id"),
                    (prior["candidate"]["release_root"], witness["release_root"], "release_root")):
                if actual != wanted:
                    raise WitnessSourceMismatchError(
                        f"accepting artifact {root} records {field}={actual!r}; witness claims "
                        f"{wanted!r}")
            source_partitions = {
                label: prior["dominance"]["partitions"][label]["candidate_vector"]
                for label in SELECTION_LABELS}
            detail = {"epoch": prior["epoch"],
                      "candidate_hash": prior["candidate"]["candidate_hash"]}
    except pub.ObjectNotFoundError as exc:
        raise WitnessSourceUnavailableError(
            f"determinism witness source {root} ({kind}) is not published: {exc}") from exc

    for label in SELECTION_LABELS:
        if source_partitions[label] != witness["partitions"][label]:
            raise WitnessSourceMismatchError(
                f"{kind} source {root} publishes a different {label!r} stored vector")
    return {"resolved": True, "source_kind": kind, "source_root": root,
            "release_root": witness["release_root"], "profile_id": witness["profile_id"],
            "source": detail}


def _vector_from_verdict(verdict: Mapping[str, Any], side: str, label: str) -> Dict[str, Any]:
    vectors = verdict.get("vectors") if isinstance(verdict, Mapping) else None
    vector = vectors.get(side) if isinstance(vectors, Mapping) else None
    if not isinstance(vector, Mapping):
        raise ReceiptBindingError(
            f"the {label!r} verdict carries no {side} absolute vector")
    profile_id = verdict.get("profile")
    if not isinstance(profile_id, str) or not profile_id:
        raise ReceiptBindingError(f"the {label!r} verdict carries no profile identity")
    return _validate_vector(
        dict(vector), f"verdicts[{label!r}].vectors.{side}", profile_id)


def parent_vector_from_verdicts(verdicts: Mapping[str, Any]) -> Dict[str, Any]:
    return {label: _vector_from_verdict(verdicts[label], "incumbent", label)
            for label in SELECTION_LABELS}


def candidate_vector_from_verdicts(verdicts: Mapping[str, Any]) -> Dict[str, Any]:
    return {label: _vector_from_verdict(verdicts[label], "candidate", label)
            for label in SELECTION_LABELS}


MEASURABLE_VECTOR_FIELDS = ("composite_micro", "logical_durable_storage_bytes",
                            "rendered_cost_micro", "work_fuel")


def assert_decided_vectors_are_measured(dominance: Mapping[str, Any],
                                        projected: Mapping[str, Any]) -> None:
    """Require every component the decision used to equal the raw measured projection."""
    for label in SELECTION_LABELS:
        for side, key in (("candidate", "candidate_vector"),
                          ("incumbent", "incumbent_vector")):
            vector = dominance["partitions"][label][key]
            measured = projected["branches"][label][side]
            for field in MEASURABLE_VECTOR_FIELDS:
                _require(vector[field] == measured[field], VerdictMismatchError,
                         f"dominance.partitions[{label!r}].{key}.{field} does not equal the "
                         "report's measured value")
            differing = sorted(
                name for name in set(vector["objectives_micro"]) |
                set(measured["objectives_micro"])
                if vector["objectives_micro"].get(name)
                != measured["objectives_micro"].get(name))
            _require(not differing, VerdictMismatchError,
                     f"dominance.partitions[{label!r}].{key}.objectives_micro differs from "
                     f"measured objectives {differing}")


def assert_determinism_witness(recomputed: Mapping[str, Any],
                               witness: Mapping[str, Any]) -> None:
    for label in SELECTION_LABELS:
        if recomputed[label] != witness["partitions"][label]:
            differing = sorted(
                key for key in set(recomputed[label]) | set(witness["partitions"][label])
                if recomputed[label].get(key) != witness["partitions"][label].get(key))
            raise DeterminismWitnessMismatchError(
                f"re-executed parent {label!r} vector differs from stored release "
                f"{witness['release_root']} on {differing}")


def dominance_block_for(verdicts: Mapping[str, Any], decision: Mapping[str, Any]
                        ) -> Dict[str, Any]:
    partitions = {}
    candidate_vectors = candidate_vector_from_verdicts(verdicts)
    incumbent_vectors = parent_vector_from_verdicts(verdicts)
    for label in SELECTION_LABELS:
        verdict = verdicts[label]
        deltas = verdict.get("deltas") or {}
        if verdict.get("engine") != DOMINANCE_ENGINE_ID:
            raise VerdictMismatchError(
                f"{label!r} verdict engine is not {DOMINANCE_ENGINE_ID!r}")
        partitions[label] = {
            "admit": bool(verdict["admit"]),
            "candidate_vector": candidate_vectors[label],
            "composite_after_ppm": int(deltas["composite_after_ppm"]),
            "composite_before_ppm": int(deltas["composite_before_ppm"]),
            "composite_gain_ppm": int(deltas["composite_gain_ppm"]),
            "floor_regressions": sorted(deltas.get("floor_regressions") or ()),
            "hard": {name: bool(value) for name, value in sorted(verdict["hard"].items())},
            "hard_ok": bool(verdict["hard_ok"]),
            "incumbent_vector": incumbent_vectors[label],
            "regressed_objectives": sorted(deltas.get("regressed_objectives") or ()),
            "regressed_resource_axes": sorted(deltas.get("regressed_resource_axes") or ()),
        }
        if verdict["admit"]:
            partitions[label]["admission_gain_ppm"] = int(verdict["admission_gain_ppm"])
            partitions[label]["progress_class"] = verdict["progress_class"]
    return {"admit": bool(decision["admit"]), "engine": DOMINANCE_ENGINE_ID,
            "partitions": partitions}


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #
def build_artifact_v3(*, epoch: int, parent_manifest: Mapping[str, Any], epoch_pins: Any = None,
                      transition: Mapping[str, Any], candidate_hash: str,
                      eval_report: Mapping[str, Any],
                      counter_resource_law: Mapping[str, Any],
                      availability: Mapping[str, Any],
                      parent_stored_vector: Mapping[str, Any],
                      counter_resource_law_root_hex: Optional[str] = None,
                      rig_receipt: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Assemble the one complete public fixed-suite artifact.

    Cases come from the sealed suite; exact incumbent identity and stored vector are mandatory;
    dominance and floor blocks are derived rather than accepted as caller claims.
    """
    fr.validate_manifest(parent_manifest)
    fr.validate_transition(transition)
    fr.check_root(candidate_hash, "candidate_hash")
    validate_counter_resource_law(counter_resource_law)

    parent_root = fr.frontier_root(parent_manifest)
    child = fr.apply_transition(parent_manifest, transition, epoch=epoch, epoch_pins=epoch_pins)
    new_root = fr.frontier_root(child)
    tbytes = fr.canonical_bytes(transition)

    body = _eval_report(eval_report)
    law_descriptor = body.get("evaluation_law")
    bound_law_id = law_descriptor.get("law_id") if isinstance(law_descriptor, Mapping) else None
    if bound_law_id != FIXED_SUITE_LAW_ID:
        raise ReceiptBindingError(
            f"a v3 artifact records an evaluation under {FIXED_SUITE_LAW_ID!r}; the supplied "
            f"report is bound to {bound_law_id!r}")
    if law_descriptor.get("canonical_suite_root") != cs.suite_root():
        raise SuiteMembershipError(
            "the evaluation report's bound law names a different canonical suite than the one "
            "this builder carries; a changed suite is a new law (LAW §3A.6)")
    project_incumbent(body.get("incumbent"))
    target = transition["target_profile"]

    suite = suite_block_for(target, body["selection"])
    floor = genesis_floor_block_for(target)
    witness = validate_parent_stored_vector(
        parent_stored_vector, expected_profile_id=target,
        expected_release_root=transition["expected_prior_release_root"],
        expected_law_id=FIXED_SUITE_LAW_ID, expected_suite_root=cs.suite_root())
    assert_determinism_witness(parent_vector_from_verdicts(body["verdicts"]), witness)

    measurements = project_measurements(body)
    # THE DECIDED VECTORS ARE THE MEASURED ONES, at MINT time as well as at verification. The
    # forgery this closes is a report whose ``verdicts[*].vectors`` disagree with its own
    # ``scores``; every binding this builder makes afterwards would then be honest by
    # construction, so the projection is the only thing that can see it. Refusing here means an
    # evaluator handed such a report cannot mint an artifact from it at all.
    dominance = dominance_block_for(body["verdicts"], body["decision"])
    assert_decided_vectors_are_measured(dominance, measurements)
    branch = counter_resource_law["branch"]
    ppm = evaluate_counter_resource_law(counter_resource_law,
                                        measurements["branches"][branch]["candidate"],
                                        measurements["branches"][branch]["incumbent"],
                                        profile_id=target,
                                        candidate_vector=dominance["partitions"][branch]
                                        ["candidate_vector"],
                                        incumbent_vector=dominance["partitions"][branch]
                                        ["incumbent_vector"])
    confirm = body["verdicts"]["confirm"]
    confirm_proj = confirm.get("admission_projection") or {}
    if body["decision"]["admit"]:
        admission_projection = {
            "class": confirm.get("progress_class") or confirm_proj.get("class"),
            "score_after_ppm": confirm.get("admission_gain_ppm")
            if confirm.get("admission_gain_ppm") is not None
            else confirm_proj.get("score_after_ppm"),
            "score_before_ppm": 0,
        }
    else:
        admission_projection = {
            "score_before_ppm": 0,
        }
    artifact = {
        "admission_projection": admission_projection,
        "availability": {name: dict(item) for name, item in availability.items()},
        "candidate": {
            "candidate_hash": candidate_hash,
            "prior_release_root": transition["expected_prior_release_root"],
            "release_root": transition["new_release_root"],
            "target_profile": target,
        },
        "counter_resource_law_root": (counter_resource_law_root_hex
                                      or counter_resource_law_root(counter_resource_law)),
        "determinism_witness": dict(witness),
        "dominance": dominance,
        "epoch": epoch,
        "format": ARTIFACT_FORMAT,
        "frontier": {
            "benchmark_law_root": child["benchmark_law_root"],
            "composition_root": transition["resulting_composition_root"],
            "new_frontier_root": new_root,
            "parent_frontier_root": parent_root,
            "runtime_abi_root": child["runtime_abi_root"],
            "transition": dict(transition),
            "transition_bytes_len": len(tbytes),
            "transition_id_sha256": fr.transition_hash(transition),
        },
        "genesis_floor": floor,
        "measurements": measurements,
        "receipt": {
            "code_roots": dict(body["code_roots"]),
            "eval_report_root": eval_report_root(body),
            "measurement_policy": body["measurement_policy"],
            "outputs_hash": body["outputs_hash"],
        },
        "replay_inputs": {
            "candidate_declaration_id": body["candidate"]["declaration_id"],
            "candidate_exec": body["candidate"]["exec"],
            "candidate_manifest_hash": body["candidate"]["manifest_hash"],
            "candidate_module_bytes": candidate_module_bytes(body),
            "incumbent": project_incumbent(body["incumbent"]),
            "parent_manifest": dict(parent_manifest),
        },
        "resource_accounting": dict(ppm, branch=branch),
        "suite": suite,
        "verdict": {
            "admit": bool(body["decision"]["admit"]),
            "consensus_critical": True,
            "decision_hash": fr.sha256_hex(pub.benchmark_canonical_bytes(body["decision"])),
            "verdict": body["decision"]["verdict"],
        },
    }
    if rig_receipt is not None:
        artifact["rig_receipt"] = dict(rig_receipt)
    return validate_artifact(artifact)


def _eval_report(report: Any) -> Dict[str, Any]:
    """Require the unsigned deterministic Benchmark-v2 report shape."""
    if not isinstance(report, dict) or report.get("format") != EVAL_REPORT_FORMAT:
        raise ReceiptBindingError(
            f"the evaluation report must be a {EVAL_REPORT_FORMAT!r} object, got "
            f"{(report or {}).get('format')!r}")
    if "signature" in report:
        raise ReceiptBindingError(
            "the evaluation report carries a 'signature' block. A result is authorized by the "
            "coordinator's EIP-712 mining receipt, which a deployed contract verifies against "
            "mining.coordinatorSigner(). A second off-chain signature over the same fact is two "
            "authorities for one result, which is the defect, not a safety margin")
    return report


def verify_artifact(artifact: Mapping[str, Any], *, expected_parent_root: str,
                    expected_new_root: str, expected_release_root: str,
                    expected_composition_root: str, expected_runtime_abi_root: str,
                    expected_benchmark_law_root: str,
                    expected_counter_resource_law_root: str,
                    expected_epoch: int,
                    expected_target_profile: Optional[str] = None,
                    eval_report: Optional[Mapping[str, Any]] = None,
                    counter_resource_law: Optional[Mapping[str, Any]] = None,
                    store: Optional[pub.ContentStore] = None,
                    check_availability: bool = False,
                    require_rig_receipt: bool = False,
                    expected_epoch_context_root: Optional[str] = None,
                    expected_core_version_hash: Optional[str] = None,
                    expected_work_policy_hash: Optional[str] = None,
                    resolve_witness_source: bool = False) -> Dict[str, Any]:
    """Verify every fixed-suite binding against values confirmed by chain state.

    The expected roots come from the chain (the registry's live root and epoch pins, the receipt's
    signed fields), never from the artifact — an artifact that only agreed with itself would prove
    nothing.

    RAISES a typed :class:`EvalArtifactError` on any failure and returns a report dict on success.
    It never returns ``False``: an unverified artifact must never be readable as a passing one
    (``frontier.verify_transition`` discipline). A validator that wants a verdict catches
    :class:`EvalArtifactError` and records a BACKLOG entry, never a pass.

    ``require_rig_receipt`` makes the rig-protocol fields mandatory before signing.
    The three ``expected_*`` rig context fields (``epoch_context_root``, ``core_version_hash``,
    ``work_policy_hash``) are the context the registry/verifier itself
    enforces; supplying one checks the artifact against it, omitting one skips only that check.

    ``resolve_witness_source`` additionally fetches the object
    ``determinism_witness.source_root`` names — the genesis baseline or prior accepted artifact —
    artifact — and requires it to publish the same stored vector. It defaults to False because it
    needs the public object surface, which a pre-sign caller does not have. IT IS NOT A SKIPPED
    CHECK WHEN OMITTED: the returned report always carries ``witness_provenance``, whose
    ``resolved`` flag says plainly whether the stored vector's origin was proved or merely
    carried. ``validator.replay.replay_advance`` — the full public replay — always asks for it.
    """
    artifact_law(artifact)
    return _verify_bindings(artifact, eval_report=eval_report,
                            expected_parent_root=expected_parent_root,
                            expected_new_root=expected_new_root,
                            expected_release_root=expected_release_root,
                            expected_composition_root=expected_composition_root,
                            expected_runtime_abi_root=expected_runtime_abi_root,
                            expected_benchmark_law_root=expected_benchmark_law_root,
                            expected_counter_resource_law_root=expected_counter_resource_law_root,
                            expected_epoch=expected_epoch,
                            epoch_pins={
                                "benchmark_law_root": expected_benchmark_law_root,
                                "runtime_abi_root": expected_runtime_abi_root,
                            },
                            expected_target_profile=expected_target_profile,
                            counter_resource_law=counter_resource_law, store=store,
                            check_availability=check_availability,
                            require_rig_receipt=require_rig_receipt,
                            expected_epoch_context_root=expected_epoch_context_root,
                            expected_core_version_hash=expected_core_version_hash,
                            expected_work_policy_hash=expected_work_policy_hash,
                            resolve_witness_source=resolve_witness_source)


def verify_suite_membership(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """Verify exact ordered membership in the sealed canonical suite."""
    suite = artifact["suite"]
    profile_id = suite["profile_id"]
    expected_root = cs.suite_root()
    _require(suite["suite_root"] == expected_root, SuiteMembershipError,
             f"the artifact names canonical suite {suite['suite_root']}; this law tree carries "
             f"{expected_root}. A changed suite is a NEW LAW (LAW §3A.6), never a variation of "
             "this one")
    _require(suite["suite_version"] == cs.suite_version(), SuiteMembershipError,
             "the artifact's suite_version is not this law tree's suite version")
    _require(list(suite["scales"]) == list(cs.suite_scales(profile_id)), SuiteMembershipError,
             "the artifact's suite scales are not the law's scales for this profile")
    expected_cases = cs.suite_cases(profile_id)
    hashes = cs.suite_case_hashes(profile_id)
    for label in SELECTION_LABELS:
        bound = suite["cases"][label]
        want = expected_cases[label]
        _require(len(bound) == len(want), SuiteMembershipError,
                 f"the artifact's {label!r} partition holds {len(bound)} cases; the canonical "
                 f"suite for {profile_id!r} declares {len(want)} and a partition is never "
                 "subsetted, extended or re-ordered")
        for index, (case, suite_case) in enumerate(zip(bound, want)):
            for field in ("instance_id", "profile_id", "scale", "seed", "suite_index"):
                _require(case[field] == suite_case[field], SuiteMembershipError,
                         f"suite.cases[{label!r}][{index}].{field} is {case[field]!r}; the "
                         f"canonical suite declares {suite_case[field]!r}")
            _require(case["instance_hash"] == hashes[case["instance_id"]], SuiteMembershipError,
                     f"suite.cases[{label!r}][{index}].instance_hash "
                     f"{case['instance_hash']} is not the suite-bound instance hash "
                     f"{hashes[case['instance_id']]} — the scored instance is not the case the "
                     "law names")
    return {"profile_id": profile_id, "suite_root": expected_root,
            "counts": dict(suite["counts"])}


def verify_genesis_floor(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The artifact's floor block must be the law's resolved floor, vector for vector."""
    floor = artifact["genesis_floor"]
    profile_id = artifact["candidate"]["target_profile"]
    if not cs.genesis_floor_resolved():
        raise GenesisFloorPendingError(
            "this law tree's constructor-genesis floor is pending, so no admission is "
            "computable and no artifact claiming one can be verified (LAW §3A.3)")
    _require(floor["suite_root"] == cs.suite_root(), SuiteMembershipError,
             "genesis_floor.suite_root is not this law tree's canonical suite root")
    # THE PROVENANCE IS LAW TOO. ``source`` names the sealed measurement authority, and
    # it was free text nobody compared to anything: an artifact could restate it as any string at
    # all while carrying the correct vectors. It is projected from the authority document exactly
    # as ``genesis_floor_block_for`` builds it, so it is a checkable claim rather than a label.
    authority_source = cs.genesis_floor_authority().get("source")
    expected_source = (authority_source if isinstance(authority_source, str)
                       else json.dumps(authority_source, sort_keys=True))
    _require(floor["source"] == expected_source, BindingMismatchError,
             f"genesis_floor.source is {floor['source']!r}; this law tree's floor was measured by "
             f"{expected_source!r}. The provenance of the floor is part of the floor")
    for label in SELECTION_LABELS:
        expected = cs.genesis_floor_vector(profile_id, label)
        _require(floor["partitions"][label] == expected, BindingMismatchError,
                 f"genesis_floor.partitions[{label!r}] is not the law-bound constructor-genesis "
                 f"floor vector for {profile_id!r}")
    return {"profile_id": profile_id, "status": floor["status"]}


def verify_dominance_block(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """Re-derive the componentwise outcome from the artifact's OWN bound vectors.

    The vectors are the evidence; the flags are a projection of them. This recomputes the
    projection — the composite gain, which objectives regressed, which resource axes regressed and
    which floor components were missed — and refuses any disagreement. It is a self-consistency
    check, deliberately: whether those vectors are the RIGHT ones is settled by
    :func:`verify_suite_membership`, :func:`verify_genesis_floor`, the measurement projection in
    step 7 and the receipt's own decision recomputation in the benchmark-v2 validator.
    """
    dom = artifact["dominance"]
    floor = artifact["genesis_floor"]["partitions"]
    for label in SELECTION_LABELS:
        part = dom["partitions"][label]
        cand_vec = part["candidate_vector"]
        inc_vec = part["incumbent_vector"]
        where = f"dominance.partitions[{label!r}]"
        canonical_floor = cs.genesis_floor_vector(
            artifact["candidate"]["target_profile"], label)
        for axis, _measured_key, e_key in cs.PRODUCT_CAP_VECTOR_FIELDS:
            canonical_c = canonical_floor[e_key]
            _require(inc_vec[e_key] == canonical_c, VerdictMismatchError,
                     f"{where}.incumbent_vector.{e_key} is {inc_vec[e_key]}, but the canonical "
                     f"fixed product cap C is {canonical_c} (axis {axis}); forged tighter or "
                     "looser parent envelopes fail")
            _require(cand_vec[e_key] == canonical_c, VerdictMismatchError,
                     f"{where}.candidate_vector.{e_key} is {cand_vec[e_key]}, but the canonical "
                     f"fixed product cap C is {canonical_c} (axis {axis}); every transition "
                     "requires E(A) = E(B) = C")
        _require(cand_vec["composite_micro"] // 100 == part["composite_after_ppm"],
                 VerdictMismatchError,
                 f"{where}.composite_after_ppm is not composite_micro // 100 of the bound "
                 "candidate vector")
        _require(inc_vec["composite_micro"] // 100 == part["composite_before_ppm"],
                 VerdictMismatchError,
                 f"{where}.composite_before_ppm is not composite_micro // 100 of the bound "
                 "incumbent vector")
        # ``hard_ok`` is recomputed from the bound map here as well as at the schema layer: this
        # function is the one a caller reaches for to re-derive the componentwise outcome, and a
        # rollup it took on trust would be a rollup an artifact could state.
        _require(bool(part["hard_ok"]) == all(bool(v) for v in part["hard"].values()),
                 VerdictMismatchError,
                 f"{where}.hard_ok does not recompute from the bound hard-gate map")
        # A KEY ABSENT FROM THE COMPARAND IS A REFUSAL, never "compare it against itself". The
        # old `.get(oid, value)` default made a dropped objective invisible to the recomputation,
        # which is exactly the shape a forger reaches for: strip the regressed axis from both
        # vectors and nothing recomputes as regressed.
        for oid in cand_vec["objectives_micro"]:
            _require(oid in inc_vec["objectives_micro"], VerdictMismatchError,
                     f"{where}.incumbent_vector carries no objective {oid!r} the candidate vector "
                     "measures; a componentwise comparison has no default for a missing component")
        for oid in inc_vec["objectives_micro"]:
            _require(oid in cand_vec["objectives_micro"], VerdictMismatchError,
                     f"{where}.candidate_vector carries no objective {oid!r} the incumbent vector "
                     "measures")
        regressed_objectives = sorted(
            oid for oid, value in cand_vec["objectives_micro"].items()
            if value < inc_vec["objectives_micro"][oid])
        _require(regressed_objectives == list(part["regressed_objectives"]),
                 VerdictMismatchError,
                 f"{where}.regressed_objectives does not recompute from the bound vectors "
                 f"(bound {part['regressed_objectives']}, recomputed {regressed_objectives})")
        regressed_axes = sorted(
            axis for axis, r_key, e_key in (("logical_durable_storage_bytes",
                                             "logical_durable_storage_bytes",
                                             "envelope_logical_durable_storage_bytes"),
                                            ("rendered_cost", "rendered_cost_micro",
                                             "envelope_rendered_cost_micro"),
                                            ("work_fuel", "work_fuel", "envelope_work_fuel"))
            if cand_vec[r_key] > inc_vec[e_key])
        _require(regressed_axes == list(part["regressed_resource_axes"]), VerdictMismatchError,
                 f"{where}.regressed_resource_axes does not recompute from the bound vectors "
                 f"(bound {part['regressed_resource_axes']}, recomputed {regressed_axes})")
        floor_vec = floor[label]
        for oid in cand_vec["objectives_micro"]:
            _require(oid in floor_vec["objectives_micro"], VerdictMismatchError,
                     f"genesis_floor.partitions[{label!r}] carries no objective {oid!r}; the "
                     "floor comparison has no default for a missing component")
        for oid in floor_vec["objectives_micro"]:
            _require(oid in cand_vec["objectives_micro"], VerdictMismatchError,
                     f"{where}.candidate_vector carries no objective {oid!r} the law-bound floor "
                     "protects")
        floor_regressions = sorted(
            ["composite_ppm"] * (cand_vec["composite_micro"] // 100
                                 < floor_vec["composite_micro"] // 100)
            + [oid for oid, value in cand_vec["objectives_micro"].items()
               if value < floor_vec["objectives_micro"][oid]])
        _require(floor_regressions == list(part["floor_regressions"]), VerdictMismatchError,
                 f"{where}.floor_regressions does not recompute against the genesis quality floor "
                 f"(bound {part['floor_regressions']}, recomputed {floor_regressions})")
        envelope_axes = (
            ("rendered_cost", "rendered_cost_micro", "envelope_rendered_cost_micro"),
            ("work_fuel", "work_fuel", "envelope_work_fuel"),
            ("logical_durable_storage_bytes", "logical_durable_storage_bytes",
             "envelope_logical_durable_storage_bytes"),
        )
        quality_advance = part["composite_gain_ppm"] >= 1
        composite_held = part["composite_gain_ppm"] >= 0
        raised_vs_parent = [
            axis for axis, r_key, _e in envelope_axes if cand_vec[r_key] > inc_vec[r_key]]
        dropped_vs_parent = [
            axis for axis, r_key, _e in envelope_axes if cand_vec[r_key] < inc_vec[r_key]]
        efficiency_advance = (composite_held and not regressed_objectives
                              and not raised_vs_parent and bool(dropped_vs_parent))
        _require(cand_vec["suite_block_id"] == inc_vec["suite_block_id"], VerdictMismatchError,
                 f"{where}.candidate_vector.suite_block_id is {cand_vec['suite_block_id']}, "
                 f"parent {inc_vec['suite_block_id']}; suite-block id is carried, never jumped")
        envelope_ok = not regressed_axes
        floor_ok = not floor_regressions
        progress_class = None
        if quality_advance and not regressed_objectives and envelope_ok and floor_ok:
            progress_class = "quality"
        elif efficiency_advance and envelope_ok and floor_ok:
            progress_class = "efficiency"
        admit = bool(part["hard_ok"] and progress_class is not None)
        _require(admit == bool(part["admit"]), VerdictMismatchError,
                 f"{where}.admit does not follow from the Q/R/E rule over the bound "
                 "vectors")
        _require(progress_class == part.get("progress_class"), VerdictMismatchError,
                 f"{where}.progress_class is {part.get('progress_class')!r}, recomputed "
                 f"{progress_class!r}")
        if admit:
            if progress_class == "quality":
                want_gain = min(1_000_000, int(part["composite_gain_ppm"]))
            else:
                best = 0
                for axis, r_key, _e in envelope_axes:
                    parent_val = inc_vec[r_key]
                    cand_val = cand_vec[r_key]
                    if cand_val >= parent_val:
                        continue
                    delta = parent_val - cand_val
                    if parent_val == 0:
                        best = max(best, 1_000_000)
                    else:
                        best = max(best, (delta * MICRO) // parent_val)
                want_gain = max(1, min(1_000_000, best))
            _require(part["admission_gain_ppm"] == want_gain, VerdictMismatchError,
                     f"{where}.admission_gain_ppm is {part['admission_gain_ppm']}, "
                     f"recomputed {want_gain}")
    proj = artifact["admission_projection"]
    if dom["admit"]:
        confirm = dom["partitions"]["confirm"]
        _require(proj.get("class") == confirm.get("progress_class"), VerdictMismatchError,
                 "admission_projection.class is not the admitting confirm partition's "
                 "progress_class")
        _require(proj.get("score_after_ppm") == confirm.get("admission_gain_ppm"),
                 VerdictMismatchError,
                 "admission_projection.score_after_ppm is not the admitting confirm "
                 "partition's admission_gain_ppm")
        _require(proj.get("score_before_ppm") == 0, VerdictMismatchError,
                 "admission_projection.score_before_ppm must be 0")
    else:
        # A receipt projection describes the FINAL gate∧confirm result.  If either partition
        # rejects, importing the other partition's class/gain would turn a final reject into an
        # admitting-looking receipt.  There is exactly one reject projection.
        _require(dict(proj) == {"score_before_ppm": 0}, VerdictMismatchError,
                 "a final REJECT must carry exactly the canonical reject admission_projection")
    return {"engine": dom["engine"], "admit": bool(dom["admit"])}


def _verify_bindings(artifact: Mapping[str, Any], *, eval_report,
                     epoch_pins: Any = None,
                     expected_parent_root: str, expected_new_root: str,
                     expected_release_root: str, expected_composition_root: str,
                     expected_runtime_abi_root: str, expected_benchmark_law_root: str,
                     expected_counter_resource_law_root: str,
                     expected_epoch: int,
                     expected_target_profile: Optional[str] = None,
                     counter_resource_law: Optional[Mapping[str, Any]] = None,
                     store: Optional[pub.ContentStore] = None,
                     check_availability: bool = False, require_rig_receipt: bool = False,
                     expected_epoch_context_root: Optional[str] = None,
                     expected_core_version_hash: Optional[str] = None,
                     expected_work_policy_hash: Optional[str] = None,
                     resolve_witness_source: bool = False) -> Dict[str, Any]:
    """Every binding of the one public fixed-suite artifact."""
    validate_artifact(artifact)
    report: Dict[str, Any] = {"checks": [], "law_id": FIXED_SUITE_LAW_ID}

    def done(name: str) -> None:
        report["checks"].append(name)

    # ---- 1. chain-asserted roots ----------------------------------------------------------
    front = artifact["frontier"]
    cand = artifact["candidate"]
    _require(front["parent_frontier_root"] == fr.check_root(expected_parent_root,
                                                            "expected_parent_root"),
             ParentRootMismatchError,
             f"artifact parent frontier root {front['parent_frontier_root']} != the confirmed "
             f"live root {expected_parent_root}")
    _require(front["new_frontier_root"] == fr.check_root(expected_new_root, "expected_new_root"),
             NewRootMismatchError,
             f"artifact new frontier root {front['new_frontier_root']} != {expected_new_root}")
    _require(cand["release_root"] == fr.check_root(expected_release_root,
                                                   "expected_release_root"),
             ReleaseRootMismatchError,
             f"artifact candidate release root {cand['release_root']} != {expected_release_root}")
    _require(front["composition_root"] == fr.check_root(expected_composition_root,
                                                        "expected_composition_root"),
             CompositionRootMismatchError,
             f"artifact composition root {front['composition_root']} != "
             f"{expected_composition_root}")
    _require(front["runtime_abi_root"] == fr.check_root(expected_runtime_abi_root,
                                                        "expected_runtime_abi_root"),
             EpochPinMismatchError,
             f"artifact runtime_abi_root {front['runtime_abi_root']} != the epoch pin "
             f"{expected_runtime_abi_root}")
    _require(front["benchmark_law_root"] == fr.check_root(expected_benchmark_law_root,
                                                          "expected_benchmark_law_root"),
             EpochPinMismatchError,
             f"artifact benchmark_law_root {front['benchmark_law_root']} != the epoch pin "
             f"{expected_benchmark_law_root}")
    _require(artifact["counter_resource_law_root"] == fr.check_root(
                 expected_counter_resource_law_root, "expected_counter_resource_law_root"),
             EpochPinMismatchError,
             f"artifact counter_resource_law_root {artifact['counter_resource_law_root']} != the "
             f"epoch pin {expected_counter_resource_law_root}")
    _require(artifact["epoch"] == fr.check_epoch(expected_epoch, "expected_epoch"),
             EpochPinMismatchError,
             f"artifact epoch {artifact['epoch']} != the receipt's epoch {expected_epoch}")
    if expected_target_profile is not None:
        _require(cand["target_profile"] == fr.check_profile_id(expected_target_profile,
                                                               "expected_target_profile"),
                 BindingMismatchError,
                 f"artifact target profile {cand['target_profile']!r} != "
                 f"{expected_target_profile!r}")
    done("chain_roots")

    # ---- 2. the transition and its two hashes ---------------------------------------------
    transition = front["transition"]
    _require(transition["target_profile"] == cand["target_profile"], BindingMismatchError,
             f"transition targets {transition['target_profile']!r} but the candidate block says "
             f"{cand['target_profile']!r}")
    _require(transition["new_release_root"] == cand["release_root"], ReleaseRootMismatchError,
             "transition new_release_root != candidate.release_root")
    _require(transition["expected_prior_release_root"] == cand["prior_release_root"],
             ReleaseRootMismatchError,
             "transition expected_prior_release_root != candidate.prior_release_root")
    _require(transition["resulting_composition_root"] == front["composition_root"],
             CompositionRootMismatchError,
             "transition resulting_composition_root != frontier.composition_root")
    tbytes = fr.canonical_bytes(transition)
    _require(len(tbytes) == front["transition_bytes_len"], BindingMismatchError,
             f"transition canonicalizes to {len(tbytes)} bytes, the artifact records "
             f"{front['transition_bytes_len']}")
    _require(len(tbytes) <= fr.MAX_TRANSITION_BYTES, fr.TransitionSizeError,
             f"transitionBytes is {len(tbytes)} bytes, over the {fr.MAX_TRANSITION_BYTES}-byte "
             "artifact replay bound")
    _require(front["transition_id_sha256"] == fr.transition_hash(transition),
             TransitionIdentityMismatchError,
             "frontier.transition_id_sha256 is not sha256 over the transition's canonical bytes")
    done("transition_identity")

    # ---- 3. the parent manifest actually produces the claimed child ------------------------
    parent = artifact["replay_inputs"]["parent_manifest"]
    computed_parent = fr.frontier_root(parent)
    _require(computed_parent == front["parent_frontier_root"], ParentRootMismatchError,
             f"the carried parent manifest hashes to {computed_parent}, not the bound "
             f"{front['parent_frontier_root']}")
    # The epoch context explicitly supplies the first parent for an epoch. That manifest may name
    # the same product epoch or an earlier one; no resolver searches backward and no inheritance
    # is inferred. What is never legitimate is a parent from a later epoch.
    _require(parent["epoch"] <= artifact["epoch"], EpochPinMismatchError,
             f"parent manifest epoch {parent['epoch']} is later than artifact epoch "
             f"{artifact['epoch']}; epochs never move backwards")
    crossed_epoch = parent["epoch"] < artifact["epoch"]
    # A same-epoch parent is already governed by the current context and must carry its exact
    # pins. Only an explicitly context-bound older parent may differ, and even then the CHILD is
    # checked above against the independently supplied expected pins.  This is the evaluator-side
    # half of the transition-index rule: public event replay additionally requires index zero for
    # this epoch-crossing edge because transition_index is authoritative chain data that the eval
    # artifact deliberately does not duplicate.
    if epoch_pins is None or not crossed_epoch:
        _require(parent["benchmark_law_root"] == front["benchmark_law_root"],
                 EpochPinMismatchError,
                 "parent manifest benchmark_law_root != the artifact's bound pin")
        _require(parent["runtime_abi_root"] == front["runtime_abi_root"],
                 EpochPinMismatchError,
                 "parent manifest runtime_abi_root != the artifact's bound pin")
    _require(parent["profiles"][cand["target_profile"]] == cand["prior_release_root"],
             ReleaseRootMismatchError,
             "the parent frontier does not serve the candidate's prior release root for the "
             "target profile — this candidate was built against a different frontier")
    # The artifact's own epoch drives the replay, so an artifact built for epoch N can never be
    # re-presented as evidence for epoch N+1 against the same parent: the reproduced root differs.
    fr.verify_transition(parent, transition, front["new_frontier_root"],
                         epoch=artifact["epoch"],
                         epoch_pins=epoch_pins)                            # raises on divergence
    done("frontier_replay")

    # ---- 4+5. There is no entropy to open and no walk to re-derive: the cases
    #      are LAW. What replaces both steps is MEMBERSHIP plus the three law-bound comparands the
    #      componentwise rule decides against — the suite, the exact parent's stored vector, and
    #      the constructor-genesis floor. Each is re-resolved HERE from the law document rather
    #      than read out of the artifact, so an artifact that only agrees with itself proves
    #      nothing (the same discipline the chain-asserted roots follow in step 1).
    verify_suite_membership(artifact)
    done("suite_membership")
    verify_genesis_floor(artifact)
    done("genesis_floor")
    verify_dominance_block(artifact)
    done("dominance")


    # ---- 6. The deterministic report is canonical, content-addressed, and unsigned. --------
    bound_root = artifact["receipt"]["eval_report_root"]
    body = eval_report
    if body is None:
        if store is None:
            raise ReceiptUnavailableError(
                "verification needs the deterministic evaluation report: pass eval_report, or "
                "a store to fetch it from by the artifact's bound eval_report_root")
        body = pub.fetch_json(bound_root, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    body = _eval_report(body)
    recomputed = eval_report_root(body)
    _require(recomputed == bound_root, ReceiptBindingError,
             f"the evaluation report's canonical bytes hash to {recomputed}, not the bound "
             f"{bound_root} — the artifact addresses a different result than the one supplied")
    _require(body["candidate"]["candidate_hash"] == cand["candidate_hash"], ReceiptBindingError,
             "receipt candidate_hash != the artifact's semantic candidate hash")
    _require(body["candidate"]["manifest_hash"]
             == artifact["replay_inputs"]["candidate_manifest_hash"], ReceiptBindingError,
             "receipt candidate manifest_hash != replay_inputs.candidate_manifest_hash")
    _require(body["candidate"]["declaration_id"]
             == artifact["replay_inputs"]["candidate_declaration_id"], ReceiptBindingError,
             "receipt candidate declaration_id != replay_inputs.candidate_declaration_id")
    _require(body["candidate"]["exec"] == artifact["replay_inputs"]["candidate_exec"],
             ReceiptBindingError, "receipt candidate exec != replay_inputs.candidate_exec")
    # Non-consensus telemetry is still recomputed rather than believed.
    _require(candidate_module_bytes(body)
             == artifact["replay_inputs"]["candidate_module_bytes"], ReceiptBindingError,
             "replay_inputs.candidate_module_bytes does not recompute from the bound report's "
             "own module source")
    inc_bound = artifact["replay_inputs"]["incumbent"]
    _require(project_incumbent(body["incumbent"]) == inc_bound, ReceiptBindingError,
             "receipt incumbent identity != replay_inputs.incumbent")
    _require(body["profile_id"] == cand["target_profile"], ReceiptBindingError,
             f"receipt profile {body['profile_id']!r} != the target profile "
             f"{cand['target_profile']!r}")
    # The report's cases are the artifact's canonical-suite cases, field for field.
    suite = artifact["suite"]
    _require(body["profile_id"] == suite["profile_id"], ReceiptBindingError,
             "receipt profile_id != the artifact's suite profile")
    for label in SELECTION_LABELS:
        rec_cases = [{"instance_hash": c["instance_hash"], "instance_id": c["instance_id"],
                      "profile_id": c["profile_id"], "scale": c["scale"], "seed": c["seed"],
                      "suite_index": c["suite_index"]}
                     for c in body["selection"][label]]
        _require(rec_cases == suite["cases"][label], SuiteMembershipError,
                 f"the artifact's {label!r} suite partition is not the receipt's {label!r} "
                 "selection")
    descriptor = body.get("evaluation_law") or {}
    _require(descriptor.get("law_id") == FIXED_SUITE_LAW_ID, ReceiptBindingError,
             f"the evaluation report is bound to {descriptor.get('law_id')!r}, not the "
             f"fixed-suite law {FIXED_SUITE_LAW_ID!r}")
    _require(descriptor.get("canonical_suite_root") == suite["suite_root"],
             SuiteMembershipError,
             "the evaluation report's bound law names a different canonical suite than the "
             "artifact's suite block")
    # The dominance block is re-derived from the report's own verdict vectors.
    expected_dominance = dominance_block_for(body["verdicts"], body["decision"])
    if expected_dominance != artifact["dominance"]:
        differing = sorted(
            label for label in SELECTION_LABELS
            if expected_dominance["partitions"][label]
            != artifact["dominance"]["partitions"][label])
        raise VerdictMismatchError(
            "the artifact's dominance block does not derive from the addressed evaluation "
            f"report's own verdicts (partitions differing: {differing or ['admit']})")
    done("dominance_report_binding")
    assert_determinism_witness(parent_vector_from_verdicts(body["verdicts"]),
                               artifact["determinism_witness"])
    done("determinism_witness")
    _require(body["round_id"] == cs.FIXED_SUITE_ROUND_ID, ReceiptBindingError,
             f"the evaluation report's round_id {body['round_id']!r} is not the fixed-suite "
             f"constant {cs.FIXED_SUITE_ROUND_ID!r}")
    for label in SELECTION_LABELS:
        field = "entropy" if label == "gate" else "confirm_entropy"
        expected_value = cs.fixed_suite_entropy(label)
        _require((body[field] or {}).get("value") == expected_value, ReceiptBindingError,
                 f"the evaluation report's {field}.value is not the inert fixed-suite "
                 f"constant {expected_value}")
    done("fixed_round_identity")
    _require(body["outputs_hash"] == artifact["receipt"]["outputs_hash"], ReceiptBindingError,
             "receipt.outputs_hash != the artifact's bound outputs hash")
    _require(dict(body["code_roots"]) == dict(artifact["receipt"]["code_roots"]),
             ReceiptBindingError,
             "receipt.code_roots != the artifact's bound code roots — the exact bytes that "
             "executed are not the ones the artifact claims")
    _require(body["measurement_policy"] == artifact["receipt"]["measurement_policy"]
             == artifact["measurements"]["policy"], ReceiptBindingError,
             "measurement policy disagrees between the receipt and the artifact")
    done("receipt_bindings")

    # ---- 7. measurements: the EXACT projection, incl. consumer-visible rendered cost --------
    projected = project_measurements(body)
    for label in SELECTION_LABELS:
        for side in ("candidate", "incumbent"):
            bound = artifact["measurements"]["branches"][label][side]
            fresh = projected["branches"][label][side]
            if bound["rendered_cost_micro"] != fresh["rendered_cost_micro"]:
                raise RenderedCostMismatchError(
                    f"measurements[{label}][{side}].rendered_cost_micro is "
                    f"{bound['rendered_cost_micro']}, the receipt measures "
                    f"{fresh['rendered_cost_micro']} (x10^-6 render_cost.v2 tokens) — the "
                    "consumer-visible cost is bound EXACTLY and cannot be restated")
            if bound != fresh:
                differing = sorted(k for k in fresh if bound.get(k) != fresh[k])
                raise ReceiptBindingError(
                    f"measurements[{label}][{side}] does not project from the receipt; "
                    f"differing: {differing}")
    done("measurements")

    # ---- 7b. THE DECIDED VECTORS ARE THE MEASURED ONES ---------------------------------------
    #
    # A Benchmark-v2 report states each side twice: once as raw ``scores`` (from which
    # ``measurements`` projects, checked immediately above) and once as ``verdicts[*].vectors``,
    # the absolute vectors the componentwise rule actually compared. Everything downstream of the
    # verdicts — the dominance block, the determinism witness, the baseline document the witness
    # resolves to — is derived from the SECOND statement, and until this check nothing tied it to
    # the first.
    #
    # That gap was exploitable end to end: raise one objective inside
    # ``verdicts[*].vectors.candidate``, leave ``scores`` untouched, flip the branch verdicts and
    # the decision, and the REAL builder minted an ADMIT artifact whose every internal binding was
    # honest by construction — measurements still projected exactly (they come from ``scores``),
    # the dominance block still derived from the verdicts, the witness still matched the parent
    # arm, and the published baseline document still backed it. Both verify shapes passed. The
    # artifact contradicted ITSELF, dominance against measurements, and nobody compared the two.
    # Only benchmark-side receipt recomputation or a full sandbox replay would have caught it,
    # neither of which the V5 artifact layer runs.
    #
    # ALL FIVE COMPONENTS, INCLUDING THE STORAGE AXIS. The measurement policy carries
    # ``logical_durable_storage_bytes`` explicitly and the fixed-suite law protects it. The
    # witness/source chain independently binds the incumbent side.
    assert_decided_vectors_are_measured(artifact["dominance"], projected)
    done("decided_vectors_are_measured")

    # ---- 8. the counter-resource law, recomputed ------------------------------------------
    law = counter_resource_law
    if law is None:
        if store is None:
            raise CounterResourceLawError(
                "verification needs the pinned counter-resource law: pass it, or a store to "
                "fetch it from by counter_resource_law_root")
        law = pub.fetch_json(artifact["counter_resource_law_root"],
                             hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    validate_counter_resource_law(law)
    law_root = counter_resource_law_root(law)
    _require(law_root == artifact["counter_resource_law_root"], EpochPinMismatchError,
             f"the supplied counter-resource law hashes to {law_root}, not the bound "
             f"{artifact['counter_resource_law_root']}")
    acct = artifact["resource_accounting"]
    _require(acct["branch"] == law["branch"], ResourceAccountingError,
             f"resource_accounting.branch {acct['branch']!r} != the law's pinned branch "
             f"{law['branch']!r}")
    branch = law["branch"]
    recomputed = evaluate_counter_resource_law(
        law, artifact["measurements"]["branches"][branch]["candidate"],
        artifact["measurements"]["branches"][branch]["incumbent"],
        profile_id=artifact["candidate"]["target_profile"],
        candidate_vector=artifact["dominance"]["partitions"][branch]["candidate_vector"],
        incumbent_vector=artifact["dominance"]["partitions"][branch]["incumbent_vector"])
    for key, value in recomputed.items():
        _require(acct[key] == value, ResourceAccountingError,
                 f"resource_accounting.{key} is {acct[key]}, the pinned counter law recomputes "
                 f"{value} from the bound measurements")
    done("counter_resource_law")

    # ---- 9. the verdict is the receipt's deterministic decision -----------------------------
    decision = body["decision"]
    verdict = artifact["verdict"]
    _require(bool(decision["admit"]) == verdict["admit"], VerdictMismatchError,
             f"artifact verdict admit={verdict['admit']} != the receipt's decision "
             f"admit={decision['admit']} — the deterministic result is the SOLE admission law")
    _require(decision["verdict"] == verdict["verdict"], VerdictMismatchError,
             f"artifact verdict {verdict['verdict']!r} != the receipt's {decision['verdict']!r}")
    decision_hash = fr.sha256_hex(pub.benchmark_canonical_bytes(decision))
    _require(decision_hash == verdict["decision_hash"], VerdictMismatchError,
             f"verdict.decision_hash {verdict['decision_hash']} != sha256 over the receipt's "
             f"decision object {decision_hash}")
    done("verdict")

    # ---- 11. the RIG-protocol receipt fields ------------------------------------------------
    # Mandatory when the artifact is being bound to a rig receipt.
    rig_present = "rig_receipt" in artifact
    if require_rig_receipt and not rig_present:
        raise RigReceiptFieldsMissingError(
            "this artifact is being verified for a RIG receipt but carries no 'rig_receipt' "
            f"block. A RigCoreTexReceipt signs {', '.join(RIG_RECEIPT_FIELDS)}; the coordinator "
            "does not invent a signed field, so there is nothing to sign.")
    if rig_present:
        rig = validate_rig_receipt_block(artifact["rig_receipt"])
        # The consolidated context root and remaining law pins. Each is checked only when the
        # caller supplies it: a validator replaying history has them, a builder may not yet.
        for field, expected in (("epoch_context_root", expected_epoch_context_root),
                                ("core_version_hash", expected_core_version_hash),
                                ("work_policy_hash", expected_work_policy_hash)):
            if expected is None:
                continue
            _require(rig[field] == fr.check_root(expected, f"expected_{field}"),
                     EpochPinMismatchError,
                     f"rig_receipt.{field} {rig[field]} != the epoch pin {expected}; the registry "
                     "would revert on the mismatched context")
        # A state advance signs the zero-extension of the descriptor's version byte. It is NOT a
        # patch width: breadth is unbounded and one transition may move three profile releases, the
        # composition root and derived state at once (spec §8).
        if rig["outcome"] == RIG_OUTCOME_STATE_ADVANCE:
            _require(rig["transition_format_version"] == RIG_TRANSITION_FORMAT_VERSION,
                     RigReceiptFieldError,
                     f"rig_receipt.transition_format_version is "
                     f"{rig['transition_format_version']}; a state advance on this lane signs "
                     f"0x{RIG_TRANSITION_FORMAT_VERSION:02x}, the one version this deployment "
                     "implements")
            _require(front["new_frontier_root"] != front["parent_frontier_root"],
                     RigReceiptFieldError,
                     "rig_receipt.outcome=2 claims a state advance but the artifact's new root "
                     "equals its parent; the registry would revert NoOpAdvance")
        else:
            # A screener pass is priced work that did NOT move the root.
            _require(front["new_frontier_root"] == front["parent_frontier_root"],
                     RigReceiptFieldError,
                     "rig_receipt.outcome=1 is a screener pass but the artifact moves the "
                     "frontier root; the registry would revert ScreenerPassMustNotAdvance")
        report["rig_receipt"] = dict(rig)
        done("rig_receipt_fields")

    # ---- 11b. WHERE THE STORED PARENT VECTOR CAME FROM ---------------------------------------
    # Steps 4-6 prove the witness is whole and that the parent arm re-executed HERE reproduced it.
    # Neither proves the stored vector was ever measured by anyone else. Resolving it needs the
    # public object surface, which not every caller has — so the outcome is REPORTED rather than
    # assumed: a caller that did not ask for resolution is told, in the report, that the witness's
    # provenance is UNRESOLVED. Silence would read as proof.
    witness_block = artifact["determinism_witness"]
    if not resolve_witness_source:
        report["witness_provenance"] = {
            "resolved": False,
            "source_kind": witness_block["source_kind"],
            "source_root": witness_block["source_root"],
            "reason": "verification ran without an object resolver; the stored parent vector "
                      "was checked for internal consistency and against the re-executed parent "
                      "arm, but its genesis baseline or prior accepted artifact was not fetched",
        }
    else:
        if store is None:
            raise ReceiptUnavailableError(
                "resolve_witness_source=True needs a store to fetch the object "
                "determinism_witness.source_root names")
        report["witness_provenance"] = resolve_determinism_witness_source(
            artifact, store=store)
        done("determinism_witness_source")
    # ---- 12. availability (optional here; MANDATORY at pre-sign) ----------------------------
    if check_availability:
        if store is None:
            raise pub.AvailabilityError(
                "check_availability=True needs a store to read the published objects back from")
        report["availability"] = pub.verify_availability(
            artifact["availability"], store=store, required=REQUIRED_AVAILABILITY)
        done("availability")

    report.update({
        "ok": True,
        "eval_report_hash": eval_report_hash(artifact),
        "parent_frontier_root": front["parent_frontier_root"],
        "new_frontier_root": front["new_frontier_root"],
        "verdict": deterministic_verdict(artifact),
        "rig_receipt_present": rig_present,
        "resource_accounting": dict(acct),
        "admission_projection": dict(artifact["admission_projection"]),
    })
    return report


def receipt_binding_for_signing(artifact: Mapping[str, Any]) -> Dict[str, str]:
    """The two values an ADMITTED artifact's EIP-712 mining receipt must bind.

    THE ONLY SIGNATURE IN THE SYSTEM. Coordinator signing
    (``coretex-memory-frontier-lane.ts``) binds two *different* documents:

      ``evalReportHash`` = SHA-256 of these canonical evaluation-artifact bytes
      ``artifactHash``   = ``candidate.release_root`` (the scored candidate)

    ``chain_first.py`` requires signed ``artifactHash == candidate.release_root``.
    A helper that restated the eval-artifact digest as both hashes could never
    replay a production-shaped advance. The signature is secp256k1/EIP-712,
    produced by the coordinator and verified BY A DEPLOYED CONTRACT against
    ``mining.coordinatorSigner()``. Off-chain recovery for AUDIT (never for
    authorization) is ``resolver/join.py`` step 7.
    """
    validate_artifact(artifact)
    artifact_law(artifact)
    if artifact["verdict"]["admit"] is not True:
        raise PreSignError(
            "receipt signing refused: the final gate AND confirm decision is REJECT")
    digest = eval_report_hash(artifact)
    release_root = artifact["candidate"]["release_root"]
    return {"evalReportHash": digest, "artifactHash": release_root,
            "eval_report_root": artifact["receipt"]["eval_report_root"]}


def publish_artifact(artifact: Mapping[str, Any], *, store: pub.ContentStore) -> str:
    """Publish the canonical artifact and read it back under ``evalReportHash``."""
    validate_artifact(artifact)
    return pub.publish_and_read_back(
        artifact, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store,
        expected_root=eval_report_hash(artifact))


def prepare_broadcastable_receipt(artifact: Mapping[str, Any], *, store: pub.ContentStore,
                                  expected_parent_root: str, expected_new_root: str,
                                  **verify_kwargs) -> Dict[str, Any]:
    """Verify an ADMIT, read availability back, and publish it before receipt minting.

    A valid REJECT remains useful public evaluation evidence, but it is never broadcastable and is
    refused before publication/signing output is produced.
    """
    verify_kwargs.setdefault("store", store)
    verify_kwargs.pop("check_availability", None)
    availability_scope = str(verify_kwargs.pop("availability_scope", "") or "").strip()
    report = verify_artifact(
        artifact, expected_parent_root=expected_parent_root,
        expected_new_root=expected_new_root, **verify_kwargs)
    if report["verdict"].get("admit") is not True:
        raise PreSignError(
            "receipt preparation refused: the final gate AND confirm decision is REJECT")
    rig_bound = bool(verify_kwargs.get("require_rig_receipt")) or "rig_receipt" in artifact
    required = RIG_REQUIRED_AVAILABILITY if rig_bound else REQUIRED_AVAILABILITY
    try:
        available = pub.verify_availability(
            artifact["availability"], store=store, required=required)
        records = pub.availability_report(
            artifact["availability"], store=store, required=required)
        report_hash = publish_artifact(artifact, store=store)
    except pub.PublicationError as exc:
        raise PreSignError(f"receipt preparation refused by publication read-back: {exc}") from exc
    front = artifact["frontier"]
    out: Dict[str, Any] = {
        "broadcastable": True,
        "law_id": report["law_id"],
        "eval_report_hash": report_hash,
        "available": available,
        "availability_records": records,
        "availability_required": list(required),
        "availability_scope": availability_scope,
        "transition_artifact_required": rig_bound,
        "epoch": artifact["epoch"],
        "parent_frontier_root": front["parent_frontier_root"],
        "new_frontier_root": front["new_frontier_root"],
        "candidate_release_root": artifact["candidate"]["release_root"],
        "composition_root": front["composition_root"],
        "benchmark_law_root": front["benchmark_law_root"],
        "runtime_abi_root": front["runtime_abi_root"],
        "counter_resource_law_root": artifact["counter_resource_law_root"],
        "target_profile": artifact["candidate"]["target_profile"],
        "utility_before_ppm": artifact["admission_projection"]["score_before_ppm"],
        "utility_after_ppm": artifact["admission_projection"].get("score_after_ppm") or 0,
        "resource_before_ppm": artifact["resource_accounting"]["resource_before_ppm"],
        "resource_after_ppm": artifact["resource_accounting"]["resource_after_ppm"],
        "progress_class": artifact["admission_projection"].get("class"),
        "verdict": report["verdict"],
        "rig_receipt_present": "rig_receipt" in artifact,
    }
    if "rig_receipt" in artifact:
        out.update(rig_receipt_projection(artifact))
    return out


def artifact_json(artifact: Mapping[str, Any], *, indent: Optional[int] = None) -> str:
    """Human-readable rendering. NEVER the addressed form — that is
    :func:`artifact_canonical_bytes`, and only that."""
    validate_artifact(artifact)
    return json.dumps(artifact, sort_keys=True, indent=indent)
