# SPDX-License-Identifier: Apache-2.0
"""Reference implementation of ``coretex.memory-eval-artifact.v1`` (Cut V5-C, ledger §17.236).

The normative text is ``v5/spec/EVAL-ARTIFACT-V1.md``. This module is its executable form: build,
canonicalize, hash and VERIFY the one artifact whose ``sha256`` is the on-chain ``evalReportHash``.

WHAT THIS OBJECT IS FOR. §17.236's consensus rule is that a public validator reproduces a mine
with no hosted API and no coordinator-private data:

    read confirmed event -> fetch parent manifest + verify root -> apply transitionBytes ->
    reproduce newFrontierRoot -> fetch eval artifact by evalReportHash -> rehash -> verify ALL
    bindings -> regenerate fresh instances from committed entropy -> execute the candidate in the
    pinned networkless sandbox -> recompute utility / safety / rendered cost / fuel / storage ->
    confirm it beat the EXACT parent incumbent under the frozen law.

Everything that walk needs is bound here or addressed from here.

DISCIPLINE (inherited from ``frontier.py``, deliberately identical):
  * canonical bytes = ``frontier.canonical_bytes`` = the shipped runtime's
    ``coretex_memory.release.canonical_manifest_bytes`` rule. No floats, no nulls, no duplicate
    keys, closed schemas, roots as BARE LOWERCASE hex.
  * :func:`verify_artifact` RAISES a typed :class:`EvalArtifactError`; it never returns ``False``
    for an unverified artifact, so an unverified artifact can never be read as a passing one.
  * every check is offline and pure given its inputs (the only I/O is an injected
    :class:`publication.ContentStore`).

FLOATS, AND WHY MEASUREMENTS ARE MICRO-INTEGERS. A signed Benchmark-v2 receipt legitimately
carries floats (``composite``, ``rendered_cost``, ``latency_ms`` — all ``round(x, 6)``), and the
V5-A canonical rule REJECTS floats because ``1`` and ``1.0`` compare equal but serialize
differently, which would give one logical value two roots. The artifact therefore never inlines
the receipt: it ADDRESSES it (``receipt.wrapper_root``, ``receipt.receipt_hash``) and carries an
EXACT integer projection of every measured quantity in micro-units (x10^6). "Exact" is enforced,
not assumed — :func:`to_micro` refuses any value that is not representable at 6 decimal places
rather than rounding it.

THE CANARY IS AUXILIARY, NORMATIVELY. The optional ``canary`` block is
``consensus_critical: false`` / ``external_model_attestation: true``. :func:`deterministic_verdict`
does not read it; :func:`verify_artifact` refuses any artifact that claims otherwise; and
:func:`verify_canary_block` — the only function that reads it — cannot alter a verdict, by
construction and by assertion. A canary that FAILS, or is absent, or whose bindings are wrong,
yields the identical deterministic verdict.

SEAM (ledger §17.238)
---------------------
SEAM:            :func:`prepare_broadcastable_receipt` (:1658) is the coordinator's ENTRY POINT —
                 the PRE-SIGN gate, called after deterministic evaluation and before any
                 signature. The coordinator lane already declares it by name: the V5-D module
                 header (``coretex-memory-frontier-lane.ts:112-113``) records "no artifact
                 publication implementation (injected port — it lives in the memory-ir-rc lane as
                 ``v5/eval_artifact.py::prepare_broadcastable_receipt``)", and the two TypeScript
                 interfaces that must be backed by it are ``MemoryFrontierEvaluator`` (:549,
                 whose result is documented at :565 as "the projection of
                 ``prepare_broadcastable_receipt`` the coordinator needs") and
                 ``MemoryArtifactAvailabilityPort`` (:607, whose contract at :595-599 cites
                 ``publication.verify_availability``). Wiring is implementing those two
                 interfaces over this module; nothing here is edited.
PORTS IT TAKES:  ``publication.ContentStore`` and an optional ``signature_verifier``. Everything
                 else is a value the CHAIN asserts (parent root, new root, release root,
                 composition root, ABI/law roots, entropy commitment, epoch, target profile),
                 which is why :func:`verify_artifact` (:1131) takes them as explicit
                 ``expected_*`` arguments rather than reading them from the artifact it checks.
NO BYPASS:       :func:`prepare_broadcastable_receipt` has no ``skip``/``force`` parameter and
                 drops any caller-supplied ``check_availability`` so that availability is always
                 a :class:`PreSignError`. A coordinator that signs without it mints a receipt for
                 evidence no validator can fetch — a permanently unreplayable confirmed state.
MINIMAL DIFF:    inside the lane's guarded block, back the evaluator + artifact-availability
                 ports with a call to this function and pass the returned ``evalReportHash`` and
                 derived fields to the signer. (That block is an ADD, not an edit — see
                 :mod:`activation.activator` and ``v5/e2e/SEAM-INVENTORY.md``.)
REVENDOR NEEDED: NO. stdlib + ``v5`` siblings; no canonical, ``vendor/`` or ``node_modules/``
                 change.
ARM:             ``CORETEX_MEMORY_LANE_ARM`` (it is only reachable from the lane's guarded
                 block).
REMOVE:          delete the guarded block. Additive data only — the artifact is one more
                 content-addressed object; no table and no existing format is touched.
"""
from __future__ import annotations

import decimal
import hashlib
import json
import os
from typing import Any, Dict, Mapping, Optional, Tuple

from . import authority_law as al
from . import canonical_suite as cs
from . import frontier as fr
from . import parent_execution as parent_exec
from . import publication as pub
from .keccak256 import keccak256_hex
# Identity constants
# --------------------------------------------------------------------------- #
ARTIFACT_FORMAT = "coretex.memory-eval-artifact.v2"
ARTIFACT_FORMAT_V1_SIGNED_ERA = "coretex.memory-eval-artifact.v1"
#: It is a new family and not a v2 with extra fields for the reason every family split here exists:
#: the v2 schema is CLOSED, so a v2 artifact with a ``suite`` block is invalid, and a v3 artifact
#: with no ``entropy`` block would be invalid as a v2. Neither direction is cross-satisfiable, which
#: is exactly what stops a post-cut evaluation from presenting as pre-cut evidence, or the reverse.
#: Every v1 and v2 artifact keeps its bytes, its ``evalReportHash`` and its verification path.
ARTIFACT_FORMAT_V3 = "coretex.memory-eval-artifact.v3"

#: The closed family -> law table :func:`authority_law.law_of_artifact` dispatches on. An artifact's
#: law is read from the bytes ``evalReportHash`` addresses, so it is fixed when the artifact is
#: minted and cannot be restated by whoever presents it afterwards. v3 joins v2 under the
#: CHAIN-COMMITTED authority law: the authorization story did not change at the v4 cut (it is still
#: the coordinator's EIP-712 receipt over ``evalReportHash``), only the admission rule did.
ARTIFACT_FAMILY_LAWS = {
    ARTIFACT_FORMAT_V1_SIGNED_ERA: al.LAW_OFF_CHAIN_SIGNATURE_V1,
    ARTIFACT_FORMAT: al.LAW_CHAIN_COMMITTED_V2,
    ARTIFACT_FORMAT_V3: al.LAW_CHAIN_COMMITTED_V2,
}

#: The Benchmark-v2 law id a v3 artifact's evaluation report must be bound to. Stated here so the
#: artifact layer refuses a mismatched pairing instead of inferring one.
FIXED_SUITE_LAW_ID = "benchmark-v2-law/dominance-fixed-suite-2026-08-25.v5"
#: The decision engine that law names. Mirrors ``benchmark-v2/frontier/dominance.ENGINE_ID``.
DOMINANCE_ENGINE_ID = "dominance.componentwise.v1"
CANARY_BLOCK_FORMAT = "coretex.memory-eval-artifact.v1/canary-reference"
COUNTER_RESOURCE_LAW_FORMAT = "coretex.counter-resource-law.v1"

EVAL_REPORT_FORMAT = "benchmark-v2/receipt/v1"
RECEIPT_BODY_FORMAT = EVAL_REPORT_FORMAT
RECEIPT_WRAPPER_FORMAT_V1_SIGNED_ERA = "benchmark-v2/signed-receipt/v1"
# Compatibility name for the historical builder and its frozen tests.
RECEIPT_WRAPPER_FORMAT = RECEIPT_WRAPPER_FORMAT_V1_SIGNED_ERA

#: The sealed canary transcript family (``benchmark-v2/canary/run_canary.build_sealed``).
CANARY_TRANSCRIPT_FORMAT = "benchmark-v2/canary/transcript/v1"

#: The selection domain the Benchmark-v2 validator derives cases under
#: (``benchmark-v2/validator/select.py::_DOMAIN``). Reproduced, never re-invented.
SELECTION_DOMAIN = "benchmark-v2/select/v1"
SELECTION_LABELS = ("gate", "confirm")

#: V5 entropy expansion domain: how the CHAIN-COMMITTED epoch secret becomes the two independent
#: Benchmark-v2 selection entropies (spec §7).
ENTROPY_DOMAIN = "coretex.memory-frontier/entropy/v1"

#: ``CoreTexMemoryMining.TRANSITION_HASH_DOMAIN_LABEL``. ``abi.encodePacked(string, bytes)`` is
#: the UTF-8 label bytes concatenated with the payload.
TRANSITION_HASH_DOMAIN_LABEL = b"coretex-memory-transition-hash-v1"

#: Fixed-point scale for every measured quantity in the artifact.
MICRO = 1_000_000
#: uint32 ceiling — the receipt's ppm fields are ``uint32`` on-chain.
MAX_UINT32 = 2 ** 32 - 1
#: uint64 ceiling — epoch and byte counters.
MAX_UINT64 = 2 ** 64 - 1

#: The committed counter-resource law document shipped with this lane.
COUNTER_RESOURCE_LAW_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "COUNTER_RESOURCE_LAW.v1.json")
#: THE SUPERSEDED WALK-ERA COUNTER LAW, kept in this wheel verbatim (root
#: ``049fe98ec08a3a47e2bf4582afa70ad45506a465584f3cec1a53286617c7b207``). It differs from the
#: current document in ONE field: its storage term read ``resource.storage_bytes`` — the
#: historical-law alias for INPUT CORPUS BYTES — while calling itself
#: "logical-durable-storage.cbor.v1 bytes". The fixed-suite cut pointed that term at the axis it
#: always named. Every artifact minted before the cut binds this document BY ROOT and must keep
#: resolving to these exact bytes, so it is preserved rather than migrated (LAW §3A.6: prior eras
#: are never reinterpreted). Nothing new is ever minted against it.
WALK_ERA_COUNTER_RESOURCE_LAW_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "COUNTER_RESOURCE_LAW.walk-era.v1.json")

REQUIRED_AVAILABILITY_V2 = (
    "candidate_bundle", "composition_manifest", "counter_resource_law",
    "eval_report", "parent_frontier_manifest")
REQUIRED_AVAILABILITY_V1_SIGNED_ERA = (
    "candidate_bundle", "composition_manifest", "counter_resource_law",
    "parent_frontier_manifest", "receipt_wrapper")
# Frozen compatibility name used by the historical builder.
REQUIRED_AVAILABILITY = REQUIRED_AVAILABILITY_V1_SIGNED_ERA

ARTIFACT_FIELDS: Tuple[str, ...] = (
    "availability", "candidate", "counter_resource_law_root", "entropy", "epoch", "format",
    "frontier", "measurements", "receipt", "replay_inputs", "resource_accounting", "selection",
    "verdict",
)
#: The OPTIONAL top-level fields. ``canary``'s presence or absence MUST NOT change the verdict.
#:
#: ``rig_receipt`` is optional for the SAME reason and with a different consequence: every
#: artifact minted before the rig protocol existed omits it, and adding a mandatory field would
#: change ``ARTIFACT_FIELDS`` for those artifacts and make every already-published
#: ``evalReportHash`` unverifiable. It is therefore additive — an artifact WITHOUT it hashes and
#: validates exactly as it did before — and the refusal lives in the verify path instead:
#: :func:`verify_artifact` with ``require_rig_receipt=True`` (which the rig pre-sign gate always
#: passes) refuses an artifact that is about to be bound to a rig receipt but carries none of the
#: nine fields such a receipt signs.
OPTIONAL_ARTIFACT_FIELDS: Tuple[str, ...] = ("canary", "rig_receipt")

ARTIFACT_FIELDS_V3: Tuple[str, ...] = (
    "availability", "candidate", "counter_resource_law_root", "determinism_witness", "dominance",
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
VECTOR_FIELDS = ("composite_micro", "logical_durable_storage_bytes", "objectives_micro",
                 "rendered_cost_micro", "work_fuel")

#: The exact parent's STORED qualifying vector, carried into the job and bound here.
#: ``source_kind`` is ``bridge`` for the one-time re-scoring that qualified a pre-cut release, and
#: ``prior_accept`` for a parent that earned its vector by being admitted under this law.
DETERMINISM_WITNESS_FIELDS = ("law_id", "partitions", "profile_id", "release_root", "source_kind",
                              "source_root", "suite_root", "witness_root")
WITNESS_SOURCE_KINDS = ("bridge", "prior_accept")

#: The PUBLISHED object a ``source_kind == "bridge"`` witness resolves to (P5 mints one per
#: profile). A ``prior_accept`` witness resolves to the accepting v3 artifact itself, addressed by
#: its ``evalReportHash`` — there is no second document for that case, because the accepting
#: artifact already publishes the candidate vector that release stores.
BRIDGE_VECTOR_FORMAT = "coretex.memory-suite-bridge-vector.v1"
BRIDGE_VECTOR_FIELDS = ("format", "law_id", "measured_by", "partitions", "profile_id",
                        "release_root", "suite_root")

#: The law-bound constructor-genesis floor, as it was resolved for this decision.
GENESIS_FLOOR_FIELDS = ("partitions", "source", "status", "suite_root")

#: The componentwise decision, DERIVED from the evaluation report's bound verdicts — never
#: restated. ``partitions.<label>.incumbent_vector`` is the parent arm's RECOMPUTED vector; the
#: determinism witness holds the STORED one, and their equality is the witness check.
DOMINANCE_FIELDS = ("admit", "engine", "partitions")
DOMINANCE_PARTITION_FIELDS = ("admit", "candidate_vector", "composite_after_ppm",
                              "composite_before_ppm", "composite_gain_ppm", "floor_regressions",
                              "hard", "hard_ok", "incumbent_vector", "regressed_objectives",
                              "regressed_resource_axes")

CANDIDATE_FIELDS = ("candidate_hash", "prior_release_root", "release_root", "target_profile")
FRONTIER_FIELDS = ("benchmark_law_root", "composition_root", "new_frontier_root",
                   "parent_frontier_root", "runtime_abi_root", "transition",
                   "transition_bytes_len", "transition_hash_keccak256", "transition_id_sha256")
# Live-epoch production artifacts publish only the commitment and derivation law. Publishing the
# opening (or its reusable gate/confirm expansions) before ``EpochSecretRevealed`` would disclose
# the coordinator-private selection entropy. The complete open shape remains valid for every
# historical artifact already addressed by an on-chain ``evalReportHash``.
ENTROPY_SEALED_FIELDS = ("commitment", "commitment_scheme", "derivation_domain")
ENTROPY_OPEN_FIELDS = ENTROPY_SEALED_FIELDS + ("confirm_value", "gate_value", "revealed_secret")
ENTROPY_FIELDS = ENTROPY_OPEN_FIELDS
SELECTION_FIELDS = ("base_sha256", "burned_head", "cases", "counts", "domain", "profile_id",
                    "round_id", "scales", "season_root")
CASE_FIELDS = ("derivation_index", "instance_hash", "instance_id", "profile_id", "scale", "seed")
MEASUREMENT_FIELDS = ("branches", "micro_scale", "policy")
SIDE_FIELDS = ("composite_micro", "compute_micro", "corpus_supported", "events_scanned",
               "hook_compute_fuel", "hook_fuel", "host_profile", "latency_micro",
               "objectives_micro", "rendered_cost_micro", "storage_bytes", "store_events",
               "store_ops", "work_fuel")
#: v3. The fixed-suite law PROTECTS ``logical_durable_storage_bytes`` as a dominance-vector
#: component, so a v3 measured side MEASURES it — as its own field, next to the unchanged
#: ``storage_bytes`` slot, which keeps its documented meaning (the historical-law alias for input
#: corpus bytes) and stays telemetry. Two different axes, both measured by
#: ``final-render-trusted-hostwork.v4``, now both projected. The walk-era set above is FROZEN: a
#: v1/v2 artifact's measurement block is not edited, and its reprojection stays byte-identical.
SIDE_FIELDS_V3 = tuple(sorted(SIDE_FIELDS + ("logical_durable_storage_bytes",)))
RECEIPT_FIELDS = ("code_roots", "eval_report_root", "measurement_policy", "outputs_hash")
RECEIPT_FIELDS_V1_SIGNED_ERA = (
    "code_roots", "measurement_policy", "outputs_hash", "receipt_hash",
    "signature_key_id", "wrapper_root")
REPLAY_INPUT_FIELDS = ("candidate_declaration_id", "candidate_exec", "candidate_manifest_hash",
                       "incumbent", "parent_manifest")
#: v3. ``candidate_module_bytes`` is the UTF-8 length of the submitted miner module —
#: NON-CONSENSUS TELEMETRY, and the schema says so by construction: nothing compares it, no rule
#: reads it, no floor bounds it. It is reported because LAW §3A.7 names module footprint as the one
#: place a candidate can carry per-case specialization WITHOUT paying
#: ``logical_durable_storage_bytes`` (the logical meter charges sanctioned durable tables only;
#: modules are bounded solely by the 256 KiB ``MAX_ARTIFACT_BYTES`` admission cap). Metering it
#: into a protected axis would be unsatisfiable — every real module exceeds the ~1 KB
#: constructor-genesis wrapper, so nothing could ever dominate that floor — so the law reports it
#: and lets a reviewer watch it instead. It re-derives from the bound report body, so a verifier
#: RECOMPUTES it rather than believing it.
REPLAY_INPUT_FIELDS_V3 = tuple(sorted(REPLAY_INPUT_FIELDS + ("candidate_module_bytes",)))
INCUMBENT_FIELDS = ("candidate_hash", "exec", "id")
INCUMBENT_EXACT_FIELDS = INCUMBENT_FIELDS + ("module_sha256", "release_root")
RESOURCE_ACCOUNTING_FIELDS = ("branch", "resource_after_ppm", "resource_before_ppm",
                              "utility_after_ppm", "utility_before_ppm")
VERDICT_FIELDS = ("admit", "consensus_critical", "decision_hash", "verdict")
CANARY_FIELDS = ("candidate_hash", "code_identity", "consensus_critical", "entropy_hex",
                 "epoch_id", "external_model_attestation", "format", "incumbent_root", "mode",
                 "policy_hash", "selection_base_sha256", "transcript_root", "verdict")
COUNTER_LAW_FIELDS = ("branch", "format", "resource_axes", "resource_ppm_max", "utility_axis",
                      "utility_ppm_max")
RESOURCE_AXIS_FIELDS = ("id", "integer_axis", "source", "unit", "weight_ppm")
# Wall-clock and candidate-side self-reported compute counters remain diagnostic evidence. They
# are deliberately forbidden as admission axes: only trusted-parent deterministic counters,
# logical durable storage and rendered output cost may price a candidate.
NON_AUTHORITATIVE_ADMISSION_SOURCES = frozenset({
    "compute", "compute_ms", "compute_micro", "latency", "latency_ms", "latency_micro",
    "resource.hook_compute_fuel",
})

# --------------------------------------------------------------------------- #
# The RIG-PROTOCOL receipt fields (V5 rig-keyed integration, step 6)
# --------------------------------------------------------------------------- #
#: The EIGHT signed ``RigCoreTexReceipt`` fields that no other part of the artifact carries.
#:
#: The rig receipt signs 24 fields. Sixteen of them the artifact already determines (the state
#: roots, ``evalReportHash``, the ppm scores) or the chain does (``rigId``, ``operator``,
#: ``epochId``, ``solveIndex``, ``prevReceiptHash``, ``workUnitsBps``,
#: ``difficultyCountSnapshot``, ``issuedAt``, ``expiresAt``, ``patchHash``, ``artifactHash``).
#: These eight are the remainder: values only the EVALUATOR can know. They live here, inside the
#: bytes ``evalReportHash`` addresses, so they are hashed and signed rather than merely asserted
#: by whichever process happened to build the calldata — the ruling
#: ``RIG-CORETEX-REGISTRY-DESIGN.md`` §5.1 made for ``stateWordCount`` and which applies equally to
#: the other seven. ``transition_format_version`` is its transition-descriptor/v3 successor
#: (§9.1): unlike the retired counter it is not evaluator-observed data, it is the descriptor's
#: version byte zero-extended to ``uint16`` — but it stays in this tuple because it is still a
#: signed field only the evaluator (never the coordinator) supplies at the moment of signing.
RIG_RECEIPT_FIELDS = ("challenge_id", "core_version_hash", "epoch_context_root", "outcome",
                      "rules_version", "transition_format_version", "work_policy_hash", "world_seed")

#: ``outcome`` values the rig verifier prices. 0 and anything above 2 revert for EVERY epoch, so
#: an artifact may not even claim them.
RIG_OUTCOME_SCREENER_PASS = 1
RIG_OUTCOME_STATE_ADVANCE = 2
RIG_SIGNABLE_OUTCOMES: Tuple[int, ...] = (RIG_OUTCOME_SCREENER_PASS, RIG_OUTCOME_STATE_ADVANCE)

#: ``uint128`` — ``worldSeed``'s signed width.
MAX_UINT128 = 2 ** 128 - 1
#: ``uint16`` — ``transitionFormatVersion``'s signed width (was ``stateWordCount``'s).
MAX_UINT16 = 2 ** 16 - 1

#: RETIRED by the descriptor family. ``stateWordCount`` was a PATCH-WIDTH counter
#: bounded 1..4 (``RIG-CORETEX-REGISTRY-DESIGN.md`` §5.1); there is no word count under v3 — a
#: single descriptor now expresses breadth the retired 4-word ceiling could never reach (spec §1.1,
#: §8 T-3). Kept, unused, so a reader who remembers the old bound can find where it went.
RIG_STATE_WORD_COUNT_MAX = 4
#: ``transitionFormatVersion`` on a STATE ADVANCE is always the descriptor version byte,
#: zero-extended — never a count of anything. ``0`` remains the SCREENER-PASS invariant ("zero iff
#: the root did not move"), which survives unchanged from the retired model.
#:
#: ``RIG_MEMORY_FRONTIER_STATE_WORD_COUNT`` (the retired ``== 1`` narrowing this constant used to
#: hold, and every assertion built on it) is DELETED rather than repointed at the new value: spec
#: §9.3 is explicit that a pin the retired model produced must be RE-MINTED, not adjusted, and a
#: constant named "word count" holding a version byte would misname what it is.
RIG_TRANSITION_FORMAT_VERSION_ADVANCE = 0x21

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

#: Fields too WIDE to survive JSON as numbers, rendered as decimal strings by
#: :func:`rig_receipt_projection`. ``world_seed`` is a ``uint128``: JSON numbers are IEEE-754
#: doubles, so a 39-digit integer decodes as a float and ``BigInt()`` refuses it. ``outcome``
#: (uint8), ``rules_version`` (uint32) and ``transition_format_version`` (uint16) all fit a JS number
#: exactly and stay numbers.
RIG_RECEIPT_WIDE_UINT_FIELDS = ("world_seed",)

#: ``receipt.incumbent.candidate_hash`` is ``null`` for the standing REFERENCE incumbent. Null is
#: not a canonical value in this law, so the artifact renders "no promoted champion" as the zero
#: sentinel — the same sentinel V5-A reserves for the genesis parent.
NO_CHAMPION = fr.ZERO_ROOT


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


class EntropyMismatchError(BindingMismatchError):
    """The entropy commitment, the revealed secret, or a derived selection entropy is wrong."""


class EntropyOpeningUnavailableError(EvalArtifactError):
    """A sealed artifact cannot be replayed until its chain opening is available.

    This is deliberately not a binding mismatch: the artifact remains structurally valid and
    hash-verifiable. A public validator records it as unresolved work and retries after observing
    ``EpochSecretRevealed``.
    """


class SelectionMismatchError(BindingMismatchError):
    """The recorded fresh selection is not what the committed entropy derives."""


class SuiteMembershipError(BindingMismatchError):
    """A v3 artifact's cases are not the immutable canonical suite's cases (LAW §3A.1).

    Refusal code ``SUITE_MEMBERSHIP_MISMATCH``. Under the fixed suite this replaces the walk
    re-derivation: a stripped, re-ordered, substituted or extra case is caught by MEMBERSHIP.
    """

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
    whole. It says nothing about whether the vector inside it was ever MEASURED by the bridge run
    or EARNED by a prior accepting artifact. Resolving ``source_root`` against the published object
    is what turns "this document says the parent scored X" into "the bridge/prior accept published
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
    """The artifact and the signed deterministic receipt disagree."""


class VerdictMismatchError(BindingMismatchError):
    """The bound verdict is not the receipt's deterministic decision."""


class RenderedCostMismatchError(BindingMismatchError):
    """A bound consumer-visible rendered cost is not the receipt's measured value."""


class ResourceAccountingError(BindingMismatchError):
    """Utility/resource ppm do not recompute from the receipt under the pinned counter law."""


class TransitionHashMismatchError(BindingMismatchError):
    """The on-chain keccak transition hash or the off-chain sha256 transition id is wrong."""


class RigReceiptFieldsMissingError(EvalArtifactError):
    """An artifact about to be bound to a RIG receipt carries no ``rig_receipt`` block.

    Deliberately NOT a :class:`BindingMismatchError`: nothing mismatched. The artifact simply
    cannot supply nine of the twenty-five fields the coordinator is about to sign, so signing
    would mean inventing them — and an invented receipt field is one no validator can reproduce
    from the evidence ``evalReportHash`` addresses.
    """


class RigReceiptFieldError(BindingMismatchError):
    """The ``rig_receipt`` block is present but not signable as it stands."""


class ReceiptUnavailableError(EvalArtifactError):
    """Verification needs the signed receipt and was given neither the object nor a store."""


class CounterResourceLawError(EvalArtifactError):
    """The counter-resource law document is malformed or unavailable."""


class CanaryConsensusError(EvalArtifactError):
    """A canary block claims consensus authority (``consensus_critical: true``, or
    ``external_model_attestation: false``). This is a violation of the deterministic law itself,
    not a canary outcome, so it is RAISED — the artifact is refused."""


class CanaryInfluenceError(EvalArtifactError):
    """Defensive: the deterministic verdict differed with and without the canary block. Must be
    unreachable; if it ever fires, the separation has been broken."""


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
    """Project a report incumbent into the closed historical or exact identity.

    The release and module roots are atomic. A partial or open identity is refused rather than
    being projected into the weaker historical statement.
    """
    if not isinstance(incumbent, dict):
        raise ReceiptBindingError("receipt incumbent must be an object")
    fields = frozenset(incumbent)
    historical_fields = frozenset(INCUMBENT_FIELDS)
    exact_fields = frozenset(INCUMBENT_EXACT_FIELDS)
    if fields not in (historical_fields, exact_fields):
        raise ReceiptBindingError(
            "receipt incumbent must be exactly the historical three-field identity or the "
            "exact five-field release/module identity")
    _check_str(incumbent["id"], "receipt incumbent.id")
    _check_str(incumbent["exec"], "receipt incumbent.exec")
    candidate_hash = incumbent.get("candidate_hash") or fr.ZERO_ROOT
    fr.check_root(candidate_hash, "receipt incumbent.candidate_hash")
    projected = {
        "candidate_hash": candidate_hash,
        "exec": incumbent["exec"],
        "id": incumbent["id"],
    }
    if fields == exact_fields:
        fr.check_root(incumbent["release_root"], "receipt incumbent.release_root")
        fr.check_root(incumbent["module_sha256"], "receipt incumbent.module_sha256")
        projected.update({
            "module_sha256": incumbent["module_sha256"],
            "release_root": incumbent["release_root"],
        })
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
    """SHA-256 identity of a canonical deterministic Benchmark-v2 report."""
    return receipt_body_hash(report)


def receipt_body_hash(body: Mapping[str, Any]) -> str:
    """``sha256`` over the Benchmark-v2 canonical bytes of a receipt body.

    Byte-identical to ``benchmark-v2/frontier/_canon.py::hash_obj``, which is what
    ``signing.signed_wrapper`` puts in ``receipt_hash``. Reproduced here (rather than imported)
    so the V5 lane stays stdlib-only and importable without ``benchmark-v2`` on the path;
    ``tests/test_eval_artifact.py`` asserts byte-identity against the real module by file path.
    """
    return fr.sha256_hex(pub.benchmark_canonical_bytes(body))


def canary_transcript_root(sealed: Mapping[str, Any]) -> str:
    """``sha256`` over the canonical bytes of a sealed canary transcript.

    Identical rule to ``benchmark-v2/canary/policy.py::seal`` (``json.dumps(sort_keys=True,
    separators=(",",":"))``; ``ensure_ascii`` defaults to True), so this reproduces
    ``transcript_root`` exactly without importing the canary package or touching a provider.
    """
    return fr.sha256_hex(pub.benchmark_canonical_bytes(sealed))


def canary_policy_hash(policy: Mapping[str, Any]) -> str:
    """``sha256`` over the canonical bytes of a canary policy dict — ``CanaryPolicy.policy_hash``."""
    return fr.sha256_hex(pub.benchmark_canonical_bytes(policy))


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
# Entropy expansion (spec §7)
# --------------------------------------------------------------------------- #
def derive_entropy_value(*, revealed_secret: str, epoch: int, parent_frontier_root: str,
                         label: str) -> str:
    """The Benchmark-v2 selection entropy for ``label``, from the CHAIN-COMMITTED epoch secret.

        sha256( ENTROPY_DOMAIN | label | secret | epoch | parent_frontier_root )

    Binding the epoch and the parent root means a selection derived for one state cannot be
    replayed against another, and binding the label gives the gate and confirmation walks two
    independent values from one commitment (the LAW §5.3 HIGH-1 requirement that no single
    input co-steers both).
    """
    fr.check_root(revealed_secret, "revealed_secret")
    fr.check_root(parent_frontier_root, "parent_frontier_root")
    fr.check_epoch(epoch)
    if label not in SELECTION_LABELS:
        raise ArtifactValueError(f"entropy label must be one of {SELECTION_LABELS}, got "
                                 f"{label!r}")
    return hashlib.sha256("|".join(
        (ENTROPY_DOMAIN, label, revealed_secret, str(epoch),
         parent_frontier_root)).encode("utf-8")).hexdigest()


def entropy_commitment_of(revealed_secret: str) -> str:
    """``keccak256(abi.encodePacked(bytes32 secret))`` — the on-chain ``epochCommit`` opening."""
    fr.check_root(revealed_secret, "revealed_secret")
    return keccak256_hex(bytes.fromhex(revealed_secret))


# --------------------------------------------------------------------------- #
# Transition hashes (spec §6)
# --------------------------------------------------------------------------- #
def transition_hash_keccak256(transition_bytes: bytes) -> str:
    """The ON-CHAIN receipt field ``transitionHash``.

    ``keccak256(abi.encodePacked(TRANSITION_HASH_DOMAIN_LABEL, transitionBytes))``. This is NOT
    the V5-A transition id (``sha256`` over the same bytes): different algorithm, different
    preimage, different purpose. Never substitute one for the other.
    """
    if not isinstance(transition_bytes, (bytes, bytearray)):
        raise ArtifactTypeError(
            f"transition_bytes must be bytes, got {type(transition_bytes).__name__}")
    data = bytes(transition_bytes)
    if len(data) > fr.MAX_TRANSITION_BYTES:
        raise fr.TransitionSizeError(
            f"transitionBytes is {len(data)} bytes, over the {fr.MAX_TRANSITION_BYTES}-byte "
            "bound the V5-A decoder and BOTH V5-B contracts enforce")
    return keccak256_hex(TRANSITION_HASH_DOMAIN_LABEL + data)


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
    _check_int(law["resource_ppm_max"], "resource_ppm_max", minimum=1, maximum=MAX_UINT32)
    _check_int(law["utility_ppm_max"], "utility_ppm_max", minimum=1, maximum=MAX_UINT32)
    util = _check_closed(law["utility_axis"], ("scale_max", "source"), "utility_axis")
    _check_str(util["source"], "utility_axis.source")
    if util["source"] != "composite":
        raise CounterResourceLawError(
            "utility_axis.source must be 'composite'; candidate-reported compute/latency is "
            "diagnostic and cannot become admission authority")
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
        if axis["source"] in NON_AUTHORITATIVE_ADMISSION_SOURCES:
            raise CounterResourceLawError(
                f"resource axis source {axis['source']!r} is candidate-side diagnostic data, "
                "not an admission authority")
        _check_str(axis["unit"], f"resource_axes[{i}].unit")
        _check_bool(axis["integer_axis"], f"resource_axes[{i}].integer_axis")
        total += _check_int(axis["weight_ppm"], f"resource_axes[{i}].weight_ppm",
                            minimum=0, maximum=MICRO)
        if axis["id"] in seen:
            raise CounterResourceLawError(f"duplicate resource axis id {axis['id']!r}")
        seen.add(axis["id"])
    if total != MICRO:
        raise CounterResourceLawError(
            f"resource axis weights sum to {total} ppm, not {MICRO}; the incumbent side must "
            "evaluate to EXACTLY 1_000_000 ppm by construction (it is the unit of comparison)")
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


def evaluate_counter_resource_law(law: Mapping[str, Any], candidate: Mapping[str, Any],
                                  incumbent: Mapping[str, Any]) -> Dict[str, int]:
    """Recompute ``{utility_before_ppm, utility_after_ppm, resource_before_ppm,
    resource_after_ppm}`` from two measured sides. EXACT integer arithmetic throughout.

    utility:  ``utility_ppm = composite_micro // scale_max`` — a composite of ``scale_max``
              is exactly 1_000_000 ppm and 0 is exactly 0.
    resource: ``resource_ppm = SUM_axes ( weight_ppm * side_micro[axis] ) // incumbent_micro[axis]``
              — a per-axis floor, weights summing to 1_000_000, so the incumbent side evaluates
              to EXACTLY 1_000_000 by construction and the candidate's value reads directly as
              "parts per million of the incumbent's metered cost".

    §17.236 records these ppm values on-chain but does NOT rank them there; the Pareto/resource
    trade-off stays off-chain under this pinned law, bound through ``evalReportHash`` +
    ``counterResourceLawRoot``. This function is that law, executable, and it needs nothing but
    the artifact — no coordinator-private state.
    """
    validate_counter_resource_law(law)
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
            base = _axis_micro(incumbent, axis, "incumbent")
            if base <= 0:
                raise CounterResourceLawError(
                    f"incumbent resource axis {axis['id']!r} is {base}; a zero baseline has no "
                    "ratio and is refused rather than treated as free")
            total += (axis["weight_ppm"] * _axis_micro(side, axis, name)) // base
        out[name] = total
    for key, value in out.items():
        limit = law["utility_ppm_max"] if key.startswith("utility") else law["resource_ppm_max"]
        if value > limit:
            raise ResourceAccountingError(
                f"{key}={value} exceeds the pinned ceiling {limit}; refused rather than clamped "
                "(a silently clamped ppm would misreport the trade-off on-chain)")
    return out


# --------------------------------------------------------------------------- #
# Measurement projection (spec §8.1)
# --------------------------------------------------------------------------- #
def project_side(side: Mapping[str, Any], where: str, *, logical_storage: bool = False,
                 bind_logical_axis: bool = False) -> Dict[str, Any]:
    """The EXACT micro-integer projection of one Benchmark-v2 measured side.

    ``hook_fuel`` / ``hook_compute_fuel`` are surfaced only when non-zero in a receipt (a
    reference/oracle arm has neither), so the projection normalizes an absent axis to ``0`` — the
    artifact schema is closed, and "absent" must not become a second way to say zero.

    ``bind_logical_axis`` projects ``logical_durable_storage_bytes`` as its OWN measured field,
    alongside the stable ``storage_bytes`` slot. The two are DIFFERENT AXES and this policy
    measures both (``scoring/measurement_policy.py``: ``storage_bytes`` is the "HISTORICAL-LAW
    alias for input corpus bytes", ``logical_durable_storage_bytes`` is "the prospective WP-C
    axis" — candidate-affectable durable state under ``logical-durable-storage.cbor.v1``). The
    fixed-suite law PROTECTS the logical one: it is a dominance vector component, a floor
    component and a determinism-witness component. Projecting it makes the decided value and the
    measured value the same number instead of two numbers nobody compared — see
    :func:`assert_decided_vectors_are_measured`.
    """
    if not isinstance(side, dict):
        raise ArtifactTypeError(f"{where} must be an object, got {type(side).__name__}")
    for key in ("composite", "rendered_cost", "latency_ms", "compute_ms", "storage_bytes",
                "corpus_supported", "objectives", "resource"):
        if key not in side:
            raise ReceiptBindingError(f"{where} carries no {key!r}")
    resource = side["resource"]
    if not isinstance(resource, dict):
        raise ArtifactTypeError(f"{where}.resource must be an object")
    objectives = side["objectives"]
    if not isinstance(objectives, dict) or not objectives:
        raise ArtifactTypeError(f"{where}.objectives must be a non-empty object")
    storage_key = "logical_durable_storage_bytes" if logical_storage else "storage_bytes"
    storage = _check_int(resource.get(storage_key), f"{where}.resource.{storage_key}")
    if _check_int(side.get(storage_key), f"{where}.{storage_key}") != storage:
        raise ReceiptBindingError(
            f"{where}: {storage_key} disagrees between the Pareto slot and the resource block")
    logical: Optional[int] = None
    if bind_logical_axis:
        logical = _check_int(resource.get("logical_durable_storage_bytes"),
                             f"{where}.resource.logical_durable_storage_bytes")
        if _check_int(side.get("logical_durable_storage_bytes"),
                      f"{where}.logical_durable_storage_bytes") != logical:
            raise ReceiptBindingError(
                f"{where}: logical_durable_storage_bytes disagrees between the Pareto slot and "
                "the resource block")
    projected = {
        "composite_micro": to_micro(side["composite"], f"{where}.composite"),
        "compute_micro": to_micro(side["compute_ms"], f"{where}.compute_ms"),
        "corpus_supported": _check_int(side["corpus_supported"], f"{where}.corpus_supported"),
        "events_scanned": _check_int(resource["events_scanned"],
                                     f"{where}.resource.events_scanned"),
        "hook_compute_fuel": _check_int(resource.get("hook_compute_fuel", 0),
                                        f"{where}.resource.hook_compute_fuel"),
        "hook_fuel": _check_int(resource.get("hook_fuel", 0), f"{where}.resource.hook_fuel"),
        "host_profile": _check_str(resource["host_profile"], f"{where}.resource.host_profile"),
        "latency_micro": to_micro(side["latency_ms"], f"{where}.latency_ms"),
        "objectives_micro": {name: to_micro(objectives[name], f"{where}.objectives[{name!r}]")
                             for name in sorted(objectives)},
        "rendered_cost_micro": to_micro(side["rendered_cost"], f"{where}.rendered_cost"),
        "storage_bytes": storage,
        "store_events": _check_int(resource["store_events"], f"{where}.resource.store_events"),
        "store_ops": _check_int(resource["store_ops"], f"{where}.resource.store_ops"),
        "work_fuel": _check_int(resource["work_fuel"], f"{where}.resource.work_fuel"),
    }
    if logical is not None:
        projected["logical_durable_storage_bytes"] = logical
    return projected


def candidate_module_bytes(receipt_body: Mapping[str, Any]) -> int:
    """The submitted miner module's UTF-8 length — NON-CONSENSUS TELEMETRY (LAW §3A.7).

    Zero for a reference/oracle arm, which submits no module. It re-derives from the report body's
    own bound module source, so a verifier recomputes it rather than believing it — but NOTHING
    compares it to anything: it is not a vector component, not a protected axis, not a floor
    component and not a counter-law term. Metering module bytes into a protected axis would be
    unsatisfiable (every real module dwarfs the ~1 KB constructor-genesis wrapper that sets the
    floor), so the law reports the footprint and lets a reviewer watch it grow.
    """
    candidate = receipt_body.get("candidate")
    module = candidate.get("module") if isinstance(candidate, Mapping) else None
    source = module.get("source") if isinstance(module, Mapping) else None
    if source is None:
        return 0
    if isinstance(source, bytes):
        return len(source)
    if isinstance(source, str):
        return len(source.encode("utf-8"))
    raise ReceiptBindingError(
        f"candidate.module.source must be text or bytes, got {type(source).__name__}")


def projects_logical_storage_axis(receipt_body: Mapping[str, Any]) -> bool:
    """Does this report's bound law protect ``logical_durable_storage_bytes`` as a vector axis?

    Read off the report's own bound law id, NOT off the measurement policy: the policy measures
    both storage axes and always did (it names them separately, and every fixed-suite side carries both),
    while it is the LAW that says which one is a protected dominance component. The fixed-suite
    law's fixed identities have declared ``storage_axis: logical_durable_storage_bytes`` since the
    v4 cut; this predicate is what makes the projection agree with that declaration instead of
    quietly projecting the other axis.

    Walk-era bodies answer False and project exactly the block they always did, so every frozen
    v1/v2 artifact still reprojects byte-identically.
    """
    descriptor = receipt_body.get("evaluation_law")
    law_id = descriptor.get("law_id") if isinstance(descriptor, Mapping) else None
    return law_id == FIXED_SUITE_LAW_ID


def project_measurements(receipt_body: Mapping[str, Any]) -> Dict[str, Any]:
    """The artifact's ``measurements`` block, projected from a signed receipt body."""
    policy = _check_str(receipt_body.get("measurement_policy"), "measurement_policy")
    # The artifact's stable ``storage_bytes`` slot is the storage axis selected by the receipt's
    # versioned law. Historical receipts retain their input-byte meaning. The frozen CEF law binds
    # canonical logical durable storage, so silently falling back to input bytes is forbidden.
    logical_storage = policy == "final-render-metered.v2"
    # ...and under the fixed-suite law the logical axis is projected as its OWN field, so the
    # ``storage_bytes`` slot keeps its documented input-byte meaning and the protected axis stops
    # being decided-but-unmeasured.
    bind_logical_axis = projects_logical_storage_axis(receipt_body)
    scores = receipt_body.get("scores")
    if not isinstance(scores, dict):
        raise ReceiptBindingError("receipt body carries no scores object")
    branches = {}
    for branch in SELECTION_LABELS:
        if branch not in scores:
            raise ReceiptBindingError(f"receipt scores carry no {branch!r} branch")
        pair = scores[branch]
        if not isinstance(pair, dict) or set(pair) != {"candidate", "incumbent"}:
            raise ReceiptBindingError(
                f"receipt scores[{branch!r}] must be {{candidate, incumbent}}")
        branches[branch] = {
            "candidate": project_side(pair["candidate"], f"scores[{branch}].candidate",
                                      logical_storage=logical_storage,
                                      bind_logical_axis=bind_logical_axis),
            "incumbent": project_side(pair["incumbent"], f"scores[{branch}].incumbent",
                                      logical_storage=logical_storage,
                                      bind_logical_axis=bind_logical_axis),
        }
    return {"branches": branches, "micro_scale": MICRO, "policy": policy}


# --------------------------------------------------------------------------- #
# Selection re-derivation (spec §7.2)
# --------------------------------------------------------------------------- #
def selection_base(*, label: str, entropy_value: str, candidate_hash: str, season_root: str,
                   profile_id: str, round_id: str) -> bytes:
    """The Benchmark-v2 selection walk base, reproduced exactly (``validator/select.py``)."""
    if label not in SELECTION_LABELS:
        raise ArtifactValueError(f"label must be one of {SELECTION_LABELS}, got {label!r}")
    for name, value in (("entropy_value", entropy_value), ("candidate_hash", candidate_hash),
                        ("season_root", season_root)):
        fr.check_root(value, name)
    _check_str(profile_id, "profile_id")
    _check_str(round_id, "round_id")
    return hashlib.sha256("|".join(
        (SELECTION_DOMAIN, label, entropy_value, candidate_hash, season_root, profile_id,
         round_id)).encode("utf-8")).digest()


def derive_step(base: bytes, index: int, scales) -> Tuple[int, str]:
    """``(seed, scale)`` at step ``index`` of the walk — ``validator/select.py``, verbatim."""
    _check_int(index, "derivation_index")
    scales = list(scales)
    if not scales:
        raise ArtifactValueError("scales must be non-empty")
    h = hashlib.sha256(base + index.to_bytes(8, "big")).digest()
    seed = int.from_bytes(h[:8], "big") % (2 ** 31)
    scale = scales[int.from_bytes(h[8:12], "big") % len(scales)]
    return seed, scale


def instance_id(profile_id: str, seed: int, scale: str) -> str:
    """``validator/select.py::instance_id``."""
    return f"{profile_id}@{scale}#s{seed}"


def verify_selection_walk(selection: Mapping[str, Any], *, entropy: Mapping[str, Any],
                          candidate_hash: str) -> Dict[str, str]:
    """Re-derive the fresh selection FROM THE COMMITTED ENTROPY and refuse any divergence.

    What is proven here, offline, with nothing but the stdlib:

      * each label's walk base is the sha256 of the exact declared inputs (so the recorded
        ``base_sha256`` cannot have been chosen);
      * EVERY recorded case genuinely sits at its claimed index of that walk — its ``seed`` and
        ``scale`` are recomputed from ``base || index`` and must match;
      * indices strictly increase (the walk only ever moves forward);
      * gate and confirmation selections are disjoint, and the counts are the declared ones.

    What is NOT proven here, and is stated rather than hidden: that no index BETWEEN two recorded
    steps was wrongly skipped. A skip is legitimate only if the instance was burned or failed the
    G6b oracle-cleanliness screen, and that screen needs the generators + the frozen runtime. It
    is V5-E's replay step, not a pure function. A cherry-picked walk therefore fails at V5-E, and
    a FABRICATED walk — one whose cases never sat at those indices at all — fails right here.
    """
    labels = {}
    for label in SELECTION_LABELS:
        value = entropy["gate_value"] if label == "gate" else entropy["confirm_value"]
        base = selection_base(label=label, entropy_value=value, candidate_hash=candidate_hash,
                              season_root=selection["season_root"],
                              profile_id=selection["profile_id"],
                              round_id=selection["round_id"])
        recorded = selection["base_sha256"][label]
        computed = fr.sha256_hex(base)
        _require(recorded == computed, SelectionMismatchError,
                 f"selection base_sha256[{label!r}] is {recorded}, but the declared inputs "
                 f"derive {computed}")
        cases = selection["cases"][label]
        _require(len(cases) == selection["counts"][label], SelectionMismatchError,
                 f"selection {label!r} holds {len(cases)} cases, counts declare "
                 f"{selection['counts'][label]}")
        last = -1
        ids = []
        for case in cases:
            index = case["derivation_index"]
            _require(index > last, SelectionMismatchError,
                     f"selection {label!r} derivation indices are not strictly increasing "
                     f"({index} after {last}) — the walk only moves forward")
            last = index
            seed, scale = derive_step(base, index, selection["scales"])
            _require(case["seed"] == seed and case["scale"] == scale, SelectionMismatchError,
                     f"selection {label!r} step {index} derives seed={seed} scale={scale!r}, "
                     f"the artifact records seed={case['seed']} scale={case['scale']!r}")
            iid = instance_id(selection["profile_id"], seed, scale)
            _require(case["instance_id"] == iid, SelectionMismatchError,
                     f"selection {label!r} instance_id {case['instance_id']!r} != {iid!r}")
            _require(case["profile_id"] == selection["profile_id"], SelectionMismatchError,
                     f"selection {label!r} case profile {case['profile_id']!r} != the "
                     f"selection's {selection['profile_id']!r}")
            ids.append(iid)
        _require(len(set(ids)) == len(ids), SelectionMismatchError,
                 f"selection {label!r} repeats an instance id")
        labels[label] = ids
    overlap = set(labels["gate"]) & set(labels["confirm"])
    _require(not overlap, SelectionMismatchError,
             f"gate and confirmation selections are not disjoint: {sorted(overlap)}")
    return {label: fr.sha256_hex("|".join(ids).encode("utf-8"))
            for label, ids in labels.items()}


# --------------------------------------------------------------------------- #
# Structural validation (spec §5)
# --------------------------------------------------------------------------- #
def artifact_law(artifact: Any) -> str:
    """Return the authorization law bound by the artifact's own format."""
    try:
        return al.law_of_artifact(
            artifact, families=ARTIFACT_FAMILY_LAWS, what="eval artifact")
    except al.UnknownLawError as exc:
        raise ArtifactSchemaError(str(exc)) from exc


def _validate_measurements_block(artifact: Mapping[str, Any], *,
                                 fixed_suite_era: bool = False) -> Dict[str, Any]:
    side_fields = SIDE_FIELDS_V3 if fixed_suite_era else SIDE_FIELDS
    integer_fields = ("composite_micro", "compute_micro", "corpus_supported",
                      "events_scanned", "hook_compute_fuel", "hook_fuel", "latency_micro",
                      "rendered_cost_micro", "storage_bytes", "store_events", "store_ops",
                      "work_fuel") + (("logical_durable_storage_bytes",)
                                      if fixed_suite_era else ())
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


def _validate_receipt_block(artifact: Mapping[str, Any], *, signed_era: bool) -> Dict[str, Any]:
    if signed_era:
        rec = _check_closed(artifact["receipt"], RECEIPT_FIELDS_V1_SIGNED_ERA, "receipt")
        for field in ("outputs_hash", "receipt_hash", "wrapper_root"):
            fr.check_root(rec[field], f"receipt.{field}")
        _check_str(rec["signature_key_id"], "receipt.signature_key_id")
    else:
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


def _validate_replay_inputs_block(artifact: Mapping[str, Any], *,
                                  signed_era: bool,
                                  fixed_suite_era: bool = False) -> Dict[str, Any]:
    roots = artifact["receipt"]["code_roots"]
    replay = _check_closed(
        artifact["replay_inputs"],
        REPLAY_INPUT_FIELDS_V3 if fixed_suite_era else REPLAY_INPUT_FIELDS, "replay_inputs")
    if fixed_suite_era:
        _check_int(replay["candidate_module_bytes"], "replay_inputs.candidate_module_bytes",
                   minimum=0)
    fr.validate_manifest(replay["parent_manifest"])
    fr.check_root(replay["candidate_manifest_hash"], "replay_inputs.candidate_manifest_hash")
    fr.check_root(replay["candidate_declaration_id"], "replay_inputs.candidate_declaration_id")
    _check_str(replay["candidate_exec"], "replay_inputs.candidate_exec")
    incumbent_fields = set(replay["incumbent"]) if isinstance(replay["incumbent"], dict) else set()
    expected_incumbent_fields = (INCUMBENT_EXACT_FIELDS
                                 if incumbent_fields == set(INCUMBENT_EXACT_FIELDS)
                                 else INCUMBENT_FIELDS)
    inc = _check_closed(replay["incumbent"], expected_incumbent_fields,
                        "replay_inputs.incumbent")
    _check_str(inc["id"], "replay_inputs.incumbent.id")
    _check_str(inc["exec"], "replay_inputs.incumbent.exec")
    fr.check_root(inc["candidate_hash"], "replay_inputs.incumbent.candidate_hash")
    if expected_incumbent_fields == INCUMBENT_EXACT_FIELDS:
        fr.check_root(inc["release_root"], "replay_inputs.incumbent.release_root")
        fr.check_root(inc["module_sha256"], "replay_inputs.incumbent.module_sha256")
    elif replay["candidate_exec"] == "candidate_module" and not signed_era \
            and not parent_exec.is_pre_exact_parent_code_roots(roots):
        raise ArtifactSchemaError(
            "a prospective candidate-module artifact under this code-root set requires the "
            "exact five-field incumbent release/module identity")
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


def _validate_vector(vector: Any, where: str, profile_id: Optional[str] = None) -> Dict[str, Any]:
    """One ABSOLUTE VECTOR (LAW §3A.2), closed and exact-integer.

    ``profile_id`` binds the vector to the profile's FULL declared objective set, exactly as
    ``benchmark-v2/validator/canonical_suite.validate_vector`` does on the law side. A MISSING
    objective is a MALFORMED VECTOR, never an unprotected one: dropping a key from both compared
    vectors is precisely how a componentwise recomputation can be made to see no regression, so
    the vocabulary is checked before anything is compared. An extra key is a vector for a
    different profile. It is optional only so the walk-era callers that have no profile in hand
    keep their historical shape check unchanged.
    """
    vec = _check_closed(vector, VECTOR_FIELDS, where)
    for field in ("composite_micro", "logical_durable_storage_bytes", "rendered_cost_micro",
                  "work_fuel"):
        _check_int(vec[field], f"{where}.{field}")
    objectives = vec["objectives_micro"]
    if not isinstance(objectives, dict) or not objectives:
        raise ArtifactTypeError(f"{where}.objectives_micro must be a non-empty object")
    for name, value in objectives.items():
        _check_str(name, f"{where}.objectives_micro key")
        _check_int(value, f"{where}.objectives_micro[{name!r}]")
    if profile_id is not None:
        declared = sorted(declared_objectives(profile_id))
        if sorted(objectives) != declared:
            raise ArtifactSchemaError(
                f"{where}.objectives_micro covers {sorted(objectives)}; the law protects "
                f"{declared} for {profile_id!r}. A missing objective is a MALFORMED vector, not "
                "an unprotected one")
    return vec


def _validate_fixed_suite_blocks(artifact: Mapping[str, Any]) -> None:
    """The four blocks that exist only in the v3 (fixed-suite) era."""
    profile_id = artifact["candidate"]["target_profile"]

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

    witness = _check_closed(artifact["determinism_witness"], DETERMINISM_WITNESS_FIELDS,
                            "determinism_witness")
    if witness["law_id"] != FIXED_SUITE_LAW_ID:
        raise ArtifactSchemaError(
            "determinism_witness.law_id is not the fixed-suite law; a vector measured under "
            "another law is not comparable and is never carried across (LAW §3A.6)")
    if witness["suite_root"] != suite["suite_root"]:
        raise ArtifactSchemaError(
            "determinism_witness.suite_root != suite.suite_root; a stored vector measured on a "
            "different exam is not this parent's vector")
    if witness["profile_id"] != profile_id:
        raise ArtifactSchemaError("determinism_witness.profile_id != the target profile")
    if witness["source_kind"] not in WITNESS_SOURCE_KINDS:
        raise ArtifactValueError(
            f"determinism_witness.source_kind must be one of {list(WITNESS_SOURCE_KINDS)}")
    for field in ("release_root", "source_root", "witness_root"):
        fr.check_root(witness[field], f"determinism_witness.{field}")
    _check_closed(witness["partitions"], SELECTION_LABELS, "determinism_witness.partitions")
    for label in SELECTION_LABELS:
        _validate_vector(witness["partitions"][label],
                         f"determinism_witness.partitions[{label!r}]", profile_id)
    recomputed = witness_root(witness)
    if recomputed != witness["witness_root"]:
        raise ArtifactSchemaError(
            f"determinism_witness.witness_root {witness['witness_root']} is not the sha256 of "
            f"its own canonical body {recomputed}")

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
        part = _check_closed(dom["partitions"][label], DOMINANCE_PARTITION_FIELDS, where)
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
        # vector STORED for that exact release by its qualifying bridge or prior accept. Their
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


class WorldSeedMismatchError(BindingMismatchError):
    """The signed ``worldSeed`` is not the epoch secret's gate expansion."""


def derive_world_seed(*, revealed_secret: str, epoch: int, parent_frontier_root: str) -> int:
    """The signed ``worldSeed``, from the CHAIN-COMMITTED epoch secret. One rule, both eras.

    ``worldSeed`` is the low 16 bytes of the gate entropy expansion
    ``sha256(ENTROPY_DOMAIN|"gate"|secret|epoch|parent_frontier_root)``. It is stated once, here,
    for the same reason the evaluator states it once: a consensus field with the truncation rule
    written down twice is a drift surface.
    """
    gate = derive_entropy_value(revealed_secret=revealed_secret, epoch=epoch,
                                parent_frontier_root=parent_frontier_root, label="gate")
    return int(gate[-32:], 16)


def verify_world_seed(artifact: Mapping[str, Any], *, revealed_secret: str) -> Dict[str, Any]:
    """Recompute the rig receipt's ``world_seed`` from the revealed secret and REFUSE a mismatch.

    WHY THIS IS A SEPARATE, ERA-AWARE STEP. Under the walk law the evaluator derived ``world_seed``
    itself, from an opening it held, and the artifact carried the same expansion in its own entropy
    block — so a validator that checked the entropy block had checked the seed by implication.
    Under the fixed suite the exam is entropy-free and the evaluator is HANDED the derived gate
    value by the coordinator (the raw opening never travels). That is the right design for the
    secret, and it leaves exactly one gap: a v3 artifact carries no entropy block, so nothing else
    in the verification chain ties the signed ``worldSeed`` to the chain-committed secret. Without
    this check the coordinator would be TRUSTED on a consensus field, which is the split-authority
    shape the v4 cut exists to close.

    It is applied to BOTH eras, because the formula is the same one and a walk-era artifact whose
    seed disagrees with its own entropy is no more acceptable than a v3 one that disagrees with the
    chain.

    Before ``EpochSecretRevealed`` lands the value is UNVERIFIABLE, and the caller is told so —
    :func:`replay.replay_advance` reports it UNRESOLVED rather than assuming it good.
    """
    block = artifact.get("rig_receipt")
    if not isinstance(block, dict):
        return {"checked": False, "reason": "the artifact binds no rig receipt"}
    expected = derive_world_seed(
        revealed_secret=fr.check_root(revealed_secret, "revealed_secret"),
        epoch=artifact["epoch"],
        parent_frontier_root=artifact["frontier"]["parent_frontier_root"])
    bound = block["world_seed"]
    if bound != expected:
        raise WorldSeedMismatchError(
            f"the rig receipt signs world_seed {bound}, but the chain-revealed epoch secret "
            f"expands under {ENTROPY_DOMAIN}|gate to {expected}. The signed seed must be a "
            "function of the committed secret and of nothing anyone chooses")
    return {"checked": True, "world_seed": expected}


def validate_artifact(artifact: Any) -> Dict[str, Any]:
    """Fail-closed structural validation. Returns the artifact unchanged; never a copy.

    LAW-DISPATCHED where the eras differ. The walk era (v1/v2) and the fixed-suite era (v3) share
    every block that describes a MEASUREMENT, a receipt binding or a verdict — those did not change
    at the v4 cut — and differ in how the cases were chosen and what the decision compared. So the
    shared blocks are validated by one implementation for both, and only the era-specific blocks
    branch.
    """
    law = artifact_law(artifact)
    signed_era = law == al.LAW_OFF_CHAIN_SIGNATURE_V1
    fixed_suite_era = isinstance(artifact, dict) and artifact.get("format") == ARTIFACT_FORMAT_V3
    family = (ARTIFACT_FORMAT_V1_SIGNED_ERA if signed_era else
              ARTIFACT_FORMAT_V3 if fixed_suite_era else ARTIFACT_FORMAT)
    _check_closed(artifact, ARTIFACT_FIELDS_V3 if fixed_suite_era else ARTIFACT_FIELDS,
                  family, OPTIONAL_ARTIFACT_FIELDS)
    fr.check_epoch(artifact["epoch"])
    fr.check_root(artifact["counter_resource_law_root"], "counter_resource_law_root")

    cand = _check_closed(artifact["candidate"], CANDIDATE_FIELDS, "candidate")
    fr.check_root(cand["candidate_hash"], "candidate.candidate_hash")
    fr.check_root(cand["release_root"], "candidate.release_root")
    fr.check_root(cand["prior_release_root"], "candidate.prior_release_root")
    fr.check_profile_id(cand["target_profile"], "candidate.target_profile")

    front = _check_closed(artifact["frontier"], FRONTIER_FIELDS, "frontier")
    for field in ("benchmark_law_root", "composition_root", "new_frontier_root",
                  "parent_frontier_root", "runtime_abi_root", "transition_hash_keccak256",
                  "transition_id_sha256"):
        fr.check_root(front[field], f"frontier.{field}")
    fr.validate_transition(front["transition"])
    _check_int(front["transition_bytes_len"], "frontier.transition_bytes_len", minimum=1,
               maximum=fr.MAX_TRANSITION_BYTES)

    if fixed_suite_era:
        _validate_fixed_suite_blocks(artifact)
        _validate_measurements_block(artifact, fixed_suite_era=True)
        _validate_receipt_block(artifact, signed_era=False)
        _validate_replay_inputs_block(artifact, signed_era=False, fixed_suite_era=True)
        _validate_accounting_and_verdict(artifact)
        pub.validate_availability(artifact["availability"])
        if "canary" in artifact:
            validate_canary_block(artifact["canary"])
        if "rig_receipt" in artifact:
            validate_rig_receipt_block(artifact["rig_receipt"])
        fr.canonical_bytes(artifact)     # fail closed before anyone addresses it
        return artifact

    ent = artifact["entropy"]
    if not isinstance(ent, dict):
        raise ArtifactTypeError("entropy must be an object")
    entropy_fields = set(ent)
    if entropy_fields not in (set(ENTROPY_SEALED_FIELDS), set(ENTROPY_OPEN_FIELDS)):
        missing = sorted(set(ENTROPY_SEALED_FIELDS) - entropy_fields)
        unknown = sorted(entropy_fields - set(ENTROPY_OPEN_FIELDS))
        partial = sorted(entropy_fields & {"confirm_value", "gate_value", "revealed_secret"})
        raise ArtifactSchemaError(
            "entropy must be either the closed sealed shape or the complete historical open "
            f"shape (missing={missing}, unknown={unknown}, partial_opening={partial})")
    fr.check_root(ent["commitment"], "entropy.commitment")
    if entropy_fields == set(ENTROPY_OPEN_FIELDS):
        for field in ("confirm_value", "gate_value", "revealed_secret"):
            fr.check_root(ent[field], f"entropy.{field}")
    _check_str(ent["commitment_scheme"], "entropy.commitment_scheme")
    _check_str(ent["derivation_domain"], "entropy.derivation_domain")

    sel = _check_closed(artifact["selection"], SELECTION_FIELDS, "selection")
    _check_str(sel["domain"], "selection.domain")
    _check_str(sel["round_id"], "selection.round_id")
    fr.check_root(sel["season_root"], "selection.season_root")
    fr.check_profile_id(sel["profile_id"], "selection.profile_id")
    scales = sel["scales"]
    if not isinstance(scales, list) or not scales or \
            not all(isinstance(s, str) and s for s in scales):
        raise ArtifactTypeError("selection.scales must be a non-empty array of strings")
    burned = _check_closed(sel["burned_head"], ("record_hash", "records"), "selection.burned_head")
    fr.check_root(burned["record_hash"], "selection.burned_head.record_hash")
    _check_int(burned["records"], "selection.burned_head.records")
    if not signed_era and burned != {"record_hash": "0" * 64, "records": 0}:
        raise ArtifactValueError(
            "prospective evaluation disables cross-attempt burn state; burned_head remains only "
            "as a frozen compatibility field and must be its canonical zero value")
    _check_closed(sel["counts"], SELECTION_LABELS, "selection.counts")
    _check_closed(sel["base_sha256"], SELECTION_LABELS, "selection.base_sha256")
    _check_closed(sel["cases"], SELECTION_LABELS, "selection.cases")
    for label in SELECTION_LABELS:
        _check_int(sel["counts"][label], f"selection.counts[{label!r}]", minimum=1)
        fr.check_root(sel["base_sha256"][label], f"selection.base_sha256[{label!r}]")
        cases = sel["cases"][label]
        if not isinstance(cases, list) or not cases:
            raise ArtifactTypeError(f"selection.cases[{label!r}] must be a non-empty array")
        for i, case in enumerate(cases):
            where = f"selection.cases[{label!r}][{i}]"
            _check_closed(case, CASE_FIELDS, where)
            _check_int(case["derivation_index"], f"{where}.derivation_index")
            _check_int(case["seed"], f"{where}.seed", maximum=2 ** 31 - 1)
            _check_str(case["scale"], f"{where}.scale")
            _check_str(case["instance_id"], f"{where}.instance_id")
            fr.check_profile_id(case["profile_id"], f"{where}.profile_id")
            fr.check_root(case["instance_hash"], f"{where}.instance_hash")

    _validate_measurements_block(artifact)
    _validate_receipt_block(artifact, signed_era=signed_era)
    _validate_replay_inputs_block(artifact, signed_era=signed_era)
    _validate_accounting_and_verdict(artifact)

    pub.validate_availability(artifact["availability"])

    if "canary" in artifact:
        validate_canary_block(artifact["canary"])
    if "rig_receipt" in artifact:
        validate_rig_receipt_block(artifact["rig_receipt"])

    fr.canonical_bytes(artifact)     # fail closed before anyone addresses it
    return artifact


def validate_rig_receipt_block(block: Any) -> Dict[str, Any]:
    """Structural validation of the OPTIONAL ``rig_receipt`` block, at the SIGNED widths.

    Every field is range-checked at the width the on-chain struct declares, here, where the
    artifact is still addressable — not at calldata-encoding time, where an over-wide value is an
    ``AbiError`` on a document a validator has already accepted.

    Two semantic rules are enforced beyond the widths, from
    ``RIG-CORETEX-REGISTRY-DESIGN.md`` §5.1 and ``coretex.transition-descriptor/v3``:

      * ``outcome`` must be 1 or 2. 0 and >2 revert for every epoch, so an artifact may not claim
        one even as an intention.
      * ``transition_format_version`` is ZERO for a screener pass (outcome 1 advances no state, so
        it MUST carry an empty descriptor and zero scores — spec §6.2, stricter than the retired
        verifier's tolerance, see :mod:`.rig_events`' ``DESCRIPTOR_UNEXPECTED``) and exactly
        :data:`RIG_TRANSITION_FORMAT_VERSION_ADVANCE` (the descriptor's version byte,
        zero-extended) for a state advance. It is no longer a counter of anything the artifact
        chooses; it is the fixed value every real v2 advance signs.
    """
    rig = _check_closed(block, RIG_RECEIPT_FIELDS, "rig_receipt")
    for field in RIG_RECEIPT_ROOT_FIELDS:
        fr.check_root(rig[field], f"rig_receipt.{field}")
    outcome = _check_int(rig["outcome"], "rig_receipt.outcome", maximum=255)
    if outcome not in RIG_SIGNABLE_OUTCOMES:
        raise RigReceiptFieldError(
            f"rig_receipt.outcome={outcome} is not signable; the verifier prices only "
            f"{list(RIG_SIGNABLE_OUTCOMES)} and every other value reverts for every epoch")
    _check_int(rig["world_seed"], "rig_receipt.world_seed", maximum=MAX_UINT128)
    _check_int(rig["rules_version"], "rig_receipt.rules_version", maximum=MAX_UINT32)
    version = _check_int(rig["transition_format_version"],
                         "rig_receipt.transition_format_version", maximum=MAX_UINT16)
    if outcome == RIG_OUTCOME_SCREENER_PASS and version != 0:
        raise RigReceiptFieldError(
            f"rig_receipt.transition_format_version={version} but outcome={outcome} is a "
            "SCREENER PASS: outcome 1 advances no state, so it MUST sign "
            "transitionFormatVersion=0 alongside an empty descriptor")
    if outcome == RIG_OUTCOME_STATE_ADVANCE and version != RIG_TRANSITION_FORMAT_VERSION_ADVANCE:
        raise RigReceiptFieldError(
            f"rig_receipt.transition_format_version={version} is not "
            f"{RIG_TRANSITION_FORMAT_VERSION_ADVANCE} (0x"
            f"{RIG_TRANSITION_FORMAT_VERSION_ADVANCE:02x}) for a state advance; it must be the "
            "zero-extension of the descriptor's version byte, and the descriptor byte is the "
            "authority")
    return rig


def rig_receipt_fields(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The nine evaluator-supplied receipt fields, or :class:`RigReceiptFieldsMissingError`.

    The artifact is VALIDATED first, for the same reason :func:`eval_report_hash` validates: an
    invalid artifact has no fields anyone may sign.
    """
    validate_artifact(artifact)
    if "rig_receipt" not in artifact:
        raise RigReceiptFieldsMissingError(
            "this artifact carries no 'rig_receipt' block, so it cannot supply outcome, "
            f"{', '.join(f for f in RIG_RECEIPT_FIELDS if f != 'outcome')}. A rig receipt signs "
            "all nine; the coordinator does not invent them.")
    return validate_rig_receipt_block(artifact["rig_receipt"])


def rig_receipt_projection(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The nine fields in BOTH spellings, for the coordinator's worker-result decoder.

    ``coretex-memory-v5-worker-client.ts`` reads each rig field as
    ``pick(e, "<snake_case>", "<camelCase>")``. Emitting both means neither lane has to guess
    which the other chose, and a rename on either side fails loudly at the closed-field check
    rather than silently defaulting a signed field to zero.

    Roots are emitted BARE (no ``0x``), exactly as every other root in this artifact lane, because
    the TypeScript side re-prefixes with ``0x`` after ``bareRoot()`` strips whatever it was given.

    ``world_seed`` IS EMITTED AS A DECIMAL STRING, and that is not cosmetic. It is a ``uint128``,
    JSON numbers are IEEE-754 doubles, and a 39-digit integer comes back out of ``JSON.parse`` as
    ``2.725425328911468e+38`` — which ``BigInt()`` refuses outright. A real rehearsal died on
    exactly that: the evaluator PASSED and the coordinator then rejected its own result with
    "Cannot convert 2.725425328911468e+38 to a BigInt". The coordinator's own
    ``MemoryEvaluationResult`` already says of this field "carried as a bigint: it does not fit a
    JS number", and ``e2e/rig_receipt.as_dict`` renders every ``uint`` as a string for the same
    reason. The ARTIFACT keeps the integer — it is hashed, and a string there would change
    ``evalReportHash`` — so the conversion belongs here, in the projection that exists solely to
    cross the language boundary.
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


def validate_canary_block(canary: Any) -> Dict[str, Any]:
    """Structural validation of the OPTIONAL auxiliary canary block.

    The two separation flags are validated HERE, not in the canary verifier, so an artifact that
    claims consensus authority for an external model is refused before it is ever addressable.
    """
    _check_closed(canary, CANARY_FIELDS, CANARY_BLOCK_FORMAT)
    if canary["format"] != CANARY_BLOCK_FORMAT:
        raise ArtifactSchemaError(
            f"canary.format {canary['format']!r} is not {CANARY_BLOCK_FORMAT!r}")
    if _check_bool(canary["consensus_critical"], "canary.consensus_critical") is not False:
        raise CanaryConsensusError(
            "canary.consensus_critical MUST be false. §17.236: the external-model canary creates "
            "no promotion eligibility and MUST NOT silently deny a deterministically earned "
            "promotion — an artifact asserting otherwise is refused, not downgraded")
    if _check_bool(canary["external_model_attestation"],
                   "canary.external_model_attestation") is not True:
        raise CanaryConsensusError(
            "canary.external_model_attestation MUST be true: a hosted model is not a reproducible "
            "function, so the block is an ATTESTATION by the party that ran it — labelling it "
            "anything else would misrepresent what a validator can check")
    for field in ("candidate_hash", "entropy_hex", "incumbent_root", "policy_hash",
                  "selection_base_sha256", "transcript_root"):
        fr.check_root(canary[field], f"canary.{field}")
    _check_str(canary["epoch_id"], "canary.epoch_id")
    _check_str(canary["mode"], "canary.mode")
    _check_str(canary["verdict"], "canary.verdict")
    ident = canary["code_identity"]
    if not isinstance(ident, dict) or not ident:
        raise ArtifactTypeError("canary.code_identity must be a non-empty object")
    for key, value in ident.items():
        _check_str(key, "canary.code_identity key")
        _check_str(value, f"canary.code_identity[{key!r}]")
    return canary


# --------------------------------------------------------------------------- #
# The verdict is deterministic-only (spec §10)
# --------------------------------------------------------------------------- #
def strip_canary(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """A copy of ``artifact`` without the auxiliary canary block. Never mutates the argument."""
    return {k: v for k, v in artifact.items() if k != "canary"}


def deterministic_verdict(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The artifact's verdict, read from the DETERMINISTIC evidence only.

    NORMATIVE (spec §10): this function does not read ``artifact["canary"]``, and no other
    function derives a verdict. The presence, absence, content or FAILURE of a canary block
    therefore cannot change what this returns — which is the whole point of the separation.
    """
    validate_artifact(artifact)
    verdict = artifact["verdict"]
    return {"admit": verdict["admit"], "verdict": verdict["verdict"],
            "decision_hash": verdict["decision_hash"],
            "authority": "benchmark-v2 deterministic receipt decision",
            "consensus_critical": True}


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #
def build_artifact(*, epoch: int, parent_manifest: Mapping[str, Any],
                   transition: Mapping[str, Any], candidate_hash: str,
                   receipt_wrapper: Mapping[str, Any], revealed_entropy_secret: str,
                   counter_resource_law: Mapping[str, Any], availability: Mapping[str, Any],
                   counter_resource_law_root_hex: Optional[str] = None,
                   canary: Optional[Mapping[str, Any]] = None,
                   rig_receipt: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Assemble a complete, self-consistent eval artifact.

    Everything derivable is DERIVED (roots, hashes, the entropy expansion, the measurement
    projection, the ppm accounting), so a builder cannot state a binding that disagrees with the
    evidence it was given. The result is then run through :func:`validate_artifact`.

    ``rig_receipt`` carries the nine :data:`RIG_RECEIPT_FIELDS`. They are the ONLY inputs here
    that cannot be derived: ``challenge_id``, the epoch-context roots and the world/rules
    parameters are facts about the evaluation the evaluator was handed, and ``outcome`` /
    ``transition_format_version`` describe what its result DID. Deriving any of them from the
    artifact would mean inventing a signed field, so they are accepted and then RANGE-CHECKED at
    their on-chain widths by :func:`validate_rig_receipt_block`. Omitting the block leaves the
    artifact byte-identical to a pre-rig one.
    """
    fr.validate_manifest(parent_manifest)
    fr.validate_transition(transition)
    fr.check_root(candidate_hash, "candidate_hash")
    fr.check_root(revealed_entropy_secret, "revealed_entropy_secret")
    validate_counter_resource_law(counter_resource_law)

    parent_root = fr.frontier_root(parent_manifest)
    # `epoch` is the epoch the candidate is being evaluated FOR. It equals the parent's epoch for
    # an ordinary within-epoch advance, and EXCEEDS it for the first transition of a new epoch,
    # which lazily inherits the previous non-empty epoch's head (ruling §17.237). Passing it here
    # is what makes the artifact's `new_frontier_root` the root the chain will actually confirm.
    child = fr.apply_transition(parent_manifest, transition, epoch=epoch)
    new_root = fr.frontier_root(child)
    tbytes = fr.canonical_bytes(transition)

    body = _receipt_body(receipt_wrapper)
    target = transition["target_profile"]
    entropy = {
        "commitment": entropy_commitment_of(revealed_entropy_secret),
        "commitment_scheme": "keccak256(abi.encodePacked(bytes32 secret))",
        "confirm_value": derive_entropy_value(revealed_secret=revealed_entropy_secret,
                                              epoch=epoch, parent_frontier_root=parent_root,
                                              label="confirm"),
        "derivation_domain": ENTROPY_DOMAIN,
        "gate_value": derive_entropy_value(revealed_secret=revealed_entropy_secret, epoch=epoch,
                                           parent_frontier_root=parent_root, label="gate"),
        "revealed_secret": revealed_entropy_secret,
    }

    selection = {
        "base_sha256": {
            label: fr.sha256_hex(selection_base(
                label=label,
                entropy_value=entropy["gate_value"] if label == "gate"
                else entropy["confirm_value"],
                candidate_hash=candidate_hash, season_root=body["season_root"],
                profile_id=body["profile_id"], round_id=body["round_id"]))
            for label in SELECTION_LABELS},
        "burned_head": {"record_hash": body["burned_head"]["record_hash"],
                        "records": body["burned_head"]["records"]},
        "cases": {label: [{"derivation_index": c["derivation_index"],
                           "instance_hash": c["instance_hash"],
                           "instance_id": c["instance_id"],
                           "profile_id": c["profile_id"],
                           "scale": c["scale"],
                           "seed": c["seed"]}
                          for c in body["selection"][label]]
                  for label in SELECTION_LABELS},
        "counts": {label: len(body["selection"][label]) for label in SELECTION_LABELS},
        "domain": SELECTION_DOMAIN,
        "profile_id": body["profile_id"],
        "round_id": body["round_id"],
        "scales": list(body["scales"]),
        "season_root": body["season_root"],
    }

    measurements = project_measurements(body)
    branch = counter_resource_law["branch"]
    ppm = evaluate_counter_resource_law(counter_resource_law,
                                        measurements["branches"][branch]["candidate"],
                                        measurements["branches"][branch]["incumbent"])
    inc = body["incumbent"]
    artifact = {
        "availability": {name: dict(item) for name, item in availability.items()},
        "candidate": {
            "candidate_hash": candidate_hash,
            "prior_release_root": transition["expected_prior_release_root"],
            "release_root": transition["new_release_root"],
            "target_profile": target,
        },
        "counter_resource_law_root": (counter_resource_law_root_hex
                                      or counter_resource_law_root(counter_resource_law)),
        "entropy": entropy,
        "epoch": epoch,
        # This compatibility builder consumes a signed wrapper and therefore can only mint the
        # closed historical family. Prospective v2 artifacts are produced by the coordinator and
        # contain an addressed evaluation report instead.
        "format": ARTIFACT_FORMAT_V1_SIGNED_ERA,
        "frontier": {
            "benchmark_law_root": parent_manifest["benchmark_law_root"],
            "composition_root": transition["resulting_composition_root"],
            "new_frontier_root": new_root,
            "parent_frontier_root": parent_root,
            "runtime_abi_root": parent_manifest["runtime_abi_root"],
            "transition": dict(transition),
            "transition_bytes_len": len(tbytes),
            "transition_hash_keccak256": transition_hash_keccak256(tbytes),
            "transition_id_sha256": fr.transition_hash(transition),
        },
        "measurements": measurements,
        "receipt": {
            "code_roots": dict(body["code_roots"]),
            "measurement_policy": body["measurement_policy"],
            "outputs_hash": body["outputs_hash"],
            "receipt_hash": receipt_wrapper["receipt_hash"],
            "signature_key_id": receipt_wrapper["signature"]["key_id"],
            "wrapper_root": fr.sha256_hex(pub.benchmark_canonical_bytes(receipt_wrapper)),
        },
        "replay_inputs": {
            "candidate_declaration_id": body["candidate"]["declaration_id"],
            "candidate_exec": body["candidate"]["exec"],
            "candidate_manifest_hash": body["candidate"]["manifest_hash"],
            "incumbent": project_incumbent(inc),
            "parent_manifest": dict(parent_manifest),
        },
        "resource_accounting": dict(ppm, branch=branch),
        "selection": selection,
        "verdict": {
            "admit": bool(body["decision"]["admit"]),
            "consensus_critical": True,
            "decision_hash": fr.sha256_hex(pub.benchmark_canonical_bytes(body["decision"])),
            "verdict": body["decision"]["verdict"],
        },
    }
    if canary is not None:
        artifact["canary"] = dict(canary)
    if rig_receipt is not None:
        artifact["rig_receipt"] = dict(rig_receipt)
    return validate_artifact(artifact)


def build_canary_block(sealed: Mapping[str, Any]) -> Dict[str, Any]:
    """Project a sealed canary transcript into the artifact's auxiliary reference block.

    Only float-free REFERENCES travel into the artifact; the transcript itself (which carries the
    policy's float thresholds) is published under the benchmark hash rule and addressed by
    ``transcript_root``. §17.236 asked for the sealed transcript's bindings to be parsed and
    VERIFIED rather than imported as an opaque root — :func:`verify_canary_block` does exactly
    that against these referenced fields.
    """
    if not isinstance(sealed, dict):
        raise ArtifactTypeError(f"sealed transcript must be an object, got "
                                f"{type(sealed).__name__}")
    if sealed.get("format") != CANARY_TRANSCRIPT_FORMAT:
        raise ArtifactSchemaError(
            f"sealed transcript format {sealed.get('format')!r} is not "
            f"{CANARY_TRANSCRIPT_FORMAT!r}")
    block = {
        "candidate_hash": sealed["candidate_hash"],
        "code_identity": {k: v for k, v in sealed["code_identity"].items()},
        "consensus_critical": False,
        "entropy_hex": sealed["entropy"]["hex"],
        "epoch_id": str(sealed["epoch_id"]),
        "external_model_attestation": True,
        "format": CANARY_BLOCK_FORMAT,
        "incumbent_root": sealed["incumbent_root"],
        "mode": sealed["mode"],
        "policy_hash": sealed["policy_hash"],
        "selection_base_sha256": sealed["entropy"]["selection_base_sha256"],
        "transcript_root": canary_transcript_root(sealed),
        "verdict": str((sealed.get("verdict") or {}).get("verdict", "UNKNOWN")),
    }
    return validate_canary_block(block)


def _receipt_body(wrapper: Any) -> Dict[str, Any]:
    """The receipt body of a Benchmark-v2 signed wrapper, structurally checked."""
    if not isinstance(wrapper, dict) or wrapper.get("format") != RECEIPT_WRAPPER_FORMAT:
        raise ReceiptBindingError(
            f"receipt wrapper must be a {RECEIPT_WRAPPER_FORMAT!r} object")
    body = wrapper.get("receipt")
    if not isinstance(body, dict) or body.get("format") != RECEIPT_BODY_FORMAT:
        raise ReceiptBindingError(f"receipt body must be a {RECEIPT_BODY_FORMAT!r} object")
    sig = wrapper.get("signature")
    if not isinstance(sig, dict) or not isinstance(sig.get("key_id"), str):
        raise ReceiptBindingError("receipt wrapper carries no signature.key_id")
    claimed = wrapper.get("receipt_hash")
    computed = receipt_body_hash(body)
    if claimed != computed:
        raise ReceiptBindingError(
            f"receipt wrapper self-hash {claimed!r} != the canonical body hash {computed}")
    return body


def _eval_report(report: Any) -> Dict[str, Any]:
    """A prospective signature-free Benchmark-v2 report, structurally identified."""
    if not isinstance(report, dict) or report.get("format") != EVAL_REPORT_FORMAT:
        raise ReceiptBindingError(
            f"evaluation report must be a {EVAL_REPORT_FORMAT!r} object")
    return report


# --------------------------------------------------------------------------- #
# Verification (spec §11)
# --------------------------------------------------------------------------- #
def suite_block_for(profile_id: str, report_selection: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the artifact's ``suite`` block and PROVE the report's cases are the law's cases.

    The block is not copied from the evaluation report — it is built from the LAW DOCUMENT and then
    the report is checked against it. A builder that transcribed the report would only ever prove
    the report agrees with itself.
    """
    expected = cs.suite_cases(profile_id)
    hashes = cs.suite_case_hashes(profile_id)
    cases: Dict[str, Any] = {}
    for label in SELECTION_LABELS:
        bound = report_selection.get(label)
        want = expected[label]
        if not isinstance(bound, list) or len(bound) != len(want):
            raise SuiteMembershipError(
                f"the evaluation report's {label!r} selection holds "
                f"{len(bound) if isinstance(bound, list) else 'a non-list'} cases; the canonical "
                f"suite for {profile_id!r} declares {len(want)}")
        rows = []
        for index, (case, suite_case) in enumerate(zip(bound, want)):
            where = f"report selection[{label!r}][{index}]"
            for field in ("instance_id", "profile_id", "scale", "seed", "suite_index"):
                if case.get(field) != suite_case[field]:
                    raise SuiteMembershipError(
                        f"{where}.{field} is {case.get(field)!r}; the canonical suite declares "
                        f"{suite_case[field]!r}")
            measured = case.get("instance_hash")
            if measured != hashes[suite_case["instance_id"]]:
                raise SuiteMembershipError(
                    f"{where}.instance_hash {measured} is not the suite-bound instance hash "
                    f"{hashes[suite_case['instance_id']]} — the scored instance is not the case "
                    "the law names")
            rows.append(dict(suite_case, instance_hash=measured))
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
    """The law-bound constructor-genesis floor, as this decision resolved it."""
    try:
        partitions = {label: cs.genesis_floor_vector(profile_id, label)
                      for label in SELECTION_LABELS}
    except cs.GenesisFloorPendingError as exc:
        raise GenesisFloorPendingError(str(exc)) from exc
    authority = cs.genesis_floor_authority()
    source = authority.get("source")
    return {
        "partitions": partitions,
        "source": source if isinstance(source, str) else json.dumps(source, sort_keys=True),
        "status": "resolved",
        "suite_root": cs.suite_root(),
    }


def build_determinism_witness(*, profile_id: str, release_root: str, source_kind: str,
                              source_root: str, partitions: Mapping[str, Any]
                              ) -> Dict[str, Any]:
    """Assemble a self-addressing STORED PARENT VECTOR document.

    This is the object a v2 job carries for its exact parent, and the object a bridge run publishes
    for a pre-cut release. ``witness_root`` is sha256 over the rest of the body, so the coordinator
    transports a content address rather than a claim.
    """
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


def build_bridge_vector_document(*, profile_id: str, release_root: str,
                                 partitions: Mapping[str, Any],
                                 measured_by: Mapping[str, Any]) -> Dict[str, Any]:
    """The published BRIDGE measurement a ``source_kind == "bridge"`` witness resolves to.

    P5's one-time bridge run measures the constructor-genesis release and each profile's CURRENT
    pre-cut release on the sealed suite. Those vectors are the stored vectors of the first
    post-cut job for each slot, and until they are PUBLISHED under a content address, a witness
    carrying them is an unbacked claim: whoever assembles the job states the number.

    ``measured_by`` is free-form provenance (image tag/digest, run id, evidence root) — it is
    recorded, hashed into the root, and never interpreted by the decision.
    """
    body = {
        "format": BRIDGE_VECTOR_FORMAT,
        "law_id": FIXED_SUITE_LAW_ID,
        "measured_by": json.loads(json.dumps(measured_by, sort_keys=True)),
        "partitions": {label: dict(partitions[label]) for label in SELECTION_LABELS},
        "profile_id": profile_id,
        "release_root": release_root,
        "suite_root": cs.suite_root(),
    }
    return validate_bridge_vector_document(body)


def validate_bridge_vector_document(document: Any) -> Dict[str, Any]:
    """Fail-closed structural validation of a :data:`BRIDGE_VECTOR_FORMAT` document."""
    doc = _check_closed(document, BRIDGE_VECTOR_FIELDS, BRIDGE_VECTOR_FORMAT)
    if doc["format"] != BRIDGE_VECTOR_FORMAT:
        raise ArtifactSchemaError(
            f"format {doc['format']!r} is not {BRIDGE_VECTOR_FORMAT!r}")
    if doc["law_id"] != FIXED_SUITE_LAW_ID:
        raise ArtifactSchemaError(
            "a bridge vector document records a measurement under the fixed-suite law and no "
            "other; a vector measured under another law is never carried across (LAW §3A.6)")
    fr.check_profile_id(doc["profile_id"], "profile_id")
    for field in ("release_root", "suite_root"):
        fr.check_root(doc[field], field)
    if not isinstance(doc["measured_by"], (dict, str)) or not doc["measured_by"]:
        raise ArtifactSchemaError(
            "a bridge vector document must name the measurement it came from")
    _check_closed(doc["partitions"], SELECTION_LABELS, "partitions")
    for label in SELECTION_LABELS:
        _validate_vector(doc["partitions"][label], f"partitions[{label!r}]", doc["profile_id"])
    return doc


def bridge_vector_root(document: Mapping[str, Any]) -> str:
    """``sha256`` over the bridge document's V5-A canonical bytes — its publication address."""
    return fr.sha256_hex(fr.canonical_bytes(validate_bridge_vector_document(document)))


def resolve_determinism_witness_source(artifact: Mapping[str, Any], *,
                                       store: pub.ContentStore) -> Dict[str, Any]:
    """Resolve ``determinism_witness.source_root`` against the PUBLIC object it names.

    ``verify_artifact`` proves the witness is whole and that the parent arm re-executed in THIS job
    reproduced it. Neither answers "where did that stored vector come from" — for that the named
    object has to be fetched and made to carry the same vector:

    ``source_kind == "bridge"``
        ``source_root`` addresses a :data:`BRIDGE_VECTOR_FORMAT` document (P5 publishes one per
        profile). Its law, suite, profile, release and both partition vectors must equal the
        witness's.

    ``source_kind == "prior_accept"``
        ``source_root`` is the ``evalReportHash`` of the ACCEPTING v3 artifact that installed this
        release. Its CANDIDATE vector is by construction the vector that release stores, so that
        is what must equal the witness's partitions — and the artifact must actually have admitted.

    Raises :class:`WitnessSourceUnavailableError` when the object is not published here and
    :class:`WitnessSourceMismatchError` when it is published and disagrees. The two are different
    outcomes and are never conflated.
    """
    witness = artifact["determinism_witness"]
    kind = witness["source_kind"]
    root = witness["source_root"]
    try:
        obj = pub.fetch_json(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        raise WitnessSourceUnavailableError(
            f"determinism_witness.source_root {root} ({kind}) is not published on this "
            f"surface: {exc}") from exc
    except pub.PublicationError as exc:
        raise WitnessSourceMismatchError(
            f"determinism_witness.source_root {root} does not fetch as a canonical object: "
            f"{exc}") from exc

    if kind == "bridge":
        try:
            doc = validate_bridge_vector_document(obj)
        except EvalArtifactError as exc:
            raise WitnessSourceMismatchError(
                f"the object at determinism_witness.source_root {root} is not a valid "
                f"{BRIDGE_VECTOR_FORMAT!r}: {exc}") from exc
        for field, value in (("law_id", witness["law_id"]), ("suite_root", witness["suite_root"]),
                             ("profile_id", witness["profile_id"]),
                             ("release_root", witness["release_root"])):
            _require(doc[field] == value, WitnessSourceMismatchError,
                     f"the bridge document at {root} records {field}={doc[field]!r}; the witness "
                     f"claims {value!r}")
        source_partitions = doc["partitions"]
        source_kind_detail = doc["measured_by"]
    else:                                             # "prior_accept" — the only other kind
        try:
            prior = validate_artifact(obj)
        except EvalArtifactError as exc:
            raise WitnessSourceMismatchError(
                f"the object at determinism_witness.source_root {root} is not a valid eval "
                f"artifact: {exc}") from exc
        _require(prior.get("format") == ARTIFACT_FORMAT_V3, WitnessSourceMismatchError,
                 f"the artifact at {root} is a {prior.get('format')!r}; only a fixed-suite (v3) "
                 "artifact stores an absolute vector for the release it installed")
        rehashed = eval_report_hash(prior)
        _require(rehashed == root, WitnessSourceMismatchError,
                 f"the artifact fetched for source_root {root} rehashes to {rehashed}")
        _require(prior["verdict"]["admit"] is True, WitnessSourceMismatchError,
                 f"the artifact at {root} is a REJECT; a rejected candidate never became a "
                 "release and stores no vector")
        for field, value, where in (
                ("suite_root", witness["suite_root"], prior["suite"]["suite_root"]),
                ("profile_id", witness["profile_id"], prior["candidate"]["target_profile"]),
                ("release_root", witness["release_root"], prior["candidate"]["release_root"])):
            _require(where == value, WitnessSourceMismatchError,
                     f"the accepting artifact at {root} records {field}={where!r}; the witness "
                     f"claims {value!r}")
        source_partitions = {label: prior["dominance"]["partitions"][label]["candidate_vector"]
                             for label in SELECTION_LABELS}
        source_kind_detail = {"epoch": prior["epoch"],
                              "candidate_hash": prior["candidate"]["candidate_hash"]}

    for label in SELECTION_LABELS:
        if source_partitions[label] != witness["partitions"][label]:
            differing = sorted(
                k for k in set(source_partitions[label]) | set(witness["partitions"][label])
                if source_partitions[label].get(k) != witness["partitions"][label].get(k))
            raise WitnessSourceMismatchError(
                f"the {kind} object at {root} publishes a different {label!r} vector for release "
                f"{witness['release_root']} than the witness carries; differing components: "
                f"{differing}")
    return {"resolved": True, "source_kind": kind, "source_root": root,
            "release_root": witness["release_root"], "profile_id": witness["profile_id"],
            "source": source_kind_detail}


def parent_vector_from_verdicts(verdicts: Mapping[str, Any]) -> Dict[str, Any]:
    """The parent arm's RECOMPUTED absolute vector per partition, read off the bound verdicts."""
    return {label: _vector_from_verdict(verdicts[label], "incumbent", label)
            for label in SELECTION_LABELS}


def candidate_vector_from_verdicts(verdicts: Mapping[str, Any]) -> Dict[str, Any]:
    """The candidate arm's absolute vector per partition — the vector this release would STORE."""
    return {label: _vector_from_verdict(verdicts[label], "candidate", label)
            for label in SELECTION_LABELS}


def _vector_from_verdict(verdict: Mapping[str, Any], side: str, label: str) -> Dict[str, Any]:
    vectors = verdict.get("vectors") if isinstance(verdict, Mapping) else None
    vector = vectors.get(side) if isinstance(vectors, Mapping) else None
    if not isinstance(vector, Mapping):
        raise ReceiptBindingError(
            f"the {label!r} verdict carries no {side} absolute vector; a fixed-suite decision is "
            "made on vectors and cannot be projected from a verdict that does not record them")
    # The verdict names the profile it was decided for (``dominance.decide`` emits it), so the
    # projection is bound to that profile's full declared vocabulary here too — the projection is
    # what the artifact then carries, and a vector that lost an objective on the way in would
    # never be caught by a comparison made after it.
    profile_id = verdict.get("profile") if isinstance(verdict, Mapping) else None
    return _validate_vector(dict(vector), f"verdicts[{label!r}].vectors.{side}",
                            profile_id if isinstance(profile_id, str) and profile_id else None)


#: The components of an ABSOLUTE VECTOR that :func:`project_measurements` also measures, so the
#: decided vector and the measured one can be compared field for field. ALL FIVE components of
#: LAW §3A.2 are covered: the three scalars, the objectives map (compared separately, by name),
#: and — since the logical axis became a projected field — ``logical_durable_storage_bytes``.
MEASURABLE_VECTOR_FIELDS = ("composite_micro", "logical_durable_storage_bytes",
                            "rendered_cost_micro", "work_fuel")


def assert_decided_vectors_are_measured(dominance: Mapping[str, Any],
                                        projected: Mapping[str, Any]) -> None:
    """The vectors the componentwise rule DECIDED on must be the ones the report MEASURED.

    A Benchmark-v2 report states each side twice: once as raw ``scores`` (from which
    :func:`project_measurements` projects) and once as ``verdicts[*].vectors``, the absolute
    vectors the rule actually compared. Everything downstream of the verdicts — the dominance
    block, the determinism witness, the bridge document the witness resolves to — derives from the
    SECOND statement, and nothing tied it to the first.

    That gap was exploitable end to end. Raise one objective inside
    ``verdicts[*].vectors.candidate``, leave ``scores`` untouched, flip the branch verdicts and the
    decision, and the REAL builder minted an ADMIT artifact whose every internal binding was honest
    by construction: measurements still projected exactly (they come from ``scores``), the
    dominance block still derived from the verdicts, the witness still matched the re-executed
    parent arm, and the published bridge document still backed it. Both verify shapes passed. The
    artifact contradicted ITSELF — dominance against measurements — and nobody compared the two.
    Only benchmark-side receipt recomputation or a full sandbox replay would have caught it, and
    the V5 artifact layer runs neither.

    ALL FIVE COMPONENTS ARE COVERED — and the fifth was the last gap. For one revision this
    function compared four (the three scalars plus the objectives) and NAMED the one it could
    not: ``logical_durable_storage_bytes`` was decided on, floor-compared and witnessed, but the
    projection did not carry it, because :func:`project_side` filled the artifact's stable
    ``storage_bytes`` slot from the raw input-byte axis and stopped there. The two are DIFFERENT
    AXES that ``final-render-trusted-hostwork.v4`` has always measured separately, and the fixed-suite
    law's own fixed identities have always declared ``storage_axis:
    logical_durable_storage_bytes`` — so the projection, not the policy, was the thing out of
    step. It now projects the logical axis as its own field and this comparison covers it, which
    makes decided == measured == witnessed == counter-metered, one value.

    The witness/bridge chain still carries it too, and that redundancy is deliberate: the witness
    binds the INCUMBENT side against a published document measured on another run, this check
    binds BOTH sides against the report's own raw scores, and neither is a restatement of the
    other.
    """
    for label in SELECTION_LABELS:
        for side, key in (("candidate", "candidate_vector"), ("incumbent", "incumbent_vector")):
            vector = dominance["partitions"][label][key]
            measured = projected["branches"][label][side]
            where = f"dominance.partitions[{label!r}].{key}"
            for field in MEASURABLE_VECTOR_FIELDS:
                _require(vector[field] == measured[field], VerdictMismatchError,
                         f"{where}.{field} is {vector[field]}, the receipt's own "
                         f"scores[{label!r}][{side!r}] measure {measured[field]}; the vector the "
                         "componentwise rule decided on is not the vector that was measured")
            bound_objectives = vector["objectives_micro"]
            measured_objectives = measured["objectives_micro"]
            differing = sorted(oid for oid in set(bound_objectives) | set(measured_objectives)
                               if bound_objectives.get(oid) != measured_objectives.get(oid))
            _require(not differing, VerdictMismatchError,
                     f"{where}.objectives_micro does not equal the receipt's measured "
                     f"scores[{label!r}][{side!r}] objectives on {differing}; a decision made on "
                     "numbers the report did not measure is not a decision under this law")


def assert_determinism_witness(recomputed: Mapping[str, Any],
                               witness: Mapping[str, Any]) -> None:
    """LAW §3A.3's determinism witness. Fails closed on ANY component difference."""
    stored = witness["partitions"]
    for label in SELECTION_LABELS:
        got = recomputed[label]
        want = stored[label]
        if got != want:
            differing = sorted(k for k in set(got) | set(want) if got.get(k) != want.get(k))
            raise DeterminismWitnessMismatchError(
                f"the re-executed parent arm's {label!r} vector does not equal the vector stored "
                f"for release {witness['release_root']} by its {witness['source_kind']} "
                f"qualification; differing components: {differing}. This is an environment-drift "
                "detector and it fails closed — it never adjusts a number and never admits.")


def dominance_block_for(verdicts: Mapping[str, Any], decision: Mapping[str, Any]
                        ) -> Dict[str, Any]:
    """The ``dominance`` block, DERIVED from the evaluation report's own bound verdicts."""
    partitions = {}
    candidate_vectors = candidate_vector_from_verdicts(verdicts)
    incumbent_vectors = parent_vector_from_verdicts(verdicts)
    for label in SELECTION_LABELS:
        verdict = verdicts[label]
        deltas = verdict.get("deltas") or {}
        if verdict.get("engine") != DOMINANCE_ENGINE_ID:
            raise VerdictMismatchError(
                f"the {label!r} verdict was produced by {verdict.get('engine')!r}, not "
                f"{DOMINANCE_ENGINE_ID!r}; a v3 artifact records a componentwise decision")
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
    return {"admit": bool(decision["admit"]), "engine": DOMINANCE_ENGINE_ID,
            "partitions": partitions}


def build_artifact_v3(*, epoch: int, parent_manifest: Mapping[str, Any], epoch_pins: Any = None,
                      transition: Mapping[str, Any], candidate_hash: str,
                      eval_report: Mapping[str, Any],
                      counter_resource_law: Mapping[str, Any],
                      availability: Mapping[str, Any],
                      parent_stored_vector: Mapping[str, Any],
                      counter_resource_law_root_hex: Optional[str] = None,
                      canary: Optional[Mapping[str, Any]] = None,
                      rig_receipt: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Assemble a complete ``coretex.memory-eval-artifact.v3`` (fixed-suite era).

    THE DIFFERENCES FROM :func:`build_artifact`, and nothing else:

      * there is no ``revealed_entropy_secret`` parameter and no ``entropy`` block. Under LAW §3A.4
        the epoch secret is not a case selector, so a v2 evaluation job is never handed one and
        this builder could not derive a commitment even if a reader expected the field;
      * ``selection`` is replaced by ``suite``, built FROM THE LAW DOCUMENT and checked against the
        report's cases (:func:`suite_block_for`);
      * ``determinism_witness``, ``genesis_floor`` and ``dominance`` are added. The witness is
        supplied (it is the exact parent's stored qualifying vector, which this job cannot
        measure); the floor is read from the law; the dominance block is DERIVED from the report's
        own verdicts. The witness equality is asserted here, so a drifting evaluator cannot mint an
        artifact at all.

    Everything else — the frontier replay, the measurement projection, the counter-law accounting,
    the receipt bindings and the rig block — is the identical code path v2 uses.
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
    if set(body.get("incumbent") or {}) == set(INCUMBENT_FIELDS):
        raise ReceiptBindingError(
            "a v3 artifact requires the exact five-field incumbent release/module identity; the "
            "historical three-field reference shape is closed to pre-cut artifacts")
    target = transition["target_profile"]

    suite = suite_block_for(target, body["selection"])
    floor = genesis_floor_block_for(target)
    witness = _check_closed(dict(parent_stored_vector), DETERMINISM_WITNESS_FIELDS,
                            "parent_stored_vector")
    if witness["release_root"] != transition["expected_prior_release_root"]:
        raise DeterminismWitnessMismatchError(
            f"the supplied stored vector is for release {witness['release_root']}, but this "
            f"evaluation's exact parent is {transition['expected_prior_release_root']}")
    assert_determinism_witness(parent_vector_from_verdicts(body["verdicts"]), witness)

    measurements = project_measurements(body)
    # THE DECIDED VECTORS ARE THE MEASURED ONES, at MINT time as well as at verification. The
    # forgery this closes is a report whose ``verdicts[*].vectors`` disagree with its own
    # ``scores``; every binding this builder makes afterwards would then be honest by
    # construction, so the projection is the only thing that can see it. Refusing here means an
    # evaluator handed such a report cannot mint an artifact from it at all.
    assert_decided_vectors_are_measured(dominance_block_for(body["verdicts"], body["decision"]),
                                        measurements)
    branch = counter_resource_law["branch"]
    ppm = evaluate_counter_resource_law(counter_resource_law,
                                        measurements["branches"][branch]["candidate"],
                                        measurements["branches"][branch]["incumbent"])
    artifact = {
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
        "dominance": dominance_block_for(body["verdicts"], body["decision"]),
        "epoch": epoch,
        "format": ARTIFACT_FORMAT_V3,
        "frontier": {
            "benchmark_law_root": child["benchmark_law_root"],
            "composition_root": transition["resulting_composition_root"],
            "new_frontier_root": new_root,
            "parent_frontier_root": parent_root,
            "runtime_abi_root": child["runtime_abi_root"],
            "transition": dict(transition),
            "transition_bytes_len": len(tbytes),
            "transition_hash_keccak256": transition_hash_keccak256(tbytes),
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
    if canary is not None:
        artifact["canary"] = dict(canary)
    if rig_receipt is not None:
        artifact["rig_receipt"] = dict(rig_receipt)
    return validate_artifact(artifact)


def verify_suite_membership(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """The v3 sibling of :func:`verify_selection_walk`: MEMBERSHIP, not re-derivation.

    Under the walk era the honest thing a pure function could prove was that each recorded case sat
    at its claimed index of a walk — and it had to say out loud that whether a SKIPPED index was
    legitimate needed the generators and the oracle screen (that is ``replay.verify_selection_complete``).
    Under a fixed suite that whole question disappears: there are no skipped indices because there
    is no walk. What must be true is that the artifact's cases ARE the law's cases, in the law's
    order, with the law's instance hashes — which is decidable offline, from the law document,
    with nothing but the stdlib.

    The suite is re-read from ``benchmark-v2/validator/CANONICAL-SUITE.v1.json`` rather than
    trusted from the artifact, and the artifact's ``suite_root`` must equal the sha256 of those
    exact bytes. An artifact carrying a suite nobody else has is therefore a mismatch, not a
    variation.
    """
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
    # THE PROVENANCE IS LAW TOO. ``source`` names the bridge measurement the floor came from, and
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
            axis for axis, key in (("logical_durable_storage_bytes",
                                    "logical_durable_storage_bytes"),
                                   ("rendered_cost", "rendered_cost_micro"),
                                   ("work_fuel", "work_fuel"))
            if cand_vec[key] > inc_vec[key])
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
               if value < floor_vec["objectives_micro"][oid]]
            + [axis for axis, key in (("logical_durable_storage_bytes",
                                       "logical_durable_storage_bytes"),
                                      ("rendered_cost", "rendered_cost_micro"),
                                      ("work_fuel", "work_fuel"))
               if cand_vec[key] > floor_vec[key]])
        _require(floor_regressions == list(part["floor_regressions"]), VerdictMismatchError,
                 f"{where}.floor_regressions does not recompute against the law-bound floor "
                 f"(bound {part['floor_regressions']}, recomputed {floor_regressions})")
        admit = bool(part["hard_ok"] and not regressed_objectives and not regressed_axes
                     and not floor_regressions
                     and part["composite_gain_ppm"] >= 1)
        _require(admit == bool(part["admit"]), VerdictMismatchError,
                 f"{where}.admit does not follow from the componentwise rule over the bound "
                 "vectors")
    return {"engine": dom["engine"], "admit": bool(dom["admit"])}


def _verify_walk_era_selection(artifact, *, expected_entropy_commitment,
                               revealed_entropy_secret, done):
    """Steps 4+5 of the WALK ERA (v1/v2), lifted verbatim into a named function.

    Moved out of :func:`verify_artifact` unchanged when the fixed-suite era landed, so the two
    eras read as "which of these two things happened here" rather than as one function with a
    flag threaded through forty lines. Every ``_require`` below is byte-for-byte what it was,
    which is what keeps every already-published v1/v2 artifact verifying exactly as before.
    """
    front = artifact["frontier"]
    cand = artifact["candidate"]
    # ---- 4. entropy: commitment opening + the two derived selection values -----------------
    ent = artifact["entropy"]
    _require(ent["derivation_domain"] == ENTROPY_DOMAIN, EntropyMismatchError,
             f"entropy.derivation_domain {ent['derivation_domain']!r} != {ENTROPY_DOMAIN!r}")
    _require(ent["commitment"] == fr.check_root(expected_entropy_commitment,
                                                "expected_entropy_commitment"),
             EntropyMismatchError,
             f"artifact entropy commitment {ent['commitment']} != the on-chain commitment "
             f"{expected_entropy_commitment}")
    embedded_opening = ent.get("revealed_secret")
    if revealed_entropy_secret is not None:
        fr.check_root(revealed_entropy_secret, "revealed_entropy_secret")
    if embedded_opening is not None and revealed_entropy_secret is not None:
        _require(embedded_opening == revealed_entropy_secret, EntropyMismatchError,
                 "the external chain opening disagrees with the artifact's historical embedded "
                 "opening")
    opening = revealed_entropy_secret or embedded_opening
    if opening is None:
        raise EntropyOpeningUnavailableError(
            "the eval artifact is sealed and EpochSecretRevealed has not supplied its opening")
    opened = entropy_commitment_of(opening)
    _require(opened == ent["commitment"], EntropyMismatchError,
             f"the revealed epoch secret opens to {opened}, not the bound commitment "
             f"{ent['commitment']} — keccak256(abi.encodePacked(bytes32 secret))")
    for label in SELECTION_LABELS:
        field = f"{label}_value"
        expected = derive_entropy_value(revealed_secret=opening,
                                        epoch=artifact["epoch"],
                                        parent_frontier_root=front["parent_frontier_root"],
                                        label=label)
        if field in ent:
            _require(ent[field] == expected, EntropyMismatchError,
                     f"entropy.{field} {ent[field]} is not the committed secret expanded under "
                     f"{ENTROPY_DOMAIN}|{label}")
    expanded_entropy = dict(ent)
    for label in SELECTION_LABELS:
        expanded_entropy[f"{label}_value"] = derive_entropy_value(
            revealed_secret=opening, epoch=artifact["epoch"],
            parent_frontier_root=front["parent_frontier_root"], label=label)
    _require(expanded_entropy["gate_value"] != expanded_entropy["confirm_value"],
             EntropyMismatchError,
             "the gate and confirmation entropies are equal; the two selections must draw from "
             "independent values so no single input co-steers both")
    done("entropy_commitment")

    # ---- 5. the fresh selection re-derives from that entropy -------------------------------
    sel = artifact["selection"]
    _require(sel["domain"] == SELECTION_DOMAIN, SelectionMismatchError,
             f"selection.domain {sel['domain']!r} != {SELECTION_DOMAIN!r}")
    _require(sel["profile_id"] == cand["target_profile"], SelectionMismatchError,
             f"selection profile {sel['profile_id']!r} != the target profile "
             f"{cand['target_profile']!r}")
    verify_selection_walk(sel, entropy=expanded_entropy, candidate_hash=cand["candidate_hash"])
    done("selection_walk")
    return expanded_entropy, sel


def verify_artifact(artifact: Mapping[str, Any], *, expected_parent_root: str,
                    expected_new_root: str, expected_release_root: str,
                    expected_composition_root: str, expected_runtime_abi_root: str,
                    expected_benchmark_law_root: str,
                    expected_counter_resource_law_root: str,
                    expected_entropy_commitment: str, expected_epoch: int,
                    expected_target_profile: Optional[str] = None,
                    eval_report: Optional[Mapping[str, Any]] = None,
                    receipt_wrapper: Optional[Mapping[str, Any]] = None,
                    counter_resource_law: Optional[Mapping[str, Any]] = None,
                    store: Optional[pub.ContentStore] = None,
                    check_availability: bool = False,
                    require_rig_receipt: bool = False,
                    expected_epoch_context_root: Optional[str] = None,
                    expected_core_version_hash: Optional[str] = None,
                    expected_work_policy_hash: Optional[str] = None,
                    signature_verifier=None,
                    revealed_entropy_secret: Optional[str] = None,
                    epoch_pins: Optional[Mapping[str, Any]] = None,
                    resolve_witness_source: bool = False) -> Dict[str, Any]:
    """Verify EVERY binding of ``artifact`` against the values a confirmed chain state asserts.

    The expected roots come from the chain (the registry's live root and epoch pins, the receipt's
    signed fields), never from the artifact — an artifact that only agreed with itself would prove
    nothing.

    RAISES a typed :class:`EvalArtifactError` on any failure and returns a report dict on success.
    It never returns ``False``: an unverified artifact must never be readable as a passing one
    (``frontier.verify_transition`` discipline). A validator that wants a verdict catches
    :class:`EvalArtifactError` and records a BACKLOG entry, never a pass.

    ``receipt_wrapper`` may be omitted IFF ``store`` is supplied, in which case the signed receipt
    is FETCHED from the publication surface by its bound ``wrapper_root`` and re-hashed — the same
    read-back a public validator performs. Supplying neither is
    :class:`ReceiptUnavailableError`, not a skipped check.

    ``require_rig_receipt`` makes the nine rig-protocol fields MANDATORY. It defaults to false so
    that every artifact minted before the rig protocol existed still verifies byte for byte; the
    rig pre-sign gate always passes true, so an artifact that is about to be bound to a rig
    receipt but cannot supply the fields that receipt signs is refused
    (:class:`RigReceiptFieldsMissingError`) rather than silently signed with invented values.
    The three ``expected_*`` rig pins (``epoch_context_root``, ``core_version_hash``,
    ``work_policy_hash``) are the epoch context the registry itself
    enforces; supplying one checks the artifact against it, omitting one skips only that check.

    ``epoch_pins`` is optional only to preserve exact historical replay. When supplied it is the
    independently verified current epoch context's frontier-pin projection. An inherited parent
    from an EARLIER epoch may carry the previous epoch's pins; the child adopts these exact
    verified values. A same-epoch parent must already carry them, so an arbitrary pin change is
    still refused.
    """
    law = artifact_law(artifact)
    signed_era = law == al.LAW_OFF_CHAIN_SIGNATURE_V1
    fixed_suite = artifact.get("format") == ARTIFACT_FORMAT_V3
    validate_artifact(artifact)
    report: Dict[str, Any] = {"checks": [], "authority_law": law}

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
             "bound enforced by the V5-A decoder and BOTH V5-B contracts")
    _require(front["transition_id_sha256"] == fr.transition_hash(transition),
             TransitionHashMismatchError,
             "frontier.transition_id_sha256 is not sha256 over the transition's canonical bytes")
    _require(front["transition_hash_keccak256"] == transition_hash_keccak256(tbytes),
             TransitionHashMismatchError,
             "frontier.transition_hash_keccak256 is not keccak256(domain label ++ "
             "transitionBytes) — the signed receipt field would not bind these bytes")
    _require(front["transition_hash_keccak256"] != front["transition_id_sha256"],
             TransitionHashMismatchError,
             "the on-chain keccak transition hash and the off-chain sha256 transition id are "
             "equal; they are different algorithms over different preimages and must never be "
             "conflated")
    done("transition_hashes")

    # ---- 3. the parent manifest actually produces the claimed child ------------------------
    parent = artifact["replay_inputs"]["parent_manifest"]
    computed_parent = fr.frontier_root(parent)
    _require(computed_parent == front["parent_frontier_root"], ParentRootMismatchError,
             f"the carried parent manifest hashes to {computed_parent}, not the bound "
             f"{front['parent_frontier_root']}")
    # LAZY INHERITANCE (ruling §17.237): the parent is the SAME epoch for an ordinary advance and
    # an EARLIER epoch for the first transition of a new epoch, which inherits the previous
    # non-empty epoch's head. Which of the two is legitimate depends on the transition INDEX —
    # chain data the artifact deliberately does not carry — and is enforced by
    # `validator.replay.replay_advance`. What is never legitimate, at any index, is a parent from
    # a LATER epoch: epochs do not run backwards.
    _require(parent["epoch"] <= artifact["epoch"], EpochPinMismatchError,
             f"parent manifest epoch {parent['epoch']} is later than artifact epoch "
             f"{artifact['epoch']}; epochs never move backwards")
    verified_frontier_pins: Optional[Dict[str, str]] = None
    if epoch_pins is not None:
        if not isinstance(epoch_pins, Mapping):
            raise EpochPinMismatchError(
                "epoch_pins must be an independently verified epoch-context mapping")
        try:
            verified_frontier_pins = {
                "benchmark_law_root": fr.check_root(
                    epoch_pins.get("benchmark_law_root"),
                    "epoch_pins.benchmark_law_root"),
                "runtime_abi_root": fr.check_root(
                    epoch_pins.get("runtime_abi_root"),
                    "epoch_pins.runtime_abi_root"),
            }
        except fr.FrontierError as exc:
            raise EpochPinMismatchError(str(exc)) from exc
        _require(
            verified_frontier_pins["benchmark_law_root"] == front["benchmark_law_root"],
            EpochPinMismatchError,
            "the independently verified epoch benchmark_law_root does not equal the "
            "artifact's bound pin")
        _require(
            verified_frontier_pins["runtime_abi_root"] == front["runtime_abi_root"],
            EpochPinMismatchError,
            "the independently verified epoch runtime_abi_root does not equal the artifact's "
            "bound pin")

    inherited = parent["epoch"] < artifact["epoch"]
    for pin in fr.EPOCH_PINNED_MANIFEST_FIELDS:
        if verified_frontier_pins is None or not inherited:
            _require(parent[pin] == front[pin], EpochPinMismatchError,
                     f"parent manifest {pin} != the artifact's bound pin")
    if verified_frontier_pins is not None and not inherited:
        _require(
            "compatibility_lock_root" not in parent, EpochPinMismatchError,
            "a same-epoch transition cannot retire compatibility_lock_root; only the first edge "
            "from an inherited prior-epoch parent retires that historical manifest copy")
    _require(parent["profiles"][cand["target_profile"]] == cand["prior_release_root"],
             ReleaseRootMismatchError,
             "the parent frontier does not serve the candidate's prior release root for the "
             "target profile — this candidate was built against a superseded frontier")
    # The artifact's own epoch drives the replay, so an artifact built for epoch N can never be
    # re-presented as evidence for epoch N+1 against the same parent: the reproduced root differs.
    fr.verify_transition(
        parent, transition, front["new_frontier_root"], epoch=artifact["epoch"],
        epoch_pins=verified_frontier_pins)                                 # raises on divergence
    done("frontier_replay")

    # ---- 4+5 (FIXED-SUITE ERA). There is no entropy to open and no walk to re-derive: the cases
    #      are LAW. What replaces both steps is MEMBERSHIP plus the three law-bound comparands the
    #      componentwise rule decides against — the suite, the exact parent's stored vector, and
    #      the constructor-genesis floor. Each is re-resolved HERE from the law document rather
    #      than read out of the artifact, so an artifact that only agrees with itself proves
    #      nothing (the same discipline the chain-asserted roots follow in step 1).
    if fixed_suite:
        _require(expected_entropy_commitment is None, EntropyMismatchError,
                 "a fixed-suite (v3) artifact binds no entropy: under LAW §3A.4 the epoch secret "
                 "is not a case selector, so there is no commitment for it to be checked against")
        verify_suite_membership(artifact)
        done("suite_membership")
        verify_genesis_floor(artifact)
        done("genesis_floor")
        verify_dominance_block(artifact)
        done("dominance")
        expanded_entropy = None
        sel = None
    else:
        expanded_entropy, sel = _verify_walk_era_selection(
            artifact, expected_entropy_commitment=expected_entropy_commitment,
            revealed_entropy_secret=revealed_entropy_secret, done=done)


    # ---- 6. the deterministic evaluation report, dispatched by the artifact's own law --------
    if signed_era:
        if eval_report is not None:
            raise ReceiptBindingError(
                "a signed-era artifact requires its historical receipt_wrapper, not a v2 "
                "evaluation report")
        wrapper = receipt_wrapper
        if wrapper is None:
            if store is None:
                raise ReceiptUnavailableError(
                    "signed-era replay needs the v1 signed wrapper: pass receipt_wrapper, or a "
                    "store to fetch it from by the artifact's bound wrapper_root")
            wrapper = pub.fetch_json(artifact["receipt"]["wrapper_root"],
                                     hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
        body = _receipt_body(wrapper)
        fetched_root = fr.sha256_hex(pub.benchmark_canonical_bytes(wrapper))
        _require(fetched_root == artifact["receipt"]["wrapper_root"], ReceiptBindingError,
                 f"the receipt wrapper hashes to {fetched_root}, not the bound "
                 f"{artifact['receipt']['wrapper_root']}")
        _require(wrapper["receipt_hash"] == artifact["receipt"]["receipt_hash"],
                 ReceiptBindingError,
                 "receipt.receipt_hash does not match the signed wrapper's self-hash")
        _require(wrapper["signature"]["key_id"] == artifact["receipt"]["signature_key_id"],
                 ReceiptBindingError, "receipt.signature_key_id does not match the wrapper")
        if signature_verifier is not None:
            if signature_verifier(wrapper) is not True:
                raise ReceiptBindingError(
                    "the signed receipt's Ed25519 signature did not verify against the pinned key")
            done("receipt_signature")
    else:
        if receipt_wrapper is not None or signature_verifier is not None:
            raise ReceiptBindingError(
                "a v2 chain-committed artifact cannot be authorized by a historical signed "
                "wrapper or off-chain signature verifier")
        bound_root = artifact["receipt"]["eval_report_root"]
        body = eval_report
        if body is None:
            if store is None:
                raise ReceiptUnavailableError(
                    "verification needs the deterministic evaluation report: pass eval_report, "
                    "or a store to fetch it by the artifact's bound eval_report_root")
            body = pub.fetch_json(bound_root, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
        body = _eval_report(body)
        recomputed = eval_report_root(body)
        _require(recomputed == bound_root, ReceiptBindingError,
                 f"the evaluation report's canonical bytes hash to {recomputed}, not the bound "
                 f"{bound_root}")
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
    if fixed_suite:
        # NON-CONSENSUS TELEMETRY, still RECOMPUTED rather than believed (LAW §3A.7). It decides
        # nothing; what it must not become is a number the artifact can quietly restate, because
        # the whole reason it is reported is so a reviewer can watch module footprint grow.
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
    if fixed_suite:
        # The report's cases are the artifact's suite cases, field for field. The suite block was
        # already proved to BE the law's suite by `verify_suite_membership`, so this equality is
        # what closes "the evaluation the artifact addresses was run on the law's exam".
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
        # The report's bound law must be the fixed-suite law AND must name this exact suite.
        descriptor = body.get("evaluation_law") or {}
        _require(descriptor.get("law_id") == FIXED_SUITE_LAW_ID, ReceiptBindingError,
                 f"the evaluation report is bound to {descriptor.get('law_id')!r}, not the "
                 f"fixed-suite law {FIXED_SUITE_LAW_ID!r}")
        _require(descriptor.get("canonical_suite_root") == suite["suite_root"],
                 SuiteMembershipError,
                 "the evaluation report's bound law names a different canonical suite than the "
                 "artifact's suite block; a changed suite is a new law (LAW §3A.6)")
        # THE DOMINANCE BLOCK IS THE REPORT'S OWN VERDICTS, RE-DERIVED. Without this the block was
        # only self-consistent: `verify_dominance_block` recomputes the flags from the vectors the
        # block itself carries, so a forger who edits BOTH vectors coherently passes it while the
        # addressed report still records the regression. Deriving the whole block from the bound
        # report and comparing it makes the report the sole source of every number in it.
        expected_dominance = dominance_block_for(body["verdicts"], body["decision"])
        if expected_dominance != artifact["dominance"]:
            differing = sorted(
                label for label in SELECTION_LABELS
                if expected_dominance["partitions"][label]
                != artifact["dominance"]["partitions"][label])
            raise VerdictMismatchError(
                "the artifact's dominance block does not derive from the addressed evaluation "
                f"report's own verdicts (partitions differing: {differing or ['admit']}); the "
                "vectors ARE the evidence and the block is a projection of them, not a second "
                "statement of them")
        done("dominance_report_binding")
        # The parent arm re-executed in THIS job must reproduce the stored qualifying vector.
        assert_determinism_witness(parent_vector_from_verdicts(body["verdicts"]),
                                   artifact["determinism_witness"])
        done("determinism_witness")
        # LAW §3A.4 / the fixed-suite round identity: candidate_id reaches nothing consensus is
        # derived from, and the values that used to carry it are law constants.
        _require(body["round_id"] == cs.FIXED_SUITE_ROUND_ID, ReceiptBindingError,
                 f"the evaluation report's round_id {body['round_id']!r} is not the fixed-suite "
                 f"constant {cs.FIXED_SUITE_ROUND_ID!r}; under LAW §3A.4 the round identity is a "
                 "law constant and a caller-derived one is how the retry lottery entered")
        for label in SELECTION_LABELS:
            field = "entropy" if label == "gate" else "confirm_entropy"
            expected_value = cs.fixed_suite_entropy(label)
            _require((body[field] or {}).get("value") == expected_value, EntropyMismatchError,
                     f"the evaluation report's {field}.value is not the inert fixed-suite "
                     f"constant {expected_value}; nothing is derived from it and nothing else may "
                     "be filled in there")
        done("fixed_round_identity")
    else:
        _require(body["entropy"]["value"] == expanded_entropy["gate_value"], EntropyMismatchError,
                 "the receipt's gate entropy value is not the chain-committed entropy expanded for "
                 "the gate label — the scored instances did not come from the committed entropy")
        _require(body["confirm_entropy"]["value"] == expanded_entropy["confirm_value"], EntropyMismatchError,
                 "the receipt's confirmation entropy value is not the chain-committed entropy "
                 "expanded for the confirm label")
        _require(body["season_root"] == sel["season_root"] and body["round_id"] == sel["round_id"]
                 and list(body["scales"]) == list(sel["scales"]), ReceiptBindingError,
                 "receipt season_root/round_id/scales do not match the artifact's selection block")
        _require(dict(body["burned_head"]) == dict(sel["burned_head"]), ReceiptBindingError,
                 "receipt burned_head != the artifact's selection.burned_head")
        for label in SELECTION_LABELS:
            rec_cases = [{"derivation_index": c["derivation_index"],
                          "instance_hash": c["instance_hash"], "instance_id": c["instance_id"],
                          "profile_id": c["profile_id"], "scale": c["scale"], "seed": c["seed"]}
                         for c in body["selection"][label]]
            _require(rec_cases == sel["cases"][label], SelectionMismatchError,
                     f"the artifact's {label!r} selection is not the receipt's {label!r} selection")
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
    # verdicts — the dominance block, the determinism witness, the bridge document the witness
    # resolves to — is derived from the SECOND statement, and until this check nothing tied it to
    # the first.
    #
    # That gap was exploitable end to end: raise one objective inside
    # ``verdicts[*].vectors.candidate``, leave ``scores`` untouched, flip the branch verdicts and
    # the decision, and the REAL builder minted an ADMIT artifact whose every internal binding was
    # honest by construction — measurements still projected exactly (they come from ``scores``),
    # the dominance block still derived from the verdicts, the witness still matched the parent
    # arm, and the published bridge document still backed it. Both verify shapes passed. The
    # artifact contradicted ITSELF, dominance against measurements, and nobody compared the two.
    # Only benchmark-side receipt recomputation or a full sandbox replay would have caught it,
    # neither of which the V5 artifact layer runs.
    #
    # ALL FIVE COMPONENTS, INCLUDING THE STORAGE AXIS. ``logical_durable_storage_bytes`` used to
    # be decided-but-unprojected under ``final-render-trusted-hostwork.v4`` — ``project_side``
    # filled the artifact's stable ``storage_bytes`` slot from the raw input-byte axis and carried
    # the logical axis nowhere — so the one protected axis a memorising candidate would inflate
    # was the one this comparison could not see. The measurement policy measures both axes and the fixed-suite law
    # declares the logical one as its ``storage_axis``; the projection now carries it as its own
    # field and this check covers it. The witness/bridge chain still binds the incumbent side
    # independently, which is redundancy on purpose, not a restatement.
    if fixed_suite:
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
        artifact["measurements"]["branches"][branch]["incumbent"])
    for key, value in recomputed.items():
        _require(acct[key] == value, ResourceAccountingError,
                 f"resource_accounting.{key} is {acct[key]}, the pinned counter law recomputes "
                 f"{value} from the bound measurements")
    _require(acct["resource_before_ppm"] == MICRO, ResourceAccountingError,
             f"resource_before_ppm is {acct['resource_before_ppm']}; the incumbent is the unit "
             f"of comparison and must evaluate to exactly {MICRO} ppm")
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

    # ---- 10. the canary changed nothing ------------------------------------------------------
    if "canary" in artifact:
        validate_canary_block(artifact["canary"])       # re-asserts the two separation flags
        with_canary = deterministic_verdict(artifact)
        without = deterministic_verdict(strip_canary(artifact))
        if with_canary != without:
            raise CanaryInfluenceError(
                "the deterministic verdict differed with and without the auxiliary canary block; "
                "the consensus/attestation separation has been broken")
        done("canary_isolation")

    # ---- 11. the RIG-protocol receipt fields ------------------------------------------------
    # Optional by default so every pre-rig artifact still verifies unchanged; MANDATORY the
    # moment an artifact is being bound to a rig receipt.
    rig_present = "rig_receipt" in artifact
    if require_rig_receipt and not rig_present:
        raise RigReceiptFieldsMissingError(
            "this artifact is being verified for a RIG receipt but carries no 'rig_receipt' "
            f"block. A RigCoreTexReceipt signs {', '.join(RIG_RECEIPT_FIELDS)}; the coordinator "
            "does not invent a signed field, so there is nothing to sign.")
    if rig_present:
        rig = validate_rig_receipt_block(artifact["rig_receipt"])
        # The three receipt/context pins. Each is checked only when the
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
        # transition_format_version's fixed value is already enforced protocol-wide by
        # `validate_rig_receipt_block` (it is the descriptor's version byte, not a per-lane
        # narrowing — the retired model's "memory-frontier lane is always exactly 1 word" rule has
        # no v2 counterpart because there is no word count to narrow). What remains lane-specific
        # is the frontier-root movement a state advance/screener pass each require.
        if rig["outcome"] == RIG_OUTCOME_STATE_ADVANCE:
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
    if fixed_suite:
        witness_block = artifact["determinism_witness"]
        if not resolve_witness_source:
            report["witness_provenance"] = {
                "resolved": False,
                "source_kind": witness_block["source_kind"],
                "source_root": witness_block["source_root"],
                "reason": "verification ran without an object resolver; the stored parent vector "
                          "was checked for INTERNAL consistency and against the re-executed parent "
                          "arm, but the bridge document / prior accepting artifact it names was "
                          "not fetched. Pass resolve_witness_source=True with a store (public "
                          "replay does) to prove where the number came from",
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
        required = (REQUIRED_AVAILABILITY_V1_SIGNED_ERA
                    if signed_era else REQUIRED_AVAILABILITY_V2)
        report["availability"] = pub.verify_availability(
            artifact["availability"], store=store, required=required)
        done("availability")

    report.update({
        "ok": True,
        "eval_report_hash": eval_report_hash(artifact),
        "parent_frontier_root": front["parent_frontier_root"],
        "new_frontier_root": front["new_frontier_root"],
        "verdict": deterministic_verdict(artifact),
        "canary_present": "canary" in artifact,
        "canary_consensus_critical": False,
        "rig_receipt_present": rig_present,
        "resource_accounting": dict(acct),
    })
    return report


def verify_signed_era_artifact(artifact: Mapping[str, Any], *, receipt_wrapper=None,
                               signature_verifier=None, **kwargs) -> Dict[str, Any]:
    """Replay a v1 artifact under its closed historical signature law only."""
    al.require_historical_law(artifact_law(artifact), what="this eval artifact")
    return verify_artifact(
        artifact, receipt_wrapper=receipt_wrapper,
        signature_verifier=signature_verifier, **kwargs)


# --------------------------------------------------------------------------- #
# The auxiliary canary path (spec §10) — reports, never decides
# --------------------------------------------------------------------------- #
def verify_canary_block(artifact: Mapping[str, Any],
                        sealed_transcript: Optional[Mapping[str, Any]] = None, *,
                        store: Optional[pub.ContentStore] = None,
                        expected_code_identity: Optional[Mapping[str, Any]] = None,
                        revealed_entropy_secret: Optional[str] = None,
                        ) -> Dict[str, Any]:
    """Validate the SEALED canary bindings without regenerating a single model token.

    §17.236's transcript-cleanup instruction is to PARSE AND VERIFY the sealed bindings rather
    than import an opaque root. That is what happens here: the transcript's own root, its policy
    hash, its scorer/questions code identity, its entropy-bound selection base, and its
    candidate / incumbent / epoch bindings are each RECOMPUTED and compared against the artifact.
    Nothing calls a provider; the answers are never regenerated (they cannot be — a hosted model
    is not a reproducible function).

    RETURN SHAPE, and why it differs from :func:`verify_artifact`. This function RETURNS a report
    with ``ok: False`` for a canary failure instead of raising, because a canary failure is an
    ADVISORY OUTCOME to be reported — not a verification error of the deterministic artifact.
    The deterministic verdict is carried in the report unchanged and is re-derived from the
    canary-free artifact, so the two can be compared by the caller and by the tests.

    The ONE canary condition that does raise is a block claiming consensus authority
    (:class:`CanaryConsensusError`), because that is a violation of the deterministic law itself.
    """
    validate_artifact(artifact)
    verdict = deterministic_verdict(strip_canary(artifact))

    def report(ok: bool, code: Optional[str], reason: str, **extra) -> Dict[str, Any]:
        out = {"ok": ok, "code": code, "reason": reason,
               "consensus_critical": False, "external_model_attestation": True,
               "may_change_verdict": False,
               "verdict_authority": "benchmark-v2 deterministic receipt decision",
               "deterministic_verdict": dict(verdict)}
        out.update(extra)
        # defensive: the deterministic verdict in this report must be the canary-free one
        if out["deterministic_verdict"] != deterministic_verdict(strip_canary(artifact)):
            raise CanaryInfluenceError(
                "a canary report attempted to carry a verdict other than the deterministic one")
        return out

    if "canary" not in artifact:
        return report(True, "no_canary",
                      "artifact carries no auxiliary canary block; the deterministic verdict "
                      "stands unchanged — a canary is OPTIONAL evidence, never a requirement")
    block = validate_canary_block(artifact["canary"])    # raises CanaryConsensusError if claimed

    sealed = sealed_transcript
    if sealed is None:
        if store is None:
            return report(False, "transcript_unavailable",
                          "the canary block references a sealed transcript that was neither "
                          "supplied nor fetchable (no store); the canary is UNVERIFIED and is "
                          "disregarded")
        try:
            sealed = pub.fetch_json(block["transcript_root"],
                                    hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
        except (pub.PublicationError, fr.FrontierError) as exc:
            return report(False, "transcript_unavailable",
                          f"sealed transcript {block['transcript_root'][:12]} is not available: "
                          f"{exc}")
    if not isinstance(sealed, dict) or sealed.get("format") != CANARY_TRANSCRIPT_FORMAT:
        return report(False, "malformed_transcript",
                      f"sealed transcript is not a {CANARY_TRANSCRIPT_FORMAT!r} object")

    computed_root = canary_transcript_root(sealed)
    if computed_root != block["transcript_root"]:
        return report(False, "transcript_root_mismatch",
                      f"the sealed transcript re-seals to {computed_root}, not the referenced "
                      f"{block['transcript_root']}")
    if sealed.get("external_model_attestation") is not True:
        return report(False, "attestation_flag_missing",
                      "the sealed transcript does not label itself external_model_attestation")

    policy = sealed.get("policy")
    if not isinstance(policy, dict):
        return report(False, "malformed_transcript", "sealed transcript carries no policy block")
    computed_policy = canary_policy_hash(policy)
    if computed_policy != sealed.get("policy_hash") or computed_policy != block["policy_hash"]:
        return report(False, "policy_hash_mismatch",
                      f"policy re-hashes to {computed_policy}; transcript claims "
                      f"{sealed.get('policy_hash')} and the artifact references "
                      f"{block['policy_hash']}")

    ident = sealed.get("code_identity")
    if not isinstance(ident, dict) or not ident:
        return report(False, "code_identity_missing",
                      "the sealed transcript carries no code_identity block, so 'sealed under "
                      "the frozen scorer' is a label rather than a checkable claim")
    if {k: v for k, v in ident.items()} != dict(block["code_identity"]):
        return report(False, "code_identity_mismatch",
                      "the artifact's referenced scorer/questions code identity is not the "
                      "transcript's")
    if expected_code_identity is not None:
        diffs = sorted(k for k in set(ident) | set(expected_code_identity)
                       if k != "format" and ident.get(k) != expected_code_identity.get(k))
        if diffs:
            return report(False, "code_identity_foreign",
                          f"the transcript was sealed under different scorer bytes than this "
                          f"build: {diffs}. A defective scorer build has a DISTINCT identity from "
                          "a corrected one; rescoring across the boundary would look like a "
                          "replay and would not be one", differences=diffs)

    art_cand = artifact["candidate"]["candidate_hash"]
    art_parent = artifact["frontier"]["parent_frontier_root"]
    for field, artifact_value, sealed_value, code in (
            ("candidate_hash", art_cand, sealed.get("candidate_hash"),
             "candidate_binding_mismatch"),
            ("incumbent_root", art_parent, sealed.get("incumbent_root"),
             "incumbent_binding_mismatch")):
        if block[field] != artifact_value or sealed_value != artifact_value:
            return report(False, code,
                          f"canary {field} binding: artifact={artifact_value}, "
                          f"block={block[field]}, transcript={sealed_value}")
    if block["epoch_id"] != str(artifact["epoch"]) or str(sealed.get("epoch_id")) != \
            str(artifact["epoch"]):
        return report(False, "epoch_binding_mismatch",
                      f"canary epoch binding: artifact={artifact['epoch']}, "
                      f"block={block['epoch_id']!r}, transcript={sealed.get('epoch_id')!r}")

    entropy_block = sealed.get("entropy")
    if not isinstance(entropy_block, dict):
        return report(False, "malformed_transcript", "sealed transcript carries no entropy block")
    # A FIXED-SUITE ARTIFACT HAS NO ENTROPY BLOCK, and the canary is optional in that era too —
    # `ARTIFACT_FIELDS_V3` carries `canary` in `OPTIONAL_ARTIFACT_FIELDS` and `build_artifact_v3`
    # accepts one. Reading `artifact["entropy"]` unconditionally therefore raised a bare KeyError
    # on exactly that combination, and a bare KeyError is not a refusal: `replay.canary_evidence`
    # catches only the typed errors, so it escaped and crashed a public validator at the LAST step
    # of an advance whose verdict was already computed. The canary's own selection is entropy-bound
    # by construction, so under a law with no entropy there is nothing for it to bind TO — which is
    # a refusal to report, not a check to skip and not an exception to leak.
    if "entropy" not in artifact:
        return report(False, "canary_era_mismatch",
                      "this artifact is bound to an entropy-free admission law, so the sealed "
                      "canary transcript's entropy binding has nothing to be checked against. A "
                      "canary minted for the walk era cannot attest a fixed-suite evaluation")
    art_entropy = artifact["entropy"].get("gate_value")
    if art_entropy is None:
        if revealed_entropy_secret is None:
            return report(False, "entropy_opening_unavailable",
                          "the artifact's canary entropy cannot be checked until the sealed "
                          "epoch opening is supplied from EpochSecretRevealed")
        art_entropy = derive_entropy_value(
            revealed_secret=revealed_entropy_secret, epoch=artifact["epoch"],
            parent_frontier_root=artifact["frontier"]["parent_frontier_root"], label="gate")
    if block["entropy_hex"] != art_entropy or entropy_block.get("hex") != art_entropy:
        return report(False, "entropy_binding_mismatch",
                      f"canary entropy binding: artifact gate entropy={art_entropy}, "
                      f"block={block['entropy_hex']}, transcript={entropy_block.get('hex')}")

    sel = sealed.get("selection")
    if not isinstance(sel, dict):
        return report(False, "malformed_transcript",
                      "sealed transcript carries no selection block")
    base = hashlib.sha256("|".join(
        (str(entropy_block.get("domain")), art_entropy, sealed["candidate_hash"],
         sealed["incumbent_root"], str(sel.get("profile_id")), str(sealed["epoch_id"]),
         str(sel.get("scale")))).encode("utf-8")).hexdigest()
    if base != entropy_block.get("selection_base_sha256") or \
            base != block["selection_base_sha256"]:
        return report(False, "selection_base_mismatch",
                      f"the canary selection base re-derives to {base}; transcript claims "
                      f"{entropy_block.get('selection_base_sha256')} and the artifact references "
                      f"{block['selection_base_sha256']}")
    if sel.get("profile_id") != artifact["candidate"]["target_profile"]:
        return report(False, "profile_binding_mismatch",
                      f"the canary ran profile {sel.get('profile_id')!r}, the artifact advances "
                      f"{artifact['candidate']['target_profile']!r}")

    sealed_verdict = (sealed.get("verdict") or {}).get("verdict")
    if str(sealed_verdict) != block["verdict"]:
        return report(False, "canary_verdict_binding_mismatch",
                      f"the artifact references canary verdict {block['verdict']!r} but the "
                      f"transcript sealed {sealed_verdict!r}")
    if str(sealed_verdict).upper() not in ("PASS", "OK", "GREEN"):
        return report(False, "canary_failed",
                      f"the auxiliary canary reports {sealed_verdict!r}. This is REPORTED, not "
                      "enforced: it creates no promotion eligibility and cannot deny a "
                      "deterministically earned promotion (§17.236). A serious failure is an "
                      "operator alert or an explicitly governed GLOBAL safety pause — never an "
                      "opaque candidate-specific consensus gate",
                      canary_verdict=str(sealed_verdict))
    return report(True, None, "sealed canary bindings verified by rescoring-free re-derivation; "
                              "advisory PASS", canary_verdict=str(sealed_verdict))


# --------------------------------------------------------------------------- #
# The PRE-SIGN availability gate (spec §9)
# --------------------------------------------------------------------------- #
def publish_artifact(artifact: Mapping[str, Any], *, store: pub.ContentStore) -> str:
    """Publish the artifact and READ IT BACK. Returns the ``evalReportHash``."""
    validate_artifact(artifact)
    return pub.publish_and_read_back(artifact, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                     store=store, expected_root=eval_report_hash(artifact))


def prepare_broadcastable_receipt(artifact: Mapping[str, Any], *, store: pub.ContentStore,
                                  expected_parent_root: str, expected_new_root: str,
                                  **verify_kwargs) -> Dict[str, Any]:
    """THE PRE-SIGN GATE. Returns the fields a coordinator may sign — or raises.

    §17.236 requires artifact availability as a PRE-SIGN requirement. In order, all fail-closed:

      1. :func:`verify_artifact` — every deterministic binding, against the CONFIRMED parent root;
      2. every required availability record is READ BACK from the publication surface (the
         candidate bundle, the composition manifest, the counter-resource law, the parent frontier
         manifest and the signed receipt) — fetched and rehashed, never read from local memory;
      3. the eval artifact itself is published and read back;
      4. only then are ``evalReportHash`` and the receipt's derived fields returned.

    A coordinator that signs without this has minted a receipt for evidence no validator can
    fetch: the chain would confirm a state whose replay permanently fails, which is the precise
    failure this gate exists to prevent. There is no bypass parameter.
    """
    verify_kwargs.setdefault("store", store)
    verify_kwargs.pop("check_availability", None)   # step 2 owns it, so it is always a PreSignError
    report = verify_artifact(artifact, expected_parent_root=expected_parent_root,
                             expected_new_root=expected_new_root, **verify_kwargs)
    try:
        required = (REQUIRED_AVAILABILITY_V1_SIGNED_ERA
                    if artifact_law(artifact) == al.LAW_OFF_CHAIN_SIGNATURE_V1
                    else REQUIRED_AVAILABILITY_V2)
        available = pub.verify_availability(
            artifact["availability"], store=store, required=required)
    except pub.PublicationError as exc:
        raise PreSignError(
            f"PRE-SIGN REFUSED — artifact availability is not satisfied: {exc}") from exc
    try:
        report_hash = publish_artifact(artifact, store=store)
    except pub.PublicationError as exc:
        raise PreSignError(
            f"PRE-SIGN REFUSED — the eval artifact itself failed publish-and-read-back: "
            f"{exc}") from exc
    front = artifact["frontier"]
    out: Dict[str, Any] = {
        "broadcastable": True,
        "eval_report_hash": report_hash,
        "available": available,
        "epoch": artifact["epoch"],
        "parent_frontier_root": front["parent_frontier_root"],
        "new_frontier_root": front["new_frontier_root"],
        "candidate_release_root": artifact["candidate"]["release_root"],
        "composition_root": front["composition_root"],
        "benchmark_law_root": front["benchmark_law_root"],
        "runtime_abi_root": front["runtime_abi_root"],
        "counter_resource_law_root": artifact["counter_resource_law_root"],
        "entropy_commitment": artifact["entropy"]["commitment"],
        "transition_hash": front["transition_hash_keccak256"],
        "transition_bytes_len": front["transition_bytes_len"],
        "target_profile": artifact["candidate"]["target_profile"],
        "utility_before_ppm": artifact["resource_accounting"]["utility_before_ppm"],
        "utility_after_ppm": artifact["resource_accounting"]["utility_after_ppm"],
        "resource_before_ppm": artifact["resource_accounting"]["resource_before_ppm"],
        "resource_after_ppm": artifact["resource_accounting"]["resource_after_ppm"],
        "verdict": report["verdict"],
    }
    # The nine RIG-protocol fields, in BOTH spellings, so the returned dict is directly the
    # `evaluation` object `coretex-memory-v5-worker-client.ts::decodeEvaluation` reads. When
    # `require_rig_receipt=True` was passed, verify_artifact has already refused their absence.
    if "rig_receipt" in artifact:
        out.update(rig_receipt_projection(artifact))
        out["rig_receipt_present"] = True
    else:
        out["rig_receipt_present"] = False
    return out


def transition_bytes_for(artifact: Mapping[str, Any]) -> bytes:
    """The exact ``transitionBytes`` a miner broadcasts for this artifact."""
    validate_artifact(artifact)
    return fr.canonical_bytes(artifact["frontier"]["transition"])


def artifact_json(artifact: Mapping[str, Any], *, indent: Optional[int] = None) -> str:
    """Human-readable rendering. NEVER the addressed form — that is
    :func:`artifact_canonical_bytes`, and only that."""
    validate_artifact(artifact)
    return json.dumps(artifact, sort_keys=True, indent=indent)
