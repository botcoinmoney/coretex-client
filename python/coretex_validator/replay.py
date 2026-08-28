# SPDX-License-Identifier: Apache-2.0
"""Independent replay of the one public descriptor-v3 transition format."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from . import eval_artifact as evaluation
from . import frontier
from . import parent_execution
from . import publication
from . import release as release_module
from . import rig_events
from .join import JoinedTransition

RESULT_FORMAT = "coretex.validator-replay/v1"


class ReplayError(ValueError):
    """A confirmed transition does not reproduce from its addressed public evidence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ReplayResult:
    epoch: int
    transition_index: int
    parent_state_root: str
    new_state_root: str
    patch_artifact_hash: str
    eval_report_hash: str
    checks: tuple[str, ...]
    evaluation: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "checks": list(self.checks),
            "epoch": self.epoch,
            "eval_report_hash": self.eval_report_hash,
            "evaluation": dict(self.evaluation),
            "format": RESULT_FORMAT,
            "new_state_root": self.new_state_root,
            "outcome": "PASS",
            "parent_state_root": self.parent_state_root,
            "patch_artifact_hash": self.patch_artifact_hash,
            "transition_index": self.transition_index,
        }


def replay_screener(*, screener: Any, parent_manifest: Mapping[str, Any],
                    release: release_module.ReleaseDirectory, epoch_parent_root: str,
                    evaluation_artifact: Mapping[str, Any],
                    evaluation_report: Mapping[str, Any],
                    epoch_context: Mapping[str, Any],
                    counter_resource_law: Mapping[str, Any],
                    store: publication.ContentStore, benchmark_runner: Any) -> Mapping[str, Any]:
    """Verify a credited outcome-1 receipt without pretending it advanced the frontier."""
    receipt = screener.receipt
    credit = screener.credit
    current_root = frontier.frontier_root(parent_manifest)
    checks = ["screener_receipt_join"]
    try:
        if receipt["epochId"] != credit.epoch \
                or receipt["parentStateRoot"] != current_root \
                or receipt["newStateRoot"] != current_root:
            raise ReplayError(
                "SCREENER_PARENT_MISMATCH",
                "screener receipt is not a no-transition evaluation of the exact current parent")
        pins = verify_epoch_context(
            epoch_context, credit.epoch, receipt["epochContextRoot"], release=release,
            active_frontier_root=epoch_parent_root)
        if receipt["coreVersionHash"] != release.release.raw["compatibility_lock_root"]:
            raise ReplayError(
                "CORE_VERSION_MISMATCH", "screener does not name the release compatibility lock")
        artifact_hash = evaluation.eval_report_hash(evaluation_artifact)
        if artifact_hash != receipt["artifactHash"] \
                or artifact_hash != receipt["evalReportHash"]:
            raise ReplayError(
                "EVALUATION_ADDRESS_MISMATCH",
                "screener signed receipt and evaluation artifact do not share one address")
        candidate = evaluation_artifact.get("candidate")
        front = evaluation_artifact.get("frontier")
        if not isinstance(candidate, Mapping) or not isinstance(front, Mapping):
            raise ReplayError("EVALUATION_INVALID", "screener artifact lacks candidate/frontier")
        profile = candidate.get("target_profile")
        rig_fields = evaluation.rig_receipt_fields(evaluation_artifact)
        bindings = {
            "challenge_id": "challengeId",
            "core_version_hash": "coreVersionHash",
            "epoch_context_root": "epochContextRoot",
            "outcome": "outcome",
            "rules_version": "rulesVersion",
            "transition_format_version": "transitionFormatVersion",
            "work_policy_hash": "workPolicyHash",
            "world_seed": "worldSeed",
        }
        for artifact_field, receipt_field in bindings.items():
            if rig_fields[artifact_field] != receipt[receipt_field]:
                raise ReplayError(
                    "EVALUATION_RECEIPT_MISMATCH",
                    f"screener evaluation {artifact_field} differs from signed receipt")
        projection = evaluation_artifact.get("admission_projection")
        if not isinstance(projection, Mapping) \
                or projection.get("score_before_ppm") != receipt["scoreBeforePpm"] \
                or projection.get("score_after_ppm") != receipt["scoreAfterPpm"]:
            raise ReplayError(
                "EVALUATION_RECEIPT_MISMATCH",
                "screener evaluation admission_projection differs from signed receipt")
        report = evaluation.verify_artifact(
            evaluation_artifact,
            expected_parent_root=current_root,
            expected_new_root=current_root,
            expected_release_root=candidate["release_root"],
            expected_composition_root=front["composition_root"],
            expected_runtime_abi_root=pins["runtime_abi_root"],
            expected_benchmark_law_root=pins["benchmark_law_root"],
            expected_counter_resource_law_root=evaluation.counter_resource_law_root(
                counter_resource_law),
            expected_epoch=credit.epoch,
            expected_target_profile=profile,
            eval_report=evaluation_report,
            counter_resource_law=counter_resource_law,
            store=store,
            check_availability=True,
            require_rig_receipt=True,
            expected_epoch_context_root=receipt["epochContextRoot"],
            expected_core_version_hash=receipt["coreVersionHash"],
            expected_work_policy_hash=receipt["workPolicyHash"],
            resolve_witness_source=True)
        checks.append("fixed_suite_evaluation")
        reference_roots = {
            profile_id: row["root"]
            for profile_id, row in release.release.raw["genesis"]["profile_releases"].items()
        }
        incumbent = parent_execution.fetch_parent_execution(
            store=store, parent_manifest=parent_manifest, target_profile=profile,
            fr_module=frontier, pub_module=publication,
            reference_release_roots=reference_roots, validate_runtime=True,
            runtime_validator=benchmark_runner.validate_execution)
        if parent_execution.compact_identity(incumbent) \
                != evaluation_artifact["replay_inputs"]["incumbent"]:
            raise ReplayError(
                "INCUMBENT_EXECUTION_MISMATCH",
                "screener was evaluated against another execution than the current parent")
        report_candidate = evaluation_report.get("candidate")
        report_module = report_candidate.get("module") \
            if isinstance(report_candidate, Mapping) else None
        availability = evaluation_artifact["availability"]
        for kind, expected_root, expected_rule in (
                ("candidate_bundle", candidate["release_root"],
                 publication.HASH_RULE_MANIFEST_BODY),
                ("candidate_module", report_module.get("sha256")
                 if isinstance(report_module, Mapping) else None, publication.HASH_RULE_BYTES),
                ("candidate_adapter_module", report_module.get("sha256")
                 if isinstance(report_module, Mapping) else None, publication.HASH_RULE_BYTES),
                ("composition_manifest", front["composition_root"],
                 publication.HASH_RULE_MANIFEST_BODY)):
            item = availability.get(kind)
            if not isinstance(item, Mapping) or item.get("root") != expected_root \
                    or item.get("hash_rule") != expected_rule:
                raise ReplayError(
                    "EVALUATION_INSTALLATION_MISMATCH",
                    f"screener availability.{kind} is not the scored object")
        benchmark_runner.replay_report(
            evaluation_report,
            expected_root=evaluation_artifact["receipt"]["eval_report_root"],
            incumbent_execution=incumbent)
        checks.append("fixed_suite_reexecution")
        return {"checks": checks, "evaluation": report, "parent_state_root": current_root}
    except ReplayError:
        raise
    except (evaluation.EvalArtifactError, frontier.FrontierError,
            parent_execution.ParentExecutionError, publication.PublicationError,
            rig_events.RigEventError) as exc:
        raise ReplayError(str(getattr(exc, "code", type(exc).__name__)), str(exc)) from exc


def _root(value: Any, where: str) -> str:
    try:
        return frontier.check_root(value, where)
    except frontier.FrontierError as exc:
        raise ReplayError("INPUT_INVALID", str(exc)) from exc


def verify_epoch_context(value: Any, epoch: int, epoch_context_root: str, *,
                         release: release_module.ReleaseDirectory,
                         active_frontier_root: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReplayError("EPOCH_CONTEXT_INVALID", "epoch context must be an object")
    fields = {
        "active_frontier_root", "admission_thresholds_ppm", "baseline_manifest_hash",
        "benchmark_law_root", "corpus_root", "counter_resource_law_root", "epoch", "format",
        "runtime_abi_root", "seed_commitment", "selection_law_root"}
    if set(value) != fields or value.get("format") != rig_events.EPOCH_CONTEXT_FORMAT:
        raise ReplayError("EPOCH_CONTEXT_INVALID", "epoch context has another or open schema")
    if value.get("epoch") != epoch:
        raise ReplayError(
            "EPOCH_CONTEXT_INVALID", f"epoch context is for {value.get('epoch')}, not {epoch}")
    observed = frontier.sha256_hex(frontier.canonical_bytes(dict(value)))
    if observed != epoch_context_root:
        raise ReplayError(
            "EPOCH_CONTEXT_INVALID",
            f"epoch context hashes to {observed}, chain commits {epoch_context_root}")
    expected_roots = {
        "active_frontier_root": active_frontier_root,
        "baseline_manifest_hash": release.release.raw["genesis"]["baseline_root"],
        "benchmark_law_root": release.release.raw["law"]["benchmark_law_root"],
        "corpus_root": release.release.raw["law"]["canonical_suite_root"],
        "counter_resource_law_root":
            release.release.raw["objects"]["counter_resource_law_root"]["root"],
        "runtime_abi_root": release.release.raw["objects"]["miner_module_abi_root"]["root"],
        "selection_law_root": release.release.raw["law"]["evaluation_law_root"],
    }
    for field, expected in expected_roots.items():
        if value[field] != expected:
            raise ReplayError(
                "EPOCH_CONTEXT_INVALID",
                f"epoch context {field}={value[field]} but release requires {expected}")
    thresholds = value["admission_thresholds_ppm"]
    if thresholds != {
            "maximum_resource_regression_ppm": 0,
            "minimum_utility_improvement_ppm": 1}:
        raise ReplayError(
            "EPOCH_CONTEXT_INVALID", "epoch context has another admission threshold set")
    seed = value["seed_commitment"]
    if seed != {
            "binding_rule":
                "revealed secret S is admitted iff keccak256(S) == epochCommit(epochId)",
            "commitment_source": "mining.epochCommit(epochId)",
            "scheme": "keccak256-hidden-seed/v1"}:
        raise ReplayError("EPOCH_CONTEXT_INVALID", "epoch context has another seed scheme")
    return {
        "benchmark_law_root": _root(value["benchmark_law_root"], "benchmark_law_root"),
        "epoch": epoch,
        "epoch_context_root": epoch_context_root,
        "runtime_abi_root": _root(value["runtime_abi_root"], "runtime_abi_root"),
    }


def pre_sign_reexecute(*, evaluation_artifact: Mapping[str, Any],
                       evaluation_report: Mapping[str, Any],
                       release: release_module.ReleaseDirectory,
                       store: publication.ContentStore,
                       benchmark_runner: Any,
                       child_manifest: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
    """Reproduce the score and installed execution before a coordinator signature.

    The caller first runs :func:`eval_artifact.verify_artifact`; this shared second stage owns
    execution, not another copy of artifact algebra. It resolves the exact public incumbent,
    reruns the release-bound benchmark, and proves the child installs precisely the scored module
    while every non-target execution remains unchanged. Confirmed replay calls the same function.
    """
    try:
        candidate = evaluation_artifact.get("candidate")
        front = evaluation_artifact.get("frontier")
        replay_inputs = evaluation_artifact.get("replay_inputs")
        availability = evaluation_artifact.get("availability")
        if not all(isinstance(value, Mapping) for value in (
                candidate, front, replay_inputs, availability)):
            raise ReplayError(
                "EVALUATION_INVALID",
                "pre-sign reexecution needs candidate/frontier/replay_inputs/availability")
        profile = candidate.get("target_profile")
        parent = replay_inputs.get("parent_manifest")
        transition = front.get("transition")
        if not isinstance(profile, str) or not isinstance(parent, Mapping) \
                or not isinstance(transition, Mapping):
            raise ReplayError(
                "EVALUATION_INVALID", "pre-sign reexecution lacks its profile/parent/transition")
        if frontier.frontier_root(parent) != front.get("parent_frontier_root"):
            raise ReplayError(
                "INCUMBENT_EXECUTION_MISMATCH",
                "the carried parent manifest does not reproduce the artifact parent root")
        derived_child = frontier.apply_transition(
            parent, transition, epoch=evaluation_artifact.get("epoch"),
            epoch_pins={
                "benchmark_law_root": front.get("benchmark_law_root"),
                "runtime_abi_root": front.get("runtime_abi_root"),
            })
        if frontier.frontier_root(derived_child) != front.get("new_frontier_root"):
            raise ReplayError(
                "EVALUATION_INSTALLATION_MISMATCH",
                "the artifact transition does not reproduce its child frontier")
        if child_manifest is not None:
            if frontier.frontier_root(child_manifest) != front.get("new_frontier_root") \
                    or dict(child_manifest) != derived_child:
                raise ReplayError(
                    "EVALUATION_INSTALLATION_MISMATCH",
                    "the independently replayed child differs from the evaluation child")
            child = dict(child_manifest)
        else:
            child = derived_child

        reference_roots = {
            profile_id: row["root"]
            for profile_id, row in release.release.raw["genesis"]["profile_releases"].items()
        }
        incumbent = parent_execution.fetch_parent_execution(
            store=store, parent_manifest=parent, target_profile=profile,
            fr_module=frontier, pub_module=publication,
            reference_release_roots=reference_roots, validate_runtime=True,
            runtime_validator=benchmark_runner.validate_execution)
        compact_incumbent = parent_execution.compact_identity(incumbent)
        if compact_incumbent != replay_inputs.get("incumbent"):
            raise ReplayError(
                "INCUMBENT_EXECUTION_MISMATCH",
                "the report was scored against another execution than the public parent")

        report_candidate = evaluation_report.get("candidate")
        report_module = report_candidate.get("module") \
            if isinstance(report_candidate, Mapping) else None
        required_cross_pins = {
            "candidate_bundle": (
                candidate.get("release_root"), publication.HASH_RULE_MANIFEST_BODY),
            "candidate_module": (
                report_module.get("sha256") if isinstance(report_module, Mapping) else None,
                publication.HASH_RULE_BYTES),
            "candidate_adapter_module": (
                report_module.get("sha256") if isinstance(report_module, Mapping) else None,
                publication.HASH_RULE_BYTES),
            "composition_manifest": (
                transition.get("resulting_composition_root"),
                publication.HASH_RULE_MANIFEST_BODY),
            "parent_frontier_manifest": (
                front.get("parent_frontier_root"), publication.HASH_RULE_FRONTIER_JSON),
            "resulting_frontier_manifest": (
                front.get("new_frontier_root"), publication.HASH_RULE_FRONTIER_JSON),
        }
        for kind, (expected_root, expected_rule) in required_cross_pins.items():
            item = availability.get(kind)
            if not isinstance(item, Mapping) or item.get("root") != expected_root \
                    or item.get("hash_rule") != expected_rule:
                raise ReplayError(
                    "EVALUATION_INSTALLATION_MISMATCH",
                    f"availability.{kind} is not the scored/installed object")
            publication.read_back(
                expected_root, hash_rule=expected_rule, store=store,
                expected_bytes_len=item.get("bytes"))

        witness = evaluation_artifact.get("determinism_witness")
        if not isinstance(witness, Mapping) or "partitions" not in witness:
            raise ReplayError(
                "PARENT_STORED_VECTOR_MISSING",
                "pre-sign reexecution needs the artifact-bound determinism_witness as "
                "parent_stored_vector; replay without it cannot reproduce issue-time E")
        benchmark_result = benchmark_runner.replay_report(
            evaluation_report,
            expected_root=evaluation_artifact["receipt"]["eval_report_root"],
            incumbent_execution=incumbent,
            parent_stored_vector=dict(witness))

        child_executions = {}
        parent_executions = {}
        for profile_id in sorted(parent["profiles"]):
            parent_executions[profile_id] = parent_execution.fetch_parent_execution(
                store=store, parent_manifest=parent, target_profile=profile_id,
                fr_module=frontier, pub_module=publication,
                reference_release_roots=reference_roots, validate_runtime=True,
                runtime_validator=benchmark_runner.validate_execution)
            child_executions[profile_id] = parent_execution.fetch_parent_execution(
                store=store, parent_manifest=child, target_profile=profile_id,
                fr_module=frontier, pub_module=publication,
                reference_release_roots=reference_roots, validate_runtime=True,
                runtime_validator=benchmark_runner.validate_execution)
            if profile_id != profile and parent_execution.compact_identity(
                    parent_executions[profile_id]) != parent_execution.compact_identity(
                        child_executions[profile_id]):
                raise ReplayError(
                    "NON_TARGET_EXECUTION_CHANGED",
                    f"transition changed non-target public execution {profile_id}")
        installed = child_executions[profile]
        installed_module = installed.get("module")
        if installed.get("exec") != "candidate_module" \
                or installed.get("release_root") != candidate.get("release_root") \
                or installed.get("candidate_hash") != candidate.get("candidate_hash") \
                or not isinstance(installed_module, Mapping) \
                or not isinstance(report_module, Mapping) \
                or installed_module.get("sha256") != report_module.get("sha256") \
                or installed_module.get("source") != report_module.get("source"):
            raise ReplayError(
                "EVALUATION_INSTALLATION_MISMATCH",
                "the child frontier installs different candidate/module bytes than were scored")
        return {
            "benchmark": dict(benchmark_result),
            "checks": [
                "exact_public_incumbent", "fixed_suite_reexecution",
                "availability_installation_cross_pins", "non_target_executions_unchanged",
                "installed_execution_binding",
            ],
            "incumbent": compact_incumbent,
            "installed": parent_execution.compact_identity(installed),
            "ok": True,
        }
    except ReplayError:
        raise
    except (evaluation.EvalArtifactError, frontier.FrontierError,
            parent_execution.ParentExecutionError, publication.PublicationError) as exc:
        code = getattr(exc, "code", type(exc).__name__)
        raise ReplayError(str(code), str(exc)) from exc


def replay_descriptor_v3(*, joined: JoinedTransition, parent_manifest: Mapping[str, Any],
                         release: release_module.ReleaseDirectory,
                         epoch_parent_root: str,
                         transition_artifact_bytes: bytes,
                         evaluation_artifact: Mapping[str, Any],
                         evaluation_report: Mapping[str, Any],
                         epoch_context: Mapping[str, Any],
                         counter_resource_law: Mapping[str, Any],
                         store: Optional[publication.ContentStore] = None,
                         component_references: Optional[Mapping[str, Any]] = None,
                         require_availability: bool = True,
                         resolve_witness_source: bool = True,
                         benchmark_runner: Any) -> ReplayResult:
    """Replay one fully joined state advance against only chain-bound public inputs.

    ``joined`` must already have passed calldata/log/signature joining.  This function then
    decodes the sole 97-byte descriptor, resolves its addressed transition artifact, reproduces
    the resulting frontier, and verifies the fixed-suite evaluation artifact and report.
    """
    advance = joined.advance
    receipt = joined.receipt
    checks: list[str] = []
    try:
        descriptor = rig_events.decode_transition_descriptor(
            advance.compact_patch_bytes,
            expected_patch_hash=advance.patch_hash,
            parent_state_root=advance.parent_state_root,
            new_state_root=advance.new_state_root,
            transition_format_version=advance.transition_format_version)
        checks.append("descriptor_v3")
        score_delta = int(receipt["scoreAfterPpm"]) - int(receipt["scoreBeforePpm"])
        transition = rig_events.verify_transition_artifact_bytes(
            transition_artifact_bytes, descriptor=descriptor, score_delta_ppm=score_delta,
            epoch_context_root_=advance.epoch_context_root)
        checks.append("transition_artifact_address")
        pins = verify_epoch_context(
            epoch_context, advance.epoch, advance.epoch_context_root, release=release,
            active_frontier_root=epoch_parent_root)
        if advance.core_version_hash != release.release.raw["compatibility_lock_root"]:
            raise ReplayError(
                "CORE_VERSION_MISMATCH",
                "confirmed advance does not name the release compatibility lock")
        child = rig_events.replay_transition_artifact(
            parent_manifest, transition, epoch_pins=pins,
            component_references=component_references)
        if frontier.frontier_root(child) != advance.new_state_root:
            raise ReplayError(
                "TRANSITION_REPLAY_MISMATCH", "transition did not reproduce the confirmed root")
        checks.append("transition_replay")

        artifact_hash = evaluation.eval_report_hash(evaluation_artifact)
        if artifact_hash != advance.eval_report_hash \
                or receipt["artifactHash"] != artifact_hash \
                or receipt["evalReportHash"] != artifact_hash:
            raise ReplayError(
                "EVALUATION_ADDRESS_MISMATCH",
                "chain event, signed receipt, and evaluation artifact do not share one address")
        candidate = evaluation_artifact.get("candidate")
        front = evaluation_artifact.get("frontier")
        if not isinstance(candidate, Mapping) or not isinstance(front, Mapping):
            raise ReplayError("EVALUATION_INVALID", "evaluation artifact lacks candidate/frontier")
        profile = candidate.get("target_profile")
        moves = transition.get("profile_releases")
        move = moves.get(profile) if isinstance(moves, Mapping) else None
        if not isinstance(move, Mapping) or move.get("new_release_root") \
                != candidate.get("release_root"):
            raise ReplayError(
                "EVALUATION_TRANSITION_MISMATCH",
                "evaluation candidate is not the release installed by the transition artifact")
        if transition.get("resulting_composition_root") != front.get("composition_root"):
            raise ReplayError(
                "EVALUATION_TRANSITION_MISMATCH",
                "evaluation and transition name different resulting compositions")
        rig_fields = evaluation.rig_receipt_fields(evaluation_artifact)
        receipt_bindings = {
            "challenge_id": "challengeId",
            "core_version_hash": "coreVersionHash",
            "epoch_context_root": "epochContextRoot",
            "outcome": "outcome",
            "rules_version": "rulesVersion",
            "transition_format_version": "transitionFormatVersion",
            "work_policy_hash": "workPolicyHash",
            "world_seed": "worldSeed",
        }
        for artifact_field, receipt_field in receipt_bindings.items():
            if rig_fields[artifact_field] != receipt[receipt_field]:
                raise ReplayError(
                    "EVALUATION_RECEIPT_MISMATCH",
                    f"evaluation {artifact_field} does not equal signed {receipt_field}")
        projection = evaluation_artifact.get("admission_projection")
        if not isinstance(projection, Mapping) \
                or projection.get("score_before_ppm") != receipt["scoreBeforePpm"] \
                or projection.get("score_after_ppm") != receipt["scoreAfterPpm"]:
            raise ReplayError(
                "EVALUATION_RECEIPT_MISMATCH",
                "evaluation admission_projection does not equal the signed before/after scores")
        report = evaluation.verify_artifact(
            evaluation_artifact,
            expected_parent_root=advance.parent_state_root,
            expected_new_root=advance.new_state_root,
            expected_release_root=candidate["release_root"],
            expected_composition_root=transition["resulting_composition_root"],
            expected_runtime_abi_root=pins["runtime_abi_root"],
            expected_benchmark_law_root=pins["benchmark_law_root"],
            expected_counter_resource_law_root=evaluation.counter_resource_law_root(
                counter_resource_law),
            expected_epoch=advance.epoch,
            expected_target_profile=profile,
            eval_report=evaluation_report,
            counter_resource_law=counter_resource_law,
            store=store,
            check_availability=require_availability,
            require_rig_receipt=True,
            expected_epoch_context_root=advance.epoch_context_root,
            expected_core_version_hash=advance.core_version_hash,
            expected_work_policy_hash=receipt["workPolicyHash"],
            resolve_witness_source=resolve_witness_source)
        checks.append("fixed_suite_evaluation")

        if store is None:
            raise ReplayError(
                "PUBLIC_EVIDENCE_REQUIRED",
                "full fixed-suite replay needs the release/composition/module object store")
        reexecution = pre_sign_reexecute(
            evaluation_artifact=evaluation_artifact,
            evaluation_report=evaluation_report,
            release=release,
            store=store,
            benchmark_runner=benchmark_runner,
            child_manifest=child,
        )
        checks.extend(reexecution["checks"])
    except ReplayError:
        raise
    except (evaluation.EvalArtifactError, frontier.FrontierError,
            parent_execution.ParentExecutionError, publication.PublicationError,
            rig_events.RigEventError) as exc:
        code = getattr(exc, "code", type(exc).__name__)
        raise ReplayError(str(code), str(exc)) from exc
    return ReplayResult(
        epoch=advance.epoch,
        transition_index=advance.transition_index,
        parent_state_root=advance.parent_state_root,
        new_state_root=advance.new_state_root,
        patch_artifact_hash=descriptor.patch_artifact_hash,
        eval_report_hash=advance.eval_report_hash,
        checks=tuple(checks),
        evaluation=report)


__all__ = [
    "RESULT_FORMAT", "ReplayError", "ReplayResult", "pre_sign_reexecute",
    "replay_descriptor_v3",
    "replay_screener",
    "verify_epoch_context",
]
