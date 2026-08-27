#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""V5-side mirror of the immutable CANONICAL SUITE (LAW §3A.1).

The authority is ``benchmark-v2/validator/CANONICAL-SUITE.v1.json`` and its loader
``benchmark-v2/validator/canonical_suite.py``. This module reads the SAME FILE, from the same
repo-relative path, and enforces the SAME CLOSED SCHEMA. ``parent_execution`` reads the sealed
genesis reference roots from this same document: there is no parallel parent-authority file.
``eval_artifact`` must remain importable without the ``benchmark-v2`` packages on ``sys.path``
(the standalone validator distribution imports it directly), while the benchmark loader needs
``frontier.profiles`` to cross-bind the protected objective vocabulary.

WHY THE VALIDATION IS DUPLICATED RATHER THAN THINNED. An earlier revision of this module checked
only the handful of fields the artifact layer reads, on the reasoning that "the two loaders read
one file and the suite ROOT is the sha256 of its bytes, so a divergence is a hash mismatch". That
reasoning is wrong wherever the two loaders are asked about DIFFERENT bytes — which is every replay
of a document that is not this tree's, every doctored-suite probe, and every standalone validator
running against a suite it was handed. A mirror that accepts a document the law refuses is not a
mirror; it is a second, weaker law. So every rule the benchmark loader enforces is enforced here:
the closed top-level/profile/case field sets, partition disjointness, the ``profile@scale#seed``
instance-id triple, the protected vocabulary, and full vector validation of a RESOLVED floor.

THE ONE CROSS-BINDING THAT CANNOT BE RE-DERIVED HERE is the profile registry
(``frontier.profiles``), which lives in ``benchmark-v2`` and must not become an import requirement.
It is mirrored as :data:`PROTECTED_QUALITY_VOCABULARY`, a sealed table, and
``v5/tests/test_canonical_suite_mirror.py`` runs the registry in a child interpreter and fails if
the table has drifted. The registry stays the single authority; this table is a checked copy.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from typing import Any, Dict, Tuple

SUITE_FORMAT = "benchmark-v2/canonical-suite/v1"
PARTITIONS = ("gate", "confirm")

#: The closed top-level field set of the suite document. Mirror of
#: ``benchmark-v2/validator/canonical_suite.SUITE_FIELDS``.
SUITE_FIELDS = frozenset({
    "aggregation", "committed_before_first_public_candidate", "decision_engine", "format",
    "genesis_floor_authority", "instance_hash_rule", "law_id", "profiles",
    "protected_resource_axes", "provenance", "scales_claimed", "case_authority",
    "slice_threshold_corpus_events", "suite_version", "why",
})

#: The closed field set of one per-profile suite block.
PROFILE_FIELDS = frozenset({
    "confirm", "counts", "gate", "profile_id", "profile_version",
    "protected_quality_objectives", "protected_resource_axes", "scales", "suite_version",
})

#: The closed field set of one suite CASE as the document stores it. ``suite_index`` is DERIVED
#: (the case's position in its partition) and is never stored.
CASE_FIELDS = frozenset({"instance_hash", "instance_id", "profile_id", "scale", "seed"})

#: The closed field set of one ABSOLUTE VECTOR (LAW §3A.2) — the DETERMINISTIC subset only.
#: Identical to ``benchmark-v2/validator/canonical_suite.VECTOR_FIELDS``; latency, compute and the
#: host profile are telemetry and are deliberately absent.
VECTOR_FIELDS = ("composite_micro", "logical_durable_storage_bytes", "objectives_micro",
                 "rendered_cost_micro", "work_fuel")

GENESIS_SOURCE_FIELDS = frozenset(
    {"qualification", "exec", "measurement", "policy", "profiles"})
GENESIS_REFERENCE_FIELDS = frozenset({"exec", "reference_runtime", "release_root"})

#: The three protected RAW resource axes of LAW §3A.2, lower-is-better, in the document's order.
PROTECTED_RESOURCE_AXES = ("rendered_cost", "work_fuel", "logical_durable_storage_bytes")

#: MIRROR of ``frontier.profiles.get_profile(pid).objectives`` — the registry is the authority and
#: this table is a checked copy (see the module docstring; the drift test is
#: ``v5/tests/test_canonical_suite_mirror.py::test_the_mirrored_vocabulary_is_the_registrys``).
PROTECTED_QUALITY_VOCABULARY: Dict[str, Tuple[str, ...]] = {
    "conv.pref.v1": ("abstention", "alias_resolution", "asof_correctness",
                     "conflict_supersession", "evidence_support", "multihop_completeness",
                     "provenance_citations", "retraction_disclosure", "selective_forgetting"),
    "doc.tool.v1": ("abstention", "asof_correctness", "conflict_supersession", "consolidation",
                    "evidence_support", "multihop_completeness", "provenance_citations",
                    "retraction_disclosure", "workflow_provenance"),
    "event.schema.v1": ("abstention", "asof_correctness", "conflict_supersession",
                        "evidence_support", "exact_lookup", "join_completeness",
                        "multihop_completeness", "provenance_citations", "retraction_disclosure",
                        "schema_evolution"),
}

#: Refusal codes, stated once so the worker and the validator name the same string.
GENESIS_FLOOR_PENDING = "GENESIS_FLOOR_PENDING"
CANONICAL_SUITE_INVALID = "CANONICAL_SUITE_INVALID"

#: THE FIXED ROUND IDENTITY OF THE FIXED SUITE (LAW §3A.4), mirrored from
#: ``benchmark-v2/validator/evaluation_law``. ``round_id`` once incorporated the caller's
#: transport-only ``candidate_id`` and thereby let identical candidate bytes receive different
#: exams. The public suite has one content-independent round id; author identity is not part of
#: the exam or receipt at all.
FIXED_SUITE_ROUND_ID = "coretex.fixed-suite/round/v1"

#: The inert entropy constants. Derived from a fixed domain string and NOTHING else — no secret, no
#: epoch, no parent root, no candidate.
FIXED_SUITE_ENTROPY_DOMAIN = "coretex.fixed-suite/inert-entropy/v1"

#: THE CLOSED HARD-GATE VOCABULARY — mirror of
#: ``benchmark-v2/validator/report_body.HARD_GATE_VOCABULARY`` (itself derived from
#: ``frontier.gates.GATE_NAMES`` plus the ``profile_floors`` clause both engines append). It is a
#: sealed table here for the same reason :data:`PROTECTED_QUALITY_VOCABULARY` is: the artifact
#: layer must stay importable without ``benchmark-v2``, and ``frontier.gates`` lives there.
#:
#: WHY IT IS CLOSED AT ALL. The artifact layer used to accept ANY non-empty hard map whose values
#: rolled up consistently with ``hard_ok`` — so a report could drop the gates that failed, state
#: the rest true, and self-consistently reach a signature. A hard map is not a set of claims a
#: report chooses; it is exactly these eight names, recomputed by the law.
#: ``v5/tests/test_canonical_suite_mirror.py::test_the_mirrored_hard_gate_vocabulary_is_the_
#: sealed_laws`` reads ``frontier.gates`` in a child interpreter and fails if this table
#: drifts from it. (That assertion was ADDED at remediation round 3: this comment claimed it
#: for one revision before any such check existed, and renaming a gate left the file green.)
HARD_GATE_VOCABULARY: Tuple[str, ...] = (
    "canonical_event_integrity",
    "declared_resource_limits",
    "deterministic_replay",
    "host_portability_matrix",
    "profile_floors",
    "provenance",
    "validity",
    "zero_stale_retracted_disclosure",
)


class CanonicalSuiteError(RuntimeError):
    code = CANONICAL_SUITE_INVALID


class GenesisFloorPendingError(CanonicalSuiteError):
    code = GENESIS_FLOOR_PENDING


def fixed_suite_entropy(label: str) -> str:
    """``sha256(domain|label)`` — a public constant, identical in every job, forever."""
    if label not in PARTITIONS:
        raise ValueError(f"label must be 'gate' or 'confirm', got {label!r}")
    return hashlib.sha256(f"{FIXED_SUITE_ENTROPY_DOMAIN}|{label}".encode("utf-8")).hexdigest()


def suite_path() -> str:
    """The wheel-vendored suite bytes bound independently by the external release graph."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "CANONICAL-SUITE.v1.json")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdef" for char in value)


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise CanonicalSuiteError(message)


def _check_case(case: Any, profile_id: str, where: str) -> None:
    _require(isinstance(case, dict) and frozenset(case) == CASE_FIELDS,
             f"{where} must be exactly {sorted(CASE_FIELDS)}")
    _require(case["profile_id"] == profile_id,
             f"{where} declares profile {case['profile_id']!r}, not {profile_id!r}")
    seed = case["seed"]
    _require(isinstance(seed, int) and not isinstance(seed, bool) and 0 <= seed < 2 ** 31,
             f"{where}.seed must be a non-negative int below 2**31")
    _require(isinstance(case["scale"], str) and case["scale"], f"{where}.scale must be a string")
    _require(case["instance_id"] == f"{profile_id}@{case['scale']}#s{seed}",
             f"{where}.instance_id is not the canonical validator.select.instance_id triple")
    _require(_is_sha256(case["instance_hash"]), f"{where}.instance_hash must be sha256 hex")


def validate_vector(vector: Any, profile_id: str, where: str, declared=None) -> Dict[str, Any]:
    """Fail-closed validation of one ABSOLUTE VECTOR (LAW §3A.2), returned as a deep copy.

    Mirror of ``benchmark-v2/validator/canonical_suite.validate_vector``: every component is an
    exact non-negative integer, and ``objectives_micro`` must carry EXACTLY the profile's declared
    objective set — a missing objective is not "unprotected", it is a malformed vector.
    """
    _require(isinstance(vector, dict) and frozenset(vector) == frozenset(VECTOR_FIELDS),
             f"{where} must be exactly {sorted(VECTOR_FIELDS)}")
    for field in ("composite_micro", "logical_durable_storage_bytes", "rendered_cost_micro",
                  "work_fuel"):
        value = vector[field]
        _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
                 f"{where}.{field} must be a non-negative integer")
    objectives = vector["objectives_micro"]
    _require(isinstance(objectives, dict) and objectives,
             f"{where}.objectives_micro must be a non-empty object")
    for name, value in objectives.items():
        _require(isinstance(name, str) and name, f"{where}.objectives_micro has a non-string key")
        _require(isinstance(value, int) and not isinstance(value, bool),
                 f"{where}.objectives_micro[{name!r}] must be an integer")
    if declared is None:
        declared = _profile(profile_id)["protected_quality_objectives"]
    _require(sorted(objectives) == sorted(declared),
             f"{where}.objectives_micro covers {sorted(objectives)}, the profile protects "
             f"{sorted(declared)}")
    return copy.deepcopy(vector)


def _validate(document: Any) -> Dict[str, Any]:
    """The CLOSED schema of LAW §3A.1 — the same rules the benchmark loader enforces."""
    _require(isinstance(document, dict) and frozenset(document) == SUITE_FIELDS,
             "canonical suite has an unknown or open schema")
    _require(document["format"] == SUITE_FORMAT,
             f"canonical suite format {document.get('format')!r} is not {SUITE_FORMAT!r}")
    _require(isinstance(document["law_id"], str) and document["law_id"],
             "canonical suite carries no law_id")
    _require(isinstance(document["decision_engine"], str) and document["decision_engine"],
             "canonical suite carries no decision_engine id")
    _require(document["committed_before_first_public_candidate"] is True,
             "canonical suite must record that it was fixed before the first public candidate")

    axes = document["protected_resource_axes"]
    _require(isinstance(axes, list) and tuple(axes) == PROTECTED_RESOURCE_AXES,
             f"canonical suite protected_resource_axes must be {list(PROTECTED_RESOURCE_AXES)}")
    scales_claimed = document["scales_claimed"]
    _require(isinstance(scales_claimed, list) and scales_claimed
             and all(isinstance(s, str) and s for s in scales_claimed),
             "canonical suite scales_claimed must be a non-empty array of strings")

    profiles = document["profiles"]
    _require(isinstance(profiles, dict) and profiles,
             "canonical suite profiles must be a non-empty object")
    for profile_id, block in profiles.items():
        where = f"canonical suite profiles[{profile_id!r}]"
        _require(isinstance(block, dict) and frozenset(block) == PROFILE_FIELDS,
                 f"{where} must be exactly {sorted(PROFILE_FIELDS)}")
        _require(block["profile_id"] == profile_id, f"{where}.profile_id disagrees with its key")
        _require(tuple(block["protected_resource_axes"]) == PROTECTED_RESOURCE_AXES,
                 f"{where}.protected_resource_axes must be {list(PROTECTED_RESOURCE_AXES)}")
        declared = block["protected_quality_objectives"]
        _require(isinstance(declared, list) and declared
                 and all(isinstance(o, str) and o for o in declared)
                 and len(set(declared)) == len(declared),
                 f"{where}.protected_quality_objectives must be unique non-empty strings")
        # THE VOCABULARY IS CROSS-BOUND, not restated — against the mirrored registry table, which
        # a drift test keeps equal to ``frontier.profiles``. A suite that protected a different set
        # from the one the profile registry declares would silently narrow or widen the law.
        registry = PROTECTED_QUALITY_VOCABULARY.get(profile_id)
        _require(registry is not None,
                 f"{where} names a profile the registry mirror does not serve; the V5 mirror is "
                 f"sealed for {sorted(PROTECTED_QUALITY_VOCABULARY)}")
        _require(sorted(declared) == sorted(registry),
                 f"{where}.protected_quality_objectives {sorted(declared)} != the profile "
                 f"registry's declared objective set {sorted(registry)}")
        scales = block["scales"]
        _require(isinstance(scales, list) and scales
                 and all(s in scales_claimed for s in scales),
                 f"{where}.scales must be a non-empty subset of scales_claimed")
        counts = block["counts"]
        _require(isinstance(counts, dict) and set(counts) == set(PARTITIONS),
                 f"{where}.counts must be exactly {list(PARTITIONS)}")
        seen = set()
        for partition in PARTITIONS:
            cases = block[partition]
            _require(isinstance(cases, list) and cases,
                     f"{where}[{partition!r}] must be a non-empty array of cases")
            declared_count = counts[partition]
            _require(isinstance(declared_count, int) and not isinstance(declared_count, bool)
                     and declared_count == len(cases),
                     f"{where}.counts[{partition!r}] is {declared_count!r}, the partition holds "
                     f"{len(cases)} cases")
            for index, case in enumerate(cases):
                _check_case(case, profile_id, f"{where}[{partition!r}][{index}]")
                _require(case["scale"] in scales,
                         f"{where}[{partition!r}][{index}].scale is not a declared suite scale")
                _require(case["instance_id"] not in seen,
                         f"{where} repeats instance {case['instance_id']!r}; the gate and confirm "
                         "partitions are disjoint by construction")
                seen.add(case["instance_id"])

    floor = document["genesis_floor_authority"]
    _require(isinstance(floor, dict) and floor,
             "canonical suite genesis_floor_authority must be an object")
    status = floor.get("status")
    _require(status in ("pending", "resolved"),
             f"canonical suite genesis_floor_authority.status {status!r} must be 'pending' or "
             "'resolved'")
    if status == "resolved":
        vectors = floor.get("vectors")
        _require(isinstance(vectors, dict) and set(vectors) == set(profiles),
                 "a resolved genesis floor must carry a vector block for every suite profile")
        for profile_id, partitions in vectors.items():
            _require(isinstance(partitions, dict) and set(partitions) == set(PARTITIONS),
                     f"genesis floor vectors[{profile_id!r}] must carry both partitions")
            for partition in PARTITIONS:
                validate_vector(partitions[partition], profile_id,
                                f"genesis floor vectors[{profile_id!r}][{partition!r}]",
                                declared=profiles[profile_id]["protected_quality_objectives"])
        source = floor.get("source")
        _require(isinstance(source, dict) and frozenset(source) == GENESIS_SOURCE_FIELDS,
                 f"a resolved genesis floor source must be exactly "
                 f"{sorted(GENESIS_SOURCE_FIELDS)}")
        _require(source.get("exec") == "reference",
                 "the genesis floor source must execute the builtin reference runtime")
        references = source.get("profiles")
        _require(isinstance(references, dict) and set(references) == set(profiles),
                 "the genesis floor source must identify one reference release per profile")
        for profile_id, reference in references.items():
            where = f"genesis floor source.profiles[{profile_id!r}]"
            _require(isinstance(reference, dict)
                     and frozenset(reference) == GENESIS_REFERENCE_FIELDS,
                     f"{where} must be exactly {sorted(GENESIS_REFERENCE_FIELDS)}")
            _require(reference.get("exec") == "reference",
                     f"{where}.exec must be 'reference'")
            _require(reference.get("reference_runtime") == {
                "id": "reference-runtime", "protocol": "rrm1"},
                f"{where}.reference_runtime must identify builtin reference-runtime/rrm1")
            _require(_is_sha256(reference.get("release_root")),
                     f"{where}.release_root must be sha256 hex")
    return document


_SUITE: Dict[str, Any] = None
_SUITE_ROOT: str = None


def _reject_duplicates(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key {key!r}")
        document[key] = value
    return document


def _reject_nonfinite(token: str):
    raise ValueError(f"non-finite JSON value {token!r}")


def _load() -> Dict[str, Any]:
    global _SUITE, _SUITE_ROOT
    if _SUITE is None:
        path = suite_path()
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            document = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
                parse_constant=_reject_nonfinite)
        except (OSError, ValueError) as exc:
            raise CanonicalSuiteError(
                f"the canonical suite is unavailable at {path}: {exc}") from exc
        _SUITE = _validate(document)
        _SUITE_ROOT = hashlib.sha256(raw).hexdigest()
    return _SUITE


def canonical_suite() -> Dict[str, Any]:
    return copy.deepcopy(_load())


def suite_root() -> str:
    """``sha256`` over the suite document's EXACT ON-DISK BYTES — the value the law identity binds."""
    _load()
    return _SUITE_ROOT


def suite_version() -> str:
    return str(_load()["suite_version"])


def suite_law_id() -> str:
    return str(_load()["law_id"])


def _profile(profile_id: str) -> Dict[str, Any]:
    profiles = _load()["profiles"]
    if profile_id not in profiles:
        raise CanonicalSuiteError(
            f"the canonical suite serves no profile {profile_id!r}; it serves {sorted(profiles)}")
    return profiles[profile_id]


def suite_cases(profile_id: str) -> Dict[str, list]:
    """The suite's cases for ``profile_id``, in the artifact's bound shape (with ``suite_index``,
    WITHOUT ``instance_hash`` — the hash is the measured fact the artifact binds separately)."""
    block = _profile(profile_id)
    return {partition: [{"instance_id": case["instance_id"], "profile_id": case["profile_id"],
                         "scale": case["scale"], "seed": case["seed"], "suite_index": index}
                        for index, case in enumerate(block[partition])]
            for partition in PARTITIONS}


def suite_case_hashes(profile_id: str) -> Dict[str, str]:
    block = _profile(profile_id)
    return {case["instance_id"]: case["instance_hash"]
            for partition in PARTITIONS for case in block[partition]}


def suite_counts(profile_id: str) -> Dict[str, int]:
    return dict(_profile(profile_id)["counts"])


def suite_scales(profile_id: str) -> list:
    return list(_profile(profile_id)["scales"])


def protected_quality_objectives(profile_id: str) -> tuple:
    return tuple(sorted(_profile(profile_id)["protected_quality_objectives"]))


def protected_resource_axes() -> tuple:
    return PROTECTED_RESOURCE_AXES


def genesis_floor_authority() -> Dict[str, Any]:
    return copy.deepcopy(_load()["genesis_floor_authority"])


def genesis_floor_resolved() -> bool:
    return _load()["genesis_floor_authority"].get("status") == "resolved"


def genesis_floor_vector(profile_id: str, partition: str) -> Dict[str, Any]:
    """The constructor-genesis floor vector, or :class:`GenesisFloorPendingError`.

    LAW §3A.3: a pending floor is a REFUSAL, never a skipped check.
    """
    if partition not in PARTITIONS:
        raise CanonicalSuiteError(f"partition {partition!r} must be one of {list(PARTITIONS)}")
    floor = _load()["genesis_floor_authority"]
    if floor.get("status") != "resolved":
        raise GenesisFloorPendingError(
            f"the canonical suite's constructor-genesis floor is {floor.get('status')!r}: no "
            "admission is computable without a resolved floor (LAW §3A.3)")
    vectors = floor["vectors"]
    if profile_id not in vectors:
        raise CanonicalSuiteError(
            f"the resolved genesis floor carries no vector for profile {profile_id!r}")
    return copy.deepcopy(vectors[profile_id][partition])


def reset_cache() -> None:
    """Drop the memoised document. TESTS ONLY."""
    global _SUITE, _SUITE_ROOT
    _SUITE = None
    _SUITE_ROOT = None
