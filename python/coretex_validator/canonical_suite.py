# SPDX-License-Identifier: Apache-2.0
"""Client-side mirror of the immutable CANONICAL SUITE (LAW §3A.1).

The authority is ``benchmark-v2/validator/CANONICAL-SUITE.v1.json`` and its loader
``benchmark-v2/validator/canonical_suite.py``. This module enforces the SAME CLOSED SCHEMA over
the SAME BYTES — exactly the mirror :mod:`parent_execution` already is for
``EXACT-PARENT-AUTHORITY.production.json``, and for the same reason: :mod:`eval_artifact` must be
usable without the ``benchmark-v2`` packages importable, while the benchmark loader needs
``frontier.profiles`` to cross-bind the protected objective vocabulary.

WHERE THE BYTES COME FROM, IN ORDER. (1) A document a caller INSTALLED with
:func:`install_suite_bytes` — that is what ``sync-law`` does after fetching the sealed ``validator``
tree, so the suite a replay decides against is the one whose tree hash the receipt's ``code_roots``
bind. (2) Otherwise the copy shipped INSIDE this wheel. The wheel copy exists because
:func:`eval_artifact.validate_artifact` resolves a profile's declared objective vocabulary from the
suite document, so even the pure schema check needs it — a clean install with no law mirror must
still be able to say what a v3 artifact's vectors are supposed to cover. :func:`packaged_suite_root`
reports the wheel copy's root so a caller can state, rather than assume, that the two agree.

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
``tests/test_canonical_suite.py`` runs the registry out of a law cache in a child interpreter and
fails if the table has drifted. The registry stays the single authority; this table is a checked
copy.
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
    "aggregation", "committed_before_any_candidate_scoring", "decision_engine", "format",
    "genesis_floor_authority", "instance_hash_rule", "law_id", "profiles",
    "protected_resource_axes", "provenance", "scales_claimed", "seed_derivation",
    "slice_threshold_corpus_events", "suite_version", "why",
})

#: The closed field set of one per-profile suite block.
PROFILE_FIELDS = frozenset({
    "confirm", "counts", "gate", "profile_id", "profile_version",
    "protected_quality_objectives", "protected_resource_axes", "scales", "screening",
    "seed_start", "suite_version",
})

#: The closed field set of one suite CASE as the document stores it. ``suite_index`` is DERIVED
#: (the case's position in its partition) and is never stored.
CASE_FIELDS = frozenset({"instance_hash", "instance_id", "profile_id", "scale", "seed"})

#: The closed field set of one ABSOLUTE VECTOR (LAW §3A.2) — the DETERMINISTIC subset only.
#: Identical to ``benchmark-v2/validator/canonical_suite.VECTOR_FIELDS``; latency, compute and the
#: host profile are telemetry and are deliberately absent.
VECTOR_FIELDS = ("composite_micro", "logical_durable_storage_bytes", "objectives_micro",
                 "rendered_cost_micro", "work_fuel")

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

#: THE FIXED ROUND IDENTITY OF THE v4 ERA (LAW §3A.4), mirrored from
#: ``benchmark-v2/validator/evaluation_law``. ``round_id`` used to be
#: ``f"v5-{epoch}-{candidate_id}"`` and the author id was the caller's ``candidate_id``; both were
#: bound into the receipt body, and ``round_id`` additionally fed the selection walk — which is
#: precisely how four submissions of IDENTICAL bytes under four candidate ids obtained four
#: different exams (live FIFO rows 20-23, epoch 185). Under the fixed suite they are law
#: constants, and the sealed law asserts them.
FIXED_SUITE_ROUND_ID = "coretex.fixed-suite/round/v1"
FIXED_SUITE_AUTHOR_ID = "coretex.fixed-suite/author/v1"

#: The inert entropy constants. Derived from a fixed domain string and NOTHING else — no secret, no
#: epoch, no parent root, no candidate.
FIXED_SUITE_ENTROPY_DOMAIN = "coretex.fixed-suite/inert-entropy/v1"


class CanonicalSuiteError(RuntimeError):
    code = CANONICAL_SUITE_INVALID


class GenesisFloorPendingError(CanonicalSuiteError):
    code = GENESIS_FLOOR_PENDING


def fixed_suite_entropy(label: str) -> str:
    """``sha256(domain|label)`` — a public constant, identical in every job, forever."""
    if label not in PARTITIONS:
        raise ValueError(f"label must be 'gate' or 'confirm', got {label!r}")
    return hashlib.sha256(f"{FIXED_SUITE_ENTROPY_DOMAIN}|{label}".encode("utf-8")).hexdigest()


#: The copy that travels inside the wheel. A clean install has this and nothing else.
PACKAGED_SUITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "CANONICAL-SUITE.v1.json")

#: Where the sealed ``validator`` tree keeps the authority, relative to a law cache / repo root.
SUITE_RELPATH = "benchmark-v2/validator/CANONICAL-SUITE.v1.json"


def suite_path() -> str:
    """The packaged suite document. See :func:`install_suite_bytes` for the law-cache route."""
    return PACKAGED_SUITE_PATH


def packaged_suite_root() -> str:
    """``sha256`` of the wheel's own copy, computed WITHOUT disturbing an installed document."""
    with open(PACKAGED_SUITE_PATH, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def install_suite_bytes(raw: bytes, *, source: str = "") -> str:
    """Validate and install suite bytes obtained from the SEALED law tree; return their root.

    This is the honest route for a standalone replay: the receipt's ``code_roots.validator`` binds
    a tree whose bytes ``sync-law`` fetched and re-addressed, and the suite document is a member of
    that tree. Installing those bytes means the artifact is decided against the suite the signed
    receipt commits to, not against whatever this wheel happened to be built with.

    The document is put through the same closed schema as the packaged one — a mirror that accepted
    a document the law refuses would be a second, weaker law.
    """
    global _SUITE, _SUITE_ROOT, _SUITE_SOURCE
    if not isinstance(raw, (bytes, bytearray)):
        raise CanonicalSuiteError(
            f"install_suite_bytes takes bytes, got {type(raw).__name__}")
    try:
        document = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CanonicalSuiteError(f"the supplied canonical suite is not JSON: {exc}") from exc
    _SUITE = _validate(document)
    _SUITE_ROOT = hashlib.sha256(bytes(raw)).hexdigest()
    _SUITE_SOURCE = source or "installed"
    return _SUITE_ROOT


def suite_source() -> str:
    """Where the loaded document came from — the packaged path, or an installed source label."""
    _load()
    return _SUITE_SOURCE


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
    _require(document["committed_before_any_candidate_scoring"] is True,
             "canonical suite must record that it was committed before any candidate was scored")

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
        _require(isinstance(floor.get("source"), (str, dict)) and floor.get("source"),
                 "a resolved genesis floor must name the bridge measurement it came from")
    return document


_SUITE: Dict[str, Any] = None
_SUITE_ROOT: str = None
_SUITE_SOURCE: str = ""


def _load() -> Dict[str, Any]:
    global _SUITE, _SUITE_ROOT, _SUITE_SOURCE
    if _SUITE is None:
        path = suite_path()
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            document = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise CanonicalSuiteError(
                f"the canonical suite is unavailable at {path}: {exc}") from exc
        _SUITE = _validate(document)
        _SUITE_ROOT = hashlib.sha256(raw).hexdigest()
        _SUITE_SOURCE = path
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
            f"the canonical suite's constructor-genesis floor is {floor.get('status')!r}: no v4 "
            "admission is computable without a resolved floor (LAW §3A.3)")
    vectors = floor["vectors"]
    if profile_id not in vectors:
        raise CanonicalSuiteError(
            f"the resolved genesis floor carries no vector for profile {profile_id!r}")
    return copy.deepcopy(vectors[profile_id][partition])


def reset_cache() -> None:
    """Drop the memoised document, reverting to the packaged copy. TESTS ONLY."""
    global _SUITE, _SUITE_ROOT, _SUITE_SOURCE
    _SUITE = None
    _SUITE_ROOT = None
    _SUITE_SOURCE = ""
