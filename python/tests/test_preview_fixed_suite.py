# SPDX-License-Identifier: Apache-2.0
"""``preview-current-parent`` under the fixed-suite law: a DETERMINISTIC prediction.

WHAT CHANGED, AND WHY THE TESTS ARE ABOUT THE PROMISE RATHER THAN THE ARITHMETIC. Under the walk
law the official evaluation drew fresh cases from future public entropy, so the preview's
``predictsAdmission`` was a hard ``false`` and had to be: the number it produced was going to be
re-rolled. Under LAW §3A the exam is immutable and public, the decision is componentwise dominance
over the exact parent plus the law-bound genesis floor, and nothing outside (candidate bytes, exact
parent, law) is an input. So the preview scores the SAME cases the adjudicator scores, and the
verdict it computes is the verdict the adjudicator computes.

The scoring child is faked here for the same reason it is faked in
``test_preview_current_parent.py`` — a real one needs the pinned trees, wasmtime and minutes per
case. What is NOT faked is which cases get scored, in which partitions, or what the report is
allowed to claim, and that is what these tests are for.
"""
from __future__ import annotations

import copy
import json

import pytest

from coretex_validator import canonical_suite as cs
from coretex_validator import preview as pv
from test_preview_current_parent import (CANDIDATE_MODULE, COMPOSITES, candidate_manifest,
                                         parent_graph, TARGET)

PROFILE = "event.schema.v1"


def _suite_probe(profile_id=PROFILE, *, floor_resolved=True):
    """The probe answer the REAL child produces when the pinned trees carry the v4 law."""
    return {
        "dev_seeds": [1002, 1003], "dev_scales": ["small"], "profiles": [profile_id],
        "law_era": "fixed-suite",
        "suite_root": cs.suite_root(),
        "suite_law_id": cs.suite_law_id(),
        "suite_version": str(cs.suite_version()),
        "dominance_engine": "dominance.componentwise.v1",
        "genesis_floor_resolved": floor_resolved,
        # THE BENCHMARK LOADER'S NAME. `validator.canonical_suite` spells this `suite_selection`
        # and the V5 mirror spells it `suite_cases`; the child calls the BENCHMARK one, because the
        # benchmark tree is what a law cache installs. Calling the mirror's name there made every
        # fixed-suite preview fall silently back to the walk era through the child's `except`.
        "suite_cases": cs.suite_cases(profile_id),
        "suite_case_hashes": cs.suite_case_hashes(profile_id),
        "suite_scales": list(cs.suite_scales(profile_id)),
        "suite_counts": dict(cs.suite_counts(profile_id)),
    }


class SuiteChild:
    """A child whose law trees carry the canonical suite and the componentwise engine."""

    name = "fake-fixed-suite-tree"
    unavailable_reason = "the fake is always available"

    def __init__(self, *, profile_id=PROFILE, admit=True, floor_resolved=True):
        self.profile_id = profile_id
        self.admit = admit
        self.floor_resolved = floor_resolved
        self.calls = []

    def available(self) -> bool:
        return True

    @staticmethod
    def _composite(arm):
        return COMPOSITES["reference"] if arm["kind"] == "reference" else COMPOSITES[arm["sha256"]]

    def __call__(self, payload):
        self.calls.append(copy.deepcopy(payload))
        mode = payload["mode"]
        if mode == "probe":
            return _suite_probe(payload.get("profile_id") or self.profile_id,
                                floor_resolved=self.floor_resolved)
        if mode == "score":
            arms = {name: {"measurement": {"composite": self._composite(arm),
                                           "dims": {"exact_lookup": self._composite(arm)}},
                           "resource": {"work_fuel": 100, "rendered_cost": 10.0},
                           "integrity": {"measured": True, "violations": 0, "reasons": []}}
                    for name, arm in payload["arms"].items()}
            return {"arms": arms, "replay_identical": {n: True for n in payload["arms"]},
                    "networkless": True}
        if mode == "aggregate_suite":
            partitions = {}
            for label, rows in payload["per_partition"].items():
                sides = {}
                for name, arm_rows in rows.items():
                    composite = round(
                        sum(r["measurement"]["composite"] for r in arm_rows) / len(arm_rows), 6)
                    sides[name] = {"composite": composite,
                                   "objectives": {"exact_lookup": composite},
                                   "rendered_cost": 10.0, "compute_ms": 100.0,
                                   "storage_bytes": 1024, "latency_ms": 7,
                                   "corpus_supported": 40}
                sides["candidate"]["declared_limits"] = dict(payload["declared_limits"])
                verdict = {"admit": bool(self.admit), "verdict": "ADMIT" if self.admit else
                           "REJECT", "engine": "dominance.componentwise.v1",
                           "regressed_objectives": [], "regressed_resource_axes": [],
                           "floor_regressions": [], "reason": "fake componentwise verdict",
                           "hard_ok": True, "satisfied_clauses": []}
                partitions[label] = {"candidate": sides["candidate"], "parent": sides["parent"],
                                     "verdict": verdict, "aggregates": {},
                                     "floor_vector": cs.genesis_floor_vector(
                                         payload["profile_id"], label)}
            return {"partitions": partitions, "portability": None,
                    "engine": "dominance.componentwise.v1", "suite_root": cs.suite_root(),
                    "admit": bool(self.admit)}
        raise AssertionError("unexpected preview child mode " + repr(mode))


@pytest.fixture()
def graph():
    return parent_graph()


def _run(child, graph, *, profile=TARGET):
    return pv.preview_current_parent(
        child=child, store=graph["store"], parent_root=graph["parent_root"],
        target_profile=profile, module_source=CANDIDATE_MODULE.decode("utf-8"),
        candidate_manifest=candidate_manifest())


# --------------------------------------------------------------------------- #
# 1. the era is READ OFF THE PINNED TREES, not configured here
# --------------------------------------------------------------------------- #
def test_the_probe_is_asked_about_the_profile_so_the_suite_can_come_back_with_it(graph):
    child = SuiteChild(profile_id=TARGET)
    _run(child, graph)
    assert child.calls[0] == {"mode": "probe", "profile_id": TARGET}


def test_a_walk_era_law_tree_still_gets_the_walk_era_preview(graph):
    """A child whose trees carry no canonical suite is a walk-era deployment, and the preview must
    keep saying it predicts nothing — the fixed-suite promise is false there."""
    from test_preview_current_parent import FakeLawTreeChild

    report = _run(FakeLawTreeChild(), graph)
    assert report["publicDevCasesOnly"] is True
    assert report["predictsAdmission"] is False
    assert "predictsDeterministicAdmission" not in report
    assert report["lawEra"] == "walk"
    assert "lawEraReason" not in report          # genuinely walk-era, nothing was downgraded


def test_a_fixed_suite_tree_whose_suite_would_not_load_says_so_out_loud(graph):
    """THE DANGEROUS CASE. The child reports "walk" both for a genuinely walk-era tree and for a
    fixed-suite tree whose suite it could not load, and the difference matters enormously: the
    second means this preview scored the WRONG CASES and said so only by omission. The reason the
    child caught must reach the report."""
    class BrokenSuiteChild(SuiteChild):
        def __call__(self, payload):
            if payload["mode"] == "probe":
                self.calls.append(dict(payload))
                return {"dev_seeds": [1002, 1003], "dev_scales": ["small"],
                        "profiles": [TARGET],
                        "law_era": "walk",
                        "law_era_reason": "CanonicalSuiteError: the canonical suite is unavailable"}
            if payload["mode"] == "aggregate":
                self.calls.append(copy.deepcopy(payload))
                sides = {}
                for name, rows in payload["per_arm"].items():
                    composite = round(
                        sum(r["measurement"]["composite"] for r in rows) / len(rows), 6)
                    sides[name] = {"composite": composite,
                                   "objectives": {"exact_lookup": composite},
                                   "rendered_cost": 10.0, "compute_ms": 100.0,
                                   "storage_bytes": 1024, "latency_ms": 7,
                                   "corpus_supported": 40}
                sides["candidate"]["declared_limits"] = dict(payload["declared_limits"])
                return {"candidate": sides["candidate"], "parent": sides["parent"],
                        "verdict": {"admit": False, "verdict": "REJECT", "hard_ok": True,
                                    "pareto_ok": False, "satisfied_clauses": [],
                                    "reason": "walk-era fallback", "deltas": {}},
                        "aggregates": {}, "portability": None}
            return super().__call__(payload)

    report = _run(BrokenSuiteChild(profile_id=TARGET), graph)
    assert report["lawEra"] == "walk"
    assert report["predictsAdmission"] is False
    assert "CanonicalSuiteError" in report["lawEraReason"]


# --------------------------------------------------------------------------- #
# 2. THE CASES SCORED ARE THE LAW'S CASES
# --------------------------------------------------------------------------- #
def test_every_scored_case_is_a_suite_case_in_its_partition_order(graph):
    child = SuiteChild(profile_id=TARGET)
    _run(child, graph)
    scored = [c for c in child.calls if c["mode"] == "score"]
    expected = cs.suite_cases(TARGET)
    hashes = cs.suite_case_hashes(TARGET)
    flat = [case for label in ("gate", "confirm") for case in expected[label]]
    assert len(scored) == len(flat)
    for call, case in zip(scored, flat):
        assert call["seed"] == case["seed"]
        assert call["scale"] == case["scale"]
        assert call["profile_id"] == case["profile_id"]
        # THE HASH TRAVELS WITH THE CASE. Without it the child would score whatever its local
        # generators produced and call it the law's case.
        assert call["instance_hash"] == hashes[case["instance_id"]]


def test_the_partitions_are_kept_separate_all_the_way_to_the_decision(graph):
    child = SuiteChild(profile_id=TARGET)
    _run(child, graph)
    aggregate = [c for c in child.calls if c["mode"] == "aggregate_suite"]
    assert len(aggregate) == 1
    counts = cs.suite_counts(TARGET)
    for label in ("gate", "confirm"):
        rows = aggregate[0]["per_partition"][label]
        assert set(rows) == {"candidate", "parent"}
        assert len(rows["candidate"]) == len(rows["parent"]) == counts[label]


def test_no_candidate_id_author_epoch_or_rig_reaches_the_child(graph):
    """LAW §3A.4: those are identity/authorization, never selection. The preview is the cheapest
    place to notice one of them creeping back into the exam."""
    child = SuiteChild(profile_id=TARGET)
    _run(child, graph)
    blob = json.dumps(child.calls)
    for word in ("candidate_id", "candidateId", "author_id", "round_id", "epoch_secret",
                 "rig_id", "season_root"):
        assert word not in blob, word


# --------------------------------------------------------------------------- #
# 3. THE PROMISE THE REPORT IS ALLOWED TO MAKE
# --------------------------------------------------------------------------- #
def test_the_fixed_suite_preview_predicts_deterministic_admission(graph):
    report = _run(SuiteChild(profile_id=TARGET), graph)
    assert report["predictsDeterministicAdmission"] is True
    assert report["publicDevCasesOnly"] is False
    assert report["lawEra"] == "fixed-suite"
    assert report["predictsAdmission"] is True
    assert report["canonicalSuite"]["root"] == cs.suite_root()
    assert report["canonicalSuite"]["law_id"] == cs.suite_law_id()
    assert report["canonicalSuite"]["counts"] == cs.suite_counts(TARGET)
    # the caveat is NAMED rather than replaced by a blanket "this predicts nothing"
    assert "CHAIN RACE" in report["disclaimer"]
    assert "IMMUTABLE CANONICAL SUITE" in report["disclaimer"]


def test_a_losing_candidate_predicts_a_refusal_rather_than_hiding_it(graph):
    report = _run(SuiteChild(profile_id=TARGET, admit=False), graph)
    assert report["predictsDeterministicAdmission"] is True
    assert report["predictsAdmission"] is False
    assert report["partitions"]["gate"]["admit"] is False
    assert report["partitions"]["confirm"]["admit"] is False


def test_both_partitions_are_reported_so_a_gate_failure_cannot_read_as_admissible(graph):
    report = _run(SuiteChild(profile_id=TARGET), graph)
    assert set(report["partitions"]) == {"gate", "confirm"}
    for label in ("gate", "confirm"):
        assert report["partitions"][label]["floor_vector"] == cs.genesis_floor_vector(
            TARGET, label)


# --------------------------------------------------------------------------- #
# 4. PREVIEW DETERMINISM — two runs, identical bytes
# --------------------------------------------------------------------------- #
def test_two_previews_of_the_same_inputs_are_byte_identical(graph):
    first = _run(SuiteChild(profile_id=TARGET), graph)
    second = _run(SuiteChild(profile_id=TARGET), parent_graph())
    canonical = lambda report: json.dumps(report, sort_keys=True, separators=(",", ":"))
    assert canonical(first) == canonical(second)


def test_the_child_is_driven_identically_on_two_runs(graph):
    first, second = SuiteChild(profile_id=TARGET), SuiteChild(profile_id=TARGET)
    _run(first, graph)
    _run(second, parent_graph())
    assert first.calls == second.calls


# --------------------------------------------------------------------------- #
# 5. a PENDING floor is a refusal, never a skipped check (LAW §3A.3)
# --------------------------------------------------------------------------- #
def test_a_pending_genesis_floor_refuses_rather_than_predicting(graph):
    with pytest.raises(pv.PreviewError) as exc:
        _run(SuiteChild(profile_id=TARGET, floor_resolved=False), graph)
    assert exc.value.code == "GENESIS_FLOOR_PENDING"
    assert "PENDING" in str(exc.value)


# --------------------------------------------------------------------------- #
# 6. the child's probe must call the names the BENCHMARK loader actually exposes
# --------------------------------------------------------------------------- #
def test_the_probe_source_calls_the_benchmark_loaders_real_api():
    """The bug this exists to prevent, found by running the probe against the real trees.

    `benchmark-v2/validator/canonical_suite` exposes `suite_selection`; the V5 mirror (and this
    client's own `canonical_suite`) exposes `suite_cases`. The child imports the BENCHMARK one,
    because that is what a law cache installs — and the child wraps the whole era probe in a bare
    `except`, so calling the wrong name did not raise: it reported `law_era: "walk"` and every
    fixed-suite preview silently scored the dev cases instead of the law's.

    Asserted on the child SOURCE because the real child cannot run without the pinned trees, and a
    test that needed them would not run here at all.
    """
    source = pv._PREVIEW_CHILD
    assert "_cs.suite_selection(_pid)" in source
    assert "_cs.suite_cases(" not in source
    # and the names the rest of the probe uses are the benchmark loader's too
    for call in ("_cs.suite_root()", "_cs.suite_law_id()", "_cs.suite_version()",
                 "_cs.genesis_floor_resolved()", "_cs.suite_case_hashes(_pid)",
                 "_cs.suite_scales(_pid)", "_cs.suite_counts(_pid)"):
        assert call in source, call
    assert "_cs.genesis_floor_vector(payload[\"profile_id\"], label)" in source


def test_cases_without_their_instance_hashes_refuse_rather_than_scoring_dev_cases(graph):
    """OPTIONAL-BY-OMISSION was the bug. The instance hash is what makes "the law's case"
    checkable; a missing one is falsy, the child's `if payload.get("instance_hash")` takes the
    other branch, and it scores a DEV case while the report still says `publicDevCasesOnly: false`
    and `predictsDeterministicAdmission: true`. A partial probe answer is a refusal."""
    class NoHashesChild(SuiteChild):
        def __call__(self, payload):
            out = super().__call__(payload)
            if payload["mode"] == "probe":
                out = dict(out)
                out.pop("suite_case_hashes", None)
            return out

    with pytest.raises(pv.PreviewError) as exc:
        _run(NoHashesChild(profile_id=TARGET), graph)
    assert exc.value.code == "SUITE_CASE_HASHES_MISSING"


def test_one_missing_hash_is_enough_to_refuse(graph):
    class OneMissingChild(SuiteChild):
        def __call__(self, payload):
            out = super().__call__(payload)
            if payload["mode"] == "probe":
                out = dict(out)
                hashes = dict(out["suite_case_hashes"])
                hashes.pop(sorted(hashes)[0])
                out["suite_case_hashes"] = hashes
            return out

    with pytest.raises(pv.PreviewError) as exc:
        _run(OneMissingChild(profile_id=TARGET), graph)
    assert exc.value.code == "SUITE_CASE_HASHES_MISSING"
    assert "1 of them" in str(exc.value)
