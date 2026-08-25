# SPDX-License-Identifier: Apache-2.0
"""The vendored law tree must still say what the canonical law tree says.

This package is a STANDALONE public validator, so it carries its own copy of the law it decides
against — the counter-resource law documents, the canonical suite, the exact-parent authority, and
hand-ported mirrors of the artifact layer and the suite loader. That vendoring is maintained BY
HAND: there is no build step that copies from canonical, and until this test existed there was no
check either. It drifted three ways at once, and each one was a wrong VERDICT rather than a
cosmetic lag:

  * the counter law sat two revisions behind — older even than the preserved walk-era document —
    so a cache populated by ``sync-law`` carried a law matching no artifact ever minted;
  * the exact-parent authority was missing a whole code-root set, so frozen tier-1 historical
    receipts could not resolve;
  * the artifact layer's CLOSED field sets predated the law cut that added
    ``measurements.*.logical_durable_storage_bytes`` and ``replay_inputs.candidate_module_bytes``,
    so every artifact minted under the CURRENT law was rejected as malformed.

WHAT THIS TEST CAN AND CANNOT PROVE, stated plainly because the distinction is the whole point.
It runs OFFLINE — the canonical tree is private and absent on a public machine — so it proves the
vendored tree still matches its RECORDED PROVENANCE (``coretex_validator/LAW-SYNC.v1.json``). It
does NOT prove the recorded provenance is current. That second half is
``python -m coretex_validator.law_sync --canonical <canonical tree>``, a standing obligation of every law cut,
and :func:`test_the_manifest_names_the_canonical_commit_it_was_generated_from` keeps the provenance
legible so a reviewer can tell at a glance which canonical commit these pins came from.
"""
from __future__ import annotations

import json
import os

import pytest

from coretex_validator import law_sync as sync


@pytest.fixture(scope="module")
def manifest():
    return sync.load_manifest()


def test_the_vendored_law_tree_matches_its_recorded_provenance(manifest):
    """The one that fails when somebody edits a vendored file without re-vendoring."""
    problems = [p for p in sync.check_vendored(manifest) if not p.startswith("NOTE:")]
    assert problems == [], (
        "the vendored law tree has drifted from LAW-SYNC.v1.json:\n  "
        + "\n  ".join(problems)
        + "\n\nFix by RE-VENDORING from the canonical tree and regenerating the manifest "
          "(python -m coretex_validator.law_sync --write --canonical <tree>), never by editing a pin.")


def test_every_vendored_document_is_pinned_and_present(manifest):
    """A law document that stopped being pinned would stop being checked, silently."""
    pinned = {entry["vendored"] for entry in manifest["documents"]}
    assert pinned == {vendored for vendored, _ in sync.VENDORED_DOCUMENTS}
    for vendored, _canonical in sync.VENDORED_DOCUMENTS:
        path = os.path.join(sync.PACKAGE_DIR, vendored)
        assert os.path.isfile(path), f"{vendored} is not in the package"


def test_both_counter_resource_laws_ship_and_hash_to_their_era(manifest):
    """The current law AND the superseded walk-era one, each at its own root.

    Every artifact minted before the fixed-suite cut binds the walk-era document BY ROOT, and
    prior eras are never reinterpreted (LAW §3A.6). Replaying published history offline therefore
    needs BOTH documents reachable — the current one is not a substitute, because the two differ
    in the storage term's ``source`` and so hash differently and price differently.
    """
    roots = {entry["vendored"]: entry["sha256"] for entry in manifest["documents"]}
    assert roots["COUNTER_RESOURCE_LAW.v1.json"] == (
        "310fe9e411909d6a091590d71d94adf67c3101dc75f0ac9ec3fb510afbe7aba3")
    assert roots["COUNTER_RESOURCE_LAW.walk-era.v1.json"] == (
        "049fe98ec08a3a47e2bf4582afa70ad45506a465584f3cec1a53286617c7b207")
    assert roots["COUNTER_RESOURCE_LAW.v1.json"] != roots["COUNTER_RESOURCE_LAW.walk-era.v1.json"]

    from coretex_validator import eval_artifact as ea
    for path, expected in ((ea.COUNTER_RESOURCE_LAW_PATH,
                            roots["COUNTER_RESOURCE_LAW.v1.json"]),
                           (ea.WALK_ERA_COUNTER_RESOURCE_LAW_PATH,
                            roots["COUNTER_RESOURCE_LAW.walk-era.v1.json"])):
        assert os.path.isfile(path), path
        with open(path, "rb") as fh:
            assert sync._sha256(fh.read()) == expected
        # Both must LOAD under the closed schema, not merely exist: a shipped document the
        # loader refuses is a fail at replay time rather than at install time.
        ea.load_counter_resource_law(path)


def test_the_v3_field_sets_carry_what_the_current_law_measures():
    """The exact two additions the fixed-suite law cut made, asserted by name.

    Pinned separately from the manifest comparison so the failure says WHICH law rule went
    missing rather than "a tuple changed".
    """
    from coretex_validator import eval_artifact as ea
    assert "logical_durable_storage_bytes" in ea.SIDE_FIELDS_V3
    assert "logical_durable_storage_bytes" not in ea.SIDE_FIELDS
    assert "candidate_module_bytes" in ea.REPLAY_INPUT_FIELDS_V3
    assert "candidate_module_bytes" not in ea.REPLAY_INPUT_FIELDS
    # The walk-era sets are FROZEN: a v1/v2 artifact must reproject byte-identically forever.
    assert set(ea.SIDE_FIELDS_V3) - set(ea.SIDE_FIELDS) == {"logical_durable_storage_bytes"}
    assert set(ea.REPLAY_INPUT_FIELDS_V3) - set(ea.REPLAY_INPUT_FIELDS) == {
        "candidate_module_bytes"}
    # Every component of the absolute vector that the projection also measures is compared.
    assert set(ea.MEASURABLE_VECTOR_FIELDS) == set(ea.VECTOR_FIELDS) - {"objectives_micro"}


def test_the_hard_gate_vocabulary_is_closed_at_eight_names():
    """A hard map is exactly the law's eight names — not a set of claims a report chooses."""
    from coretex_validator import canonical_suite as cs
    assert len(cs.HARD_GATE_VOCABULARY) == 8
    assert tuple(sorted(cs.HARD_GATE_VOCABULARY)) == cs.HARD_GATE_VOCABULARY


def test_the_exact_parent_authority_carries_every_permitted_code_root_set(manifest):
    """Each entry is a standing permission to accept the weaker incumbent identity.

    The vendored copy was missing the frozen tier-1 set entirely, which is why replaying the
    published walk-era corpus could not resolve those receipts. Gaining or losing an entry is a
    law change; it must move here and in canonical together.
    """
    path = os.path.join(sync.PACKAGE_DIR, "EXACT-PARENT-AUTHORITY.production.json")
    with open(path, "rb") as fh:
        document = json.loads(fh.read().decode("utf-8"))
    ids = sorted(entry["id"] for entry in document["pre_exact_parent_code_root_sets"])
    assert ids == ["production-pre-exact-parent-r12", "tier1-frozen-2026-07-28"]


def test_the_manifest_names_the_canonical_commit_it_was_generated_from(manifest):
    """Provenance a reviewer can read without running anything."""
    commit = manifest.get("canonical_commit")
    assert isinstance(commit, str) and len(commit) == 40 and int(commit, 16) >= 0


def test_the_offline_check_is_not_mistaken_for_the_cross_repo_one(manifest, tmp_path):
    """The check must FAIL on a drifted tree, or it proves nothing.

    Perturbs a pinned constant in the loaded module and asserts the checker names it. Without
    this, a checker that silently skipped every symbol would pass the suite forever.
    """
    from coretex_validator import eval_artifact as ea
    original = ea.MEASURABLE_VECTOR_FIELDS
    try:
        ea.MEASURABLE_VECTOR_FIELDS = ("composite_micro",)
        problems = sync.check_vendored(manifest)
        assert any("MEASURABLE_VECTOR_FIELDS" in p for p in problems), problems
    finally:
        ea.MEASURABLE_VECTOR_FIELDS = original
    assert [p for p in sync.check_vendored(manifest) if not p.startswith("NOTE:")] == []
