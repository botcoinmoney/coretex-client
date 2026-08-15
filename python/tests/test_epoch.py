# SPDX-License-Identifier: Apache-2.0
"""Epoch head: LAZY INHERITANCE + finalization (spec §8, operator ruling §17.237).

WHAT CHANGED AND WHY (this file previously proved `carry_forward`).

`carry_forward` minted an epoch-N+1 manifest — a NEW root — at every epoch boundary, including
boundaries where nobody mined. §17.237 removes that operation outright:

  * it required a boundary TRANSACTION (or, in V5-F's case, an invented
    `CoreTexMemoryEpochCarriedForward` event) for the root to be reachable by replay;
  * a root the chain never named would otherwise be a local pointer, which is exactly what the
    V5 directive forbids;
  * and the operator chose the alternative explicitly: the first valid transition in epoch N
    names, as its parent, the confirmed FINAL root of the latest preceding epoch.

So the epoch mover is now `apply_transition(..., epoch=N)`, and an epoch with zero transitions
mints NOTHING — it has no head of its own and is skipped by the next epoch's inheritance. Every
assertion below is the §17.237 replacement of the corresponding carry-forward assertion.
"""
from __future__ import annotations

import copy

import pytest

from conftest import ROOT_COMP2, make_manifest

import frontier as fr


def _t(manifest, **overrides):
    kwargs = {"target_profile": "doc.tool.v1",
              "expected_prior_release_root": manifest["profiles"]["doc.tool.v1"],
              "new_release_root": "d" * 64, "resulting_composition_root": ROOT_COMP2}
    kwargs.update(overrides)
    return fr.make_transition(**kwargs)


# --------------------------------------------------------------------------- #
# finalization (unchanged by the ruling: it asserts a fact, it mints nothing)
# --------------------------------------------------------------------------- #
def test_finalize_epoch_records_the_head(manifest):
    record = fr.finalize_epoch(manifest)
    assert record == {"epoch": manifest["epoch"], "final_root": fr.frontier_root(manifest),
                      "format": fr.FINALIZATION_FORMAT}
    fr.canonical_bytes(record)


def test_finalize_epoch_does_not_change_state(manifest):
    before = copy.deepcopy(manifest)
    fr.finalize_epoch(manifest)
    assert manifest == before


# --------------------------------------------------------------------------- #
# lazy inheritance
# --------------------------------------------------------------------------- #
def test_the_inherited_parent_of_a_new_epoch_is_the_previous_head_root(manifest):
    """Rule 3: epoch N inherits the confirmed FINAL root of the latest preceding epoch."""
    assert fr.inherited_epoch_parent(manifest, epoch=manifest["epoch"] + 1) == \
        fr.frontier_root(manifest)


def test_inheritance_mints_nothing(manifest):
    """The replacement for `test_carry_forward_mints_a_new_root_even_with_identical_content`.

    That test asserted the boundary produced a NEW root even with no mining. Under lazy
    inheritance the opposite is true and is the point: nothing exists between the two epochs, so
    the inherited parent IS the previous head, byte for byte.
    """
    before = copy.deepcopy(manifest)
    inherited = fr.inherited_epoch_parent(manifest, epoch=manifest["epoch"] + 4)
    assert inherited == fr.frontier_root(manifest)
    assert manifest == before, "pure: nothing was carried, copied or mutated"


def test_an_empty_epoch_has_no_head_of_its_own(manifest):
    """The replacement for `test_an_epoch_with_no_mining_still_has_a_head`.

    An epoch that never mined mints no manifest, so there is nothing to finalize and nothing to
    address. What it 'has' is what the NEXT epoch inherits — and that is the previous non-empty
    epoch's head, reached by skipping every empty epoch in between. Rule 7, empty epochs.
    """
    head_epoch = manifest["epoch"]
    # epochs head_epoch+1 .. head_epoch+5 are all empty
    for skipped in range(1, 6):
        assert fr.inherited_epoch_parent(manifest, epoch=head_epoch + skipped) == \
            fr.frontier_root(manifest)


def test_an_epoch_never_inherits_from_itself_or_backwards(manifest):
    for bad in (manifest["epoch"], manifest["epoch"] - 1, 0):
        with pytest.raises(fr.EpochRegressionError):
            fr.inherited_epoch_parent(manifest, epoch=bad)


def test_inheritance_validates_its_head_and_its_epoch(manifest):
    with pytest.raises(fr.FrontierValueError):
        fr.inherited_epoch_parent(manifest, epoch=fr.MAX_EPOCH + 1)
    with pytest.raises(fr.FrontierTypeError):
        fr.inherited_epoch_parent(manifest, epoch=True)
    with pytest.raises(fr.FrontierSchemaError):
        fr.inherited_epoch_parent({"format": "nope"}, epoch=99)


# --------------------------------------------------------------------------- #
# the first transition of an epoch is what moves the epoch
# --------------------------------------------------------------------------- #
def test_transitions_never_change_the_epoch_by_default(manifest):
    child = fr.apply_transition(manifest, _t(manifest))
    assert child["epoch"] == manifest["epoch"]


def test_the_first_transition_of_an_epoch_is_the_epoch_mover(manifest):
    """Rule 3, LAZY INITIALIZATION: no separate carry-forward transaction exists."""
    child = fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] + 1)
    assert child["epoch"] == manifest["epoch"] + 1
    assert child["parent_frontier_root"] == fr.frontier_root(manifest), \
        "the inherited parent is named directly; there is no intermediate root"
    for field in ("benchmark_law_root", "runtime_abi_root"):
        assert child[field] == manifest[field]


def test_an_inheriting_transition_may_skip_arbitrarily_many_empty_epochs(manifest):
    child = fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] + 9)
    assert child["epoch"] == manifest["epoch"] + 9
    assert child["parent_frontier_root"] == fr.frontier_root(manifest)


def test_an_explicit_same_epoch_is_exactly_the_default(manifest):
    assert fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"]) == \
        fr.apply_transition(manifest, _t(manifest))


def test_a_transition_can_never_move_the_epoch_backwards(manifest):
    with pytest.raises(fr.EpochRegressionError):
        fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] - 1)


def test_the_epoch_is_inside_the_hashed_body_so_inheritance_changes_the_root(manifest):
    """The epoch boundary is not free: the same edit in a new epoch is a DIFFERENT state.

    This is what stops an epoch-N eval/receipt binding from replaying into epoch N+1 — the
    guarantee `carry_forward`'s new root used to provide, now provided by the epoch field of the
    child itself.
    """
    same = fr.apply_transition(manifest, _t(manifest))
    inherited = fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] + 1)
    assert fr.frontier_root(same) != fr.frontier_root(inherited)


def test_the_epoch_head_of_a_closed_epoch_stays_immutable_and_addressable(manifest):
    """Old epochs stay replayable: the next epoch's first transition does not disturb the head."""
    head_root = fr.frontier_root(manifest)
    record = fr.finalize_epoch(manifest)
    fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] + 1)
    assert fr.frontier_root(manifest) == head_root == record["final_root"]


def test_inheriting_transitions_are_deterministic_and_pure(manifest):
    before = copy.deepcopy(manifest)
    a = fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] + 1)
    b = fr.apply_transition(manifest, _t(manifest), epoch=manifest["epoch"] + 1)
    assert a == b and manifest == before


def test_the_epoch_ceiling_is_still_enforced():
    """The replacement for `test_carry_forward_refuses_to_overflow`."""
    top = make_manifest(epoch=fr.MAX_EPOCH)
    with pytest.raises(fr.FrontierValueError):
        fr.apply_transition(top, _t(top), epoch=fr.MAX_EPOCH + 1)
    with pytest.raises(fr.FrontierValueError):
        fr.inherited_epoch_parent(top, epoch=fr.MAX_EPOCH + 1)


def test_carry_forward_is_gone(manifest):
    """§17.237 rule 3: no separate carry-forward transaction, so no carry-forward operation.

    Asserted rather than merely deleted, so nobody re-introduces a root-minting boundary helper
    that the chain would never name.
    """
    assert not hasattr(fr, "carry_forward")


def test_verify_transition_reports_the_inheritance(manifest):
    transition = _t(manifest)
    child = fr.apply_transition(manifest, transition, epoch=manifest["epoch"] + 1)
    result = fr.verify_transition(manifest, transition, fr.frontier_root(child),
                                  epoch=manifest["epoch"] + 1)
    assert result["inherited"] is True and result["epoch"] == manifest["epoch"] + 1
    plain = fr.apply_transition(manifest, transition)
    result = fr.verify_transition(manifest, transition, fr.frontier_root(plain))
    assert result["inherited"] is False and result["epoch"] == manifest["epoch"]


def test_verify_transition_refuses_the_wrong_epoch(manifest):
    """A replayer that used the wrong epoch reproduces a different root and is refused."""
    transition = _t(manifest)
    child = fr.apply_transition(manifest, transition, epoch=manifest["epoch"] + 1)
    with pytest.raises(fr.RootMismatchError):
        fr.verify_transition(manifest, transition, fr.frontier_root(child))
    with pytest.raises(fr.RootMismatchError):
        fr.verify_transition(manifest, transition, fr.frontier_root(child),
                             epoch=manifest["epoch"] + 2)
