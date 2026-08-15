# SPDX-License-Identifier: Apache-2.0
"""Transition law: shape, size bound, staleness, no-ops, purity, rollback (spec §6/§7/§9)."""
from __future__ import annotations

import copy
import json

import pytest

from conftest import ROOT_A, ROOT_B, ROOT_C, ROOT_COMP, ROOT_COMP2

import frontier as fr

NEW_RELEASE = "d" * 64


def _t(**overrides):
    kwargs = {"target_profile": "doc.tool.v1", "expected_prior_release_root": ROOT_B,
              "new_release_root": NEW_RELEASE, "resulting_composition_root": ROOT_COMP2}
    kwargs.update(overrides)
    return fr.make_transition(**kwargs)


# --------------------------------------------------------------------------- #
# transitionBytes is a SMALL canonical manifest edit
# --------------------------------------------------------------------------- #
def test_transition_bytes_shape_and_content():
    raw = fr.transition_bytes(target_profile="event.schema.v1",
                              expected_prior_release_root=ROOT_C,
                              new_release_root=NEW_RELEASE,
                              resulting_composition_root=ROOT_COMP2)
    decoded = json.loads(raw)
    assert set(decoded) == set(fr.TRANSITION_FIELDS)
    assert decoded["format"] == fr.TRANSITION_FORMAT
    assert decoded["target_profile"] == "event.schema.v1"


def test_exact_and_enforced_size_bound():
    assert fr.max_transition_bytes() == 364
    assert fr.MAX_TRANSITION_BYTES == 384
    assert fr.max_transition_bytes() <= fr.MAX_TRANSITION_BYTES
    for pid in fr.PROFILE_IDS:
        raw = fr.transition_bytes(target_profile=pid, expected_prior_release_root=ROOT_A,
                                  new_release_root=NEW_RELEASE,
                                  resulting_composition_root=ROOT_COMP2)
        assert len(raw) <= fr.MAX_TRANSITION_BYTES
        assert len(raw) == fr.max_transition_bytes() - (
            len("event.schema.v1") - len(pid))


def test_oversized_payload_is_refused():
    """A transition can never smuggle a bundle: the size check is unconditional."""
    fat = dict(_t(), format=fr.TRANSITION_FORMAT)
    fat["resulting_composition_root"] = "e" * 64
    raw = fr.canonical_bytes(fat)
    assert len(raw) <= fr.MAX_TRANSITION_BYTES
    with pytest.raises(fr.TransitionSizeError):
        fr.parse_transition_bytes(raw + b" " * fr.MAX_TRANSITION_BYTES)


def test_transition_round_trips_through_bytes():
    raw = fr.transition_bytes(target_profile="conv.pref.v1",
                              expected_prior_release_root=ROOT_A,
                              new_release_root=NEW_RELEASE,
                              resulting_composition_root=ROOT_COMP2)
    assert fr.canonical_bytes(fr.parse_transition_bytes(raw)) == raw


def test_non_canonical_encoding_of_a_valid_transition_is_refused():
    t = _t()
    pretty = json.dumps(t, indent=2).encode("utf-8")
    assert json.loads(pretty) == t                        # semantically identical...
    with pytest.raises(fr.FrontierSchemaError) as exc:    # ...but not the canonical bytes
        fr.parse_transition_bytes(pretty)
    assert "canonical form" in str(exc.value)


def test_transition_hash_is_over_the_canonical_bytes():
    t = _t()
    assert fr.transition_hash(t) == fr.sha256_hex(fr.canonical_bytes(t))


def test_unknown_or_missing_transition_field_is_rejected():
    t = _t()
    t["extra"] = "x"
    with pytest.raises(fr.FrontierSchemaError):
        fr.validate_transition(t)
    t = _t()
    del t["target_profile"]
    with pytest.raises(fr.FrontierSchemaError):
        fr.validate_transition(t)


def test_transition_family_tag_is_enforced():
    t = _t()
    t["format"] = fr.MANIFEST_FORMAT
    with pytest.raises(fr.FrontierSchemaError) as exc:
        fr.validate_transition(t)
    assert "domain-separated" in str(exc.value)


def test_unknown_target_profile_is_rejected():
    with pytest.raises(fr.UnknownProfileError):
        _t(target_profile="chat.voice.v1")
    with pytest.raises(fr.UnknownProfileError):
        _t(target_profile="Doc.Tool.v1")
    with pytest.raises(fr.UnknownProfileError):
        _t(target_profile=fr.LEGACY_PROFILE_ID)


def test_transition_bytes_are_bytes_not_str():
    with pytest.raises(fr.FrontierTypeError):
        fr.parse_transition_bytes("{}")


# --------------------------------------------------------------------------- #
# NO-OP
# --------------------------------------------------------------------------- #
def test_no_op_transition_is_rejected_at_construction():
    with pytest.raises(fr.NoOpTransitionError) as exc:
        _t(new_release_root=ROOT_B)                       # new == expected prior
    assert "advances nothing" in str(exc.value)


def test_no_op_transition_is_rejected_on_the_wire_too():
    """Even hand-built bytes cannot sneak a no-op past the decoder."""
    raw = fr.canonical_bytes({
        "expected_prior_release_root": ROOT_B, "format": fr.TRANSITION_FORMAT,
        "new_release_root": ROOT_B, "resulting_composition_root": ROOT_COMP2,
        "target_profile": "doc.tool.v1"})
    with pytest.raises(fr.NoOpTransitionError):
        fr.parse_transition_bytes(raw)


# --------------------------------------------------------------------------- #
# STALE PARENT (the off-chain twin of the contract CAS)
# --------------------------------------------------------------------------- #
def test_stale_expected_prior_release_root_is_rejected(manifest):
    stale = _t(expected_prior_release_root="f" * 64)
    with pytest.raises(fr.StaleParentError) as exc:
        fr.apply_transition(manifest, stale)
    assert "rebase" in str(exc.value)


def test_a_transition_bound_to_the_wrong_profiles_prior_root_is_stale(manifest):
    """``conv.pref.v1``'s root supplied for a ``doc.tool.v1`` edit: still stale, not accepted."""
    with pytest.raises(fr.StaleParentError):
        fr.apply_transition(manifest, _t(expected_prior_release_root=ROOT_A))


def test_two_candidates_against_one_parent_only_one_applies(manifest):
    """The race the contract resolves by CAS, reproduced off-chain."""
    first = _t(new_release_root="1" * 64, resulting_composition_root="a1" + "0" * 62)
    second = _t(new_release_root="2" * 64, resulting_composition_root="a2" + "0" * 62)
    landed = fr.apply_transition(manifest, first)
    with pytest.raises(fr.StaleParentError):
        fr.apply_transition(landed, second)               # loser must rebase, never fork
    rebased = fr.make_transition(
        target_profile="doc.tool.v1",
        expected_prior_release_root=landed["profiles"]["doc.tool.v1"],
        new_release_root="2" * 64, resulting_composition_root="a2" + "0" * 62)
    assert fr.apply_transition(landed, rebased)["profiles"]["doc.tool.v1"] == "2" * 64


# --------------------------------------------------------------------------- #
# COMPOSITION must follow the frontier
# --------------------------------------------------------------------------- #
def test_unchanged_composition_root_is_rejected(manifest):
    with pytest.raises(fr.CompositionUnchangedError) as exc:
        fr.apply_transition(manifest, _t(resulting_composition_root=ROOT_COMP))
    assert "superseded bundle" in str(exc.value)


# --------------------------------------------------------------------------- #
# apply_transition: pure, total, deterministic
# --------------------------------------------------------------------------- #
def test_apply_transition_does_not_mutate_its_inputs(manifest):
    t = _t()
    before_manifest = copy.deepcopy(manifest)
    before_transition = copy.deepcopy(t)
    fr.apply_transition(manifest, t)
    assert manifest == before_manifest
    assert t == before_transition


def test_apply_transition_returns_a_detached_document(manifest):
    child = fr.apply_transition(manifest, _t())
    child["profiles"]["conv.pref.v1"] = "9" * 64
    assert manifest["profiles"]["conv.pref.v1"] == ROOT_A


def test_apply_transition_is_deterministic(manifest):
    t = _t()
    results = [fr.frontier_root(fr.apply_transition(manifest, t)) for _ in range(25)]
    assert len(set(results)) == 1


def test_apply_transition_carries_pins_and_siblings_forward(manifest):
    child = fr.apply_transition(manifest, _t())
    assert child["epoch"] == manifest["epoch"]
    assert child["benchmark_law_root"] == manifest["benchmark_law_root"]
    assert child["runtime_abi_root"] == manifest["runtime_abi_root"]
    assert child["profiles"]["conv.pref.v1"] == ROOT_A
    assert child["profiles"]["event.schema.v1"] == ROOT_C
    assert child["profiles"]["doc.tool.v1"] == NEW_RELEASE
    assert child["default_composition_root"] == ROOT_COMP2
    assert child["parent_frontier_root"] == fr.frontier_root(manifest)
    assert child["format"] == fr.MANIFEST_FORMAT


def test_child_is_a_valid_manifest_and_never_carries_the_genesis_sentinel(manifest):
    child = fr.apply_transition(manifest, _t())
    fr.validate_manifest(child)
    assert child["parent_frontier_root"] != fr.ZERO_ROOT


def test_apply_transition_rejects_an_invalid_parent():
    with pytest.raises(fr.FrontierSchemaError):
        fr.apply_transition({"format": fr.MANIFEST_FORMAT}, _t())


# --------------------------------------------------------------------------- #
# verify_transition (public replay)
# --------------------------------------------------------------------------- #
def test_verify_transition_accepts_the_reproduced_root(manifest):
    t = _t()
    child = fr.apply_transition(manifest, t)
    result = fr.verify_transition(manifest, t, fr.frontier_root(child))
    assert result["new_manifest"] == child
    assert result["parent_root"] == fr.frontier_root(manifest)
    assert result["transition_hash"] == fr.transition_hash(t)


def test_verify_transition_raises_on_a_wrong_claimed_root(manifest):
    with pytest.raises(fr.RootMismatchError):
        fr.verify_transition(manifest, _t(), "e" * 64)


def test_verify_transition_rejects_a_malformed_claimed_root(manifest):
    with pytest.raises(fr.FrontierValueError):
        fr.verify_transition(manifest, _t(), "0x" + "e" * 62)


def test_verify_transition_never_returns_false(manifest):
    """A failed verification is an exception, so it can never be read as a pass."""
    try:
        fr.verify_transition(manifest, _t(), "e" * 64)
    except fr.FrontierError:
        return
    pytest.fail("verify_transition returned instead of failing closed")


# --------------------------------------------------------------------------- #
# ROLLBACK is an ordinary NEW transition (spec §9)
# --------------------------------------------------------------------------- #
def test_rollback_is_a_normal_transition_and_mints_a_new_root(manifest):
    forward = _t()
    advanced = fr.apply_transition(manifest, forward)
    back = fr.rollback_transition(advanced, target_profile="doc.tool.v1",
                                  restore_release_root=ROOT_B,
                                  resulting_composition_root=ROOT_COMP)
    assert back["format"] == fr.TRANSITION_FORMAT            # same family, no special opcode
    restored = fr.apply_transition(advanced, back)
    # the SERVED release is the original one again...
    assert restored["profiles"] == manifest["profiles"]
    assert restored["default_composition_root"] == manifest["default_composition_root"]
    # ...but the frontier root is NEW: history is append-only, never rewound.
    assert fr.frontier_root(restored) != fr.frontier_root(manifest)
    assert restored["parent_frontier_root"] == fr.frontier_root(advanced)


def test_rollback_to_the_currently_served_release_is_a_no_op_and_refused(manifest):
    with pytest.raises(fr.NoOpTransitionError):
        fr.rollback_transition(manifest, target_profile="doc.tool.v1",
                               restore_release_root=ROOT_B,
                               resulting_composition_root=ROOT_COMP2)


def test_rollback_replays_like_any_other_transition(manifest):
    advanced = fr.apply_transition(manifest, _t())
    back = fr.rollback_transition(advanced, target_profile="doc.tool.v1",
                                  restore_release_root=ROOT_B,
                                  resulting_composition_root=ROOT_COMP)
    restored = fr.apply_transition(advanced, back)
    assert fr.verify_transition(advanced, back, fr.frontier_root(restored))["new_root"] \
        == fr.frontier_root(restored)


def test_chain_of_roots_is_a_total_order(manifest):
    """Every state in a chain has a distinct root, including a return to earlier content."""
    roots = [fr.frontier_root(manifest)]
    state = manifest
    comps = ["a" + "0" * 63, "b" + "0" * 63, "c" + "0" * 63]
    releases = ["1" * 64, "2" * 64, ROOT_B]                  # the third RESTORES the original
    for comp, rel in zip(comps, releases):
        t = fr.make_transition(target_profile="doc.tool.v1",
                               expected_prior_release_root=state["profiles"]["doc.tool.v1"],
                               new_release_root=rel, resulting_composition_root=comp)
        state = fr.apply_transition(state, t)
        roots.append(fr.frontier_root(state))
    assert len(set(roots)) == len(roots)
