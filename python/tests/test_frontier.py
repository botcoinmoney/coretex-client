from __future__ import annotations

import copy

import pytest

from coretex_validator import frontier


def manifest():
    return frontier.new_manifest(
        epoch=1,
        parent_frontier_root="1" * 64,
        benchmark_law_root="2" * 64,
        runtime_abi_root="3" * 64,
        default_composition_root="4" * 64,
        profiles={profile: str(index) * 64 for index, profile in enumerate(
            frontier.PROFILE_IDS, start=5)},
    )


def test_transition_is_pure_and_reproduces_one_child():
    parent = manifest()
    before = copy.deepcopy(parent)
    transition = frontier.make_transition(
        target_profile="doc.tool.v1",
        expected_prior_release_root=parent["profiles"]["doc.tool.v1"],
        new_release_root="8" * 64,
        resulting_composition_root="9" * 64,
    )
    child = frontier.apply_transition(parent, transition)
    assert parent == before
    verified = frontier.verify_transition(parent, transition, frontier.frontier_root(child))
    assert verified["new_root"] == frontier.frontier_root(child)


def test_transition_refuses_stale_parent_and_open_schema():
    parent = manifest()
    transition = frontier.make_transition(
        target_profile="doc.tool.v1",
        expected_prior_release_root="a" * 64,
        new_release_root="b" * 64,
        resulting_composition_root="c" * 64,
    )
    with pytest.raises(frontier.StaleParentError):
        frontier.apply_transition(parent, transition)
    with pytest.raises(frontier.FrontierSchemaError):
        frontier.validate_manifest({**parent, "note": "not hashed law"})
