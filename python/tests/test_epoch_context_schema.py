from __future__ import annotations

import hashlib

import pytest

from coretex_validator import dispatch


def _root(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _manifest() -> dict[str, object]:
    return {
        "format": "coretex.epoch-context/v1",
        "epoch": 1,
        "corpus_root": _root("corpus"),
        "active_frontier_root": _root("frontier"),
        "baseline_manifest_hash": _root("baseline"),
        "benchmark_law_root": _root("benchmark-law"),
        "runtime_abi_root": _root("runtime-abi"),
        "counter_resource_law_root": _root("counter-resource-law"),
        "selection_law_root": _root("selection-law"),
        "seed_commitment": {
            "scheme": "keccak256-hidden-seed/v1",
            "binding_rule": (
                "revealed secret S is admitted iff keccak256(S) == epochCommit(epochId)"),
            "commitment_source": "mining.epochCommit(epochId)",
        },
    }


def test_selection_law_root_is_the_only_admission_law_binding() -> None:
    manifest = _manifest()
    assert dispatch.validate_epoch_context(manifest) == manifest
    assert "admission_thresholds_ppm" not in dispatch.EPOCH_CONTEXT_FIELDS


def test_obsolete_duplicate_threshold_description_is_rejected() -> None:
    manifest = {
        **_manifest(),
        "admission_thresholds_ppm": {
            "maximum_resource_regression_ppm": 0,
            "minimum_utility_improvement_ppm": 1,
        },
    }
    with pytest.raises(dispatch.EpochContextError) as raised:
        dispatch.validate_epoch_context(manifest)
    assert raised.value.code == dispatch.EPOCH_CONTEXT_MALFORMED

