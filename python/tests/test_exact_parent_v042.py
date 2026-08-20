# SPDX-License-Identifier: Apache-2.0
"""Exact-parent compatibility tests for the public 0.4.2 validator cut.

These fixtures stay entirely inside the standalone package contract: no checkout-relative
``v5/GENESIS`` file and no installed CoreTex runtime is needed to authenticate the public CAS
graph. Candidate execution remains the separate pinned-sandbox stage.
"""
from __future__ import annotations

import copy
import hashlib

import pytest

from coretex_validator import eval_artifact as ea
from coretex_validator import frontier as fr
from coretex_validator import parent_execution as pe
from coretex_validator import publication as pub
from coretex_validator import replay as rp
from coretex_validator import release_graph as rg


TARGET = "doc.tool.v1"
MODULE_BYTES = (
    b"from coretex_memory import abi2\n"
    b"from coretex_memory.hooks import HookDispatch\n\n"
    b"def make_hooks(context):\n"
    b"    dispatch = HookDispatch()\n"
    b"    dispatch.set_override(abi2.M6, context.ref_m6_pack)\n"
    b"    return dispatch\n"
)


def _publish_signed(document, store):
    root = pub.root_of(
        pub.encode(document, pub.HASH_RULE_SIGNED_MANIFEST_BODY),
        pub.HASH_RULE_SIGNED_MANIFEST_BODY,
    )
    addressed = {**document, "manifest_self_sha256": root}
    published = pub.publish_item(
        addressed, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    assert published["root"] == root
    return root, addressed


def _release(profile_id, module_sha256, store):
    body = {
        "schema": "coretex-memory/release-manifest",
        "manifest_schema_version": rg.SANDBOXED_RELEASE_SCHEMA,
        "policy_id": f"fixture-{profile_id}",
        "module_sha256": module_sha256,
        "source_provenance": {
            "entry": "Fixture",
            "miner": f"miner-{profile_id}",
            "profile_id": profile_id,
            "base_modules": {},
        },
        "abi_version": "memory-hooks.v1",
        "runtime_version_min": "0.1.5",
        "runtime_version_max": "0.1.5",
        "candidate_provider": "fixture",
        "counter": "fixture",
        "store_schema_version": "1",
        "deployment_profile": profile_id,
        "rollback_id": f"rollback-{profile_id}",
        "hooks": {"m6_pack": "1"},
        "capabilities": ["cap.text.v1"],
        "capabilities_used": ["cap.text.v1"],
        "content_authority": rg.CONTENT_AUTHORITY,
        "admission_report_hash": "ab" * 32,
        "analyzer_ruleset_root": "cd" * 32,
        "wrapper_format": rg.DIRECT_WRAPPER_FORMAT,
    }
    return _publish_signed(body, store)


def _parent_graph():
    store = pub.InMemoryCAS()
    module_sha256 = pub.publish_item(
        MODULE_BYTES, hash_rule=pub.HASH_RULE_BYTES, store=store)["root"]
    releases = {}
    manifests = {}
    for profile_id in fr.PROFILE_IDS:
        releases[profile_id], manifests[profile_id] = _release(
            profile_id, module_sha256, store)
    candidates = {
        profile_id: hashlib.sha256(f"candidate:{profile_id}".encode()).hexdigest()
        for profile_id in fr.PROFILE_IDS
    }
    miners = {profile_id: f"miner-{profile_id}" for profile_id in fr.PROFILE_IDS}
    composition_body = {
        "format": rg.COMPOSITION_FORMAT,
        "content_authority": rg.CONTENT_AUTHORITY,
        "profile_bindings": {
            **{
                profile_id: {
                    "release_id": releases[profile_id],
                    "bundle_manifest_sha256": releases[profile_id],
                    "candidate_hash": candidates[profile_id],
                    "module_sha256": module_sha256,
                    "miner_sha256": module_sha256,
                    "miner_id": miners[profile_id],
                    "bundle_dir": f"bundles/{miners[profile_id]}",
                    "is_baseline": False,
                }
                for profile_id in fr.PROFILE_IDS
            },
            fr.LEGACY_PROFILE_ID: {
                "bundle_dir": None,
                "is_baseline": True,
                "miner_id": None,
            },
        },
        "delegation_candidate_hashes": {
            **candidates,
            fr.LEGACY_PROFILE_ID: None,
        },
        "bundles": {
            **{profile_id: f"bundles/{miners[profile_id]}" for profile_id in fr.PROFILE_IDS},
            fr.LEGACY_PROFILE_ID: None,
        },
        "composition": {**miners, fr.LEGACY_PROFILE_ID: None},
    }
    composition_root, _ = _publish_signed(composition_body, store)
    parent = {
        "benchmark_law_root": "11" * 32,
        "default_composition_root": composition_root,
        "epoch": 181,
        "format": fr.MANIFEST_FORMAT,
        "parent_frontier_root": "22" * 32,
        "profiles": releases,
        "runtime_abi_root": "33" * 32,
    }
    return store, parent, releases, candidates, module_sha256


def _law_inputs(parent, incumbent):
    return {
        "artifact": {
            "format": ea.ARTIFACT_FORMAT,
            "candidate": {
                "prior_release_root": parent["profiles"][TARGET],
                "target_profile": TARGET,
            },
            "receipt": {"code_roots": {"validator": "fe" * 32}},
            "replay_inputs": {"incumbent": incumbent},
        },
        "parent_manifest": parent,
        "target_profile": TARGET,
        "ppm": {
            "utility_before_ppm": 900_000,
            "utility_after_ppm": 950_000,
            "resource_before_ppm": ea.MICRO,
            "resource_after_ppm": ea.MICRO,
        },
        "deterministic": {"admit": True, "verdict": "ADMIT"},
    }


def test_exact_five_field_identity_round_trips_without_a_sibling_v5_tree():
    store, parent, releases, candidates, module_sha256 = _parent_graph()

    execution = pe.fetch_parent_execution(
        store=store, parent_manifest=parent, target_profile=TARGET)
    identity = pe.compact_identity(execution)

    assert identity == {
        "candidate_hash": candidates[TARGET],
        "exec": "candidate_module",
        "id": releases[TARGET],
        "module_sha256": module_sha256,
        "release_root": releases[TARGET],
    }
    assert ea.project_incumbent(identity) == identity


def test_exact_parent_rehashes_module_bytes_instead_of_trusting_the_label():
    store, parent, _, _, module_sha256 = _parent_graph()
    store._objects[module_sha256] = b"def substituted():\n    return True\n"

    with pytest.raises((pe.ParentExecutionError, pub.PublicationError),
                       match="module.*hash|hash.*module|rehashes"):
        pe.fetch_parent_execution(store=store, parent_manifest=parent, target_profile=TARGET)


def test_partial_or_open_incumbent_identities_are_refused():
    exact = {
        "candidate_hash": "44" * 32,
        "exec": "candidate_module",
        "id": "55" * 32,
        "release_root": "55" * 32,
        "module_sha256": "66" * 32,
    }
    for invalid in (
        {key: value for key, value in exact.items() if key != "module_sha256"},
        {**exact, "unbound": "field"},
    ):
        with pytest.raises(ea.ReceiptBindingError):
            ea.project_incumbent(invalid)


def test_reference_label_cannot_stand_in_for_a_non_initial_parent():
    _, parent, _, _, _ = _parent_graph()
    historical_reference = {
        "candidate_hash": fr.ZERO_ROOT,
        "exec": "reference",
        "id": "reference-runtime",
    }

    result = rp._beat_incumbent(**_law_inputs(parent, historical_reference))

    assert result["code"] == "wrong_incumbent_execution"


def test_exact_parent_identity_is_bound_to_public_release_and_module_bytes():
    store, parent, _, _, _ = _parent_graph()
    execution = pe.fetch_parent_execution(
        store=store, parent_manifest=parent, target_profile=TARGET)
    exact = pe.compact_identity(execution)

    result = rp._beat_incumbent(**_law_inputs(parent, exact), store=store)
    tampered = copy.deepcopy(exact)
    tampered["module_sha256"] = "ff" * 32
    rejected = rp._beat_incumbent(**_law_inputs(parent, tampered), store=store)

    assert result["code"] is None
    assert rejected["code"] == "wrong_incumbent_execution"


def test_only_the_exact_frozen_pre_cut_code_roots_authorize_three_fields():
    frozen = copy.deepcopy(pe.PRE_EXACT_PARENT_CODE_ROOT_SETS[0])
    assert pe.is_pre_exact_parent_code_roots(frozen)
    mutated = copy.deepcopy(frozen)
    mutated["validator"] = "ff" * 32
    assert not pe.is_pre_exact_parent_code_roots(mutated)
