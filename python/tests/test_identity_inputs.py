from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from coretex_validator import (
    canonical_suite, cli, eval_artifact, frontier, parent_execution, release_schema,
    rig_receipt_binding,
)
from coretex_validator.rig_receipt_binding import (
    RIG_BINDING_AUTHORITY_SHA256,
    TRANSITION_DESCRIPTOR_BYTES,
    TRANSITION_DESCRIPTOR_VERSION,
)


PACKAGE = Path(__file__).parents[1] / "coretex_validator"


def test_fixed_suite_and_contract_are_current_closed_inputs():
    assert canonical_suite.suite_law_id() == "benchmark-v2-law/dominance-fixed-suite.v2"
    assert len(canonical_suite.suite_root()) == 64
    contract = json.loads((PACKAGE / "RELEASE-CONTRACT.v1.json").read_text())
    assert contract["product"] == {
        "name": "coretex", "predecessor": None, "sequence": 1, "version": "1.0.0"}
    assert set(contract["profiles"]) == set(canonical_suite.canonical_suite()["profiles"])
    assert release_schema.RELEASE_FORMAT == contract["release_format"]


def test_rig_wire_sidecar_is_bound_to_embedded_authority():
    raw = (PACKAGE / "RIG-CONTRACT-AUTHORITY.base-mainnet.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RIG_BINDING_AUTHORITY_SHA256
    assert (TRANSITION_DESCRIPTOR_VERSION, TRANSITION_DESCRIPTOR_BYTES) == (0x21, 97)


def test_genesis_profiles_are_builtin_runtime_identities_not_phantom_modules():
    source = canonical_suite.genesis_floor_authority()["source"]
    for profile, row in source["profiles"].items():
        assert row == {
            "exec": "reference",
            "reference_runtime": {"id": "reference-runtime", "protocol": "rrm1"},
            "release_root": row["release_root"],
        }
        descriptor = {
            "abi": {
                "capabilities": ["cap.text.v1", "cap.lexicon.v1"],
                "hooks": [
                    "m1_ingest_transform", "m2_organize", "m3_consolidate",
                    "m4_candidates", "m5_rank", "m6_pack",
                ],
                "id": "coretex-memory/miner-module/v1",
                "module_version": 2,
                "policy_version": 1,
            },
            "exec": "reference",
            "format": "coretex.genesis-reference-release/v1",
            "profile_id": profile,
            "reference_runtime": {"id": "reference-runtime", "protocol": "rrm1"},
        }
        assert frontier.sha256_hex(frontier.canonical_bytes(descriptor)) == row["release_root"]
        assert "module" not in descriptor and "module_sha256" not in descriptor

        compact = parent_execution.compact_identity({
            "candidate_hash": None,
            "exec": "reference",
            "id": "reference-runtime",
            "release_manifest": descriptor,
            "release_root": row["release_root"],
        })
        assert compact == {
            "candidate_hash": None,
            "exec": "reference",
            "id": "reference-runtime",
            "protocol": "rrm1",
            "release_root": row["release_root"],
        }
        assert eval_artifact.project_incumbent(compact) == {
            **compact, "candidate_hash": frontier.ZERO_ROOT,
        }


def test_all_external_or_embedded_json_entry_points_refuse_duplicate_keys(tmp_path):
    duplicate = b'{"value":1,"value":2}'
    path = tmp_path / "duplicate.json"
    path.write_bytes(duplicate)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        cli._load_json(str(path))
    with pytest.raises(RuntimeError, match="duplicate JSON key"):
        release_schema._decode_json(duplicate, "fixture")
    with pytest.raises(RuntimeError, match="duplicate JSON key"):
        rig_receipt_binding._json(duplicate, "fixture")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        canonical_suite._reject_duplicates([("value", 1), ("value", 2)])
    with pytest.raises(ValueError, match="non-finite JSON value"):
        canonical_suite._reject_nonfinite("NaN")
