# SPDX-License-Identifier: Apache-2.0
"""The deployed worldSeed ABI member is reserved as zero by the CoreTex product."""
from __future__ import annotations

import pytest

from coretex_validator import eval_artifact as ea


def _rig_receipt(world_seed: int) -> dict:
    return {
        "challenge_id": "11" * 32,
        "core_version_hash": "22" * 32,
        "epoch_context_root": "33" * 32,
        "outcome": ea.RIG_OUTCOME_STATE_ADVANCE,
        "rules_version": 1,
        "transition_format_version": ea.RIG_TRANSITION_FORMAT_VERSION,
        "work_policy_hash": "44" * 32,
        "world_seed": world_seed,
    }


def test_artifact_verifier_accepts_reserved_integer_zero():
    rig = ea.validate_rig_receipt_block(_rig_receipt(0))
    assert rig["world_seed"] == ea.RIG_CORETEX_RESERVED_WORLD_SEED == 0


@pytest.mark.parametrize("world_seed", [1, 2 ** 127, ea.MAX_UINT128])
def test_artifact_verifier_refuses_every_nonzero_world_seed(world_seed):
    with pytest.raises(ea.RigReceiptFieldError, match="reserves this deployed-ABI member as 0"):
        ea.validate_rig_receipt_block(_rig_receipt(world_seed))
