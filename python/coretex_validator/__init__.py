# SPDX-License-Identifier: Apache-2.0
"""Independent validation for the first public CoreTex descriptor-v3 rig lane.

The package verifies the closed 1.0.0 release, starts chain discovery at the paired activation
epoch and confirmed event block, joins signed receipts to logs and calldata, and replays the fixed
suite transition. Full scoring runs only the runtime and support bytes bound by that release; no
package is downloaded or selected from the ambient environment.
"""
from __future__ import annotations

__all__ = [
    "__version__",
    "abi",
    "activation",
    "benchmark_replay",
    "canonical_suite",
    "cli",
    "compat_lock",
    "discovery",
    "dispatch",
    "eval_artifact",
    "frontier",
    "epoch_law",
    "join",
    "keccak256",
    "parent_execution",
    "publication",
    "receipt_chain",
    "release",
    "release_schema",
    "replay",
    "rig_events",
    "rpc",
    "secp256k1",
    "snapshot",
]

#: The Python validator, TypeScript client, and npm package are one first-public product.
__version__ = "1.0.0"
