# SPDX-License-Identifier: Apache-2.0
"""The public CoreTex validator for the canonical descriptor-v3 rig lane.

WHAT THIS PACKAGE IS FOR. A CoreTex state transition is a claim, and the whole point of the
protocol is that the claim is checkable by someone who trusts nobody in it. This package is that
checker, packaged so a clean machine can run it: it discovers a release, verifies the deployed
bytecode against the hashes the release recorded, replays per-rig receipt continuity, reconstructs
the exact transition from chain logs + calldata, reruns deterministic admission, checks the law
that applied AT THAT TRANSITION, reproduces the resolver's unsigned snapshot payload byte for
byte, and exports the verified snapshot for portable activation.

WHY THERE IS NO THIRD-PARTY CRYPTO DEPENDENCY. Everything on-chain that has to be recomputed —
``keccak256``, EIP-712 digests, ABI encodings, ``ecrecover`` — is implemented here on the standard
library (:mod:`.keccak256`, :mod:`.abi`, :mod:`.secp256k1`). That is a deliberate property, not an
accident of packaging: a validator whose answer depends on a wheel it downloaded is a validator
whose answer depends on whoever published that wheel. ``pyproject.toml`` declares ZERO runtime
dependencies and a clean-install test asserts it.

PRODUCTION LANE. The public command subscribes only to the canonical descriptor-v3 rig contracts.
Its state bootstrap is the confirmed verifier epoch-context parent, never the registry constructor
genesis. Historical decoder modules remain internal regression evidence and are not selectable by
the production command.
"""
from __future__ import annotations

__all__ = [
    "__version__",
    "abi",
    "authority_law",
    "backlog",
    "chain_first",
    "dispatch",
    "eval_artifact",
    "export",
    "frontier",
    "historical_law",
    "join",
    "keccak256",
    "law",
    "parent_execution",
    "publication",
    "receipt_chain",
    "release",
    "release_graph",
    "replay",
    "rig_events",
    "rpc",
    "secp256k1",
    "snapshot",
    "sync",
]

#: Independent of the npm package version on purpose: the two ship together but are versioned by
#: what they each promise. Bumped when a check is added, removed or changed in meaning.
#:
#: 0.4.0 is the one-shape law break. Prospective materialization accepts only schema 4, direct
#: wrapper format 3, explicit empty ``base_modules``, and byte-identical miner/module content with
#: admission-report, analyzer-ruleset, and ``capabilities_used`` commitments. Schema 3 remains
#: available only through an explicitly historical inspection function and cannot activate state.
#:
#: 0.4.1 adds ``coretex-validator setup`` (verify the live deployment, cache kit packages, read
#: the chain head). Verification semantics are unchanged from 0.4.0.
#:
#: 0.4.2 binds an exact five-field incumbent identity to the confirmed parent's composition,
#: release and module bytes. The historical three-field shape remains replayable only for the
#: exact frozen pre-cut code-root set embedded in the wheel.
__version__ = "0.4.2"
