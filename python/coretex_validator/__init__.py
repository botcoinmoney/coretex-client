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
#: 0.3.0 COLLAPSES A THREE-WAY SKEW. Up to 0.2.x this package had three live versions at once —
#: source 0.2.3, a built wheel 0.2.2, and an agent extra pinning ``==0.2.1`` — which meant nobody
#: could say which checks a given "coretex-validator" performed. Spec §8 requires ONE released
#: version, pinned exactly, and this is it. What is new in it: ``sync-law`` (fetch + verify the
#: published admission law and pin it), ``replay-advance`` and ``verify-receipt``.
__version__ = "0.3.0"
