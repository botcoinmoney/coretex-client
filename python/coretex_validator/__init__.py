# SPDX-License-Identifier: Apache-2.0
"""The public CoreTex validator: legacy V4 replay, and the V5 rig lane beside it.

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

THE TWO LANES, AND WHY THEY ARE SEPARATE MODULES.

* **V4** (``coretex.state.v4``) is frozen. Its decoder dispatches on the ``CoreTexStateAdvanced``
  topic0 and reads fixed ABI word offsets. Nothing here changes it, and
  ``test_v4_decode_is_byte_for_byte`` pins it.
* **The rig lane** (``coretex.rig-state.v1``) is new. It is NOT a variant of V4 with a flag: it is
  a different registry, a different receipt shape, a rig id instead of a miner address, and an
  epoch context that lives on the VERIFIER rather than the registry.

They coexist by ADDRESS, not by topic0 — and that is forced rather than chosen. The exact rig
registry emits an advance event whose topic0 is BYTE-IDENTICAL to V4's (see :mod:`.rig_events`
and ``docs/V5-RIG-VALIDATOR.md``), so topic0 is not an identity and any dispatch that treats it as
one silently mixes the two lanes' logs.

CLASSIFICATION. Snapshots this package produces for the rehearsal deployment are
``MAINNET_REHEARSAL`` and never ``MAINNET_CANONICAL``. The distinction is enforced in
:mod:`.export`, not left to a convention.
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
    "publication",
    "receipt_chain",
    "release",
    "replay",
    "rig_events",
    "rpc",
    "secp256k1",
    "snapshot",
    "sync",
]

#: Independent of the npm package version on purpose: the two ship together but are versioned by
#: what they each promise. Bumped when a check is added, removed or changed in meaning.
__version__ = "0.1.0"
