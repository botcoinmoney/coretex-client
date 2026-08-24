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
    "preview",
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
#:
#: 0.4.3 is the "a stranger can get to a verdict from a URL" cut. Nothing about what a check
#: MEANS moved; what moved is how much a clean machine has to be handed before it can run one.
#:   * ``preview-current-parent`` scores a candidate against the LIVE confirmed parent rather
#:     than against a parent the caller names, so "would this advance" is answerable without
#:     first knowing which parent is current.
#:   * every object fetch carries the manifest's committed hash rule with it
#:     (:func:`.publication.get_for_rule`), instead of re-deciding the rule at each call site.
#:     A publication that commits ``sha256-bytes`` can no longer be verified under some other
#:     rule that happened to be the local default.
#:   * the rehearsal default publication root is GONE, along with the flat layout that could
#:     never have verified against it. A rehearsal root silently pinned on a live host is a
#:     validator that reports a verified cache for the wrong law; there is now no default at
#:     all, and ``--root`` (or ``setup``) must supply one.
#:   * ``setup`` discovers the deployment's publication root from the coordinator's kit and
#:     installs the admission law itself, so step 5 of ``reproduce`` no longer BACKLOGs on a
#:     machine that started with nothing.
#:   * ``replay-latest`` replays the newest confirmed advance without being told which one.
#:
#: 0.4.4 is the published 0.4.3 feature set plus PUBLIC COMPATIBILITY-LOCK SUPPORT. Nothing that
#: 0.4.3 checked changed meaning; what changed is that the compatibility lock is now obtainable
#: and verifiable from a URL instead of having to be handed to the machine out of band.
#:   * the lock is fetched from the coordinator's public object route,
#:     ``GET /coretex/v5/object/<coreVersionHash>?hashRule=compatibility-lock-root``. The rule is
#:     named in the request because a lock root is not a ``sha256`` over the served bytes and a
#:     surface cannot guess which construction the caller committed to.
#:   * the served bytes must BE the canonical serialisation of what they decode to, and the
#:     document is re-addressed here —
#:     ``keccak256(0x19 || "coretex.compatibility-lock/v1" || 0x0a || canonical body without
#:     lock_root)``. The recomputed root, the document's own ``lock_root`` and the chain's word
#:     must be one value. The server's own ``verified: true`` is never read.
#:   * ``setup`` binds that lock: the exact verified bytes are cached under their root in
#:     ``<packages-dir>/artifacts/``, and the root is recorded in ``ACTIVE-INSTALL.json`` so a
#:     later run can see which lock the installation was bound to. A coordinator that cannot
#:     serve the rule leaves ``lock.verified: false`` with a remedy and setup still exits 0 —
#:     unreachable is not refuted — while bytes that contradict their address fail loudly.
#:   * descriptor-v3 snapshot reproduction consumes that verified fetch: the cached lock is read
#:     from the artifacts directory rather than seeded by hand, so a clean machine reproduces a
#:     published snapshot without being trusted to supply the lock itself.
__version__ = "0.4.4"
