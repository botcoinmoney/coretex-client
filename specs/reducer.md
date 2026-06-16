# Cortex Epoch Reducer CoreTex

**Phase**: 6 — Credit + Reducer Mechanics
**Owner**: Economics + Protocol subagents
**Status**: Complete

---

## Overview

The reducer is a **deterministic, public-replayable** function that seals the
state-advance checkpoints emitted during a 24-hour epoch and produces:

- `accepted` — ordered list of state-advancing patches
- `rejected` — list of skipped patches with stable rejection codes
- `patchSetRoot` — Merkle root committing to the accepted set
- `newStateRoot` — Merkle root of the updated CortexState

**Canonical invariant**: any external party who holds only the on-chain
`CortexPatchAccepted` events for an epoch (which carry full `compactPatchBytes`)
and the `parentStateRoot` can run `scripts/replay-reducer.mjs` to re-derive the
same `patchSetRoot` and `newStateRoot` byte-identically.

---

## Algorithm

```
function reduce(parentState, screenerPassPatches, threshold):
  { newState, patchSetRoot, accepted, rejected }

  // 1. Sort — deterministic ordering by quality then size then hash
  ordered = stable-sort(screenerPassPatches, key = (-scoreDelta, +patchSize, +patchHash))

  // 2. Apply greedily with target-overlap and semantic-conflict guards
  current         = parentState
  acceptedSet     = []
  rejected        = []
  acceptedTargets = new Set<int>()

  for patch in ordered:
    // 2a. Target-overlap guard
    if patch.indices.any(i => acceptedTargets.has(i)):
      rejected.push({ patch, reason: 'R01_TARGET_OVERLAP' })
      continue

    // 2b. Semantic-conflict guard — re-evaluate marginal gain on `current`
    marginalGain = evaluator.scoreDelta(current, patch)
    if marginalGain < threshold:
      rejected.push({ patch, reason: 'R02_SEMANTIC_CONFLICT' })
      continue

    // 2c. Apply
    current = applyPatch(current, patch).state
    acceptedSet.push(patch)
    for i in patch.indices: acceptedTargets.add(i)

  // 3. patchSetRoot commitment
  //    leaves = keccak256(compactPatchBytes) for each accepted patch
  //    sorted by acceptance index (= stable acceptance order)
  //    root = merkle tree over those leaves
  patchSetRoot = merkleizePatchSet(acceptedSet)

  return { newState: current, patchSetRoot, accepted: acceptedSet, rejected }
```

---

## Sort key

`(-scoreDelta, +patchSize, +patchHash)` — descending priority:

1. **Higher `scoreDelta`** wins. Score delta is the primary quality signal from the
   screener eval report.
2. **Smaller `patchSize`** (word count) wins on tie. Prefer minimally invasive changes.
3. **Lower `patchHash`** (lexicographic on bytes) wins on remaining tie. Provides
   a stable, coordinator-independent tiebreak that any replayer can reproduce.

The sort is **stable** — patches with identical keys preserve submission order,
which is also deterministic because submission order is indexed by the on-chain
`CortexPatchAccepted` event's log index.

---

## Rejection codes

| Code | Reason | Description |
|------|--------|-------------|
| `R01_TARGET_OVERLAP` | Target-index collision | At least one of the patch's target word indices was already committed by a higher-priority accepted patch. |
| `R02_SEMANTIC_CONFLICT` | Marginal-gain drop | The patch's marginal score-delta re-evaluated on top of already-accepted state falls below `threshold`. |
| `R03_THRESHOLD_DROP` | Score below threshold | The evaluated score-delta for the patch as a standalone candidate is below the epoch threshold. (Used at screener; reducer uses R02 for marginal-gain drops.) |

---

## Threshold parameter

`threshold` is the **minimum marginal score-delta required** for a patch to be
accepted by the reducer. It is posted on-chain at epoch start via
`CortexRegistry.setEpochThreshold(epoch, threshold)` and is included in the
public reducer input set. The default CoreTex value is `0` — any non-negative
marginal gain is accepted. The screener already enforces a positive delta; the
reducer threshold guards against patches whose marginal contribution drops to
zero or negative when combined with already-accepted state.

---

## patchSetRoot construction

```
leaves[i] = keccak256(compactPatchBytes[i])   // i = acceptance index
root      = keccak256(concat(leaves))         // flat concat, not Merkle tree
```

In CoreTex the `patchSetRoot` is `keccak256(concat(keccak256(bytes_0) ‖ ... ‖ keccak256(bytes_n)))`.
The leaves are ordered by acceptance index (the order patches were accepted, not
submission order). Any replayer recomputes this from the `CortexPatchAccepted`
events, sorted by log index (= submission order used as input; acceptance order
may differ from submission order because of the sort step).

---

## Public-replay equivalence

An external script (`scripts/replay-reducer.mjs`) takes:

```
{ epoch, parentStateRoot, threshold, events: CortexPatchAccepted[] }
```

and produces:

```
{ patchSetRoot, newStateRoot, accepted: patchHash[], rejected: { patchHash, reason }[] }
```

The script reads only chain-observable data:
- `parentStateRoot` from the previous `CortexEpochFinalized` event (or genesis)
- `threshold` from `CortexRegistry.getEpochThreshold(epoch)`
- `events` from `CortexPatchAccepted(epoch=...)` filtered from chain logs

No coordinator data. No off-chain state. Same output as the coordinator reducer.

---

## Credit mechanics

### Layer A — State-advance credits

A patch earns a `StateAdvance` credit only when it is verified as a real
marginal improvement on the current live state and emitted as
`CortexStateAdvanced`. Credits = miner's current on-chain tier credits, or a
published function of `improvementCredits`, paid through the existing
`BotcoinMiningV3.submitReceipt` path. A screener-looking patch that does not
advance the live state receives a stable rejection code and earns no receipt.

The epoch remains 24 hours. The state may advance many times inside that epoch;
epoch end seals the ordered checkpoint list into `patchSetRoot` and
`newStateRoot`.

### Layer B — Stale merge bonus disabled

The separate merge multiplier is disabled for production launch:

```
MERGE_MULTIPLIER_BPS = 10000
bonusBOTCOIN = 0
```

`CortexMergeBonus` remains in-tree for compatibility and previous proof testing,
but coordinators should not fund zero-uplift epochs. This removes the incentive
to skim weak screener passes, withhold a better patch for a future multiplier,
or optimize for an end-of-epoch jackpot instead of advancing the organism now.

### No double-credit invariant

For any `(epoch, miner, patchHash)`:
- `CortexStateAdvanced` produces at most one credit issuance
- duplicate state-advance events for the same tuple are skipped in replay
- screener-only candidates produce no credits

---

## Anti-centralization properties

1. **State-advance credits** are distributed to verified improvements, not mere submissions.
2. **No separate multiplier** means there is no extra payout to game by withholding.
3. Multiple non-overlapping improvements in the same epoch can all advance state.
   Later overlapping improvements can also advance if they rebase on the current
   live root and improve it further.
4. Simulation target (verified in Phase 6 E2E): no single miner captures > 25% of any
   epoch's combined-lane credits (measured 9.47%); Gini coefficient stays below
   the documented threshold of 0.70 over 50 epochs with a 100-miner weak/medium/strong
   mix (measured 0.5743). The 0.70 threshold reflects structural tier inequality
   (1×/2×/5× credits across tiers) rather than protocol centralization; the per-epoch
   25% cap is the meaningful anti-centralization guarantee.

---

## Determinism guarantees

The reducer is a **pure function**:
- Same `parentState`, same `screenerPassPatches`, same `threshold` → same output
- No I/O, no clock, no random state
- Sort is stable; tie-break uses `patchHash` (deterministic from patch bytes)
- `applyPatch` is deterministic (Phase 1 frozen)
- `merkleizeState` is deterministic (Phase 1 frozen)

Public-replay equivalence is non-negotiable: the replay script and the coordinator
reducer share the same deterministic algorithm; divergence is a bug.

---

## Screener rejection codes (filler battery)

| Code | Reason |
|------|--------|
| `S01_NOOP` | Patch is a no-op (new words = old words) |
| `S02_RANDOM_MUTATION` | Score delta ≤ 0 (no improvement) |
| `S03_OVERFIT` | Patch improves only on public test set; hidden-shard score < threshold |
| `S04_PROTECTED_REGRESSION` | Patch causes a drop on any protected anchor |
| `S05_OVERSIZE` | Patch exceeds budget (wordCount > 4 or wire size > limit) |

---

## V1 paths (deferred)

- `threshold` per family (not just global)
- Soft-cap mode: additional merges in same epoch earn diminishing (not zero) uplift
- ZK scoring fraud proofs
- `BotcoinMining.submitCortexReceipt(...)` with explicit field names
