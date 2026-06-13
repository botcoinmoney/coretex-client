/**
 * Cortex Epoch Reducer CoreTex
 *
 * Deterministic greedy-by-marginal-gain patch selection.
 * Per reducer.md:
 *   Sort by (-scoreDelta, +patchSize, +patchHash) then apply greedily,
 *   skipping target-overlap and semantic-conflict (marginal-gain below threshold).
 *
 * This is a pure function: same inputs → same outputs. No I/O, no clock.
 */

import type { CortexState, Patch } from '../state/types.js';
import {
  applyPatch,
  applyPatchOntoCurrent,
  patchMatchesEpochParent,
  encodePatch,
} from '../state/patch.js';
import { merkleizeState, bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import { computePatchHash } from '../eval/seed-derivation.js';
import { evaluateAndApplyOntoCurrent } from './accept-core.js';

// ── Types ─────────────────────────────────────────────────────────────────────

/** Stable rejection codes for the reducer. */
export type RejectionCode =
  | 'R01_TARGET_OVERLAP'
  | 'R02_SEMANTIC_CONFLICT'
  | 'R03_WRONG_PARENT_ROOT'
  | 'R04_INVALID_TARGET'
  | 'R05_RESERVED_BIT_SET';

/** A screener-pass patch as input to the reducer. */
export interface ReducerInputPatch {
  /** Decoded patch object. */
  readonly patch: Patch;
  /** Compact wire bytes for this patch (used for hash computation). */
  readonly patchBytes: Uint8Array;
  /** Claimed score delta from the screener eval report (bigint, signed). */
  readonly scoreDelta: bigint;
  /**
   * Marginal-gain evaluator: re-evaluates this patch on top of `currentState`.
   * Must be a pure function. Returns bigint (signed).
   *
   * In production this is `CoreTex benchmarkEvaluator.scoreDelta(currentState, patch)`.
   * In replay scripts it is the same evaluator loaded from Core CoreTex.
   * In CoreTex with Phase 4 not yet merged: defaults to returning `scoreDelta`
   * unchanged (no semantic-conflict check on top of state — only threshold
   * comparison). TODO: wire in Phase 4 evaluator when it lands.
   */
  readonly marginalEvaluator: MarginalEvaluator;
}

/**
 * Marginal-gain evaluator function.
 * Given the current state (after previously accepted patches) and the
 * candidate patch, returns the marginal score-delta for that patch.
 *
 * TODO(phase-4): Replace the stub implementation with the real CoreTex benchmark
 * evaluator once Phase 4 (CoreTex pre-launch) is merged into main.
 */
export type MarginalEvaluator = (currentState: CortexState, patch: Patch) => bigint;

/**
 * Stub marginal evaluator: returns the patch's declared scoreDelta.
 * This is the current default before Phase 4 lands. It still enforces the
 * threshold check (anything >= threshold passes; anything < threshold fails
 * with R02_SEMANTIC_CONFLICT). The stub is conservative — it does NOT
 * re-evaluate the actual marginal gain on top of accepted patches, meaning
 * semantic conflicts that reduce marginal gain are not detected unless the
 * threshold is > 0.
 */
export function stubMarginalEvaluator(
  _currentState: CortexState,
  patch: Patch,
): bigint {
  // TODO(phase-4): replace with real CoreTex benchmark evaluator
  return patch.scoreDelta;
}

/** An accepted patch in the reducer output. */
export interface AcceptedPatch {
  readonly patch: Patch;
  readonly patchBytes: Uint8Array;
  /** Marginal score-delta as computed by the evaluator at acceptance time. */
  readonly marginalGain: bigint;
  /** Acceptance index (0-based, in order accepted). */
  readonly acceptanceIndex: number;
}

/** A rejected patch in the reducer output. */
export interface RejectedPatch {
  readonly patch: Patch;
  readonly patchBytes: Uint8Array;
  readonly reason: RejectionCode;
}

/** Full reducer output. */
export interface ReducerOutput {
  readonly newState: CortexState;
  /** 32-byte patchSetRoot committing to the accepted patch set. */
  readonly patchSetRoot: Uint8Array;
  /** Human-readable hex of patchSetRoot. */
  readonly patchSetRootHex: string;
  /** 32-byte newStateRoot. */
  readonly newStateRoot: Uint8Array;
  /** Human-readable hex of newStateRoot. */
  readonly newStateRootHex: string;
  readonly accepted: AcceptedPatch[];
  readonly rejected: RejectedPatch[];
}

// ── Sorting ───────────────────────────────────────────────────────────────────

/**
 * Compare two patches by reducer sort key: (-scoreDelta, +patchSize, +patchHash).
 * Returns negative if a should come before b (higher priority).
 */
function comparePatchPriority(
  a: { scoreDelta: bigint; patch: Patch; patchBytes: Uint8Array },
  b: { scoreDelta: bigint; patch: Patch; patchBytes: Uint8Array },
): number {
  // 1. Higher scoreDelta wins
  if (b.scoreDelta !== a.scoreDelta) {
    return b.scoreDelta > a.scoreDelta ? 1 : -1;
  }
  // 2. Smaller patchSize (wordCount) wins
  if (a.patch.wordCount !== b.patch.wordCount) {
    return a.patch.wordCount - b.patch.wordCount;
  }
  // 3. Lower patchHash (lexicographic) wins — deterministic tiebreak.
  // Use the DOMAIN-PREFIXED patchHash (computePatchHash) so the live reducer's ordering matches
  // verify-epoch's "patchHash asc" tiebreak and the on-chain patch id. (0x-hex, fixed length →
  // lexicographic string compare == byte-wise compare.)
  const aHash = computePatchHash(a.patchBytes);
  const bHash = computePatchHash(b.patchBytes);
  return aHash < bHash ? -1 : aHash > bHash ? 1 : 0;
}

/**
 * Stable sort — preserves relative order of equal-key elements.
 * JavaScript's Array.sort is stable in Node.js 11+ (V8 7.0+).
 */
function stableSort<T>(arr: T[], cmp: (a: T, b: T) => number): T[] {
  return arr.slice().sort(cmp);
}

// ── patchSetRoot ──────────────────────────────────────────────────────────────

/**
 * Compute the patchSetRoot from an ordered list of accepted patches.
 *
 * patchSetRoot = keccak256(concat(keccak256(patchBytes_0) ‖ ... ‖ keccak256(patchBytes_n)))
 *
 * If there are no accepted patches, patchSetRoot = keccak256(empty) = well-known constant.
 */
export function computePatchSetRoot(accepted: AcceptedPatch[]): Uint8Array {
  if (accepted.length === 0) {
    return keccak256(new Uint8Array(0));
  }
  const leafBuf = new Uint8Array(accepted.length * 32);
  for (let i = 0; i < accepted.length; i++) {
    const leaf = keccak256(accepted[i]!.patchBytes);
    leafBuf.set(leaf, i * 32);
  }
  return keccak256(leafBuf);
}

// ── Main reducer function ─────────────────────────────────────────────────────

/**
 * Run the epoch reducer.
 *
 * @param parentState   - CortexState at the start of the epoch
 * @param patches       - All screener-pass patches for this epoch
 * @param threshold     - Minimum marginal score-delta for acceptance (default 0n)
 * @returns             - ReducerOutput with accepted/rejected sets and roots
 */
export function reduce(
  parentState: CortexState,
  patches: ReducerInputPatch[],
  threshold: bigint = 0n,
  policyAtomsMode = false,
): ReducerOutput {
  // The EPOCH parent root: every screener-pass patch must reference this.
  const epochParentRoot = merkleizeState(parentState);

  // Pre-pass: drop patches whose parentStateRoot does not match the epoch
  // parent. They are rejected with R03_WRONG_PARENT_ROOT and never compete
  // for ordering. Without this pass, applyPatch in the loop would reject
  // every patch after the first because `current` advances.
  const eligible: ReducerInputPatch[] = [];
  const rejectedSet: RejectedPatch[] = [];
  for (const item of patches) {
    if (!patchMatchesEpochParent(item.patch, epochParentRoot)) {
      rejectedSet.push({
        patch: item.patch,
        patchBytes: item.patchBytes,
        reason: 'R03_WRONG_PARENT_ROOT',
      });
      continue;
    }
    eligible.push(item);
  }

  // 1. Sort by (-scoreDelta, +patchSize, +patchHash) — stable
  const ordered = stableSort(eligible, (a, b) =>
    comparePatchPriority(
      { scoreDelta: a.scoreDelta, patch: a.patch, patchBytes: a.patchBytes },
      { scoreDelta: b.scoreDelta, patch: b.patch, patchBytes: b.patchBytes },
    ),
  );

  // 2. Greedy application onto `current` (parent root has already been
  //    validated; we apply word writes only via applyPatchOntoCurrent).
  let current: CortexState = parentState;
  const acceptedSet: AcceptedPatch[] = [];
  const acceptedTargets = new Set<number>();

  for (const item of ordered) {
    // 2a. Target-overlap guard
    const overlaps = item.patch.indices.some((i) => acceptedTargets.has(i));
    if (overlaps) {
      rejectedSet.push({
        patch: item.patch,
        patchBytes: item.patchBytes,
        reason: 'R01_TARGET_OVERLAP',
      });
      continue;
    }

    // 2b + 2c. Shared accept-step kernel (threshold check, apply-onto-current,
    // E-code map). Batch lane: gain >= threshold (strictImprovement: false).
    const step = evaluateAndApplyOntoCurrent<RejectionCode>({
      current,
      patch: item.patch,
      marginalEvaluator: item.marginalEvaluator,
      threshold,
      strictImprovement: false,
      policyAtomsMode,
      codes: {
        notImprovement: 'R02_SEMANTIC_CONFLICT',
        wrongParent: 'R03_WRONG_PARENT_ROOT',
        reservedBit: 'R05_RESERVED_BIT_SET',
        invalidTarget: 'R04_INVALID_TARGET',
      },
    });
    if (!step.ok) {
      rejectedSet.push({
        patch: item.patch,
        patchBytes: item.patchBytes,
        reason: step.reason,
      });
      continue;
    }

    current = step.state;
    acceptedSet.push({
      patch: item.patch,
      patchBytes: item.patchBytes,
      marginalGain: step.marginalGain,
      acceptanceIndex: acceptedSet.length,
    });
    for (const idx of item.patch.indices) {
      acceptedTargets.add(idx);
    }
  }

  // 3. Compute roots
  const patchSetRoot = computePatchSetRoot(acceptedSet);
  const newStateRoot = merkleizeState(current);

  return {
    newState: current,
    patchSetRoot,
    patchSetRootHex: bytesToHex(patchSetRoot),
    newStateRoot,
    newStateRootHex: bytesToHex(newStateRoot),
    accepted: acceptedSet,
    rejected: rejectedSet,
  };
}

// ── Wire helper ───────────────────────────────────────────────────────────────

/**
 * Build a ReducerInputPatch from a decoded Patch object.
 * Uses the stub marginal evaluator (Phase 4 TODO).
 */
export function makeReducerInput(
  patch: Patch,
  patchBytes?: Uint8Array,
): ReducerInputPatch {
  const bytes = patchBytes ?? encodePatch(patch);
  return {
    patch,
    patchBytes: bytes,
    scoreDelta: patch.scoreDelta,
    marginalEvaluator: stubMarginalEvaluator,
  };
}
