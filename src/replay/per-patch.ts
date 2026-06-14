/**
 * Per-patch eval-receipt replay verification.
 *
 * Given a signed PerPatchReceipt from the coordinator, this verifies:
 *
 *   1. The receipt's `blockhash` equals `rpcClient.getBlockHash(targetBlock)`
 *      — i.e., the coordinator didn't pick a fictional blockhash and
 *      didn't reorg out a stale one.
 *   2. Re-deriving `gateSeed` + `confirmSeed` from (epochSecret,
 *      blockhash, epochId, patchHash, parentRoot, corpusRoot, bundleHash)
 *      reproduces the receipt's seeds byte-for-byte. NOTE: `minerAddress`
 *      is intentionally NOT a seed input (see seed-derivation.ts EvalSeedInput
 *      + test fixtures/seed-derivation-golden.json) — seeds are bound to the
 *      patch + parent + epoch randomness, not the submitter, so the first
 *      submitter of a given (parentRoot, patchBytes) wins via the dedup cache.
 *   3. Re-deriving `patchHash` from the patch bytes matches the
 *      receipt's patchHash.
 *   4. Re-deriving `dedupKey` from (parentRoot, patchBytes) matches.
 *   5. Re-scoring both packs via the injected scorer reproduces the
 *      receipt's gateScorePpm and confirmScorePpm within
 *      `replayTolerancePpm`.
 *
 * What this catches:
 *   - Coordinator using a fictional or forged blockhash
 *   - Coordinator deriving seeds from a wrong epochSecret reveal
 *   - Coordinator hashing different patch bytes than what's on chain
 *   - Coordinator's reranker non-determinism beyond the pinned
 *     replayTolerancePpm ceiling
 *
 * What this does NOT catch:
 *   - A coordinator that omits a receipt entirely (replay watcher must
 *     iterate over the chain's accepted-patch logs, not just receipts)
 *   - Coordinator who delays processing to wait for a favorable
 *     blockhash (mitigated separately by the PatchReceivedNotice log)
 *
 * Pure orchestration. Same receipt + same deps → byte-identical
 * verification outcome. Production wires `evaluateRetrievalBenchmarkPatch`
 * as the scorer in task #38; tests pass a deterministic fake.
 */
import {
  deriveGateEvalSeed,
  deriveConfirmEvalSeed,
  computePatchHash,
  computeDedupKey,
} from '../eval/seed-derivation.js';
import type { BaseRpcClient } from '../coordinator/base-blockhash.js';
import type { PerPatchReceipt } from '../coordinator/per-patch-evaluator.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PerPatchVerificationDeps {
  readonly rpcClient: BaseRpcClient;
  /** Maximum allowed |coordinatorScore - replayScore| in ppm. Pinned
   *  in the bundle as evaluator.profile.replayTolerancePpm. */
  readonly replayTolerancePpm: number;
  /** Same scorer shape as PerPatchScorer (floors-aware result). Production binds the SAME pinned
   *  BGE-M3 + Qwen3 scorer used by the coordinator; replay only consumes `.scorePpm` for the
   *  determinism/tolerance check (acceptance was decided + recorded by the coordinator). */
  readonly scorer: (args: {
    readonly normalizedPatchBytes: Uint8Array;
    readonly parentRoot: string;
    readonly evalSeed: string;
    readonly which: 'gate' | 'confirm';
  }) => Promise<{ readonly scorePpm: number; readonly accepted: boolean; readonly rejectionReason?: string }>;
  /** Bundle constants the seed derivation needs. */
  readonly epochSecret: string;
  readonly corpusRoot: string;
  readonly bundleHash: string;
  /** Raw patch bytes from the on-chain log (NOT from the receipt — the
   *  receipt only carries patchHash). The watcher pulls these from
   *  the CoretexPatchBytes event and feeds them in here. */
  readonly normalizedPatchBytes: Uint8Array;
}

export type PerPatchVerificationResult =
  | {
      readonly ok: true;
      readonly gateDeltaPpm: number;         // |receipt - replay| in ppm, ≤ tolerance
      readonly confirmDeltaPpm: number;
    }
  | {
      readonly ok: false;
      readonly code: PerPatchVerificationFailureCode;
      readonly detail: string;
    };

export type PerPatchVerificationFailureCode =
  | 'BLOCKHASH_MISMATCH'                  // rpc returned a different hash for targetBlock
  | 'GATE_SEED_MISMATCH'                  // re-derivation differs from receipt
  | 'CONFIRM_SEED_MISMATCH'
  | 'PATCH_HASH_MISMATCH'                 // patch bytes don't hash to receipt's patchHash
  | 'DEDUP_KEY_MISMATCH'                  // dedup key re-derivation differs
  | 'GATE_SCORE_BEYOND_TOLERANCE'         // |scores| > replayTolerancePpm
  | 'CONFIRM_SCORE_BEYOND_TOLERANCE'
  | 'RPC_ERROR';                          // RPC call threw

// ─── Verification ─────────────────────────────────────────────────────────────

export async function verifyPerPatchReceipt(
  receipt: PerPatchReceipt,
  deps: PerPatchVerificationDeps,
): Promise<PerPatchVerificationResult> {
  // 1. patchHash + dedupKey must reproduce from public patch bytes.
  const replayPatchHash = computePatchHash(deps.normalizedPatchBytes);
  if (!hexEq(replayPatchHash, receipt.patchHash)) {
    return { ok: false, code: 'PATCH_HASH_MISMATCH', detail: `replay=${replayPatchHash} receipt=${receipt.patchHash}` };
  }
  const replayDedupKey = computeDedupKey(receipt.parentRoot, deps.normalizedPatchBytes);
  if (!hexEq(replayDedupKey, receipt.dedupKey)) {
    return { ok: false, code: 'DEDUP_KEY_MISMATCH', detail: `replay=${replayDedupKey} receipt=${receipt.dedupKey}` };
  }

  // 2. The receipt may carry a rejection that never derived seeds — those
  // are documented but not scored. Watchers verify the rejection reason
  // is consistent with what they'd compute, but there's no score to
  // reproduce. The orchestrator here ONLY verifies receipts that reached
  // the dual-pack scoring stage (i.e. receivedAtBlock > 0).
  if (receipt.receivedAtBlock === 0) {
    // Pre-RPC rejection (structural / dedup / cap). Nothing seed-related
    // to verify — but patchHash + dedupKey checks above did fire. Treat
    // as ok with zero score deltas.
    return { ok: true, gateDeltaPpm: 0, confirmDeltaPpm: 0 };
  }

  // 3. The blockhash on the receipt must match what the chain says
  // about that block. This is the anti-forgery check — a coordinator
  // that signed a receipt with a fictional blockhash would be caught
  // here.
  let chainBlockhash: string;
  try {
    chainBlockhash = await deps.rpcClient.getBlockHash(receipt.targetBlock);
  } catch (e) {
    return { ok: false, code: 'RPC_ERROR', detail: e instanceof Error ? e.message : String(e) };
  }
  if (!hexEq(chainBlockhash, receipt.blockhash)) {
    return { ok: false, code: 'BLOCKHASH_MISMATCH', detail: `chain=${chainBlockhash} receipt=${receipt.blockhash}` };
  }

  // 4. Re-derive both seeds. The receipt fixes every other input, so
  // any mismatch means the coordinator hashed something different
  // than what the receipt claims.
  const seedInput = {
    epochSecret: deps.epochSecret,
    blockhash: receipt.blockhash,
    epochId: receipt.epochId,
    patchHash: receipt.patchHash,
    parentRoot: receipt.parentRoot,
    corpusRoot: deps.corpusRoot,
    bundleHash: deps.bundleHash,
  };
  const replayGateSeed = deriveGateEvalSeed(seedInput);
  if (!hexEq(replayGateSeed, receipt.gateSeed)) {
    return { ok: false, code: 'GATE_SEED_MISMATCH', detail: `replay=${replayGateSeed} receipt=${receipt.gateSeed}` };
  }
  const replayConfirmSeed = deriveConfirmEvalSeed(seedInput);
  if (!hexEq(replayConfirmSeed, receipt.confirmSeed)) {
    return { ok: false, code: 'CONFIRM_SEED_MISMATCH', detail: `replay=${replayConfirmSeed} receipt=${receipt.confirmSeed}` };
  }

  // 5. Re-score both packs. Production wires the pinned reranker; tests
  // pass a fake. Score divergence beyond replayTolerancePpm is a
  // determinism failure on either the coordinator or this watcher.
  const gateScoreReplay = await deps.scorer({
    normalizedPatchBytes: deps.normalizedPatchBytes,
    parentRoot: receipt.parentRoot,
    evalSeed: receipt.gateSeed,
    which: 'gate',
  });
  const gateDeltaPpm = Math.abs(gateScoreReplay.scorePpm - receipt.gateScorePpm);
  if (gateDeltaPpm > deps.replayTolerancePpm) {
    return {
      ok: false,
      code: 'GATE_SCORE_BEYOND_TOLERANCE',
      detail: `coordinator=${receipt.gateScorePpm} replay=${gateScoreReplay.scorePpm} delta=${gateDeltaPpm} tolerance=${deps.replayTolerancePpm}`,
    };
  }
  const confirmScoreReplay = await deps.scorer({
    normalizedPatchBytes: deps.normalizedPatchBytes,
    parentRoot: receipt.parentRoot,
    evalSeed: receipt.confirmSeed,
    which: 'confirm',
  });
  const confirmDeltaPpm = Math.abs(confirmScoreReplay.scorePpm - receipt.confirmScorePpm);
  if (confirmDeltaPpm > deps.replayTolerancePpm) {
    return {
      ok: false,
      code: 'CONFIRM_SCORE_BEYOND_TOLERANCE',
      detail: `coordinator=${receipt.confirmScorePpm} replay=${confirmScoreReplay.scorePpm} delta=${confirmDeltaPpm} tolerance=${deps.replayTolerancePpm}`,
    };
  }

  return { ok: true, gateDeltaPpm, confirmDeltaPpm };
}

function hexEq(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
