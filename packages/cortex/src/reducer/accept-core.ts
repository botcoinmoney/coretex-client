/**
 * THE shared accept-step kernel for both reducer lanes (audit Q5 / C8).
 *
 * The end-of-epoch batch reducer (`reduce()`) and the live conveyor
 * (`advanceEpochState()`) previously duplicated the same three-step kernel —
 * marginal-gain threshold check, `applyPatchOntoCurrent`, and the verbatim
 * E-code → rejection-code map — differing ONLY in:
 *   - threshold strictness (`strictImprovement`: live requires gain > threshold,
 *     mirroring the on-chain `scoreAfterPpm <= scoreBeforePpm` revert; the
 *     batch reducer accepts gain >= threshold). The divergence is now ONE
 *     explicit parameter instead of two buried comparison operators.
 *   - rejection-code labels (each lane keeps its own union via `codes`).
 *
 * Each lane keeps its own PRE-checks (target-overlap guard / live parent-root
 * check) and its own accept-side bookkeeping (ordering, rewards, merkle
 * strategy) — only the kernel is shared.
 */
import type { CortexState, Patch } from '../state/types.js';
import { applyPatchOntoCurrent } from '../state/patch.js';
import type { MarginalEvaluator } from './reducer.js';

export interface AcceptStepCodes<C extends string> {
  /** Below-threshold marginal gain AND E05 (no-op vs current). */
  readonly notImprovement: C;
  /** E01 — only reachable on lanes without an epoch-parent pre-pass. */
  readonly wrongParent: C;
  /** E04 — reserved-bit set in the resulting state. */
  readonly reservedBit: C;
  /** E02/E03 — invalid target index / over budget. */
  readonly invalidTarget: C;
}

export type AcceptStepResult<C extends string> =
  | { readonly ok: true; readonly state: CortexState; readonly marginalGain: bigint }
  | { readonly ok: false; readonly reason: C };

export function evaluateAndApplyOntoCurrent<C extends string>(args: {
  readonly current: CortexState;
  readonly patch: Patch;
  readonly marginalEvaluator: MarginalEvaluator;
  readonly threshold: bigint;
  /** true → require gain > threshold (live lane); false → gain >= threshold (batch). */
  readonly strictImprovement: boolean;
  readonly policyAtomsMode: boolean;
  readonly codes: AcceptStepCodes<C>;
}): AcceptStepResult<C> {
  const { current, patch, threshold, codes } = args;

  const marginalGain = args.marginalEvaluator(current, patch);
  const improves = args.strictImprovement ? marginalGain > threshold : marginalGain >= threshold;
  if (!improves) return { ok: false, reason: codes.notImprovement };

  const applyResult = applyPatchOntoCurrent(current, patch, args.policyAtomsMode);
  if (!applyResult.ok) {
    const reason =
      applyResult.code === 'E01' ? codes.wrongParent
      : applyResult.code === 'E04' ? codes.reservedBit
      : applyResult.code === 'E05' ? codes.notImprovement
      : codes.invalidTarget;
    return { ok: false, reason };
  }
  return { ok: true, state: applyResult.state, marginalGain };
}
