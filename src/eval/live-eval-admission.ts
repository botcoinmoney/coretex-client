/**
 * Live-eval admission decision. Anti-abuse gate at the entry of
 * `POST /coretex/evaluate`, BEFORE the costly blockhash wait + eval
 * pipeline.
 *
 * Three rules, in precedence order:
 *
 *   1. Structural validity — patch decodes, indices in range, no
 *      duplicate words, EIP-712 signature valid. Caller passes
 *      `structurallyValid` after running the structural check.
 *   2. Dedup-key collapse — patches with the same dedupKey as a prior
 *      accepted patch in this epoch get the cached verdict. Anti-
 *      probing: a miner submitting the same patch twice does not get
 *      a fresh pack-roll.
 *   3. Per-miner cap — once a miner reaches `perMinerCap` admissions
 *      in this epoch, further admissions don't earn credit (the
 *      patch can still flow into eval for transparency, but no
 *      additional screener credit is awarded).
 *
 * Pure function. The host owns the cache + admission counters and is
 * responsible for inserting into them after this returns `admit: true`.
 *
 * This file is the survivor of the sealed-eval rip (see
 * docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md). The earlier sealed-eval
 * design needed this helper for post-commit admission; the per-patch
 * design uses it at live-eval entry. Same three rules, same precedence,
 * adapted field names: `commitmentHash` → `patchHash`,
 * `admittedDuplicateKeysThisEpoch` → `dedupedKeysThisEpoch`,
 * `postCommitAdmissionPassed` → `structurallyValid`.
 */

export interface LiveEvalAdmissionInput {
  /** Miner submitting the patch. bytes20 hex (lowercased). */
  readonly minerAddress: string;
  /** Patch hash from `seed-derivation.ts:computePatchHash`. bytes32 hex. */
  readonly patchHash: string;
  /** Dedup key from `seed-derivation.ts:computeDedupKey`. bytes32 hex. */
  readonly dedupKey: string;
  /** Lower-cased dedup keys already evaluated this epoch. */
  readonly dedupedKeysThisEpoch: ReadonlySet<string>;
  /** Count of admissions awarded to this miner so far this epoch. */
  readonly minerAdmissionsThisEpoch: number;
  /** Maximum admissions per miner per epoch. */
  readonly perMinerCap: number;
  /** True iff the patch passes structural validity (decoded, indices
   *  in range, signature valid, etc.). Host computes this before
   *  calling. */
  readonly structurallyValid: boolean;
}

export type LiveEvalAdmissionDecision =
  | { readonly admit: true; readonly reason: 'OK' }
  | { readonly admit: false; readonly reason: LiveEvalAdmissionRejectReason };

export type LiveEvalAdmissionRejectReason =
  | 'malformed-input'
  | 'structurally-invalid'
  | 'duplicate-key-collapsed'
  | 'per-miner-cap-reached';

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const BYTES32_RE = /^0x[0-9a-fA-F]{64}$/;

/**
 * Returns `{ admit: true, reason: 'OK' }` iff all three rules pass.
 * Otherwise returns the most specific rejection reason. Precedence:
 *   structurally-invalid > duplicate-key-collapsed > per-miner-cap-reached.
 */
export function liveEvalAdmissionDecision(input: LiveEvalAdmissionInput): LiveEvalAdmissionDecision {
  // Fail-closed input validation. Anything malformed → 'malformed-input'.
  if (!ADDR_RE.test(input.minerAddress)) return { admit: false, reason: 'malformed-input' };
  if (!BYTES32_RE.test(input.patchHash)) return { admit: false, reason: 'malformed-input' };
  if (!BYTES32_RE.test(input.dedupKey)) return { admit: false, reason: 'malformed-input' };
  if (typeof input.structurallyValid !== 'boolean') return { admit: false, reason: 'malformed-input' };
  if (!Number.isInteger(input.minerAdmissionsThisEpoch) || input.minerAdmissionsThisEpoch < 0) {
    return { admit: false, reason: 'malformed-input' };
  }
  if (!Number.isInteger(input.perMinerCap) || input.perMinerCap < 1) {
    return { admit: false, reason: 'malformed-input' };
  }
  if (!(input.dedupedKeysThisEpoch instanceof Set)) {
    return { admit: false, reason: 'malformed-input' };
  }

  // Rule 1: structural validity. Most specific — if the patch doesn't
  // decode, nothing else matters.
  if (!input.structurallyValid) return { admit: false, reason: 'structurally-invalid' };

  // Rule 2: dedup-key collapse. A patch with the same dedupKey already
  // ran the full eval; return the cached verdict (caller handles the
  // cache lookup). No additional credit awarded.
  const dedupKeyLower = '0x' + input.dedupKey.replace(/^0x/i, '').toLowerCase();
  if (input.dedupedKeysThisEpoch.has(dedupKeyLower)) {
    return { admit: false, reason: 'duplicate-key-collapsed' };
  }

  // Rule 3: per-miner cap. The patch still flows into eval (for
  // transparency / audit trail), but the screener credit doesn't
  // accrue beyond the cap.
  if (input.minerAdmissionsThisEpoch >= input.perMinerCap) {
    return { admit: false, reason: 'per-miner-cap-reached' };
  }

  return { admit: true, reason: 'OK' };
}
