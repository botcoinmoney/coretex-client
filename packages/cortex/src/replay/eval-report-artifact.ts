/**
 * Canonical post-reveal eval-report artifact (§3 score-honesty).
 *
 * This is THE artifact whose hash the coordinator commits on-chain: the
 * builder computes ONE hash and sets BOTH `artifactHash` and
 * `evalReportHash` to it, and the accepted receipt carries that same
 * bytes32 on-chain. There is no second "local" artifact schema — the
 * production evaluator builds this exact shape and validators re-fetch it
 * from `<CORETEX_ARTIFACT_BASE_URL>/eval-reports/<artifactHash>.json`
 * (see `evalReportArtifactRelativePath`).
 *
 * The artifact surfaces the FULL seed-derivation inputs as mandatory
 * fields (`seedDerivation`) so a validator can re-derive the gate/confirm
 * hidden packs independently after the epochSecret reveal, plus the
 * dual-pack acceptance threshold so the min(gate, confirm) >= threshold
 * semantics are verifiable, not asserted.
 */
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';
import type { PerPatchReceipt } from '../coordinator/per-patch-evaluator.js';
import { verifyPerPatchReceipt, type PerPatchVerificationDeps, type PerPatchVerificationResult } from './per-patch.js';
import { canonicalJson } from '../canonical/json.js';

/** Public seed-derivation inputs — everything `deriveGate/ConfirmEvalSeed`
 *  consumes except the (post-reveal) epochSecret. */
export interface CoreTexEvalSeedDerivationInputs {
  readonly mode: 'future_blockhash_dual_pack';
  readonly epochId: number;
  readonly receivedAtBlock: number;
  readonly targetBlock: number;
  readonly targetBlockOffset: number;
  readonly blockhash: string;
  readonly patchHash: string;
  readonly parentStateRoot: string;
  readonly corpusRoot: string;
  readonly bundleHash: string;
}

export interface CoreTexPostRevealEvalReportArtifact {
  readonly version: 'coretex-post-reveal-eval-report-v1';
  /** == artifactHash. The on-chain receipt's evalReportHash IS the artifact hash. */
  readonly evalReportHash: string;
  readonly artifactHash: string;
  readonly epochId: number;
  readonly minerAddress: string;
  readonly outcome: 'SCREENER_PASS' | 'STATE_ADVANCE';
  readonly compactPatchBytesHex: string;
  /** Dual-pack acceptance threshold (ppm) BOTH packs must clear. */
  readonly thresholdPpm: number;
  readonly seedDerivation: CoreTexEvalSeedDerivationInputs;
  readonly receipt: PerPatchReceipt;
  readonly context: {
    readonly parentStateRoot: string;
    readonly corpusRoot: string;
    readonly coreVersionHash: string;
    readonly hiddenSeedCommit: string;
    readonly replayTolerancePpm: number;
  };
}

export type PostRevealEvalArtifactVerificationResult =
  | ({ readonly ok: true; readonly artifactHash: string } & Extract<PerPatchVerificationResult, { readonly ok: true }>)
  | { readonly ok: false; readonly code: string; readonly detail: string };

// ─── Published artifact layout ────────────────────────────────────────────────

export const EVAL_REPORT_ARTIFACT_DIR = 'eval-reports';

/** Canonical published path under CORETEX_ARTIFACT_BASE_URL. The validator's
 *  verify-patch fetches exactly this layout; the publish side must import
 *  this helper rather than re-encode the convention. */
export function evalReportArtifactRelativePath(artifactHash: string): string {
  if (!isBytes32(artifactHash)) throw new Error('evalReportArtifactRelativePath: artifactHash must be bytes32');
  return `${EVAL_REPORT_ARTIFACT_DIR}/${artifactHash.toLowerCase()}.json`;
}

export function evalReportArtifactUrl(baseUrl: string, artifactHash: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/${evalReportArtifactRelativePath(artifactHash)}`;
}

// ─── Build + hash ─────────────────────────────────────────────────────────────

/** Hash excludes BOTH self-referential hash fields. */
export function hashPostRevealEvalReportArtifact(
  artifact: Omit<CoreTexPostRevealEvalReportArtifact, 'artifactHash' | 'evalReportHash'>
    | CoreTexPostRevealEvalReportArtifact,
): string {
  const payload = { ...(artifact as Record<string, unknown>) };
  delete payload.artifactHash;
  delete payload.evalReportHash;
  return bytesToHex(keccak256(new TextEncoder().encode(canonicalJson(payload)))).toLowerCase();
}

/** Builder computes ONE hash and sets both `artifactHash` and
 *  `evalReportHash` to it — the on-chain commitment and the published
 *  artifact can never disagree by construction. */
export function buildPostRevealEvalReportArtifact(
  artifact: Omit<CoreTexPostRevealEvalReportArtifact, 'artifactHash' | 'evalReportHash'>,
): CoreTexPostRevealEvalReportArtifact {
  const hash = hashPostRevealEvalReportArtifact(artifact);
  return { ...artifact, artifactHash: hash, evalReportHash: hash };
}

// ─── Verification ─────────────────────────────────────────────────────────────

export async function verifyPostRevealEvalReportArtifact(
  artifact: CoreTexPostRevealEvalReportArtifact,
  deps: Omit<PerPatchVerificationDeps, 'normalizedPatchBytes' | 'replayTolerancePpm' | 'corpusRoot' | 'bundleHash'>,
): Promise<PostRevealEvalArtifactVerificationResult> {
  const shape = validateArtifactShape(artifact);
  if (shape) return { ok: false, code: 'EVAL_ARTIFACT_MALFORMED', detail: shape };
  const hash = hashPostRevealEvalReportArtifact(artifact);
  if (hash !== artifact.artifactHash.toLowerCase()) {
    return { ok: false, code: 'EVAL_ARTIFACT_HASH_MISMATCH', detail: `${hash} != ${artifact.artifactHash}` };
  }
  if (artifact.evalReportHash.toLowerCase() !== artifact.artifactHash.toLowerCase()) {
    return {
      ok: false,
      code: 'EVAL_REPORT_HASH_MISMATCH',
      detail: `evalReportHash ${artifact.evalReportHash} != artifactHash ${artifact.artifactHash}`,
    };
  }
  const seedInputs = validateSeedDerivationBinding(artifact);
  if (seedInputs) return { ok: false, code: 'EVAL_ARTIFACT_SEED_INPUTS_MISMATCH', detail: seedInputs };
  // Threshold semantics: a published SCREENER_PASS / STATE_ADVANCE artifact
  // must carry an ACCEPTED dual-pack receipt whose worse pack still clears
  // the committed threshold. min(gate, confirm) is also the score the
  // coordinator may credit — never the max.
  if (!artifact.receipt.accepted) {
    return { ok: false, code: 'EVAL_ARTIFACT_THRESHOLD_VIOLATION', detail: 'accepted outcome with non-accepted receipt' };
  }
  const minDualPpm = Math.min(artifact.receipt.gateScorePpm, artifact.receipt.confirmScorePpm);
  if (minDualPpm < artifact.thresholdPpm) {
    return {
      ok: false,
      code: 'EVAL_ARTIFACT_THRESHOLD_VIOLATION',
      detail: `min(gate=${artifact.receipt.gateScorePpm}, confirm=${artifact.receipt.confirmScorePpm}) < thresholdPpm=${artifact.thresholdPpm}`,
    };
  }
  const secretCommit = bytesToHex(keccak256(hexToBytes(deps.epochSecret))).toLowerCase();
  if (secretCommit !== artifact.context.hiddenSeedCommit.toLowerCase()) {
    return { ok: false, code: 'EPOCH_SECRET_COMMIT_MISMATCH', detail: `${secretCommit} != ${artifact.context.hiddenSeedCommit}` };
  }
  const compactPatchBytes = hexToBytes(artifact.compactPatchBytesHex);
  const replay = await verifyPerPatchReceipt(artifact.receipt, {
    ...deps,
    replayTolerancePpm: artifact.context.replayTolerancePpm,
    corpusRoot: artifact.context.corpusRoot,
    bundleHash: artifact.context.coreVersionHash,
    normalizedPatchBytes: compactPatchBytes,
  });
  if (!replay.ok) return { ok: false, code: replay.code, detail: replay.detail };
  return { ok: true, artifactHash: hash, gateDeltaPpm: replay.gateDeltaPpm, confirmDeltaPpm: replay.confirmDeltaPpm };
}

function validateArtifactShape(artifact: CoreTexPostRevealEvalReportArtifact): string | null {
  if (artifact.version !== 'coretex-post-reveal-eval-report-v1') return 'version mismatch';
  if (!isBytes32(artifact.evalReportHash)) return 'evalReportHash must be bytes32';
  if (!isBytes32(artifact.artifactHash)) return 'artifactHash must be bytes32';
  if (!Number.isSafeInteger(artifact.epochId) || artifact.epochId < 0) return 'epochId invalid';
  if (!isAddress(artifact.minerAddress)) return 'minerAddress invalid';
  if (artifact.outcome !== 'SCREENER_PASS' && artifact.outcome !== 'STATE_ADVANCE') return 'outcome invalid';
  if (!/^0x[0-9a-fA-F]*$/.test(artifact.compactPatchBytesHex) || (artifact.compactPatchBytesHex.length - 2) % 2 !== 0) {
    return 'compactPatchBytesHex invalid';
  }
  if (!Number.isSafeInteger(artifact.thresholdPpm) || artifact.thresholdPpm < 0) return 'thresholdPpm invalid';
  const seed = artifact.seedDerivation;
  if (!seed || typeof seed !== 'object') return 'seedDerivation missing';
  if (seed.mode !== 'future_blockhash_dual_pack') return 'seedDerivation.mode invalid';
  for (const key of ['epochId', 'receivedAtBlock', 'targetBlock', 'targetBlockOffset'] as const) {
    if (!Number.isSafeInteger(seed[key]) || seed[key] < 0) return `seedDerivation.${key} invalid`;
  }
  for (const key of ['blockhash', 'patchHash', 'parentStateRoot', 'corpusRoot', 'bundleHash'] as const) {
    if (!isBytes32(seed[key])) return `seedDerivation.${key} must be bytes32`;
  }
  if (!artifact.context || typeof artifact.context !== 'object') return 'context missing';
  for (const key of ['parentStateRoot', 'corpusRoot', 'coreVersionHash', 'hiddenSeedCommit'] as const) {
    if (!isBytes32(artifact.context[key])) return `context.${key} must be bytes32`;
  }
  if (!Number.isSafeInteger(artifact.context.replayTolerancePpm) || artifact.context.replayTolerancePpm < 0) {
    return 'context.replayTolerancePpm invalid';
  }
  if (artifact.receipt.epochId !== artifact.epochId) return 'receipt epoch mismatch';
  if (artifact.receipt.parentRoot.toLowerCase() !== artifact.context.parentStateRoot.toLowerCase()) return 'receipt parent mismatch';
  if (artifact.receipt.minerAddress.toLowerCase() !== artifact.minerAddress.toLowerCase()) return 'receipt miner mismatch';
  return null;
}

/** The mandatory seedDerivation block must agree with the receipt + context
 *  it claims to describe — a validator re-derives packs from THESE fields,
 *  so any drift between them and the replay-verified receipt is a forgery. */
function validateSeedDerivationBinding(artifact: CoreTexPostRevealEvalReportArtifact): string | null {
  const seed = artifact.seedDerivation;
  const receipt = artifact.receipt;
  if (seed.epochId !== artifact.epochId) return `seedDerivation.epochId ${seed.epochId} != ${artifact.epochId}`;
  if (seed.receivedAtBlock !== receipt.receivedAtBlock) {
    return `seedDerivation.receivedAtBlock ${seed.receivedAtBlock} != receipt ${receipt.receivedAtBlock}`;
  }
  if (seed.targetBlock !== receipt.targetBlock) {
    return `seedDerivation.targetBlock ${seed.targetBlock} != receipt ${receipt.targetBlock}`;
  }
  if (seed.receivedAtBlock + seed.targetBlockOffset !== seed.targetBlock) {
    return `targetBlock ${seed.targetBlock} != receivedAtBlock ${seed.receivedAtBlock} + offset ${seed.targetBlockOffset}`;
  }
  if (!hexEq(seed.blockhash, receipt.blockhash)) return `seedDerivation.blockhash != receipt blockhash`;
  if (!hexEq(seed.patchHash, receipt.patchHash)) return `seedDerivation.patchHash != receipt patchHash`;
  if (!hexEq(seed.parentStateRoot, receipt.parentRoot)) return `seedDerivation.parentStateRoot != receipt parentRoot`;
  if (!hexEq(seed.parentStateRoot, artifact.context.parentStateRoot)) return `seedDerivation.parentStateRoot != context`;
  if (!hexEq(seed.corpusRoot, artifact.context.corpusRoot)) return `seedDerivation.corpusRoot != context corpusRoot`;
  if (!hexEq(seed.bundleHash, artifact.context.coreVersionHash)) return `seedDerivation.bundleHash != context coreVersionHash`;
  return null;
}


function hexEq(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

function isBytes32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) throw new Error('hexToBytes: malformed hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
