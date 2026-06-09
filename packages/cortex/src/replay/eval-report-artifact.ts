import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';
import type { PerPatchReceipt } from '../coordinator/per-patch-evaluator.js';
import { verifyPerPatchReceipt, type PerPatchVerificationDeps, type PerPatchVerificationResult } from './per-patch.js';

export interface CoreTexPostRevealEvalReportArtifact {
  readonly version: 'coretex-post-reveal-eval-report-v1';
  readonly evalReportHash: string;
  readonly artifactHash: string;
  readonly epochId: number;
  readonly minerAddress: string;
  readonly outcome: 'SCREENER_PASS' | 'STATE_ADVANCE';
  readonly compactPatchBytesHex: string;
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

export function hashPostRevealEvalReportArtifact(
  artifact: Omit<CoreTexPostRevealEvalReportArtifact, 'artifactHash'> | CoreTexPostRevealEvalReportArtifact,
): string {
  const payload = { ...(artifact as Record<string, unknown>) };
  delete payload.artifactHash;
  return bytesToHex(keccak256(new TextEncoder().encode(canonicalJson(payload)))).toLowerCase();
}

export function buildPostRevealEvalReportArtifact(
  artifact: Omit<CoreTexPostRevealEvalReportArtifact, 'artifactHash'>,
): CoreTexPostRevealEvalReportArtifact {
  const artifactHash = hashPostRevealEvalReportArtifact(artifact);
  return { ...artifact, artifactHash };
}

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

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
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
