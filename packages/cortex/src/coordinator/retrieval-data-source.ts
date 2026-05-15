/**
 * Coordinator data-source factory for the retrieval-benchmark endpoints.
 *
 * Spec: plan §Phase F.
 *
 * Wires:
 *   - GET /coretex/challenge
 *   - POST /coretex/submit
 *   - GET /coretex/status
 *   - GET /coretex/bundle/by-core-version/:coreVersionHash
 *   - GET /coretex/bundle/:bundleHash
 *   - immutable artifact reads (substrate/patch/patch-received/eval-report/corpus-delta)
 *
 * Production wiring expects:
 *   - the loaded CoreTexBundleManifest
 *   - a challenge callback (dynamic packet)
 *   - a submit callback (single write-path)
 *   - a status callback (non-secret dynamic context)
 */

import { createHash } from 'node:crypto';

import type {
  CoreTexCoordinatorDataSource,
  CoreTexRouteGuardContext,
  CoreTexRouteGuardResult,
} from './endpoints.js';
import type { CoreTexBundleManifest } from '../bundle/index.js';

export interface RetrievalDataSourceOptions {
  readonly bundleManifest: CoreTexBundleManifest;
  readonly bundleHash: string;
  readonly getChallenge: () => Promise<unknown> | unknown;
  readonly submit: (body: unknown) => Promise<unknown> | unknown;
  readonly getStatus: () => Promise<unknown> | unknown;
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  readonly getPatch?: (hash: string) => Promise<unknown> | unknown;
  readonly getPatchReceivedNotice?: (hash: string) => Promise<unknown> | unknown;
  readonly getEvalReport?: (hash: string) => Promise<unknown> | unknown;
  readonly getCorpusDelta?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getBundleByCoreVersionHash?: (coreVersionHash: string) => Promise<unknown> | unknown;
  readonly authorize?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly rateLimit?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly health?: () => Promise<unknown> | unknown;
}

export function createRetrievalDataSource(opts: RetrievalDataSourceOptions): CoreTexCoordinatorDataSource {
  const manifest = opts.bundleManifest;
  if (manifest.bundleHash.toLowerCase() !== opts.bundleHash.toLowerCase()) {
    throw new Error(`createRetrievalDataSource: bundle manifest hash ${manifest.bundleHash} != provided ${opts.bundleHash}`);
  }

  const ds: CoreTexCoordinatorDataSource = {
    async getChallenge() {
      return sanitizeChallengeResponse(await opts.getChallenge(), manifest.bundleHash);
    },
    async submit(body) {
      return sanitizeSubmitResponse(await opts.submit(body));
    },
    async getStatus() {
      return sanitizeStatusResponse(await opts.getStatus(), manifest.bundleHash);
    },
    async getBundleByCoreVersionHash(coreVersionHash: string) {
      if (opts.getBundleByCoreVersionHash) return opts.getBundleByCoreVersionHash(coreVersionHash);
      // Default coreVersionHash -> bundleHash mapping in v2 bundles:
      // assertBundleBindingAtStartup enforces on-chain coreVersionHash equals
      // bundleHash; expose this direct alias for watcher/miner compatibility.
      if (coreVersionHash.toLowerCase() !== manifest.bundleHash.toLowerCase()) {
        return { error: 'coretex-bundle-not-found', coreVersionHash };
      }
      return manifest;
    },
    async getBundle(bundleHash: string) {
      if (bundleHash.toLowerCase() !== manifest.bundleHash.toLowerCase()) {
        return { error: 'coretex-bundle-not-found', bundleHash };
      }
      return manifest;
    },
    async health() {
      if (opts.health) return opts.health();
      return {
        ok: true,
        service: 'coretex',
        bundleHash: manifest.bundleHash.toLowerCase(),
        serverTime: new Date().toISOString(),
      };
    },
  };
  if (opts.getSubstrate) (ds as Mutable).getSubstrate = opts.getSubstrate;
  if (opts.getPatch) (ds as Mutable).getPatch = opts.getPatch;
  if (opts.getPatchReceivedNotice) {
    const inner = opts.getPatchReceivedNotice;
    (ds as Mutable).getPatchReceivedNotice = async (hash: string) => sanitizePatchReceivedNotice(await inner(hash));
  }
  if (opts.getEvalReport) (ds as Mutable).getEvalReport = opts.getEvalReport;
  if (opts.getCorpusDelta) (ds as Mutable).getCorpusDelta = opts.getCorpusDelta;
  if (opts.getBundleByCoreVersionHash) (ds as Mutable).getBundleByCoreVersionHash = opts.getBundleByCoreVersionHash;
  if (opts.rateLimit) (ds as Mutable).rateLimit = opts.rateLimit;
  if (opts.authorize) (ds as Mutable).authorize = opts.authorize;
  return ds;
}

type Mutable = { -readonly [K in keyof CoreTexCoordinatorDataSource]: CoreTexCoordinatorDataSource[K] };

function sanitizeChallengeResponse(raw: unknown, manifestBundleHash: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') {
    return { error: 'coretex-challenge-malformed' };
  }
  const r = raw as Record<string, unknown>;
  const lane = r.lane === 'coretex' ? 'coretex' : null;
  const challengeId = asBytes32Hex(r.challengeId);
  const expiresAt = asPosInt(r.expiresAt);
  const parentStateRoot = asBytes32Hex(r.parentStateRoot);
  const epochId = asNonNegativeInt(r.epochId);
  const substrate = sanitizeSubstrateEnvelope(r.substrate);
  const coreVersionHash = asBytes32Hex(r.coreVersionHash) ?? manifestBundleHash.toLowerCase();
  const bundleHash = asBytes32Hex(r.bundleHash) ?? manifestBundleHash.toLowerCase();
  if (!lane || !challengeId || expiresAt === null || !parentStateRoot || epochId === null || !substrate) {
    return { error: 'coretex-challenge-malformed' };
  }
  return {
    lane,
    challengeId,
    expiresAt,
    epochId,
    parentStateRoot,
    coreVersionHash,
    bundleHash,
    substrate,
  };
}

function sanitizeSubmitResponse(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') {
    return { status: 'rejected', code: 'rejected' };
  }
  const r = raw as Record<string, unknown>;
  const accepted = r.status === 'accepted' || r.accepted === true;
  const patchHash = asBytes32Hex(r.patchHash);
  if (!accepted) {
    // Opaque rejection surface: do not leak retrieval-correlated details.
    return patchHash ? { status: 'rejected', code: 'rejected', patchHash } : { status: 'rejected', code: 'rejected' };
  }
  const evalReportHash = asBytes32Hex(r.evalReportHash);
  const receipt = sanitizeReceiptEnvelope(r.receipt);
  return {
    status: 'accepted',
    ...(patchHash ? { patchHash } : {}),
    ...(evalReportHash ? { evalReportHash } : {}),
    ...(receipt ? { receipt } : {}),
  };
}

/**
 * Receipt envelope must only carry signature-shaped fields. Anything that
 * could expose retrieval correlations (per-family deltas, scoreAfterPpm,
 * recency hints) MUST NOT pass this boundary, even if the host put it in
 * the receipt. Allow-list:
 *   keyId, algorithm, signature, signedFields, sig
 */
function sanitizeReceiptEnvelope(raw: unknown): Record<string, unknown> | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  if (typeof r.keyId === 'string' && r.keyId.length <= 128) out.keyId = r.keyId;
  if (r.algorithm === 'RSA-SHA256' || r.algorithm === 'ECDSA-SHA256') out.algorithm = r.algorithm;
  if (typeof r.signature === 'string' && /^0x[0-9a-fA-F]+$/.test(r.signature)) out.signature = r.signature.toLowerCase();
  // 'sig' is a common shortcut for {signature}; keep for backward-compat
  // but only when it looks like a hex signature.
  if (typeof r.sig === 'string' && /^0x[0-9a-fA-F]+$/.test(r.sig)) out.sig = r.sig.toLowerCase();
  if (Array.isArray(r.signedFields) && r.signedFields.every((f) => typeof f === 'string')) {
    out.signedFields = r.signedFields.slice();
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * Strict-shape projection of a PatchReceivedNotice (see
 * `packages/cortex/src/coordinator/patch-received-notice.ts`). The notice
 * is the only seed-input artifact the coordinator publishes off-chain;
 * replay watchers depend on the exact field set. Refuse to pass through
 * anything else.
 */
function sanitizePatchReceivedNotice(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') {
    return { error: 'coretex-patch-received-notice-malformed' };
  }
  const r = raw as Record<string, unknown>;
  const patchHash = asBytes32Hex(r.patchHash);
  const receivedAtBlock = asNonNegativeInt(r.receivedAtBlock);
  const receivedAtTimestamp = asNonNegativeInt(r.receivedAtTimestamp);
  const coordinatorAddress =
    typeof r.coordinatorAddress === 'string' && /^0x[0-9a-f]{40}$/.test(r.coordinatorAddress.toLowerCase())
      ? r.coordinatorAddress.toLowerCase()
      : null;
  const signer = sanitizeReceiptEnvelope(r.signer);
  if (!patchHash || receivedAtBlock === null || receivedAtTimestamp === null || !coordinatorAddress) {
    return { error: 'coretex-patch-received-notice-malformed' };
  }
  return {
    patchHash,
    receivedAtBlock,
    receivedAtTimestamp,
    coordinatorAddress,
    ...(signer ? { signer } : {}),
  };
}

function sanitizeStatusResponse(raw: unknown, manifestBundleHash: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') {
    return { error: 'coretex-status-malformed' };
  }
  const r = raw as Record<string, unknown>;
  const lane = r.lane === 'coretex' ? 'coretex' : null;
  const epochId = asNonNegativeInt(r.epochId);
  const stateRoot = asBytes32Hex(r.stateRoot);
  const wordCount = asPosInt(r.wordCount);
  const transitionCount = asNonNegativeInt(r.transitionCount);
  const rulesVersion = asNonNegativeInt(r.rulesVersion);
  const workPolicyHash = asBytes32Hex(r.workPolicyHash);
  const corpusRoot = asBytes32Hex(r.corpusRoot);
  const coreVersionHash = asBytes32Hex(r.coreVersionHash) ?? manifestBundleHash.toLowerCase();
  const bundleHash = asBytes32Hex(r.bundleHash) ?? manifestBundleHash.toLowerCase();
  const minImprovementPpm = asNonNegativeInt(r.minImprovementPpm);
  const evalSeedCommit = asBytes32Hex(r.evalSeedCommit);
  const substrate = sanitizeUriEnvelope(r.substrate);
  const bundle = sanitizeUriEnvelope(r.bundle);
  if (
    !lane
    || epochId === null
    || !stateRoot
    || wordCount === null
    || transitionCount === null
    || rulesVersion === null
    || !workPolicyHash
    || !corpusRoot
    || minImprovementPpm === null
    || !evalSeedCommit
    || !substrate
    || !bundle
  ) {
    return { error: 'coretex-status-malformed' };
  }
  const out = {
    lane,
    epochId,
    stateRoot,
    wordCount,
    transitionCount,
    rulesVersion,
    workPolicyHash,
    corpusRoot,
    coreVersionHash,
    bundleHash,
    minImprovementPpm,
    evalSeedCommit,
    substrate,
    bundle,
  };
  return {
    ...out,
    // Lightweight poll-friendly change token for clients that can't use ETag.
    statusVersion: stableHashHex(out),
  };
}

function sanitizeSubstrateEnvelope(raw: unknown): { encoding: 'coretex-packed-substrate-v1'; bytes?: string; uri?: string } | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (r.encoding !== 'coretex-packed-substrate-v1') return null;
  const bytes = typeof r.bytes === 'string' && /^0x[0-9a-fA-F]*$/.test(r.bytes) ? r.bytes.toLowerCase() : null;
  const uri = typeof r.uri === 'string' && r.uri.startsWith('/coretex/substrate/') ? r.uri : null;
  if (!bytes && !uri) return null;
  return {
    encoding: 'coretex-packed-substrate-v1',
    ...(bytes ? { bytes } : {}),
    ...(uri ? { uri } : {}),
  };
}

function sanitizeUriEnvelope(raw: unknown): { uri: string } | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.uri !== 'string') return null;
  // Restrict to the immutable artifact endpoint shapes. A misbehaving host
  // can't redirect clients at arbitrary /coretex/* paths (e.g. dashboards).
  const allowed = /^\/coretex\/(substrate|bundle|patch|eval-report|corpus-delta)\/[0-9a-fA-Fx]+$/;
  return allowed.test(r.uri) ? { uri: r.uri } : null;
}

function asBytes32Hex(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.toLowerCase();
  return /^0x[0-9a-f]{64}$/.test(s) ? s : null;
}

function asPosInt(v: unknown): number | null {
  if (!Number.isSafeInteger(v) || Number(v) <= 0) return null;
  return Number(v);
}

function asNonNegativeInt(v: unknown): number | null {
  if (!Number.isSafeInteger(v) || Number(v) < 0) return null;
  return Number(v);
}

function stableHashHex(v: unknown): string {
  return `0x${createHash('sha256').update(stableStringify(v)).digest('hex')}`;
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}
