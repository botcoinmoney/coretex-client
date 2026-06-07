/**
 * v0 launch CoreTex coordinator data-source factory.
 *
 * Wires the canonical 5-endpoint surface (`endpoints.ts`):
 *
 *   GET  /coretex/health
 *   GET  /coretex/status?miner=0x…
 *   GET  /coretex/substrate/:stateRoot
 *   POST /coretex/submit
 *   GET  /coretex/receipt/:hash
 *
 * The status response folds in everything the legacy `/coretex/challenge` payload
 * carried (epoch pins, allowed patch types, screener threshold, etc.) PLUS the
 * miner-specific counters (perMinerScreenerCap, screenersThisEpoch, nextIndex,
 * lastReceiptHash, acceptingSubmissions). There is no separate challenge endpoint
 * in v0.
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
  /** Per-miner dynamic context (`query.miner` is the miner address). Folds in every
   *  field the legacy challenge payload exposed. */
  readonly getStatus: (query: Record<string, string | readonly string[] | undefined>) => Promise<unknown> | unknown;
  /** POST /coretex/submit handler. */
  readonly submit: (body: unknown) => Promise<unknown> | unknown;
  /** Optional packed-substrate-by-root reader. */
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  /** Receipt lookup by patchHash (returns `{status, body}` envelope or null). */
  readonly getReceipt?: (hash: string) => Promise<{ readonly status: number; readonly body: unknown } | null> | { readonly status: number; readonly body: unknown } | null;
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
    async submit(body) {
      return sanitizeSubmitResponse(await opts.submit(body));
    },
    async getStatus(query) {
      return sanitizeStatusResponse(await opts.getStatus(query), manifest.bundleHash);
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
  if (opts.getReceipt) (ds as Mutable).getReceipt = opts.getReceipt;
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
  if (hasForbiddenPublicKey(r)) return { error: 'coretex-challenge-malformed' };
  const lane = r.lane === undefined ? undefined : r.lane === 'coretex' ? 'coretex' : null;
  const challengeId = asBytes32Hex(r.challengeId);
  const expiresAt = asPosInt(r.expiresAt);
  const parentStateRoot = asBytes32Hex(r.parentStateRoot);
  const currentStateRoot = asBytes32Hex(r.currentStateRoot) ?? parentStateRoot;
  const epochId = asNonNegativeInt(r.epochId);
  const substrate = sanitizeSubstrateEnvelope(r.substrate);
  const substrateAccess = sanitizeSubstrateAccess(r.substrateAccess);
  const coreVersionHash = asBytes32Hex(r.coreVersionHash) ?? manifestBundleHash.toLowerCase();
  const bundleHash = asBytes32Hex(r.bundleHash) ?? manifestBundleHash.toLowerCase();
  if (lane === null || !parentStateRoot || !currentStateRoot || epochId === null || (!substrate && !substrateAccess)) {
    return { error: 'coretex-challenge-malformed' };
  }
  const out: Record<string, unknown> = {
    ...(lane ? { lane } : {}),
    ...(challengeId ? { challengeId } : {}),
    ...(expiresAt !== null ? { expiresAt } : {}),
    epochId,
    parentStateRoot,
    currentStateRoot,
    coreVersionHash,
    bundleHash,
    ...(substrate ? { substrate } : {}),
    ...(substrateAccess ? { substrateAccess } : {}),
  };
  copyBytes32Field(out, r, 'corpusRoot');
  copyNullableBytes32Field(out, r, 'activeFrontierRoot');
  copySafeStringField(out, r, 'profileName');
  copySafeStringField(out, r, 'pipelineVersion');
  copySafeStringField(out, r, 'memoryIRSchemaVersion');
  copySafeStringField(out, r, 'hiddenEvalWarning', 512);
  copyNonNegativeIntField(out, r, 'patchWordBudget');
  copyNonNegativeIntField(out, r, 'minImprovementPpm');
  copyNonNegativeIntField(out, r, 'replayTolerancePpm');
  copyNonNegativeIntField(out, r, 'screenerThresholdPpm');
  // v0 canonical: perMinerScreenerCap only. The legacy `perMinerCap` alias is
  // intentionally dropped here so a coordinator that still emits it will not have
  // it propagated to the public response.
  copyNonNegativeIntField(out, r, 'perMinerScreenerCap');
  copyNonNegativeIntField(out, r, 'perMinerScreenerRemaining');
  copyStringArrayField(out, r, 'activeSubstrateSurfaces');
  copyPublicJsonField(out, r, 'allowedPatchTypes');
  copyPublicJsonField(out, r, 'patchWordRanges');
  copyPublicJsonField(out, r, 'corpusMeta');
  copyPublicJsonField(out, r, 'workMultiplierBps');
  copyPublicJsonField(out, r, 'exampleValidPatch');
  return out;
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
  if (hasForbiddenPublicKey(r)) return { error: 'coretex-status-malformed' };
  const lane = r.lane === undefined ? undefined : r.lane === 'coretex' ? 'coretex' : null;
  const epochId = asNonNegativeInt(r.epochId);
  const currentStateRoot = asBytes32Hex(r.currentStateRoot) ?? asBytes32Hex(r.stateRoot);
  const stateRoot = asBytes32Hex(r.stateRoot) ?? currentStateRoot;
  const coreVersionHash = asBytes32Hex(r.coreVersionHash) ?? manifestBundleHash.toLowerCase();
  const bundleHash = asBytes32Hex(r.bundleHash) ?? manifestBundleHash.toLowerCase();
  const substrate = sanitizeUriEnvelope(r.substrate);
  const bundle = sanitizeUriEnvelope(r.bundle);
  if ((r.substrate !== undefined && !substrate) || (r.bundle !== undefined && !bundle)) {
    return { error: 'coretex-status-malformed' };
  }
  if (lane === null || epochId === null || !currentStateRoot || !stateRoot) {
    return { error: 'coretex-status-malformed' };
  }
  const out: Record<string, unknown> = {
    ...(lane ? { lane } : {}),
    epochId,
    currentStateRoot,
    stateRoot,
    coreVersionHash,
    bundleHash,
    ...(substrate ? { substrate } : {}),
    ...(bundle ? { bundle } : {}),
  };
  copyNonNegativeIntField(out, r, 'wordCount');
  copyNonNegativeIntField(out, r, 'transitionCount');
  copyNonNegativeIntField(out, r, 'rulesVersion');
  copyNonNegativeIntField(out, r, 'minImprovementPpm');
  copyNonNegativeIntField(out, r, 'replayTolerancePpm');
  copyNonNegativeIntField(out, r, 'screenerThresholdPpm');
  copyNonNegativeIntField(out, r, 'baselineScorePpm');
  copyNonNegativeIntField(out, r, 'recentNoiseFloorPpm');
  copyNonNegativeIntField(out, r, 'qualifiedScreenerPassesSinceLastStateAdvance');
  copyNonNegativeIntField(out, r, 'nextStateAdvanceWorkBps');
  copyBytes32Field(out, r, 'workPolicyHash');
  copyBytes32Field(out, r, 'corpusRoot');
  copyBytes32Field(out, r, 'evalSeedCommit');
  copyNullableBytes32Field(out, r, 'activeFrontierRoot');
  copyPublicJsonField(out, r, 'activeFrontier');
  copyPublicJsonField(out, r, 'corpus');
  copyPublicJsonField(out, r, 'perMiner');
  return {
    ...out,
    // Lightweight poll-friendly change token for clients that can't use ETag.
    statusVersion: stableHashHex(out),
  };
}

const FORBIDDEN_PUBLIC_KEY_RE = /qrel|truthdoc|hardnegativ|answerid|answer_id|epochsecret|epoch_secret|evalseed(?!commit)|eval_seed(?!_commit)|hiddenpack|hidden_pack|truth|relevance|failurestat/i;

function hasForbiddenPublicKey(raw: unknown): boolean {
  if (!raw || typeof raw !== 'object') return false;
  if (Array.isArray(raw)) return raw.some(hasForbiddenPublicKey);
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (FORBIDDEN_PUBLIC_KEY_RE.test(k)) return true;
    if (hasForbiddenPublicKey(v)) return true;
  }
  return false;
}

function copyBytes32Field(out: Record<string, unknown>, src: Record<string, unknown>, key: string): void {
  const v = asBytes32Hex(src[key]);
  if (v) out[key] = v;
}

function copyNullableBytes32Field(out: Record<string, unknown>, src: Record<string, unknown>, key: string): void {
  if (src[key] === null) {
    out[key] = null;
    return;
  }
  copyBytes32Field(out, src, key);
}

function copyNonNegativeIntField(out: Record<string, unknown>, src: Record<string, unknown>, key: string): void {
  const v = asNonNegativeInt(src[key]);
  if (v !== null) out[key] = v;
}

function copySafeStringField(out: Record<string, unknown>, src: Record<string, unknown>, key: string, maxLen = 128): void {
  const v = asSafeString(src[key], maxLen);
  if (v !== null) out[key] = v;
}

function copyStringArrayField(out: Record<string, unknown>, src: Record<string, unknown>, key: string): void {
  const v = sanitizeStringArray(src[key]);
  if (v) out[key] = v;
}

function copyPublicJsonField(out: Record<string, unknown>, src: Record<string, unknown>, key: string): void {
  const v = sanitizePublicJson(src[key]);
  if (v !== undefined) out[key] = v;
}

function sanitizeSubstrateAccess(raw: unknown): { byRoot: string; wordCount?: number; packedBytes?: number } | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const byRoot = typeof r.byRoot === 'string' && /^\/coretex\/substrate\/0x[0-9a-fA-F]{64}$/.test(r.byRoot) ? r.byRoot : null;
  if (!byRoot) return null;
  const wordCount = asPosInt(r.wordCount);
  const packedBytes = asPosInt(r.packedBytes);
  return {
    byRoot,
    ...(wordCount !== null ? { wordCount } : {}),
    ...(packedBytes !== null ? { packedBytes } : {}),
  };
}

function sanitizeStringArray(raw: unknown): string[] | null {
  if (!Array.isArray(raw) || raw.length > 64) return null;
  const out: string[] = [];
  for (const v of raw) {
    const s = asSafeString(v, 128);
    if (s === null) return null;
    out.push(s);
  }
  return out;
}

function sanitizePublicJson(raw: unknown, depth = 0): unknown | undefined {
  if (raw === undefined) return undefined;
  if (raw === null) return null;
  if (typeof raw === 'string') return raw.length <= 4096 ? raw : undefined;
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw : undefined;
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'bigint') return raw.toString();
  if (depth >= 8 || typeof raw !== 'object') return undefined;
  if (Array.isArray(raw)) {
    if (raw.length > 256) return undefined;
    const arr = [];
    for (const v of raw) {
      const sv = sanitizePublicJson(v, depth + 1);
      if (sv === undefined) return undefined;
      arr.push(sv);
    }
    return arr;
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length > 128) return undefined;
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    if (FORBIDDEN_PUBLIC_KEY_RE.test(k)) return undefined;
    const sv = sanitizePublicJson(obj[k], depth + 1);
    if (sv === undefined) return undefined;
    out[k] = sv;
  }
  return out;
}

function asSafeString(v: unknown, maxLen: number): string | null {
  return typeof v === 'string' && v.length > 0 && v.length <= maxLen ? v : null;
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
