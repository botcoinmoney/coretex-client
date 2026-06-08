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
 * The status response is the sole dynamic miner context surface: epoch pins,
 * allowed patch types, screener threshold, miner counters, and
 * acceptingSubmissions. There is no separate challenge endpoint in v0.
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
  /** Per-miner dynamic context (`query.miner` is the miner address). */
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
      const raw = opts.health ? await opts.health() : {
        ok: true,
        service: 'coretex',
        bundleHash: manifest.bundleHash.toLowerCase(),
        serverTime: new Date().toISOString(),
      };
      return sanitizeHealthResponse(raw, manifest.bundleHash);
    },
  };
  if (opts.getSubstrate) (ds as Mutable).getSubstrate = opts.getSubstrate;
  if (opts.getReceipt) (ds as Mutable).getReceipt = opts.getReceipt;
  if (opts.rateLimit) (ds as Mutable).rateLimit = opts.rateLimit;
  if (opts.authorize) (ds as Mutable).authorize = opts.authorize;
  return ds;
}

type Mutable = { -readonly [K in keyof CoreTexCoordinatorDataSource]: CoreTexCoordinatorDataSource[K] };

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
  const transaction = sanitizeTransactionEnvelope(r.transaction);
  return {
    status: 'accepted',
    ...(patchHash ? { patchHash } : {}),
    ...(evalReportHash ? { evalReportHash } : {}),
    ...(receipt ? { receipt } : {}),
    ...(transaction ? { transaction } : {}),
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
  // Optional compact alias used by some signers; only hex signatures pass.
  if (typeof r.sig === 'string' && /^0x[0-9a-fA-F]+$/.test(r.sig)) out.sig = r.sig.toLowerCase();
  if (Array.isArray(r.signedFields) && r.signedFields.every((f) => typeof f === 'string')) {
    out.signedFields = r.signedFields.slice();
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function sanitizeTransactionEnvelope(raw: unknown): { to: string; chainId: number; value: string; data: string } | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const to = typeof r.to === 'string' && /^0x[0-9a-fA-F]{40}$/i.test(r.to) ? r.to.toLowerCase().replace(/^0x/i, '0x') : null;
  const chainId = asPosInt(r.chainId);
  const value = typeof r.value === 'string' && /^(0|[1-9][0-9]*)$/.test(r.value) ? r.value : null;
  const data = typeof r.data === 'string' && /^0x[0-9a-fA-F]*$/i.test(r.data) ? r.data.toLowerCase().replace(/^0x/i, '0x') : null;
  if (!to || chainId === null || value === null || data === null) return null;
  return { to, chainId, value, data };
}

function sanitizeStatusResponse(raw: unknown, manifestBundleHash: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') {
    return { error: 'coretex-status-malformed' };
  }
  const r = raw as Record<string, unknown>;
  if (hasForbiddenPublicKey(r)) return { error: 'coretex-status-malformed' };
  if (r.stateRoot !== undefined || r.transitionCount !== undefined) return { error: 'coretex-status-malformed' };
  const lane = r.lane === undefined ? undefined : r.lane === 'coretex' ? 'coretex' : null;
  const epochId = asNonNegativeInt(r.epochId);
  const currentStateRoot = asBytes32Hex(r.currentStateRoot);
  const coreVersionHash = asBytes32Hex(r.coreVersionHash) ?? manifestBundleHash.toLowerCase();
  const bundleHash = asBytes32Hex(r.bundleHash) ?? manifestBundleHash.toLowerCase();
  const substrate = sanitizeUriEnvelope(r.substrate);
  if (r.substrate !== undefined && !substrate) {
    return { error: 'coretex-status-malformed' };
  }
  if (lane === null || epochId === null || !currentStateRoot) {
    return { error: 'coretex-status-malformed' };
  }
  const out: Record<string, unknown> = {
    ...(lane ? { lane } : {}),
    epochId,
    currentStateRoot,
    coreVersionHash,
    bundleHash,
    ...(substrate ? { substrate } : {}),
  };
  copyNonNegativeIntField(out, r, 'wordCount');
  copyNonNegativeIntField(out, r, 'confirmedTransitionCount');
  copyNonNegativeIntField(out, r, 'rulesVersion');
  copyNonNegativeIntField(out, r, 'minImprovementPpm');
  copyNonNegativeIntField(out, r, 'replayTolerancePpm');
  copyNonNegativeIntField(out, r, 'screenerThresholdPpm');
  copyNonNegativeIntField(out, r, 'patchWordBudget');
  copyNonNegativeIntField(out, r, 'perMinerScreenerCap');
  copyNonNegativeIntField(out, r, 'baselineScorePpm');
  copyNonNegativeIntField(out, r, 'recentNoiseFloorPpm');
  copyNonNegativeIntField(out, r, 'qualifiedScreenerPassesSinceLastStateAdvance');
  copyNonNegativeIntField(out, r, 'nextStateAdvanceWorkBps');
  copyBytes32Field(out, r, 'workPolicyHash');
  copyBytes32Field(out, r, 'corpusRoot');
  copyBytes32Field(out, r, 'parentStateRoot');
  copyBytes32Field(out, r, 'baselineManifestHash');
  copyBytes32Field(out, r, 'rotationManifestHash');
  copyBytes32Field(out, r, 'corpusDeltaHash');
  copyBytes32Field(out, r, 'evalSeedCommit');
  copyNullableBytes32Field(out, r, 'activeFrontierRoot');
  copyNonNegativeIntField(out, r, 'currentEpoch');
  copySafeStringField(out, r, 'rotationManifestUrl', 1024);
  copySafeStringField(out, r, 'corpusDeltaUrl', 1024);
  copySafeStringField(out, r, 'epochSigningPublicKeyId', 128);
  copySafeStringField(out, r, 'epochSigningPublicKeyUrl', 1024);
  copyBytes32Field(out, r, 'epochSigningPublicKeyFingerprint');
  copySafeStringField(out, r, 'pipelineVersion');
  copySafeStringField(out, r, 'memoryIRSchemaVersion');
  copySafeStringField(out, r, 'hiddenEvalWarning', 512);
  copyStringArrayField(out, r, 'activeSubstrateSurfaces');
  copyPublicJsonField(out, r, 'activeFrontier');
  copyPublicJsonField(out, r, 'corpus');
  copyPublicJsonField(out, r, 'perMiner');
  copyPublicJsonField(out, r, 'allowedPatchTypes');
  copyPublicJsonField(out, r, 'patchWordRanges');
  copyPublicJsonField(out, r, 'exampleValidPatch');
  copyPublicJsonField(out, r, 'nextEpochReadiness');
  copyPublicJsonField(out, r, 'lastEvolveDecision');
  copyRunwayTelemetryField(out, r);
  if (typeof r.acceptingSubmissions === 'boolean') out.acceptingSubmissions = r.acceptingSubmissions;
  copySafeStringField(out, r, 'reason', 256);
  return {
    ...out,
    // Lightweight poll-friendly change token for clients that can't use ETag.
    statusVersion: stableHashHex(out),
  };
}

function sanitizeHealthResponse(raw: unknown, manifestBundleHash: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object') return { error: 'coretex-health-malformed' };
  const r = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  if (typeof r.ok === 'boolean') out.ok = r.ok;
  copySafeStringField(out, r, 'service');
  copySafeStringField(out, r, 'version');
  copyNonNegativeIntField(out, r, 'epoch');
  copyNonNegativeIntField(out, r, 'chainId');
  copyNonNegativeIntField(out, r, 'confirmationDepth');
  copyNonNegativeIntField(out, r, 'finalityLagBlocks');
  copyBytes32Field(out, r, 'chainLiveRoot');
  copyBytes32Field(out, r, 'confirmedLiveRoot');
  copyBytes32Field(out, r, 'bundleHash');
  if (!out.bundleHash && manifestBundleHash) out.bundleHash = manifestBundleHash.toLowerCase();
  if (typeof r.acceptingSubmissions === 'boolean') out.acceptingSubmissions = r.acceptingSubmissions;
  copySafeStringField(out, r, 'reason', 256);
  copySafeStringField(out, r, 'serverTime', 64);

  const pins = sanitizeEpochPins(r.epochPins);
  if (pins) out.epochPins = pins;
  return Object.keys(out).length > 0 ? out : { error: 'coretex-health-malformed' };
}

function sanitizeEpochPins(raw: unknown): Record<string, string> | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const out: Record<string, string> = {};
  for (const k of ['parentStateRoot', 'coreVersionHash', 'corpusRoot', 'activeFrontierRoot', 'baselineManifestHash', 'hiddenSeedCommit']) {
    const v = asBytes32Hex(r[k]);
    if (v) out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : null;
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

function copyRunwayTelemetryField(out: Record<string, unknown>, src: Record<string, unknown>): void {
  const v = sanitizeRunwayTelemetry(src.runwayTelemetry);
  if (v) out.runwayTelemetry = v;
}

function sanitizeRunwayTelemetry(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of [
    'updatedAtEpoch',
    'strictMinableRatioPpm',
    'alreadySolvedRatioPpm',
    'tooHardRatioPpm',
    'acceptedFamilyEntropyPpm',
    'acceptedFingerprintReusePpm',
    'acceptedSelectorReusePpm',
    'randomControlAccepts',
    'randomControlAttempts',
    'noopControlAccepts',
    'noopControlAttempts',
    'hillControlAccepts',
    'hillControlAttempts',
    'reserveRemaining',
    'reserveAdded',
    'activeChurn',
    'oldCorpusDamageRejects',
    'goldDamageRejects',
    'acceptedOldCorpusDamageCount',
    'acceptedGoldDamageCount',
  ]) {
    copyNonNegativeIntField(out, r, key);
  }
  for (const key of [
    'activeLivePackFamilyDistribution',
    'familyAttempts',
    'familyAccepts',
    'familyRejects',
    'familyFirstRejectBuckets',
    'fingerprintAttempts',
    'fingerprintAccepts',
  ]) {
    const m = sanitizeTelemetryCountMap(r[key]);
    if (m) out[key] = m;
  }
  return Object.keys(out).length > 0 ? out : null;
}

function sanitizeTelemetryCountMap(raw: unknown): Record<string, number> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const keys = Object.keys(raw as Record<string, unknown>);
  if (keys.length > 256) return null;
  const out: Record<string, number> = {};
  for (const key of keys) {
    if (!/^[a-zA-Z0-9_:.:-]{1,96}$/.test(key) || FORBIDDEN_PUBLIC_KEY_RE.test(key)) return null;
    const v = asNonNegativeInt((raw as Record<string, unknown>)[key]);
    if (v === null) return null;
    out[key] = v;
  }
  return Object.keys(out).length > 0 ? out : null;
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

function sanitizeUriEnvelope(raw: unknown): { uri: string } | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.uri !== 'string') return null;
  const allowed = /^\/coretex\/substrate\/0x[0-9a-fA-F]{64}$/;
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
