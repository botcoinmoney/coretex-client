import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

import type { CortexState } from '../state/types.js';
import { bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import type { CorpusLoader } from './index.js';

export type ProductionCorpusFamily = 'near_collision' | 'temporal' | 'long_horizon';

export type ProductionCorpusRegion = 'memory_index' | 'retrieval_keys' | 'relations' | 'temporal' | 'codebook';

export type ProductionCorpusNoveltyBucket = 'low' | 'medium' | 'high';

export interface ProductionCorpusEvent {
  readonly id: string;
  readonly family: ProductionCorpusFamily;
  readonly taskType: string;
  readonly isProtected: boolean;
  readonly epochCommitted: number;
  readonly sourceRef: string;
  readonly queryText: string;
  readonly truthText: string;
  readonly isStaleTruth: boolean;
  readonly relevant: boolean;
  // §9 extension fields
  readonly distractors: readonly string[];
  readonly relations: readonly string[];
  readonly expectedStateRegions: ReadonlyArray<ProductionCorpusRegion>;
  readonly validFromEpoch: number;
  readonly expiresAtEpoch: number;
  readonly noveltyBucket: ProductionCorpusNoveltyBucket;
  readonly hardnessSignal: number;
}

export interface ProductionCorpus {
  readonly events: Record<ProductionCorpusFamily, readonly ProductionCorpusEvent[]>;
  readonly sources: Record<string, unknown>;
  readonly corpusRoot: string;
}

export interface ProductionCorpusLoaderOptions {
  readonly evalItemsPerFamily?: number;
}

export interface ProductionCorpusScore {
  readonly composite: number;
  readonly components: {
    readonly nearCollisionRetrieval: number;
    readonly temporalCurrentStale: number;
    readonly longHorizonCompression: number;
    readonly relationMultiHop: number;
    readonly codebookCompression: number;
    readonly localModelAgreement: number;
    readonly exactRetrieval: number;
    readonly staleMemoryRejection: number;
    readonly temporalUpdateCorrectness: number;
    readonly compressionSurvival: number;
    readonly routingAccuracy: number;
  };
  readonly familyScores: Record<string, number>;
  readonly hits: Record<string, number>;
  readonly totals: Record<string, number>;
}

export class ProductionCorpusLoader implements CorpusLoader {
  readonly corpusRoot: string;
  readonly corpus: ProductionCorpus;
  readonly evalItemsPerFamily: number;

  constructor(corpus: ProductionCorpus, opts: ProductionCorpusLoaderOptions = {}) {
    this.corpus = corpus;
    this.corpusRoot = corpus.corpusRoot;
    this.evalItemsPerFamily = opts.evalItemsPerFamily ?? 256;
  }

  static fromFile(path: string, opts: ProductionCorpusLoaderOptions = {}): ProductionCorpusLoader {
    return new ProductionCorpusLoader(loadProductionCorpus(path), opts);
  }

  score(_decoded: unknown, _shardId: Uint8Array): number {
    return 0;
  }

  scoreState(state: CortexState, shardId: Uint8Array): number {
    return scoreProductionState(state, this.corpus, {
      shardId: bytesToHex(shardId),
      evalItemsPerFamily: this.evalItemsPerFamily,
    }).composite;
  }
}

export function loadProductionCorpus(path: string): ProductionCorpus {
  if (!existsSync(path)) throw new Error(`production corpus file not found: ${path}`);
  const raw = JSON.parse(readFileSync(path, 'utf8')) as {
    items?: unknown[];
    corpus_hash?: string;
    experience_corpus_root?: string;
    [key: string]: unknown;
  };
  const { corpus_hash: embeddedHash, experience_corpus_root: embeddedRoot, ...withoutHashes } = raw;
  if (!Array.isArray(raw.items)) throw new Error('production corpus must contain items[]');
  if (embeddedHash) {
    const got = createHash('sha256').update(JSON.stringify(withoutHashes)).digest('hex');
    if (got !== embeddedHash) throw new Error(`production corpus sha256 mismatch: expected ${embeddedHash} got ${got}`);
  }

  const events: Record<ProductionCorpusFamily, ProductionCorpusEvent[]> = {
    near_collision: [],
    temporal: [],
    long_horizon: [],
  };
  for (const item of raw.items) {
    const event = normalizeProductionItem(item);
    events[event.family].push(event);
  }
  const corpusRoot = embeddedRoot && isBytes32(embeddedRoot) ? embeddedRoot.toLowerCase() : computeProductionCorpusRoot(raw.items);
  if (embeddedRoot && corpusRoot !== embeddedRoot.toLowerCase()) {
    throw new Error(`production corpus root mismatch: expected ${embeddedRoot} got ${corpusRoot}`);
  }
  return {
    events,
    corpusRoot,
    sources: {
      version: raw.version,
      source: raw.source,
      license_spdx: raw.license_spdx,
      record_count: raw.record_count,
      corpus_hash: embeddedHash,
    },
  };
}

export function scoreProductionState(
  state: CortexState,
  corpus: ProductionCorpus,
  opts: { readonly shardId: string; readonly evalItemsPerFamily?: number },
): ProductionCorpusScore {
  const selected = selectScoredEvents(corpus.events, opts.shardId, opts.evalItemsPerFamily ?? 256);
  const activeMemIds = new Set<bigint>();
  const revokedMemIds = new Set<bigint>();
  for (let s = 0; s < 44; s++) {
    const w0 = state.words[32 + s * 8] ?? 0n;
    if (w0 === 0n) continue;
    const eventId = (w0 >> 128n) & ((1n << 128n) - 1n);
    if (eventId === 0n) continue;
    const flags = Number((w0 >> 64n) & 0xffffn);
    if ((flags & 0x0001) === 0) continue;
    if ((flags & 0x0002) !== 0) revokedMemIds.add(eventId);
    else activeMemIds.add(eventId);
  }

  const activeKeyIds = new Set<bigint>();
  for (let s = 0; s < 36; s++) {
    const w0 = state.words[384 + s * 8] ?? 0n;
    if (w0 === 0n) continue;
    const keyId = (w0 >> 128n) & ((1n << 128n) - 1n);
    if (keyId === 0n) continue;
    const flags = Number((w0 >> 80n) & 0xffffn);
    if ((flags & 0x0001) !== 0) activeKeyIds.add(keyId);
  }

  let filledRel = 0;
  for (let i = 672; i <= 799; i++) {
    if (((state.words[i] ?? 0n) >> 192n) & 0xffffn) filledRel++;
  }
  let activeCodebook = 0;
  for (let slot = 0; slot < 48; slot++) {
    const w0 = state.words[896 + slot * 2] ?? 0n;
    const code = Number((w0 >> 240n) & 0xffffn);
    const codeType = Number((w0 >> 224n) & 0xffffn);
    const flags = Number((w0 >> 208n) & 0xffffn);
    if (code !== 0 && (codeType === 1 || codeType === 2) && (flags & 0x0001) !== 0) activeCodebook++;
  }

  const nc = selected.near_collision.filter((event) => event.relevant);
  const stale = selected.temporal.filter((event) => event.isStaleTruth);
  const current = selected.temporal.filter((event) => !event.isStaleTruth);
  const lh = selected.long_horizon;

  const ncHits = countHits(nc, activeKeyIds, eventIdToKey128);
  const staleHits = countHits(stale, revokedMemIds, eventIdToMem128);
  const currentHits = countHits(current, activeMemIds, eventIdToMem128);
  const longHits = countHits(lh, activeMemIds, eventIdToMem128);

  const exactRetrieval = ratio(ncHits, nc.length);
  const staleMemoryRejection = ratio(staleHits, stale.length);
  const temporalUpdateCorrectness = ratio(currentHits, current.length);
  const compressionSurvival = ratio(longHits, lh.length);
  const routingAccuracy = filledRel / 128;
  const nearCollisionRetrieval = exactRetrieval;
  const temporalCurrentStale = (staleMemoryRejection + temporalUpdateCorrectness) / 2;
  const longHorizonCompression = compressionSurvival;
  const relationMultiHop = routingAccuracy;
  const codebookCompression = activeCodebook / 48;
  const localModelAgreement = (
    nearCollisionRetrieval
    + temporalCurrentStale
    + longHorizonCompression
    + relationMultiHop
    + codebookCompression
  ) / 5;
  const composite = clamp01(
    0.20 * nearCollisionRetrieval
    + 0.20 * temporalCurrentStale
    + 0.20 * longHorizonCompression
    + 0.20 * relationMultiHop
    + 0.10 * codebookCompression
    + 0.10 * localModelAgreement,
  );

  return {
    composite,
    components: {
      nearCollisionRetrieval,
      temporalCurrentStale,
      longHorizonCompression,
      relationMultiHop,
      codebookCompression,
      localModelAgreement,
      exactRetrieval,
      staleMemoryRejection,
      temporalUpdateCorrectness,
      compressionSurvival,
      routingAccuracy,
    },
    familyScores: {
      near_collision_retrieval: nearCollisionRetrieval,
      temporal_current_stale: temporalCurrentStale,
      long_horizon: longHorizonCompression,
      relation_multi_hop: relationMultiHop,
      codebook_compression: codebookCompression,
      local_model_agreement: localModelAgreement,
      near_collision: nearCollisionRetrieval,
      temporal: temporalCurrentStale,
    },
    hits: { near_collision: ncHits, stale: staleHits, current: currentHits, long_horizon: longHits, relations: filledRel, codebook: activeCodebook },
    totals: { near_collision: nc.length, stale: stale.length, current: current.length, long_horizon: lh.length, relations: 128, codebook: 48 },
  };
}

export function eventIdToKey128(eventId: string): bigint {
  return lowBytesToBigInt(sha256Bytes(`cortex-key128:${eventId}`), 16);
}

export function eventIdToMem128(eventId: string): bigint {
  return lowBytesToBigInt(sha256Bytes(`cortex-mem128:${eventId}`), 16);
}

function normalizeProductionItem(item: unknown): ProductionCorpusEvent {
  const obj = item as Record<string, unknown>;
  const rawFamily = String(obj.family ?? '');
  const family = rawFamily === 'near_collision' || rawFamily === 'temporal' || rawFamily === 'long_horizon'
    ? rawFamily
    : fail(`production corpus item ${String(obj.id)} has unsupported family ${rawFamily}`);

  // §9 extension: distractors
  const distractors: readonly string[] = Array.isArray(obj.distractors)
    ? (obj.distractors as unknown[]).map((d) => String(d))
    : [];

  // §9 extension: relations
  const relations: readonly string[] = Array.isArray(obj.relations)
    ? (obj.relations as unknown[]).map((r) => String(r))
    : [];

  // §9 extension: expectedStateRegions
  const validRegions: ReadonlyArray<ProductionCorpusRegion> = ['memory_index', 'retrieval_keys', 'relations', 'temporal', 'codebook'];
  const expectedStateRegions: ReadonlyArray<ProductionCorpusRegion> = Array.isArray(obj.expected_state_regions)
    ? (obj.expected_state_regions as unknown[])
        .map((r) => String(r))
        .filter((r): r is ProductionCorpusRegion => (validRegions as readonly string[]).includes(r))
    : defaultRegionsForFamily(family);

  // §9 extension: validFromEpoch / expiresAtEpoch
  const epochCommitted = Number(obj.epoch_committed ?? 0);
  const validFromEpoch = obj.valid_from_epoch !== undefined ? Number(obj.valid_from_epoch) : epochCommitted;
  const expiresAtEpoch = Number(obj.expires_at_epoch ?? 0);

  // §9 extension: noveltyBucket — derive from field or hash-bucket manifestHash/id
  const noveltyBucket: ProductionCorpusNoveltyBucket = (() => {
    const raw = String(obj.novelty_bucket ?? '');
    if (raw === 'low' || raw === 'medium' || raw === 'high') return raw;
    // derive from id hash if not present
    const h = sha256Bytes(String(obj.id ?? ''));
    const v = (h[0]! + h[1]! * 256) % 3;
    return v === 0 ? 'low' : v === 1 ? 'medium' : 'high';
  })();

  // §9 extension: hardnessSignal — derive from field or hash of (id + epochCommitted)
  const hardnessSignal: number = (() => {
    if (typeof obj.hardness_signal === 'number') return Math.max(0, Math.min(1, obj.hardness_signal));
    const h = sha256Bytes(`${String(obj.id ?? '')}:${String(epochCommitted)}`);
    return ((h[0]! * 256 + h[1]!) % 100) / 100;
  })();

  return {
    id: String(obj.id ?? fail('production corpus item missing id')),
    family,
    taskType: String(obj.task ?? obj.config ?? obj.source ?? family),
    isProtected: obj.protected === true,
    epochCommitted,
    sourceRef: String(obj.source_ref ?? ''),
    queryText: String(obj.query ?? ''),
    truthText: String(obj.truth ?? obj.passage ?? ''),
    isStaleTruth: obj.is_stale === true,
    relevant: obj.relevant !== false,
    // §9 fields
    distractors,
    relations,
    expectedStateRegions,
    validFromEpoch,
    expiresAtEpoch,
    noveltyBucket,
    hardnessSignal,
  };
}

function defaultRegionsForFamily(family: ProductionCorpusFamily): ReadonlyArray<ProductionCorpusRegion> {
  if (family === 'near_collision') return ['memory_index', 'retrieval_keys'];
  if (family === 'temporal') return ['memory_index', 'temporal'];
  return ['memory_index', 'retrieval_keys']; // long_horizon
}

export function computeProductionCorpusRoot(items: readonly unknown[]): string {
  const events = items
    .map((item) => {
      const obj = item as Record<string, unknown>;
      const payload = new TextEncoder().encode(JSON.stringify({
        family: obj.family,
        task: obj.task ?? obj.config ?? obj.source ?? obj.family,
        query: obj.query,
        truth: obj.truth,
        is_stale: obj.is_stale === true,
        epoch_committed: obj.epoch_committed,
        source_ref: obj.source_ref,
      }));
      return { id: String(obj.id), payload };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
  if (events.length === 0) return '0x' + '00'.repeat(32);
  let nodes = events.map((event) => {
    const idBytes = new TextEncoder().encode(event.id);
    const leaf = new Uint8Array(4 + idBytes.length + event.payload.length);
    leaf[0] = (idBytes.length >>> 24) & 0xff;
    leaf[1] = (idBytes.length >>> 16) & 0xff;
    leaf[2] = (idBytes.length >>> 8) & 0xff;
    leaf[3] = idBytes.length & 0xff;
    leaf.set(idBytes, 4);
    leaf.set(event.payload, 4 + idBytes.length);
    return keccak256(leaf);
  });
  const zero = new Uint8Array(32);
  let n = 1;
  while (n < nodes.length) n <<= 1;
  while (nodes.length < n) nodes.push(zero);
  while (nodes.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const pair = new Uint8Array(64);
      pair.set(nodes[i]!, 0);
      pair.set(nodes[i + 1]!, 32);
      next.push(keccak256(pair));
    }
    nodes = next;
  }
  return bytesToHex(nodes[0]!);
}

function selectScoredEvents(
  events: ProductionCorpus['events'],
  shardId: string,
  limit: number,
): Record<ProductionCorpusFamily, ProductionCorpusEvent[]> {
  return {
    near_collision: selectByShard(events.near_collision, shardId, limit),
    temporal: selectByShard(events.temporal, shardId, limit),
    long_horizon: selectByShard(events.long_horizon, shardId, limit),
  };
}

function selectByShard(events: readonly ProductionCorpusEvent[], shardId: string, limit: number): ProductionCorpusEvent[] {
  if (limit <= 0 || events.length <= limit) return [...events];
  return events
    .map((event) => ({ event, key: createHash('sha256').update(`${shardId}:${event.id}`).digest('hex') }))
    .sort((a, b) => a.key.localeCompare(b.key) || a.event.id.localeCompare(b.event.id))
    .slice(0, limit)
    .map(({ event }) => event);
}

function countHits(
  events: readonly ProductionCorpusEvent[],
  ids: ReadonlySet<bigint>,
  mapper: (id: string) => bigint,
): number {
  let hits = 0;
  for (const event of events) if (ids.has(mapper(event.id))) hits++;
  return hits;
}

function sha256Bytes(input: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest());
}

function lowBytesToBigInt(bytes: Uint8Array, count: number): bigint {
  let value = 0n;
  for (let i = count - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

function ratio(hits: number, total: number): number {
  return total === 0 ? 0 : hits / total;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function isBytes32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function fail(message: string): never {
  throw new Error(message);
}
