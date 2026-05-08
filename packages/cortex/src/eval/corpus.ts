import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

import type { CortexState } from '../state/types.js';
import { bytesToHex } from '../state/merkle.js';
import { keccak256 } from '../state/keccak256.js';
import type { CorpusLoader } from './index.js';

export type ProductionCorpusFamily = 'near_collision' | 'temporal' | 'long_horizon';

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
    readonly exactRetrieval: number;
    readonly staleMemoryRejection: number;
    readonly temporalUpdateCorrectness: number;
    readonly compressionSurvival: number;
    readonly routingAccuracy: number;
  };
  readonly familyScores: Record<ProductionCorpusFamily, number>;
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
  const longHorizon = (compressionSurvival * 0.30 + routingAccuracy * 0.05) / 0.35;
  const composite = clamp01(
    0.30 * exactRetrieval
    + 0.15 * staleMemoryRejection
    + 0.15 * temporalUpdateCorrectness
    + 0.30 * compressionSurvival
    + 0.05 * routingAccuracy,
  );

  return {
    composite,
    components: {
      exactRetrieval,
      staleMemoryRejection,
      temporalUpdateCorrectness,
      compressionSurvival,
      routingAccuracy,
    },
    familyScores: {
      near_collision: exactRetrieval,
      temporal: (staleMemoryRejection + temporalUpdateCorrectness) / 2,
      long_horizon: longHorizon,
    },
    hits: { near_collision: ncHits, stale: staleHits, current: currentHits, long_horizon: longHits, relations: filledRel },
    totals: { near_collision: nc.length, stale: stale.length, current: current.length, long_horizon: lh.length, relations: 128 },
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
  return {
    id: String(obj.id ?? fail('production corpus item missing id')),
    family,
    taskType: String(obj.task ?? obj.config ?? obj.source ?? family),
    isProtected: obj.protected === true,
    epochCommitted: Number(obj.epoch_committed ?? 0),
    sourceRef: String(obj.source_ref ?? ''),
    queryText: String(obj.query ?? ''),
    truthText: String(obj.truth ?? obj.passage ?? ''),
    isStaleTruth: obj.is_stale === true,
    relevant: obj.relevant !== false,
  };
}

function computeProductionCorpusRoot(items: readonly unknown[]): string {
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
