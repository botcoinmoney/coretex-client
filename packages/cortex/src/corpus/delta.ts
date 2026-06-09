/**
 * Corpus delta — append/remove records and track root continuity.
 *
 * `corpusRoot[N+1] = root(corpusRecords[N] + corpus_delta[N])`
 * `parentCorpusRoot[N+1] = corpusRoot[N]`
 *
 * Spec: specs/corpus_retrieval.md §"CorpusDelta carrying embeddings".
 *
 * The delta carries embedding bytes inline; replay watchers depend on them
 * to recompute scores deterministically.
 */

import { createHash, createSign, createVerify } from 'node:crypto';

import type {
  CorpusRootLeafCache,
  ProductionCorpus,
  ProductionCorpusEvent,
  ProductionCorpusEventOnDisk,
  RetrievalKeyLayout,
} from '../eval/retrieval-corpus.js';
import { computeCorpusRoot, expectedSplitForRecord, updateCorpusRootLeafCache } from '../eval/retrieval-corpus.js';

// ── Delta shape ───────────────────────────────────────────────────────────────

export interface LabelingProvenance {
  readonly modelId: string;
  readonly revision: string;
  readonly runtime: string;            // serialized runtimePin label
  readonly batchHash: string;          // sha256 of serialized labeling batch
}

export interface CorpusDelta {
  readonly schemaVersion: 'coretex.corpus-delta.v1';
  readonly previousRoot: string;
  readonly nextRoot: string;
  readonly addedIds: readonly string[];
  readonly addedRecords: readonly ProductionCorpusEvent[];
  readonly removedIds: readonly string[];
  readonly labelingProvenance: LabelingProvenance;
  readonly biEncoder: { readonly modelId: string; readonly revision: string; readonly layout: RetrievalKeyLayout };
  readonly epoch: number;
  readonly corpusEpoch: number;
  readonly generatedAt: string;
  readonly signature?: string;         // 0x-prefixed signature bytes
  readonly signerKeyId?: string;
}

export interface CorpusDeltaFileShape extends Omit<CorpusDelta, 'addedRecords'> {
  readonly addedRecords: readonly ProductionCorpusEventOnDisk[];
}

// ── Build delta ───────────────────────────────────────────────────────────────

export interface BuildCorpusDeltaOptions {
  readonly previousCorpus: ProductionCorpus;
  readonly additions: readonly ProductionCorpusEvent[];
  readonly removals: readonly string[];
  readonly epoch: number;
  readonly labelingProvenance: LabelingProvenance;
  readonly generatedAt?: string;
  /** Optional acceleration cache. Semantics must match computeCorpusRoot(previous + delta). */
  readonly previousRootCache?: CorpusRootLeafCache;
}

export function buildCorpusDelta(opts: BuildCorpusDeltaOptions): CorpusDelta {
  const { previousCorpus, additions, removals, epoch, labelingProvenance } = opts;
  const removalSet = new Set(removals);
  const remaining = removalSet.size > 0 ? previousCorpus.events.filter((e) => !removalSet.has(e.id)) : previousCorpus.events;
  const remainingIds = removalSet.size > 0 ? new Set(remaining.map((e) => e.id)) : previousCorpus.byId;
  const newAdditions = additions.filter((e) => !remainingIds.has(e.id));

  // Validate per-record: split assignment must be deterministic, embeddings must
  // reference the bundle's bi-encoder.
  for (const e of newAdditions) {
    const expectedSplit = expectedSplitForRecord(e.id, previousCorpus.corpusEpoch);
    if (e.split !== expectedSplit) {
      throw new Error(`buildCorpusDelta: record ${e.id} declared split ${e.split}, expected ${expectedSplit}`);
    }
    if (e.embeddings.modelId !== previousCorpus.biEncoderModelId
     || e.embeddings.revision !== previousCorpus.biEncoderRevision) {
      throw new Error(`buildCorpusDelta: record ${e.id} embeddings model id/revision do not match corpus bi-encoder`);
    }
  }

  const rootCache = opts.previousRootCache ?? previousCorpus.corpusRootCache;
  if (rootCache && rootCache.root.toLowerCase() !== previousCorpus.corpusRoot.toLowerCase()) {
    throw new Error(`buildCorpusDelta: previousRootCache root ${rootCache.root} does not match previousCorpus.corpusRoot ${previousCorpus.corpusRoot}`);
  }
  const nextRoot = rootCache
    ? updateCorpusRootLeafCache(rootCache, { additions: newAdditions, removals }).root
    : computeCorpusRoot([...remaining, ...newAdditions]);

  return {
    schemaVersion: 'coretex.corpus-delta.v1',
    previousRoot: previousCorpus.corpusRoot,
    nextRoot,
    addedIds: newAdditions.map((e) => e.id),
    addedRecords: newAdditions,
    removedIds: removals.filter((id) => previousCorpus.byId.has(id)),
    labelingProvenance,
    biEncoder: {
      modelId: previousCorpus.biEncoderModelId,
      revision: previousCorpus.biEncoderRevision,
      layout: previousCorpus.biEncoderRetrievalKeyLayout,
    },
    epoch,
    corpusEpoch: previousCorpus.corpusEpoch,
    generatedAt: opts.generatedAt ?? new Date().toISOString(),
  };
}

// ── Apply delta ───────────────────────────────────────────────────────────────

export interface ApplyCorpusDeltaOptions {
  /** Optional acceleration cache. If provided, full computeCorpusRoot(next) is skipped. */
  readonly rootCache?: CorpusRootLeafCache;
  /** Attach the updated cache to the returned ProductionCorpus. Default false. */
  readonly attachRootCache?: boolean;
  /** Full-root verification when no cache is available. Default true. */
  readonly verifyRoot?: boolean;
}

export function applyCorpusDelta(corpus: ProductionCorpus, delta: CorpusDelta, options: ApplyCorpusDeltaOptions = {}): ProductionCorpus {
  if (delta.schemaVersion !== 'coretex.corpus-delta.v1') {
    throw new Error(`applyCorpusDelta: unsupported schemaVersion ${delta.schemaVersion}`);
  }
  if (delta.previousRoot.toLowerCase() !== corpus.corpusRoot.toLowerCase()) {
    throw new Error(
      `applyCorpusDelta: hash continuity check failed — delta.previousRoot=${delta.previousRoot} but corpus.corpusRoot=${corpus.corpusRoot}`,
    );
  }
  if (delta.biEncoder.modelId !== corpus.biEncoderModelId
   || delta.biEncoder.revision !== corpus.biEncoderRevision) {
    throw new Error('applyCorpusDelta: bi-encoder pinning mismatch');
  }

  const removalSet = new Set(delta.removedIds);
  const addedSet = new Set(delta.addedIds);
  const addedRecordsById = new Map(delta.addedRecords.map((e) => [e.id, e]));

  if (addedRecordsById.size !== delta.addedRecords.length) {
    throw new Error('applyCorpusDelta: duplicate addedRecords id');
  }
  for (const id of addedSet) {
    if (!addedRecordsById.has(id)) {
      throw new Error(`applyCorpusDelta: addedId ${id} is missing from addedRecords`);
    }
  }
  for (const e of delta.addedRecords) {
    if (!addedSet.has(e.id)) {
      throw new Error(`applyCorpusDelta: addedRecord ${e.id} is not listed in addedIds`);
    }
  }

  const kept = corpus.events.filter((e) => !removalSet.has(e.id) && !addedSet.has(e.id));
  const next = [...kept, ...delta.addedRecords];

  // Verify embeddings model id/revision per added record.
  for (const e of delta.addedRecords) {
    if (e.embeddings.modelId !== corpus.biEncoderModelId
     || e.embeddings.revision !== corpus.biEncoderRevision) {
      throw new Error(`applyCorpusDelta: record ${e.id} embeddings bi-encoder mismatch`);
    }
    if (expectedSplitForRecord(e.id, corpus.corpusEpoch) !== e.split) {
      throw new Error(`applyCorpusDelta: record ${e.id} split assignment mismatch`);
    }
  }

  const rootCache = options.rootCache ?? corpus.corpusRootCache;
  let nextRootCache: CorpusRootLeafCache | undefined;
  if (rootCache) {
    if (rootCache.root.toLowerCase() !== corpus.corpusRoot.toLowerCase()) {
      throw new Error(`applyCorpusDelta: rootCache root ${rootCache.root} does not match corpus.corpusRoot ${corpus.corpusRoot}`);
    }
    nextRootCache = updateCorpusRootLeafCache(rootCache, { additions: delta.addedRecords, removals: delta.removedIds });
    if (nextRootCache.root.toLowerCase() !== delta.nextRoot.toLowerCase()) {
      throw new Error(
        `applyCorpusDelta: cached nextRoot=${nextRootCache.root} does not match delta.nextRoot=${delta.nextRoot}`,
      );
    }
  } else if (options.verifyRoot ?? true) {
    const computed = computeCorpusRoot(next);
    if (computed.toLowerCase() !== delta.nextRoot.toLowerCase()) {
      throw new Error(
        `applyCorpusDelta: computed nextRoot=${computed} does not match delta.nextRoot=${delta.nextRoot}`,
      );
    }
  }

  return {
    events: next,
    byId: new Map(next.map((e) => [e.id, e])),
    ...(options.attachRootCache && nextRootCache ? { corpusRootCache: nextRootCache } : {}),
    corpusRoot: delta.nextRoot,
    corpusEpoch: corpus.corpusEpoch,
    biEncoderModelId: corpus.biEncoderModelId,
    biEncoderRevision: corpus.biEncoderRevision,
    biEncoderRetrievalKeyLayout: corpus.biEncoderRetrievalKeyLayout,
    labelingModelId: delta.labelingProvenance.modelId,
    labelingModelRevision: delta.labelingProvenance.revision,
  };
}

// ── Signing ───────────────────────────────────────────────────────────────────

export function deltaCanonicalBytes(delta: Omit<CorpusDelta, 'signature'>): Uint8Array {
  return new TextEncoder().encode(canonicalJson(delta));
}

export function signCorpusDelta(
  delta: Omit<CorpusDelta, 'signature' | 'signerKeyId'>,
  privateKeyPem: string,
  signerKeyId: string,
  algorithm: 'RSA-SHA256' | 'sha256' = 'RSA-SHA256',
): CorpusDelta {
  const sign = createSign(algorithm);
  sign.update(deltaCanonicalBytes(delta));
  const sig = sign.sign(privateKeyPem);
  return { ...delta, signature: '0x' + sig.toString('hex'), signerKeyId };
}

export function verifyCorpusDeltaSignature(
  delta: CorpusDelta,
  publicKeyPem: string,
  algorithm: 'RSA-SHA256' | 'sha256' = 'RSA-SHA256',
): boolean {
  if (!delta.signature) return false;
  const verify = createVerify(algorithm);
  const { signature: _sig, signerKeyId: _sk, ...rest } = delta;
  verify.update(deltaCanonicalBytes(rest));
  return verify.verify(publicKeyPem, Buffer.from(delta.signature.slice(2), 'hex'));
}

export function corpusDeltaSha256(delta: CorpusDelta): string {
  const hash = createHash('sha256');
  hash.update(deltaCanonicalBytes(delta));
  return hash.digest('hex');
}

export function serializeCorpusDelta(delta: CorpusDelta): CorpusDeltaFileShape {
  return {
    ...delta,
    addedRecords: delta.addedRecords.map(eventToDisk),
  };
}

export function parseCorpusDelta(raw: CorpusDeltaFileShape): CorpusDelta {
  return {
    ...raw,
    addedRecords: raw.addedRecords.map(eventFromDisk),
  };
}

function eventToDisk(e: ProductionCorpusEvent): ProductionCorpusEventOnDisk {
  const out = { ...e } as unknown as Record<string, unknown>;
  delete out.embeddings;
  return {
    ...out,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: uint8ToHex(e.embeddings.query),
      perTruth: Object.fromEntries(Array.from(e.embeddings.perTruth.entries()).map(([k, v]) => [k, uint8ToHex(v)])),
      perNegative: Object.fromEntries(Array.from(e.embeddings.perNegative.entries()).map(([k, v]) => [k, uint8ToHex(v)])),
    },
  } as unknown as ProductionCorpusEventOnDisk;
}

function eventFromDisk(e: ProductionCorpusEventOnDisk): ProductionCorpusEvent {
  return {
    ...e,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: hexToUint8(e.embeddings.query),
      perTruth: new Map(Object.entries(e.embeddings.perTruth).map(([k, v]) => [k, hexToUint8(v)])),
      perNegative: new Map(Object.entries(e.embeddings.perNegative).map(([k, v]) => [k, hexToUint8(v)])),
    },
  };
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'undefined') return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (value instanceof Uint8Array) return JSON.stringify(uint8ToHex(value));
  if (value instanceof Map) {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of value) obj[String(k)] = v;
    return canonicalJson(obj);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
}

function uint8ToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function hexToUint8(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('hexToUint8: odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
