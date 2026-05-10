/**
 * CoreTex production corpus — retrieval-benchmark shape.
 *
 * Spec: specs/corpus_retrieval_v0.md.
 *
 * This is the production corpus shape. The legacy slot-fill ProductionCorpus
 * (event ledger with structural-commitment scoring) is gone. The retrieval
 * corpus carries graded qrels, splits, embeddings, and provenance.
 *
 * Loading and root computation are deterministic and reproducible from the
 * pinned bundle.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export type ProductionCorpusFamily =
  | 'near_collision'
  | 'temporal'
  | 'long_horizon'
  | 'multi_hop_relation';

export type CorpusSplit = 'train_visible' | 'calibration' | 'eval_hidden' | 'canary';

export type RelationEdgeType =
  | 'supports'
  | 'supersedes'
  | 'coreference_of'
  | 'causes'
  | 'derived_from'
  | 'co_occurs_with';

export type GradedRelevance = 0.0 | 0.2 | 0.4 | 0.6 | 0.8 | 1.0;

export interface TruthDocument {
  readonly id: string;
  readonly text: string;
  readonly isCurrent: boolean;
}

export interface QrelEntry {
  readonly documentId: string;
  readonly relevance: GradedRelevance;
}

export interface TemporalAnnotation {
  readonly validFromEpoch: number;
  readonly validUntilEpoch: number;     // 2^53-1 == open
  readonly currentStaleFlag: boolean;
  readonly supersedes_id?: string;
  readonly superseded_by_id?: string;
}

export interface RelationAnnotation {
  readonly other_id: string;
  readonly edgeType: RelationEdgeType;
}

export type ProvenanceSource = 'dataset_v2_direct' | 'hf_export' | 'synthetic_challenge';

export interface Provenance {
  readonly source: ProvenanceSource;
  readonly s3Key?: string;
  readonly challengeSeed?: string;       // hex-encoded uint128
  readonly challengeId?: string;
  readonly attemptId?: string;
  readonly sessionId?: string;
  readonly pairId?: string;
  readonly questionId?: string;
  readonly sourceHash: string;           // bytes32 hex
}

export interface RetrievalKeyLayout {
  readonly dim: number;
  readonly quantization: 'int8' | 'bf16';
  readonly headerBytes: number;
}

export interface EmbeddingPayload {
  readonly modelId: string;
  readonly revision: string;
  readonly layout: RetrievalKeyLayout;
  /** Per-record query embedding bytes (length === dim × bytesPerScalar). */
  readonly query: Uint8Array;
  /** Per truth document id → embedding bytes. */
  readonly perTruth: ReadonlyMap<string, Uint8Array>;
  /** Per hard-negative document id → embedding bytes. */
  readonly perNegative: ReadonlyMap<string, Uint8Array>;
}

export interface ProductionCorpusEvent {
  readonly id: string;
  readonly family: ProductionCorpusFamily;
  readonly domain: string;
  readonly split: CorpusSplit;
  readonly queryText: string;
  readonly truthDocuments: readonly TruthDocument[];
  readonly hardNegatives: readonly { readonly id: string; readonly text: string }[];
  readonly qrels: readonly QrelEntry[];
  readonly protected: boolean;
  readonly temporal?: TemporalAnnotation;
  readonly relations?: readonly RelationAnnotation[];
  readonly provenance: Provenance;
  readonly embeddings: EmbeddingPayload;
}

export interface ProductionCorpus {
  readonly events: readonly ProductionCorpusEvent[];
  readonly byId: ReadonlyMap<string, ProductionCorpusEvent>;
  readonly corpusRoot: string;            // bytes32 hex
  readonly corpusEpoch: number;
  readonly biEncoderRevision: string;
  readonly biEncoderModelId: string;
  readonly biEncoderRetrievalKeyLayout: RetrievalKeyLayout;
  readonly labelingModelRevision: string;
  readonly labelingModelId: string;
}

// ─── Split ratios ─────────────────────────────────────────────────────────────

export interface SplitRatios {
  readonly trainVisiblePct: number;
  readonly calibrationPct: number;
  readonly evalHiddenPct: number;
  readonly canaryPct: number;
}

export const DEFAULT_SPLIT_RATIOS: SplitRatios = {
  trainVisiblePct: 70,
  calibrationPct: 10,
  evalHiddenPct: 15,
  canaryPct: 5,
};

/**
 * Deterministic split for a record id at a given corpus epoch. Stable across
 * deltas so a record's split never changes.
 */
export function splitForRecord(id: string, corpusEpoch: number, ratios: SplitRatios = DEFAULT_SPLIT_RATIOS): CorpusSplit {
  const total = ratios.trainVisiblePct + ratios.calibrationPct + ratios.evalHiddenPct + ratios.canaryPct;
  if (total !== 100) throw new Error(`SplitRatios must sum to 100, got ${total}`);
  const enc = new TextEncoder();
  const u64 = new Uint8Array(8);
  let v = BigInt(corpusEpoch);
  for (let i = 7; i >= 0; i--) {
    u64[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const idBytes = enc.encode(id);
  const buf = new Uint8Array(idBytes.length + 8);
  buf.set(idBytes, 0);
  buf.set(u64, idBytes.length);
  const digest = keccak256(buf);
  // first 8 bytes → uint64
  let h = 0n;
  for (let i = 0; i < 8; i++) h = (h << 8n) | BigInt(digest[i]!);
  const bucket = Number(h % 100n);
  if (bucket < ratios.trainVisiblePct) return 'train_visible';
  if (bucket < ratios.trainVisiblePct + ratios.calibrationPct) return 'calibration';
  if (bucket < ratios.trainVisiblePct + ratios.calibrationPct + ratios.evalHiddenPct) return 'eval_hidden';
  return 'canary';
}

// ─── Canonical hashing ────────────────────────────────────────────────────────

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'undefined') return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'string') return JSON.stringify(value);
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

/**
 * Compute the canonical corpus root by Merkleizing per-record canonical-JSON
 * leaves under keccak256.
 */
export function computeCorpusRoot(events: readonly ProductionCorpusEvent[]): string {
  if (events.length === 0) return '0x' + '00'.repeat(32);
  const sorted = [...events].sort((a, b) => a.id.localeCompare(b.id));
  let leaves = sorted.map((event) => {
    // Canonical-JSON of the full event (embeddings serialize as hex strings via canonicalJson).
    const enc = new TextEncoder();
    return keccak256(enc.encode(canonicalJson(event)));
  });
  const zero = new Uint8Array(32);
  let n = 1;
  while (n < leaves.length) n <<= 1;
  while (leaves.length < n) leaves.push(zero);
  while (leaves.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const pair = new Uint8Array(64);
      pair.set(leaves[i]!, 0);
      pair.set(leaves[i + 1]!, 32);
      next.push(keccak256(pair));
    }
    leaves = next;
  }
  return bytesToHex(leaves[0]!);
}

// ─── Loader ───────────────────────────────────────────────────────────────────

export interface CorpusFileShape {
  readonly schemaVersion: 'coretex.production-corpus.v1';
  readonly corpusEpoch: number;
  readonly biEncoder: { readonly modelId: string; readonly revision: string; readonly layout: RetrievalKeyLayout };
  readonly labelingModel: { readonly modelId: string; readonly revision: string };
  readonly events: readonly ProductionCorpusEventOnDisk[];
  readonly corpusRoot: string;
}

export interface ProductionCorpusEventOnDisk
  extends Omit<ProductionCorpusEvent, 'embeddings' | 'hardNegatives' | 'qrels' | 'truthDocuments' | 'relations'> {
  readonly truthDocuments: readonly TruthDocument[];
  readonly hardNegatives: readonly { readonly id: string; readonly text: string }[];
  readonly qrels: readonly QrelEntry[];
  readonly relations?: readonly RelationAnnotation[];
  readonly embeddings: {
    readonly modelId: string;
    readonly revision: string;
    readonly layout: RetrievalKeyLayout;
    readonly query: string;                        // hex
    readonly perTruth: Record<string, string>;     // id -> hex
    readonly perNegative: Record<string, string>;  // id -> hex
  };
}

export function loadProductionCorpus(path: string): ProductionCorpus {
  if (!existsSync(path)) throw new Error(`production corpus file not found: ${path}`);
  const raw = JSON.parse(readFileSync(path, 'utf8')) as CorpusFileShape;
  if (raw.schemaVersion !== 'coretex.production-corpus.v1') {
    throw new Error(`production corpus has unsupported schemaVersion: ${raw.schemaVersion}`);
  }
  const events: ProductionCorpusEvent[] = raw.events.map((e) => ({
    ...e,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: hexToUint8(e.embeddings.query),
      perTruth: new Map(Object.entries(e.embeddings.perTruth).map(([k, v]) => [k, hexToUint8(v)])),
      perNegative: new Map(Object.entries(e.embeddings.perNegative).map(([k, v]) => [k, hexToUint8(v)])),
    },
  }));
  const computed = computeCorpusRoot(events);
  if (computed.toLowerCase() !== raw.corpusRoot.toLowerCase()) {
    throw new Error(`production corpus root mismatch: expected ${raw.corpusRoot} got ${computed}`);
  }
  // Verify per-event split assignment is stable.
  for (const e of events) {
    const expected = splitForRecord(e.id, raw.corpusEpoch);
    if (e.split !== expected) {
      throw new Error(`production corpus event ${e.id} declared split ${e.split} but splitForRecord returned ${expected}`);
    }
  }
  // Verify embeddings model id/revision matches the bundle bi-encoder.
  for (const e of events) {
    if (e.embeddings.modelId !== raw.biEncoder.modelId || e.embeddings.revision !== raw.biEncoder.revision) {
      throw new Error(`production corpus event ${e.id} embeddings model mismatch`);
    }
  }
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: raw.corpusRoot.toLowerCase(),
    corpusEpoch: raw.corpusEpoch,
    biEncoderModelId: raw.biEncoder.modelId,
    biEncoderRevision: raw.biEncoder.revision,
    biEncoderRetrievalKeyLayout: raw.biEncoder.layout,
    labelingModelId: raw.labelingModel.modelId,
    labelingModelRevision: raw.labelingModel.revision,
  };
}

export function serializeProductionCorpus(corpus: ProductionCorpus): CorpusFileShape {
  const events: ProductionCorpusEventOnDisk[] = corpus.events.map((e) => ({
    id: e.id,
    family: e.family,
    domain: e.domain,
    split: e.split,
    queryText: e.queryText,
    truthDocuments: e.truthDocuments,
    hardNegatives: e.hardNegatives,
    qrels: e.qrels,
    protected: e.protected,
    ...(e.temporal !== undefined ? { temporal: e.temporal } : {}),
    ...(e.relations !== undefined ? { relations: e.relations } : {}),
    provenance: e.provenance,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: uint8ToHex(e.embeddings.query),
      perTruth: Object.fromEntries(Array.from(e.embeddings.perTruth.entries()).map(([k, v]) => [k, uint8ToHex(v)])),
      perNegative: Object.fromEntries(Array.from(e.embeddings.perNegative.entries()).map(([k, v]) => [k, uint8ToHex(v)])),
    },
  }));
  return {
    schemaVersion: 'coretex.production-corpus.v1',
    corpusEpoch: corpus.corpusEpoch,
    biEncoder: {
      modelId: corpus.biEncoderModelId,
      revision: corpus.biEncoderRevision,
      layout: corpus.biEncoderRetrievalKeyLayout,
    },
    labelingModel: {
      modelId: corpus.labelingModelId,
      revision: corpus.labelingModelRevision,
    },
    events,
    corpusRoot: corpus.corpusRoot,
  };
}

// ─── SHA-256 helper ───────────────────────────────────────────────────────────

export function corpusFileSha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export { canonicalJson as canonicalJsonForCorpus };
