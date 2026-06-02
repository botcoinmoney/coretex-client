/**
 * Canonical bridge from a logical-corpus delta (the output of the live-update generator
 * `scripts/lib/evolve-corpus.mjs`) to production-corpus event additions ready for
 * `buildCorpusDelta(...).additions`.
 *
 * The mapping mirrors the one in `scripts/lib/build-v2-production-corpus.mjs` so the events
 * a churn epoch ADDS are byte-shape-compatible with events the genesis bridge built. Putting
 * this in `packages/cortex` removes the largest piece of product logic that lived in
 * calibration scripts; the harness is now just CLI plumbing + the embedding step.
 *
 * Embeddings are passed PRE-COMPUTED (`addedDocEmbeddings`, `addedQueryEmbeddings` as Maps of
 * int8-encoded Uint8Array). The package cannot spawn the Python bi-encoder runner; the
 * harness owns that step and feeds the int8 bytes in.
 */
import type { ProductionCorpus, ProductionCorpusEvent, ProductionCorpusFamily, CorpusSplit, RelationAnnotation, HardNegativeRecord, RelationEdgeType, HardNegativeCategory } from '../eval/retrieval-corpus.js';
import { assertGradedRelevance, splitForRecord } from '../eval/retrieval-corpus.js';

export interface LogicalDeltaDoc {
  readonly id: string;
  readonly lane: string;
  readonly kind?: string;
  readonly text: string;
  readonly timestamp?: string;
  readonly currentStaleFlag?: boolean;
  readonly aspectTags?: readonly string[];
  readonly entityIds?: readonly string[];
  readonly lifecycleState?: string;
  readonly lifecycleScope?: string;
  readonly liveUpdateEpoch?: number;
  readonly shape?: string;
}

export interface LogicalDeltaRelation {
  readonly src: string;
  readonly dst: string;
  readonly type: string;
  readonly label?: string;
}

export interface LogicalDeltaQrel {
  readonly docId: string;
  readonly relevance: number;
  readonly role?: string;
}

export interface LogicalDeltaHardNeg {
  readonly docId: string;
  readonly category?: string;
}

export interface LogicalDeltaQuery {
  readonly id: string;
  readonly lane: string;
  readonly family: string;
  readonly queryText: string;
  readonly qrels?: readonly LogicalDeltaQrel[];
  readonly hardNegatives?: readonly LogicalDeltaHardNeg[];
  readonly band?: string;
  readonly subjectEntityId?: string;
  readonly ownerEntityId?: string;
  readonly ownerScoped?: boolean;
  readonly liveUpdateEpoch?: number;
}

export interface LogicalDelta {
  readonly epoch: number;
  readonly seed: string;
  readonly churnFraction: number;
  readonly addedDocs: readonly LogicalDeltaDoc[];
  readonly addedRelations: readonly LogicalDeltaRelation[];
  readonly addedQueries: readonly LogicalDeltaQuery[];
  readonly churnedSubjects: readonly string[];
  readonly liveChurnRate: number;
}

export interface BiEncoderPin {
  readonly modelId: string;
  readonly revision: string;
  readonly layout: { readonly dim: number; readonly quantization: string; readonly headerBytes?: number };
}

export interface BridgeLogicalDeltaOptions {
  readonly previousCorpus: ProductionCorpus;
  readonly logicalDelta: LogicalDelta;
  /** Pre-computed int8-encoded query-side embeddings, keyed by logical doc id (NOT mem_*). */
  readonly addedDocEmbeddings: ReadonlyMap<string, Uint8Array>;
  /** Pre-computed int8-encoded query embeddings, keyed by logical query id. */
  readonly addedQueryEmbeddings: ReadonlyMap<string, Uint8Array>;
  /** Pinned bi-encoder model/revision/layout — must match previousCorpus.biEncoder*. */
  readonly biEncoder: BiEncoderPin;
}

const memId = (id: string): string => `mem_${id}`;
const legacyLiveTailMemId = (id: string): string => `zz_mem_${id}`;

function epochKey(epoch: number): string {
  if (!Number.isInteger(epoch) || epoch < 0) throw new Error(`live tail epoch must be a non-negative integer: ${epoch}`);
  return String(epoch).padStart(12, '0');
}

function epochFromLogicalId(id: string): number | null {
  const m = /^[dq]_e(\d+)_/.exec(id);
  if (!m) return null;
  const epoch = Number(m[1]);
  return Number.isInteger(epoch) && epoch >= 0 ? epoch : null;
}

const liveTailMemId = (id: string, epoch: number): string => `zz_e${epochKey(epoch)}_mem_${id}`;
const liveTailQueryId = (id: string, epoch: number): string => `zz_e${epochKey(epoch)}_q_${id}`;

function possibleLiveTailMemIds(id: string): string[] {
  const epoch = epochFromLogicalId(id);
  return [
    ...(epoch !== null ? [liveTailMemId(id, epoch)] : []),
    legacyLiveTailMemId(id),
  ];
}

function productionMemIdForAddedDoc(doc: LogicalDeltaDoc): string {
  return doc.liveUpdateEpoch !== undefined ? liveTailMemId(doc.id, doc.liveUpdateEpoch) : memId(doc.id);
}

function productionQueryIdForAddedQuery(query: LogicalDeltaQuery): string {
  return query.liveUpdateEpoch !== undefined ? liveTailQueryId(query.id, query.liveUpdateEpoch) : query.id;
}

function previousMemoryEventForDocId(previousCorpus: ProductionCorpus, docId: string): ProductionCorpusEvent | undefined {
  const staticEvent = previousCorpus.byId.get(memId(docId));
  if (staticEvent) return staticEvent;
  for (const id of possibleLiveTailMemIds(docId)) {
    const liveEvent = previousCorpus.byId.get(id);
    if (liveEvent) return liveEvent;
  }
  return undefined;
}

function productionMemIdForRelationTarget(
  previousCorpus: ProductionCorpus,
  addedProductionIdsByDocId: ReadonlyMap<string, string>,
  docId: string,
): string {
  const added = addedProductionIdsByDocId.get(docId);
  if (added) return added;
  for (const id of possibleLiveTailMemIds(docId)) if (previousCorpus.byId.has(id)) return id;
  return memId(docId);
}

const PROVENANCE = { source: 'synthetic_challenge', sourceHash: '0x' + '00'.repeat(32) } as const;

/**
 * Canonical V2 family bucketing — same as buildV2ProductionCorpus.bucket. Logical families
 * (temporal_update, multi_session_bridge, …) collapse into ProductionCorpusFamily buckets.
 */
export function bucketLogicalFamily(f: string): ProductionCorpusFamily {
  if (f === 'temporal_update') return 'temporal';
  if (f === 'multi_session_bridge' || f === 'causal_memory_chain' || f === 'decision_provenance') return 'multi_hop_relation';
  if (f === 'conflict_lifecycle') return 'conflict_lifecycle';
  if (f === 'aspect_constraint') return 'aspect_constraint';
  if (f === 'coreference_resolution') return 'coreference';
  return 'near_collision';
}

/**
 * Resolve a doc id to {text, isCurrent} by looking in the live-update added docs first,
 * then falling back to the previousCorpus memory-doc event's truthDocuments[0].
 */
function resolveDocMeta(
  docId: string,
  addedDocs: ReadonlyMap<string, LogicalDeltaDoc>,
  previousCorpus: ProductionCorpus,
): { text: string; isCurrent: boolean } | null {
  const added = addedDocs.get(docId);
  if (added) {
    return { text: added.text, isCurrent: added.currentStaleFlag === false ? false : true };
  }
  const memEv = previousMemoryEventForDocId(previousCorpus, docId);
  if (memEv && memEv.truthDocuments.length > 0) {
    const t = memEv.truthDocuments[0]!;
    return { text: t.text, isCurrent: t.isCurrent !== false };
  }
  return null;
}

/**
 * Resolve a doc id's int8 embedding bytes from either the per-epoch addedDocEmbeddings map
 * OR the previousCorpus's existing memory-doc event's perTruth map.
 */
function resolveDocEmbeddingBytes(
  docId: string,
  addedDocEmbeddings: ReadonlyMap<string, Uint8Array>,
  previousCorpus: ProductionCorpus,
): Uint8Array | null {
  const added = addedDocEmbeddings.get(docId);
  if (added) return added;
  const memEv = previousMemoryEventForDocId(previousCorpus, docId);
  const fromCorpus = memEv?.embeddings?.perTruth?.get(docId);
  return fromCorpus ?? null;
}

/**
 * Convert a `LogicalDelta` to `ProductionCorpusEvent[]` additions suitable for
 * `buildCorpusDelta({previousCorpus, additions: …}).` Performs the canonical V2 mapping:
 *
 *   - each added doc → one `mem_<doc.id>` event with split=train_visible, qrels=[{doc.id, 1.0}],
 *     relations from `addedRelations.filter(r.src === doc.id)`, perTruth=Map(doc.id → docEmb)
 *   - each added query → one event with split=splitForRecord(q.id, previousCorpus.corpusEpoch),
 *     truthDocuments resolved from qrels (added-first, then previousCorpus fallback),
 *     hardNegatives resolved similarly, perTruth + perNegative pointing at resolved int8 bytes,
 *     family = bucketLogicalFamily(q.family), logicalFamily preserved verbatim
 *
 * Hard-fails if a truth/hard-neg doc id can't be resolved in either the delta or the
 * previousCorpus (signals corrupted live-update logical delta).
 */
export function bridgeLogicalDeltaToProductionEvents(
  opts: BridgeLogicalDeltaOptions,
): ProductionCorpusEvent[] {
  const { previousCorpus, logicalDelta, addedDocEmbeddings, addedQueryEmbeddings, biEncoder } = opts;
  if (biEncoder.modelId !== previousCorpus.biEncoderModelId || biEncoder.revision !== previousCorpus.biEncoderRevision) {
    throw new Error(`bridgeLogicalDeltaToProductionEvents: biEncoder pin mismatch — opts ${biEncoder.modelId}@${biEncoder.revision} vs previousCorpus ${previousCorpus.biEncoderModelId}@${previousCorpus.biEncoderRevision}`);
  }
  const addedDocsById = new Map(logicalDelta.addedDocs.map((d) => [d.id, d] as const));
  const addedProductionIdsByDocId = new Map(logicalDelta.addedDocs.map((d) => [d.id, productionMemIdForAddedDoc(d)] as const));
  const relsBySrc = new Map<string, LogicalDeltaRelation[]>();
  for (const r of logicalDelta.addedRelations) {
    if (!relsBySrc.has(r.src)) relsBySrc.set(r.src, []);
    relsBySrc.get(r.src)!.push(r);
  }

  const events: ProductionCorpusEvent[] = [];
  const layout = previousCorpus.biEncoderRetrievalKeyLayout;

  // mem_* events (train_visible) for every added doc
  for (const d of logicalDelta.addedDocs) {
    const e = addedDocEmbeddings.get(d.id);
    if (!e) throw new Error(`bridgeLogicalDeltaToProductionEvents: missing addedDocEmbeddings entry for ${d.id}`);
    const memEvent: ProductionCorpusEvent = {
      id: productionMemIdForAddedDoc(d),
      family: 'near_collision' as ProductionCorpusFamily,
      domain: d.lane,
      split: 'train_visible' as CorpusSplit,
      queryText: d.text,
      truthDocuments: [{ id: d.id, text: d.text, isCurrent: d.currentStaleFlag === false ? false : true,
        ...(d.aspectTags && d.aspectTags.length > 0 ? { aspectTags: [...d.aspectTags] } : {}) }],
      hardNegatives: [],
      qrels: [{ documentId: d.id, relevance: assertGradedRelevance(1.0, `${productionMemIdForAddedDoc(d)} qrel`) }],
      protected: false,
      relations: (relsBySrc.get(d.id) ?? []).map((r): RelationAnnotation => ({
        other_id: productionMemIdForRelationTarget(previousCorpus, addedProductionIdsByDocId, r.dst),
        edgeType: r.type as RelationEdgeType,
        ...(r.label ? { label: r.label } : {}),
      })),
      ...(d.entityIds && d.entityIds.length > 0 ? { entityIds: [...d.entityIds] } : {}),
      provenance: PROVENANCE,
      embeddings: { modelId: biEncoder.modelId, revision: biEncoder.revision, layout, query: e,
        perTruth: new Map([[d.id, e]]), perNegative: new Map() },
    };
    events.push(memEvent);
  }

  // query events for every added query
  for (const q of logicalDelta.addedQueries) {
    const qe = addedQueryEmbeddings.get(q.id);
    if (!qe) throw new Error(`bridgeLogicalDeltaToProductionEvents: missing addedQueryEmbeddings entry for ${q.id}`);
    const truths = (q.qrels ?? []).filter((r) => r.relevance > 0).map((r) => {
      const meta = resolveDocMeta(r.docId, addedDocsById, previousCorpus);
      if (!meta) throw new Error(`bridgeLogicalDeltaToProductionEvents: missing truth doc ${r.docId} for query ${q.id}`);
      return { id: r.docId, text: meta.text, isCurrent: meta.isCurrent };
    });
    const negs = (q.hardNegatives ?? []).map((n) => {
      const meta = resolveDocMeta(n.docId, addedDocsById, previousCorpus);
      if (!meta) throw new Error(`bridgeLogicalDeltaToProductionEvents: missing hard-neg doc ${n.docId} for query ${q.id}`);
      const out: HardNegativeRecord = { id: n.docId, text: meta.text, ...(n.category ? { category: n.category as HardNegativeCategory } : {}) };
      return out;
    });
    const perTruthEntries: [string, Uint8Array][] = [];
    for (const t of truths) {
      const bytes = resolveDocEmbeddingBytes(t.id, addedDocEmbeddings, previousCorpus);
      if (!bytes) throw new Error(`bridgeLogicalDeltaToProductionEvents: missing truth doc embedding ${t.id} for query ${q.id}`);
      perTruthEntries.push([t.id, bytes]);
    }
    const perNegativeEntries: [string, Uint8Array][] = [];
    for (const n of negs) {
      const bytes = resolveDocEmbeddingBytes(n.id, addedDocEmbeddings, previousCorpus);
      if (!bytes) throw new Error(`bridgeLogicalDeltaToProductionEvents: missing hard-neg embedding ${n.id} for query ${q.id}`);
      perNegativeEntries.push([n.id, bytes]);
    }
    const bucketed = bucketLogicalFamily(q.family);
    const eventId = productionQueryIdForAddedQuery(q);
    const qEventBase = {
      id: eventId,
      family: bucketed,
      domain: q.lane,
      split: splitForRecord(eventId, previousCorpus.corpusEpoch) as CorpusSplit,
      queryText: q.queryText,
      truthDocuments: truths,
      hardNegatives: negs,
      qrels: (q.qrels ?? []).map((r) => ({ documentId: r.docId, relevance: assertGradedRelevance(r.relevance, `${q.id} qrel ${r.docId}`) })),
      protected: false,
      relations: [],
      provenance: PROVENANCE,
      embeddings: { modelId: biEncoder.modelId, revision: biEncoder.revision, layout, query: qe,
        perTruth: new Map(perTruthEntries), perNegative: new Map(perNegativeEntries) },
    };
    const qEvent: ProductionCorpusEvent = Object.assign(
      qEventBase,
      q.family ? { logicalFamily: q.family } : {},
      q.band ? { band: q.band } : {},
      q.ownerEntityId !== undefined ? { ownerEntityId: q.ownerEntityId, ownerScoped: q.ownerScoped !== false } : {},
      q.subjectEntityId !== undefined ? { subjectEntityId: q.subjectEntityId } : {},
    ) as ProductionCorpusEvent;
    if (bucketed === 'temporal') {
      (qEvent as { temporal?: unknown }).temporal = { validFromEpoch: 1, validUntilEpoch: Number.MAX_SAFE_INTEGER, currentStaleFlag: false };
    }
    events.push(qEvent);
  }

  return events;
}
