/**
 * CoreTex production retrieval scorer.
 *
 * Spec: specs/retrieval_benchmark_v0.md.
 *
 * Replaces the legacy slot-fill `scoreProductionState` /
 * `evaluateStateWithReranker` path. The reward law is `nDCG@10` over the
 * per-epoch hidden query pack, retrieval-dominant, with sanity, temporal,
 * multi-hop, and abstention sub-metrics.
 */

import type { CortexState, Patch } from '../state/index.js';
import { applyPatch } from '../state/patch.js';
import { keccak256 } from '../state/keccak256.js';
import { decodeSubstrate, type DecodedSubstrate } from '../substrate/retrieval-decoder.js';
import { biEncoderModelIdHash } from '../substrate/retrieval-decoder.js';
import { structuralValidity } from '../substrate/structural-validity.js';
import type { CrossEncoderReranker } from './reranker.js';
import type { BiEncoder } from './bi-encoder.js';
import { cosineSimilarity, dequantize } from './bi-encoder.js';
import type {
  ProductionCorpus,
  ProductionCorpusEvent,
  RetrievalKeyLayout,
} from './retrieval-corpus.js';
import type { QueryPack } from './hidden-query-pack.js';
import {
  ndcgAtK,
  mrrAtK,
  recallAtK,
  temporalCurrentStaleHit,
  temporalCurrentStaleAccuracy,
  multiHopRelationHit,
  multiHopRelationRecallAtK,
  abstentionAccuracy,
} from './ir-metrics.js';

export interface CompositeWeights {
  readonly w_retrieval: number;
  readonly w_temporal: number;
  readonly w_relation_recall: number;
  readonly w_abstention: number;
  readonly w_structural_sanity: number;
}

export const DEFAULT_COMPOSITE_WEIGHTS: CompositeWeights = {
  w_retrieval: 0.75,
  w_temporal: 0.08,
  w_relation_recall: 0.07,
  w_abstention: 0.05,
  w_structural_sanity: 0.05,
};

export function assertValidWeights(w: CompositeWeights): void {
  const sum = w.w_retrieval + w.w_temporal + w.w_relation_recall + w.w_abstention + w.w_structural_sanity;
  if (Math.abs(sum - 1) > 1e-6) throw new Error(`composite weights must sum to 1.0 (got ${sum})`);
  if (w.w_retrieval < 0.7 - 1e-9) throw new Error(`w_retrieval must be >= 0.70 (got ${w.w_retrieval})`);
  if (w.w_structural_sanity > 0.10 + 1e-9)
    throw new Error(`w_structural_sanity must be <= 0.10 (got ${w.w_structural_sanity})`);
  if (w.w_temporal <= 0 || w.w_relation_recall <= 0 || w.w_abstention <= 0) {
    throw new Error('w_temporal, w_relation_recall, w_abstention must be > 0');
  }
}

export interface ScoringOptions {
  readonly weights: CompositeWeights;
  readonly biEncoder: BiEncoder;
  readonly reranker: CrossEncoderReranker;
  readonly retrievalKeyLayout: RetrievalKeyLayout;
  readonly biEncoderHash: string;          // bundle-pinned 4-byte hash hex
  readonly relationHopBudget: number;      // calibrated, typ. 2-3
  readonly abstentionThreshold: number;    // calibrated
  readonly rerankerTopK: number;           // calibrated, e.g. 10
  readonly retrievalKeyTopK: number;       // calibrated, e.g. 50 from BGE-M3
}

export interface PerQueryBreakdown {
  readonly recordId: string;
  readonly family: string;
  readonly nDCG10: number;
  readonly mrr10: number;
  readonly recall10: number | null;
  readonly temporalHit: boolean | null;
  readonly multiHopHit: boolean | null;
  readonly abstentionHit: boolean | null;
  readonly top1Score: number;
}

export interface CompositeScore {
  readonly composite: number;
  readonly nDCG10: number;
  readonly mrr10: number;
  readonly recall10: number;
  readonly temporal: number;
  readonly multiHopRecall10: number;
  readonly abstention: number;
  readonly structuralValidity: number;
  readonly perQuery: readonly PerQueryBreakdown[];
}

export interface PatchEvalResult {
  readonly accepted: boolean;
  readonly reason?: string;
  readonly before: CompositeScore;
  readonly after: CompositeScore;
  readonly deltaPpm: number;
  readonly perFamilyDelta: Record<string, number>;
}

// ─── Scoring ─────────────────────────────────────────────────────────────────

/**
 * Score a single query against the substrate. The substrate provides
 * candidate retrieval-key vectors (top-k by cosine to the query embedding),
 * which are then reranked by the cross-encoder over (query, candidate-doc)
 * pairs from the corpus.
 */
export async function scoreSubstrateAgainstQuery(
  decoded: DecodedSubstrate,
  query: ProductionCorpusEvent,
  corpus: ProductionCorpus,
  opts: ScoringOptions,
): Promise<{
  ranked: readonly { documentId: string; relevance: number; rerankerScore: number; memorySlot: number | null }[];
  top1Score: number;
}> {
  // 1) Decode candidate retrieval keys → cosine similarity to query embedding.
  const queryVec = dequantize(query.embeddings.query, opts.retrievalKeyLayout);
  const candidates: { slotIndex: number; cosine: number; recordId: bigint; memorySlotIndex: number }[] = [];
  for (let s = 0; s < decoded.retrievalKeys.length; s++) {
    const key = decoded.retrievalKeys[s];
    if (!key) continue;
    if (key.modelIdHash.toLowerCase() !== opts.biEncoderHash.toLowerCase()) continue;
    const candVec = dequantize(key.quantizedBytes, opts.retrievalKeyLayout);
    const cos = cosineSimilarity(queryVec, candVec);
    // Find which memory slot points at this retrieval slot.
    let memSlotIdx = -1;
    let recordId = 0n;
    for (let m = 0; m < decoded.memoryIndex.length; m++) {
      const mem = decoded.memoryIndex[m];
      if (mem && mem.retrievalSlot === s && !mem.revoked) {
        memSlotIdx = m;
        recordId = mem.recordId;
        break;
      }
    }
    if (memSlotIdx < 0) continue;
    candidates.push({ slotIndex: s, cosine: cos, recordId, memorySlotIndex: memSlotIdx });
  }
  candidates.sort((a, b) => b.cosine - a.cosine);
  const topRetrieval = candidates.slice(0, opts.retrievalKeyTopK);

  // 2) Map each retrieval candidate's memory-slot record id back to a corpus
  //    record. We have to find any corpus record whose 128-bit truncated id
  //    matches the substrate's recordId. Production corpora carry this
  //    mapping in a per-record index; for the v1 scorer we accept any record
  //    whose stable id keccak256(id) low-128 matches.
  const allDocs: { documentId: string; recordId: bigint; text: string; memorySlot: number }[] = [];
  for (const c of topRetrieval) {
    for (const doc of resolveCorpusDocsForRecordId(c.recordId, corpus)) {
      allDocs.push({ documentId: doc.id, recordId: c.recordId, text: doc.text, memorySlot: c.memorySlotIndex });
    }
  }
  // Do not inject the query's own truth documents here. The ranked list must be
  // composed only of documents reachable through substrate retrieval keys;
  // otherwise an empty or wrong substrate can receive oracle-fed nDCG credit.

  // 3) Rerank with the cross-encoder.
  const pairs = allDocs.map((d) => ({ query: query.queryText, document: d.text }));
  const scores = pairs.length === 0 ? [] : await opts.reranker.score(pairs);
  const qrelById = new Map(query.qrels.map((q) => [q.documentId, q.relevance]));
  const ranked = allDocs
    .map((d, i) => ({
      documentId: d.documentId,
      memorySlot: d.memorySlot >= 0 ? d.memorySlot : null,
      rerankerScore: scores[i] ?? 0,
      relevance: qrelById.get(d.documentId) ?? 0,
    }))
    .sort((a, b) => b.rerankerScore - a.rerankerScore);

  const top1Score = ranked.length > 0 ? ranked[0]!.rerankerScore : 0;
  return { ranked, top1Score };
}

function resolveCorpusDocsForRecordId(
  recordId: bigint,
  corpus: ProductionCorpus,
): { id: string; text: string }[] {
  // Production corpus indexes records by stable string id. The substrate's
  // 128-bit recordId is the truncation of keccak256(id). For scoring, we
  // build the map lazily and cache it on the corpus by side-channel.
  const cache = recordIdIndexCache.get(corpus);
  if (cache) {
    const event = cache.get(recordId);
    if (!event) return [];
    return [...event.truthDocuments.map((d) => ({ id: d.id, text: d.text })),
            ...event.hardNegatives.map((n) => ({ id: n.id, text: n.text }))];
  }
  const built = new Map<bigint, ProductionCorpusEvent>();
  for (const e of corpus.events) {
    built.set(stableRecordIdFor(e.id), e);
  }
  recordIdIndexCache.set(corpus, built);
  const event = built.get(recordId);
  if (!event) return [];
  return [...event.truthDocuments.map((d) => ({ id: d.id, text: d.text })),
          ...event.hardNegatives.map((n) => ({ id: n.id, text: n.text }))];
}

const recordIdIndexCache = new WeakMap<ProductionCorpus, Map<bigint, ProductionCorpusEvent>>();

/**
 * Stable 128-bit substrate record id for a corpus event. Public so corpus
 * builders use the same mapping when constructing memory-index slots.
 */
export function stableRecordIdFor(id: string): bigint {
  // Lazy-loaded keccak from state.
  // We use the same keccak256 the substrate uses to keep the mapping aligned.
  const enc = new TextEncoder();
  const bytes = keccak256(enc.encode(`coretex:record:${id}`));
  let v = 0n;
  for (let i = 0; i < 16; i++) v = (v << 8n) | BigInt(bytes[i]!);
  return v;
}

/**
 * Score the substrate against the entire query pack. Returns the composite
 * score and per-query breakdown.
 */
export async function evaluateRetrievalBenchmarkState(
  state: CortexState,
  corpus: ProductionCorpus,
  pack: QueryPack,
  opts: ScoringOptions,
): Promise<CompositeScore> {
  assertValidWeights(opts.weights);
  const decoded = decodeSubstrate(state, {
    biEncoderModelIdHash: opts.biEncoderHash,
    retrievalKeyHeaderBytes: opts.retrievalKeyLayout.headerBytes,
  });
  const sv = structuralValidity(decoded);

  const perQuery: PerQueryBreakdown[] = [];
  const ndcgs: number[] = [];
  const mrrs: number[] = [];
  const recalls: number[] = [];
  const tempHits: (boolean | null)[] = [];
  const multiHits: (boolean | null)[] = [];
  const abstHits: (boolean | null)[] = [];

  // Build the relation graph once.
  const relGraph = new Map<number, number[]>();
  for (const e of decoded.relations) {
    const arr = relGraph.get(e.sourceSlot) ?? [];
    arr.push(e.targetSlot);
    relGraph.set(e.sourceSlot, arr);
  }

  for (const query of pack.events) {
    const isAbstentionProbe = query.truthDocuments.length === 0;
    const { ranked, top1Score } = await scoreSubstrateAgainstQuery(decoded, query, corpus, opts);

    // nDCG / MRR / Recall over reranked list.
    const idealRels = query.qrels.map((q) => q.relevance);
    const totalRel = query.qrels.filter((q) => q.relevance > 0).length;
    const ndcg = ndcgAtK(ranked, idealRels, opts.rerankerTopK);
    const mrr = mrrAtK(ranked, opts.rerankerTopK);
    const rec = recallAtK(ranked, totalRel, opts.rerankerTopK);

    let tempHit: boolean | null = null;
    if (query.family === 'temporal' && query.temporal) {
      const currentDoc = query.truthDocuments.find((d) => d.isCurrent);
      const staleDocs = query.truthDocuments.filter((d) => !d.isCurrent).map((d) => d.id);
      tempHit = temporalCurrentStaleHit(ranked, currentDoc?.id ?? null, staleDocs);
    }

    let multiHit: boolean | null = null;
    if (query.family === 'multi_hop_relation') {
      // Resolve candidate memory slots from the top-k retrieval candidates.
      const candidateSlots = ranked
        .slice(0, opts.rerankerTopK)
        .map((r) => r.memorySlot)
        .filter((s): s is number => s !== null);
      // Resolve answer memory slots: find memory-index slots whose recordId
      // matches any of the query's truth docs' record ids (proxied by the
      // corpus event's id).
      const truthEventIds = new Set<string>();
      if (query.relations && query.relations.length > 0) {
        for (const rel of query.relations) truthEventIds.add(rel.other_id);
      } else {
        truthEventIds.add(query.id);
      }
      const answerSlots = new Set<number>();
      for (let m = 0; m < decoded.memoryIndex.length; m++) {
        const slot = decoded.memoryIndex[m];
        if (!slot) continue;
        for (const eid of truthEventIds) {
          if (slot.recordId === stableRecordIdFor(eid)) answerSlots.add(m);
        }
      }
      multiHit = multiHopRelationHit(candidateSlots, answerSlots, relGraph, opts.relationHopBudget);
    }

    let abstHit: boolean | null = null;
    if (isAbstentionProbe) {
      abstHit = top1Score < opts.abstentionThreshold;
    }

    ndcgs.push(ndcg);
    mrrs.push(mrr);
    if (rec !== null) recalls.push(rec);
    tempHits.push(tempHit);
    multiHits.push(multiHit);
    abstHits.push(abstHit);

    perQuery.push({
      recordId: query.id,
      family: query.family,
      nDCG10: ndcg,
      mrr10: mrr,
      recall10: rec,
      temporalHit: tempHit,
      multiHopHit: multiHit,
      abstentionHit: abstHit,
      top1Score,
    });
  }

  const meanNdcg = ndcgs.length === 0 ? 0 : ndcgs.reduce((a, b) => a + b, 0) / ndcgs.length;
  const meanMrr = mrrs.length === 0 ? 0 : mrrs.reduce((a, b) => a + b, 0) / mrrs.length;
  const meanRec = recalls.length === 0 ? 0 : recalls.reduce((a, b) => a + b, 0) / recalls.length;
  const tempAcc = temporalCurrentStaleAccuracy(tempHits);
  const multiAcc = multiHopRelationRecallAtK(multiHits);
  const abstAcc = abstentionAccuracy(abstHits);

  const composite =
    opts.weights.w_retrieval * meanNdcg +
    opts.weights.w_temporal * tempAcc +
    opts.weights.w_relation_recall * multiAcc +
    opts.weights.w_abstention * abstAcc +
    opts.weights.w_structural_sanity * sv;

  return {
    composite: clamp01(composite),
    nDCG10: meanNdcg,
    mrr10: meanMrr,
    recall10: meanRec,
    temporal: tempAcc,
    multiHopRecall10: multiAcc,
    abstention: abstAcc,
    structuralValidity: sv,
    perQuery,
  };
}

export interface PatchAcceptanceFloors {
  readonly minImprovementPpm: number;
  readonly structuralFloor: number;
  readonly protectedRegressionFloor: number;
  readonly familyCatastrophicFloor: number;
}

export async function evaluateRetrievalBenchmarkPatch(
  parentState: CortexState,
  patch: Patch,
  corpus: ProductionCorpus,
  pack: QueryPack,
  opts: ScoringOptions,
  floors: PatchAcceptanceFloors,
): Promise<PatchEvalResult> {
  const before = await evaluateRetrievalBenchmarkState(parentState, corpus, pack, opts);
  const applied = applyPatch(parentState, patch);
  if (!applied.ok) {
    return {
      accepted: false,
      reason: `apply_failed:${applied.code}`,
      before,
      after: before,
      deltaPpm: 0,
      perFamilyDelta: {},
    };
  }
  const after = await evaluateRetrievalBenchmarkState(applied.state, corpus, pack, opts);

  if (after.structuralValidity < floors.structuralFloor) {
    return {
      accepted: false,
      reason: 'structural_validity_below_floor',
      before,
      after,
      deltaPpm: Math.round((after.composite - before.composite) * 1_000_000),
      perFamilyDelta: perFamilyDelta(before, after),
    };
  }

  // Per-record protected regression check.
  const beforeById = new Map(before.perQuery.map((q) => [q.recordId, q]));
  for (const q of after.perQuery) {
    const ev = corpus.byId.get(q.recordId);
    if (!ev || !ev.protected) continue;
    const prev = beforeById.get(q.recordId);
    if (!prev) continue;
    const drop = prev.nDCG10 - q.nDCG10;
    if (drop > floors.protectedRegressionFloor) {
      return {
        accepted: false,
        reason: `protected_regression:${q.recordId}`,
        before,
        after,
        deltaPpm: Math.round((after.composite - before.composite) * 1_000_000),
        perFamilyDelta: perFamilyDelta(before, after),
      };
    }
  }

  // Per-family catastrophic regression.
  const familyDelta = perFamilyDelta(before, after);
  for (const [family, deltaInfo] of Object.entries(familyDelta)) {
    void family;
    void deltaInfo;
  }
  const familyBefore = perFamilyMean(before);
  const familyAfter = perFamilyMean(after);
  for (const fam of Object.keys(familyBefore)) {
    const beforeVal = familyBefore[fam] ?? 0;
    const afterVal = familyAfter[fam] ?? 0;
    if (beforeVal > 0 && afterVal < floors.familyCatastrophicFloor * beforeVal) {
      return {
        accepted: false,
        reason: `family_catastrophic:${fam}`,
        before,
        after,
        deltaPpm: Math.round((after.composite - before.composite) * 1_000_000),
        perFamilyDelta: familyDelta,
      };
    }
  }

  const deltaPpm = Math.round((after.composite - before.composite) * 1_000_000);
  if (deltaPpm < floors.minImprovementPpm) {
    return {
      accepted: false,
      reason: 'no_retrieval_improvement',
      before,
      after,
      deltaPpm,
      perFamilyDelta: familyDelta,
    };
  }
  return { accepted: true, before, after, deltaPpm, perFamilyDelta: familyDelta };
}

function perFamilyMean(score: CompositeScore): Record<string, number> {
  const buckets = new Map<string, number[]>();
  for (const q of score.perQuery) {
    const arr = buckets.get(q.family) ?? [];
    arr.push(q.nDCG10);
    buckets.set(q.family, arr);
  }
  const out: Record<string, number> = {};
  for (const [k, vs] of buckets) {
    out[k] = vs.length === 0 ? 0 : vs.reduce((a, b) => a + b, 0) / vs.length;
  }
  return out;
}

function perFamilyDelta(before: CompositeScore, after: CompositeScore): Record<string, number> {
  const b = perFamilyMean(before);
  const a = perFamilyMean(after);
  const out: Record<string, number> = {};
  for (const k of new Set([...Object.keys(b), ...Object.keys(a)])) {
    out[k] = (a[k] ?? 0) - (b[k] ?? 0);
  }
  return out;
}

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}

export { biEncoderModelIdHash };
