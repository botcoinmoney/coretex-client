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
import {
  buildPublicCorpusIndex,
  firstStageCandidates,
  type PublicCorpusIndex,
} from './public-corpus-index.js';
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

/**
 * Canonical acceptance threshold in ppm. Combines the three bundle-
 * pinned terms that callers previously had to fold in manually:
 *
 *   threshold = minImprovementPpm + replayTolerancePpm + baselineVariancePpm
 *
 * Hosts wiring the per-patch evaluator pass the result here as
 * `thresholdPpm`. Centralizing this prevents call sites from forgetting
 * a term (replay tolerance + baseline variance must BOTH be on top of
 * minImprovement so that pack-luck advances within reranker-noise
 * range don't qualify).
 */
export function computeAcceptanceThresholdPpm(profile: {
  readonly patchAcceptanceFloors: { readonly minImprovementPpm: number };
  readonly replayTolerancePpm: number;
  readonly baselineVariancePpm?: number;
}): number {
  return profile.patchAcceptanceFloors.minImprovementPpm
       + profile.replayTolerancePpm
       + (profile.baselineVariancePpm ?? 0);
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

  // ─── v2-lens pipeline params (substrate-hardening Phase A) ───
  readonly firstStageTopK: number;             // calibrated per-stratum (Run 1)
  readonly lensTopK: number;                   // how many lens vectors contribute to stage-2 reweighting
  readonly lensWeight: number;                 // stage-2 lens bonus scale (Run 0)
  readonly anchorWeight: number;               // stage-2 anchor bonus scale (Run 0)
  readonly relationExpansionBudget: number;    // stage-2 relation BFS doc cap (Run 0)
  readonly temporalCurrentBoost: number;       // stage-2 temporal bonus (current truth)
  readonly temporalStaleSuppression: number;   // stage-2 temporal penalty (stale truth)
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
 * Score a single query against the substrate using the v2-lens pipeline.
 *
 * Spec: docs/CORETEX_SUBSTRATE_EXPANSION_HARDENING.md §3.
 *
 * Two-stage retrieval, substrate is the bias not the gate:
 *   Stage 1: blind BGE-M3 cosine over the full public corpus index →
 *            Top-`firstStageTopK` docs. Substrate-agnostic; same answer
 *            for every miner against a given query, including a miner
 *            with no submitted patch.
 *   Stage 2: substrate-driven bias. Lens vectors (RetrievalKeys), anchor
 *            exemplars (MemoryIndex), relation BFS expansion, temporal
 *            modulation. Adds bonuses to rerank scores; bonuses cannot
 *            manufacture docs from thin air — relation expansion only
 *            adds docs already in the public corpus, reachable via the
 *            decoder's domain-share-validated relation edges.
 *
 * Anti-cheat invariant: empty substrate → score = stage1 baseline. No
 * free oracle credit. The labeled corpus is never read by stage-1 (the
 * `firstStageCandidates` signature accepts only `PublicCorpusIndex`,
 * which contains no qrels or truth-as-answer-set).
 *
 * Pinned formula:
 *   substrateBonus(d)         = lensBonus(d) + anchorBonus(d) + temporalBonus(d)
 *   finalReorderingScore(d)   = rerankerScore(d) + substrateBonus(d)
 *
 * `max` over active lenses/anchors prevents miners from gaming by
 * stacking N colinear vectors. The decoder's lens-diversity floor
 * (substrate-hardening §6.4) closes the residual collapse case.
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
  const queryVec = dequantize(query.embeddings.query, opts.retrievalKeyLayout);
  const publicIndex = getOrBuildPublicIndex(corpus);

  // ─── Stage 1: substrate-agnostic BGE-M3 first-stage retrieval ────────────
  // Stage-1 output is substrate-agnostic — depends only on (queryVec,
  // publicIndex, K). The same query scored twice in a dual-pack flow
  // (parent vs candidate substrate) shares its Top-K. Cache per
  // (corpus, query.id, K) to amortize the ~600ms cosine sweep across all
  // patch evaluations within a pack. See substrate-hardening §6.7.
  const stage1Docs = getOrComputeStage1(corpus, query.id, opts.firstStageTopK, () =>
    firstStageCandidates(queryVec, publicIndex, opts.firstStageTopK),
  );

  // Resolve doc text for the reranker pairs (text lives in the labeled corpus).
  const docTextById = getOrBuildDocTextIndex(corpus);

  // Map: docId → { embedding, text, eventId, memorySlot, provenance }
  type CandidateRecord = {
    docId: string;
    embedding: Uint8Array;
    text: string;
    eventId: string;
    memorySlot: number | null; // anchor slot that brought it via stage-2 (if any)
    isCurrentTruth: boolean;
    isStaleTruth: boolean;
  };
  const pool = new Map<string, CandidateRecord>();

  for (const d of stage1Docs) {
    const text = docTextById.get(d.id);
    if (!text) continue; // skip if text is missing (shouldn't happen with a built index)
    pool.set(d.id, {
      docId: d.id,
      embedding: d.embedding,
      text,
      eventId: d.eventId,
      memorySlot: null,
      isCurrentTruth: false,
      isStaleTruth: false,
    });
  }

  // ─── Stage 2: substrate-driven candidate expansion via relations BFS ─────
  // Build an anchor-slot → corpus-event map once per scoring call.
  const corpusByRecordId = getOrBuildRecordIdIndex(corpus);
  const anchorSlotToEvent = new Map<number, ProductionCorpusEvent>();
  for (let m = 0; m < decoded.memoryIndex.length; m++) {
    const slot = decoded.memoryIndex[m];
    if (!slot || slot.revoked) continue;
    const ev = corpusByRecordId.get(slot.recordId);
    if (ev) anchorSlotToEvent.set(m, ev);
  }

  // Relation adjacency (sourceSlot → [targetSlot]). Decoder has already
  // dropped domain-share-failing edges (substrate-hardening §6.4).
  const relAdj = new Map<number, number[]>();
  for (const e of decoded.relations) {
    const arr = relAdj.get(e.sourceSlot) ?? [];
    arr.push(e.targetSlot);
    relAdj.set(e.sourceSlot, arr);
  }

  // BFS from active anchors up to `relationHopBudget` hops; add truth docs of
  // visited anchors to the pool until `relationExpansionBudget` is reached.
  let expansionAdded = 0;
  const visited = new Set<number>(anchorSlotToEvent.keys());
  let frontier: number[] = Array.from(visited);
  for (let hop = 0; hop < opts.relationHopBudget && expansionAdded < opts.relationExpansionBudget; hop++) {
    const next: number[] = [];
    for (const slot of frontier) {
      const neighbors = relAdj.get(slot) ?? [];
      for (const nbr of neighbors) {
        if (visited.has(nbr)) continue;
        visited.add(nbr);
        const ev = anchorSlotToEvent.get(nbr);
        if (!ev) continue;
        // Add this neighbor's truth docs to the pool.
        for (const td of ev.truthDocuments) {
          if (pool.has(td.id)) continue;
          const emb = ev.embeddings.perTruth.get(td.id);
          if (!emb) continue;
          pool.set(td.id, {
            docId: td.id,
            embedding: emb,
            text: td.text,
            eventId: ev.id,
            memorySlot: nbr,
            isCurrentTruth: td.isCurrent,
            isStaleTruth: !td.isCurrent,
          });
          expansionAdded++;
          if (expansionAdded >= opts.relationExpansionBudget) break;
        }
        next.push(nbr);
        if (expansionAdded >= opts.relationExpansionBudget) break;
      }
      if (expansionAdded >= opts.relationExpansionBudget) break;
    }
    frontier = next;
  }

  // Tag pool entries that match an active anchor directly with the anchor's slot.
  for (const [slot, ev] of anchorSlotToEvent) {
    for (const td of ev.truthDocuments) {
      const entry = pool.get(td.id);
      if (entry && entry.memorySlot === null) {
        entry.memorySlot = slot;
        entry.isCurrentTruth = td.isCurrent;
        entry.isStaleTruth = !td.isCurrent;
      }
    }
  }

  // ─── Stage 2 bonuses: lens, anchor, temporal ─────────────────────────────
  const activeLensVecs: Float32Array[] = [];
  for (let s = 0; s < decoded.retrievalKeys.length; s++) {
    const key = decoded.retrievalKeys[s];
    if (!key) continue;
    if (key.modelIdHash.toLowerCase() !== opts.biEncoderHash.toLowerCase()) continue;
    activeLensVecs.push(dequantize(key.quantizedBytes, opts.retrievalKeyLayout));
    if (activeLensVecs.length >= opts.lensTopK) break;
  }

  // Anchor truth embeddings (one per active anchor that has a current/sole truth).
  const anchorTruthVecs: Float32Array[] = [];
  for (const [, ev] of anchorSlotToEvent) {
    // Pick the current truth if any, else the first truth.
    const truth = ev.truthDocuments.find((t) => t.isCurrent) ?? ev.truthDocuments[0];
    if (!truth) continue;
    const emb = ev.embeddings.perTruth.get(truth.id);
    if (!emb) continue;
    anchorTruthVecs.push(dequantize(emb, opts.retrievalKeyLayout));
  }

  const isTemporalQuery = query.family === 'temporal';

  // Compute substrateBonus per pool entry.
  const candidates: { record: CandidateRecord; substrateBonus: number; docVec: Float32Array }[] = [];
  for (const record of pool.values()) {
    const docVec = dequantize(record.embedding, opts.retrievalKeyLayout);

    let lensMaxCos = 0;
    for (const lens of activeLensVecs) {
      const c = cosineSimilarity(docVec, lens);
      if (c > lensMaxCos) lensMaxCos = c;
    }
    const lensBonus = activeLensVecs.length > 0 ? opts.lensWeight * lensMaxCos : 0;

    let anchorMaxCos = 0;
    for (const av of anchorTruthVecs) {
      const c = cosineSimilarity(docVec, av);
      if (c > anchorMaxCos) anchorMaxCos = c;
    }
    const anchorBonus = anchorTruthVecs.length > 0 ? opts.anchorWeight * anchorMaxCos : 0;

    let temporalBonus = 0;
    if (isTemporalQuery) {
      if (record.isCurrentTruth) temporalBonus = opts.temporalCurrentBoost;
      else if (record.isStaleTruth) temporalBonus = -opts.temporalStaleSuppression;
    }

    candidates.push({ record, substrateBonus: lensBonus + anchorBonus + temporalBonus, docVec });
  }

  if (candidates.length === 0) {
    return { ranked: [], top1Score: 0 };
  }

  // ─── Reranker: cross-encoder over (query, candidate-text) pairs ──────────
  const pairs = candidates.map((c) => ({ query: query.queryText, document: c.record.text }));
  const scores = await opts.reranker.score(pairs);
  if (scores.length !== pairs.length) {
    throw new Error(
      `retrieval-benchmark: reranker returned ${scores.length} scores for ${pairs.length} pairs`,
    );
  }
  for (let i = 0; i < scores.length; i++) {
    if (!Number.isFinite(scores[i])) {
      throw new Error(`retrieval-benchmark: reranker score[${i}] is non-finite (${scores[i]})`);
    }
  }

  // ─── Pinned final ranking formula ────────────────────────────────────────
  const qrelById = new Map(query.qrels.map((q) => [q.documentId, q.relevance]));
  const ranked = candidates
    .map((c, i) => ({
      documentId: c.record.docId,
      memorySlot: c.record.memorySlot,
      rerankerScore: scores[i]!,
      finalReorderingScore: scores[i]! + c.substrateBonus,
      relevance: qrelById.get(c.record.docId) ?? 0,
    }))
    .sort((a, b) => {
      if (b.finalReorderingScore !== a.finalReorderingScore) {
        return b.finalReorderingScore - a.finalReorderingScore;
      }
      if (b.rerankerScore !== a.rerankerScore) return b.rerankerScore - a.rerankerScore;
      return a.documentId < b.documentId ? -1 : a.documentId > b.documentId ? 1 : 0;
    })
    .map((r) => ({
      documentId: r.documentId,
      memorySlot: r.memorySlot,
      rerankerScore: r.rerankerScore,
      relevance: r.relevance,
    }));

  const top1Score = ranked.length > 0 ? ranked[0]!.rerankerScore : 0;
  return { ranked, top1Score };
}

// ─── Per-call corpus-side index caches ──────────────────────────────────────

const publicIndexCache = new WeakMap<ProductionCorpus, PublicCorpusIndex>();
function getOrBuildPublicIndex(corpus: ProductionCorpus): PublicCorpusIndex {
  const cached = publicIndexCache.get(corpus);
  if (cached) return cached;
  const idx = buildPublicCorpusIndex(corpus);
  publicIndexCache.set(corpus, idx);
  return idx;
}

const docTextCache = new WeakMap<ProductionCorpus, Map<string, string>>();
function getOrBuildDocTextIndex(corpus: ProductionCorpus): Map<string, string> {
  const cached = docTextCache.get(corpus);
  if (cached) return cached;
  const map = new Map<string, string>();
  for (const event of corpus.events) {
    for (const t of event.truthDocuments) if (!map.has(t.id)) map.set(t.id, t.text);
    for (const n of event.hardNegatives) if (!map.has(n.id)) map.set(n.id, n.text);
  }
  docTextCache.set(corpus, map);
  return map;
}

const recordIdIndexCacheV2 = new WeakMap<ProductionCorpus, Map<bigint, ProductionCorpusEvent>>();
function getOrBuildRecordIdIndex(corpus: ProductionCorpus): Map<bigint, ProductionCorpusEvent> {
  const cached = recordIdIndexCacheV2.get(corpus);
  if (cached) return cached;
  const built = new Map<bigint, ProductionCorpusEvent>();
  for (const e of corpus.events) built.set(stableRecordIdFor(e.id), e);
  recordIdIndexCacheV2.set(corpus, built);
  return built;
}

/**
 * Substrate-hardening §6.7 — per-(query, K) stage-1 cache. Keyed by corpus
 * (WeakMap) and by `${query.id}#${K}` (Map) so a long-running coordinator
 * process reuses the Top-K across all patch evaluations against the same
 * parent state in a pack.
 *
 * Memory: bounded by the live query set. For pack_size=128 queries × 2 packs
 * × Top-K=3200 docs × ~16 bytes per PublicCorpusDoc reference ≈ 13 MB per
 * corpus. Negligible; the dense embedding bytes live in the index, not in
 * the cache.
 *
 * `invalidateStage1CacheForCorpus(corpus)` clears the per-corpus cache. The
 * coordinator calls this on epoch transitions to drop stale Top-Ks if the
 * cache survives across epochs in the same process.
 */
const stage1Cache = new WeakMap<ProductionCorpus, Map<string, readonly { id: string; eventId: string; embedding: Uint8Array }[]>>();
function getOrComputeStage1(
  corpus: ProductionCorpus,
  queryId: string,
  k: number,
  compute: () => readonly { id: string; eventId: string; embedding: Uint8Array }[],
): readonly { id: string; eventId: string; embedding: Uint8Array }[] {
  let perCorpus = stage1Cache.get(corpus);
  if (!perCorpus) {
    perCorpus = new Map();
    stage1Cache.set(corpus, perCorpus);
  }
  const key = `${queryId}#${k}`;
  const cached = perCorpus.get(key);
  if (cached) return cached;
  const fresh = compute();
  perCorpus.set(key, fresh);
  return fresh;
}

/** Drop the stage-1 Top-K cache for a corpus. Coordinator calls this on
 *  epoch transitions if the cache outlives a single epoch in-process. */
export function invalidateStage1CacheForCorpus(corpus: ProductionCorpus): void {
  stage1Cache.delete(corpus);
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
