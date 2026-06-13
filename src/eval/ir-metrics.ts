/**
 * IR metric primitives for the CoreTex production retrieval scorer.
 *
 * Spec: specs/retrieval_benchmark.md.
 *
 * All metrics are computed per-query and then averaged across the pack by
 * the higher-level scorer (eval/retrieval-benchmark.ts). These primitives
 * operate on a single ranked candidate list with attached graded relevance.
 */

export interface RankedCandidate {
  readonly documentId: string;
  /** 0..1 graded relevance (5-level scale: 0, 0.2, 0.4, 0.6, 0.8, 1.0). */
  readonly relevance: number;
}

/** Exponential gain DCG: gain(rel) = 2^rel - 1. */
function dcgAtK(ranked: readonly RankedCandidate[], k: number): number {
  const limit = Math.min(k, ranked.length);
  let dcg = 0;
  for (let i = 0; i < limit; i++) {
    const rel = ranked[i]!.relevance;
    const gain = Math.pow(2, rel) - 1;
    const discount = Math.log2(i + 2);
    dcg += gain / discount;
  }
  return dcg;
}

/**
 * nDCG@k with exponential gain (gain = 2^rel - 1) and log2 discount,
 * normalized by ideal DCG given the qrels for the query.
 *
 * @param ranked      retrieval-ordered candidates with attached relevance
 * @param idealRels   all relevance grades available for this query (any order)
 * @param k           cutoff
 */
export function ndcgAtK(
  ranked: readonly RankedCandidate[],
  idealRels: readonly number[],
  k: number,
): number {
  const dcg = dcgAtK(ranked, k);
  const ideal = [...idealRels].sort((a, b) => b - a);
  const idealRanked = ideal.map((r, i) => ({ documentId: `ideal_${i}`, relevance: r }));
  const idcg = dcgAtK(idealRanked, k);
  if (idcg === 0) return 0;
  return dcg / idcg;
}

/** MRR@k: reciprocal of the first-relevant rank within the cutoff. */
export function mrrAtK(ranked: readonly RankedCandidate[], k: number): number {
  const limit = Math.min(k, ranked.length);
  for (let i = 0; i < limit; i++) {
    if (ranked[i]!.relevance > 0) return 1 / (i + 1);
  }
  return 0;
}

/**
 * Recall@k: fraction of relevant documents that appear within the cutoff.
 *
 * @returns null when the query has no relevant documents (caller should
 *          drop the query from the recall mean rather than count it as 0).
 */
export function recallAtK(
  ranked: readonly RankedCandidate[],
  totalRelevant: number,
  k: number,
): number | null {
  if (totalRelevant <= 0) return null;
  const limit = Math.min(k, ranked.length);
  let hits = 0;
  for (let i = 0; i < limit; i++) {
    if (ranked[i]!.relevance > 0) hits++;
  }
  return hits / totalRelevant;
}

/**
 * Temporal current/stale accuracy for a single query.
 *
 * Hit when:
 *   - top-1 candidate id == currentDocId
 *   - none of top-3 candidate ids are in staleDocIds
 *
 * For non-temporal queries call returns null and caller skips.
 */
export function temporalCurrentStaleHit(
  ranked: readonly RankedCandidate[],
  currentDocId: string | null,
  staleDocIds: readonly string[],
): boolean | null {
  if (currentDocId === null) return null;
  if (ranked.length === 0) return false;
  if (ranked[0]!.documentId !== currentDocId) return false;
  const staleSet = new Set(staleDocIds);
  for (let i = 0; i < Math.min(3, ranked.length); i++) {
    if (staleSet.has(ranked[i]!.documentId)) return false;
  }
  return true;
}

/**
 * Pack-level aggregator for temporalCurrentStaleAccuracy.
 *
 * @param hits  per-query hit booleans (or null to exclude)
 */
export function temporalCurrentStaleAccuracy(hits: readonly (boolean | null)[]): number {
  let counted = 0;
  let positive = 0;
  for (const h of hits) {
    if (h === null) continue;
    counted++;
    if (h) positive++;
  }
  return counted === 0 ? 0 : positive / counted;
}

/**
 * Per-query multi-hop hit:
 *   answer-bearing memory slot is reachable from the top-k retrieval-key
 *   candidates via the Relations graph within `relationHopBudget` hops.
 *
 * Inputs are pre-resolved by the scorer:
 *   - candidateMemorySlots: memory slots pointed to by the top-k retrieval
 *     candidates (in retrieval order; duplicates fine)
 *   - answerMemorySlots:   set of slots that bear the answer
 *   - relationGraph:       adjacency map sourceSlot -> [targetSlot, ...]
 *
 * For non-multi-hop queries the caller passes null and excludes from mean.
 */
export function multiHopRelationHit(
  candidateMemorySlots: readonly number[],
  answerMemorySlots: ReadonlySet<number>,
  relationGraph: ReadonlyMap<number, readonly number[]>,
  hopBudget: number,
): boolean {
  if (answerMemorySlots.size === 0) return false;
  const visited = new Set<number>(candidateMemorySlots);
  if (anyOverlap(visited, answerMemorySlots)) return true;
  let frontier = Array.from(visited);
  for (let h = 0; h < hopBudget; h++) {
    const next: number[] = [];
    for (const slot of frontier) {
      const neighbours = relationGraph.get(slot);
      if (!neighbours) continue;
      for (const n of neighbours) {
        if (visited.has(n)) continue;
        visited.add(n);
        next.push(n);
        if (answerMemorySlots.has(n)) return true;
      }
    }
    if (next.length === 0) return false;
    frontier = next;
  }
  return false;
}

export function multiHopRelationRecallAtK(hits: readonly (boolean | null)[]): number {
  let counted = 0;
  let positive = 0;
  for (const h of hits) {
    if (h === null) continue;
    counted++;
    if (h) positive++;
  }
  return counted === 0 ? 0 : positive / counted;
}

/**
 * Per-query abstention hit: top-1 reranker score is below the threshold.
 *
 * @returns null when the query is not an abstention probe (caller skips).
 */
export function abstentionHit(top1Score: number, abstentionThreshold: number): boolean {
  return top1Score < abstentionThreshold;
}

export function abstentionAccuracy(hits: readonly (boolean | null)[]): number {
  let counted = 0;
  let positive = 0;
  for (const h of hits) {
    if (h === null) continue;
    counted++;
    if (h) positive++;
  }
  return counted === 0 ? 0 : positive / counted;
}

function anyOverlap<T>(a: ReadonlySet<T>, b: ReadonlySet<T>): boolean {
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  for (const v of small) if (large.has(v)) return true;
  return false;
}
