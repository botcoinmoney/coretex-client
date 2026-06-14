# CoreTex Retrieval Benchmark — IR Metric Definitions

Status: launch-blocking spec. Pinned by bundle hash.

## Scope

This spec defines the IR-style metrics evaluated by the production CoreTex
reward law. They are computed by the coordinator over a hidden query pack
derived from the corpus and a revealed seed (see `hidden_query_pack.md`).
They are reproducible deterministically from the pinned bundle (see
`determinism.md`).

**Dual-pack acceptance**: production scores every live patch on TWO domain-separated packs derived
from the same on-chain blockhash — a `gate` pack and a `confirm` pack.
A patch is accepted only if BOTH packs clear
`patchAcceptanceFloors.minImprovementPpm + replayTolerancePpm +
baselineVariancePpm`. The confirm-pack draw is independent of the gate-pack
draw, so a pack-lucky borderline result on one pack is filtered by the
other (false-acceptance probability `p` drops to `p²`).

The reward law is composite: retrieval-dominant (≥70% of weight), with
sanity, temporal, multi-hop, and abstention components. This spec
documents the metric primitives only.

## Notation

For a query `q` with graded qrels `rel(q, d) ∈ {0.0, 0.2, 0.4, 0.6, 0.8, 1.0}`,
let `ranked(q) = [d_1, d_2, …, d_n]` be the candidate documents in their
final reranker-determined order (descending score). All metrics are
per-query and then averaged across the pack.

## nDCG@k (primary metric, exponential gain)

```
gain(rel)  = 2^rel - 1
DCG@k(q)   = Σ_{i=1..k}  gain(rel(q, ranked(q)[i])) / log2(i + 1)
IDCG@k(q)  = Σ_{i=1..k}  gain(rel(q, ideal(q)[i])) / log2(i + 1)
nDCG@k(q)  = DCG@k(q) / IDCG@k(q)        (0 if IDCG@k(q) == 0)
```

`ideal(q)` is the qrel-sorted list of all qrel-bearing documents for `q`.

The bundle profile pins `k = 10`. The metric is `nDCG@10`.

## MRR@k

```
MRR@k(q) = 1 / firstRank(q)   if firstRank(q) <= k, else 0
```

`firstRank(q)` is the 1-indexed position in `ranked(q)` of the first document
with `rel(q, d) > 0`.

## Recall@k

```
recall@k(q) = |{d ∈ ranked(q)[1..k] : rel(q, d) > 0}| / |{d : rel(q, d) > 0}|
```

If the query has no relevant documents (e.g. abstention probe), recall is
undefined for that query and the query is excluded from the recall mean.

## temporalCurrentStaleAccuracy

For queries whose qrel record carries a `temporal.currentStaleFlag`:
the substrate must serve the `current` truth and suppress the `stale` truth.

```
let currentDoc = qrels[q].truthDocuments[currentIndex]
let staleDocs  = qrels[q].truthDocuments[staleIndices]
hit(q) = (top1(ranked(q)).id == currentDoc.id)
       AND (no document in ranked(q)[1..3] is in staleDocs)
temporalCurrentStaleAccuracy = mean(hit(q)) over temporal queries
```

## multiHopRelationRecall@k

For queries with a `multi_hop_relation` family flag, the substrate's
`Relations` graph must connect the top-k retrieval candidates to the
answer-bearing memory within `relationHopBudget` hops (calibrated, typ. 2–3).

```
candidates(q)   = ranked(q)[1..k]
reachable(q, h) = BFS over substrate.Relations starting from candidate slots,
                  bounded by h hops, intersecting answer-bearing memory slots
hit(q) = reachable(q, relationHopBudget) is non-empty
multiHopRelationRecall@k = mean(hit(q)) over multi-hop queries
```

## abstentionAccuracy

For queries deliberately inserted with no truthDocuments (negative probes):
the top-1 reranker score for the candidate document must fall below
`abstentionThreshold` (calibrated).

```
hit(q) = top1Score(ranked(q)) < abstentionThreshold
abstentionAccuracy = mean(hit(q)) over negative queries
```

If the top-1 score is at or above `abstentionThreshold`, the query is
counted as a hallucinated retrieval and contributes 0.

## structuralValidity

Boolean clamp of the substrate decoder: 1.0 if the substrate decodes
without errors (no reserved-bit violations, all memory pointers resolve
to valid retrieval slots, all retrieval-key headers reference the pinned
bi-encoder, codebook entries consistent with the bi-encoder's quantization,
relation graph references valid slots), otherwise a fractional value:

```
structuralValidity = max(0, 1 - decodeFailures / decodeAttempts)
```

The denominator counts attempted decodes (memory slots + retrieval key
slots + relation entries + temporal entries + codebook entries). A patch
that decodes cleanly produces 1.0; one whose candidate substrate fails
in 5% of decode attempts produces 0.95.

`structuralValidity` is multiplied by `w_structural_sanity` (≤ 0.10) in the
composite. It is a sanity gate, not a reward; it cannot dominate.

## Composite

```
composite = w_retrieval        * nDCG@10
          + w_temporal          * temporalCurrentStaleAccuracy
          + w_relation_recall   * multiHopRelationRecall@10
          + w_abstention        * abstentionAccuracy
          + w_structural_sanity * structuralValidity
```

The weights satisfy:

- `w_retrieval ≥ 0.70`
- `w_structural_sanity ≤ 0.10`
- `w_temporal > 0`, `w_relation_recall > 0`, `w_abstention > 0`
- weights sum to 1.0

Concrete values are calibration outputs (see calibration table in the
hardening plan). The bundle manifest pins them per epoch.

## Determinism contract

Every metric is computed in the canonical CPU-only runtime against the
pinned bi-encoder + reranker. Replay watchers recompute the same composite
from the pinned bundle and check that

```
|coordinatorScore - watcherScore| <= replayTolerancePpm
```

`replayTolerancePpm` is a calibration output bound into the bundle.
