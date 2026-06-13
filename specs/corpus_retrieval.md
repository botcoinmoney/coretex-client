# Corpus Retrieval — Record Schema, Qrels, Splits, Embeddings

Status: launch-blocking spec. Pinned by bundle hash.

## Scope

This spec replaces the previous `ProductionCorpusEvent` (event-ledger) shape.
The CoreTex production corpus is a graded-relevance retrieval benchmark.

## ProductionCorpusEvent (retrieval shape)

```
ProductionCorpusEvent {
  id:              string                // stable across deltas
  family:          'near_collision'
                 | 'temporal'
                 | 'long_horizon'
                 | 'multi_hop_relation'  // extensible
  domain:          string                // coordinator source domain
  split:           'train_visible'
                 | 'calibration'
                 | 'eval_hidden'
                 | 'canary'
  queryText:       string
  truthDocuments:  TruthDocument[]       // length >= 0; 0 = abstention probe
  hardNegatives:   string[]              // distractor texts
  qrels:           QrelEntry[]           // graded labels per truth + neg
  protected:       boolean               // protected from regression veto
  temporal?:       TemporalAnnotation
  relations?:      RelationAnnotation[]
  provenance:      Provenance
  embeddings:      EmbeddingPayload      // pinned bi-encoder bytes
}
```

### TruthDocument

```
TruthDocument {
  id:        string              // unique per record (record_id::truth_n)
  text:      string
  isCurrent: boolean             // true unless this truth is a stale one
}
```

### QrelEntry

Graded label, per-document, in the 5-level scale shared with MemReranker:

```
QrelEntry {
  documentId: string             // matches TruthDocument.id or hardNeg.id
  relevance:  0.0 | 0.2 | 0.4 | 0.6 | 0.8 | 1.0
}
```

Scale:

```
0.0  irrelevant
0.2  low (mentions topic, not answer)
0.4  partial (related entity or fact)
0.6  partial (answer-bearing in part)
0.8  highly relevant (answer-bearing, full)
1.0  direct answer (the canonical truth)
```

### TemporalAnnotation

```
TemporalAnnotation {
  validFromEpoch:    uint64
  validUntilEpoch:   uint64           // 2^64 - 1 == open
  currentStaleFlag:  boolean
  supersedes_id?:    string           // record id of older version
  superseded_by_id?: string           // record id of newer version
}
```

### RelationAnnotation

```
RelationAnnotation {
  other_id: string
  edgeType: 'supports' | 'supersedes' | 'coreference_of'
          | 'causes' | 'derived_from' | 'co_occurs_with'
}
```

Edge types are bound into the bundle's `relationEdgeTypes` and are aligned
with the substrate decoder's enum (see `substrate_retrieval_semantics.md`).

### Provenance

```
Provenance {
  source:       'dataset_v2_direct' | 'hf_export' | 'synthetic_challenge'
  s3Key?:       string                // present for dataset_v2_direct
  challengeSeed?:    uint128
  challengeId?:      string
  attemptId?:        string
  sessionId?:        string
  pairId?:           string
  questionId?:       string
  sourceHash:        bytes32          // keccak256 of canonical-JSON of source
}
```

### EmbeddingPayload

Bytes are produced by the pinned bi-encoder (see `determinism.md`) and
copied verbatim into the substrate's `RetrievalKeys` slot when a miner
pins this record.

```
EmbeddingPayload {
  modelId:     string                 // pinned bi-encoder modelId
  revision:    string                 // pinned commit
  layout:      RetrievalKeyLayout     // dim, quantization, headerBytes
  query:       bytes                  // bi-encoder of queryText
  perTruth:    Map<documentId, bytes> // bi-encoder per truth doc
  perNegative: Map<documentId, bytes> // bi-encoder per hard neg
}
```

`embeddings` is load-bearing in production: replay watchers depend on it
to recompute scores deterministically. A delta whose `embeddings` map has
non-canonical bytes (e.g. wrong dim, wrong modelId) is rejected at apply
time.

## Splits

`splitForRecord(id, corpusEpoch)` is deterministic and stable: same `id`
always returns the same `split` (forever, even across corpus deltas). The
function is:

```
splitForRecord(id, corpusEpoch):
    h = uint64(keccak256(id || u64(corpusEpoch)))
    bucket = h % 100
    if bucket < TRAIN_VISIBLE_PCT:           return 'train_visible'
    if bucket < TRAIN_VISIBLE_PCT + CALIBRATION_PCT: return 'calibration'
    if bucket < TRAIN_VISIBLE_PCT + CALIBRATION_PCT + EVAL_HIDDEN_PCT:
                                              return 'eval_hidden'
    return 'canary'
```

Default split percentages (calibration outputs; pinned in bundle profile):
`70 / 10 / 15 / 5`.

## Graded qrel labeling

Production hard-negative labels are emitted by the challenge synthesizer as
structural negative categories and resolved through the bundle's
`negCategoryRelevanceMap`.

```
category  = challengeSynthesizer.hardNegative.category
relevance = bundle.evaluator.profile.negCategoryRelevanceMap[category]
```

This keeps corpus expansion CPU-cheap and replayable. A separately pinned
stronger reranker may be used as an offline audit/reference model, but it is
not in the production corpus-generation hot path and live eval never uses it.

## CorpusDelta carrying embeddings

```
CorpusDelta {
  previousRoot:        bytes32
  nextRoot:            bytes32
  addedRecordIds:      string[]
  removedRecordIds:    string[]
  recordPayloads:      Map<id, ProductionCorpusEvent>
  embeddingPayloads:   Map<id, EmbeddingPayload>
  labelingProvenance:  { modelId, revision, runtime, batchHash }
  epoch:               uint64
  generatedAt:         ISO8601
  signature:           bytes
}
```

Hashing covers all fields including embedding bytes (canonical-JSON over
the entire delta). `applyCorpusDelta` enforces:

1. `delta.previousRoot == corpus.corpusRoot`  (hash-continuity)
2. recompute `nextRoot` and assert match
3. verify operator signature
4. verify embedding model id + revision match the bundle's pinned bi-encoder
5. verify `splitForRecord` returns each record's declared `split`

## Reproducibility

A fresh corpus build, on two clean machines using the pinned challenge
synthesizer, bundle `negCategoryRelevanceMap`, and pinned bi-encoder,
produces a byte-identical `corpusRoot`. The bundle manifest binds the qrel map
and model file hashes, so labels and embeddings are reproducible.

## Coordinator API surface

`GET /coretex/corpus/:id` masks `truthDocuments`, `hardNegatives`, and
`qrels` for `eval_hidden` and `canary` records. `train_visible` records
return the full payload. `calibration` records return the full payload to
calibration callers only (gated by an additional flag at the coordinator).

`GET /coretex/corpus/:id/embedding` returns `embeddings.query` and
`embeddings.perTruth[*]` for `train_visible` records, 404 for hidden
records until epoch close + reveal.
