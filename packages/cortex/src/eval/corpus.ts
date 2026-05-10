/**
 * Compat re-export.
 *
 * The legacy slot-fill `scoreProductionState`, `eventIdToKey128`,
 * `eventIdToMem128`, `evaluateStateWithReranker`, `evaluatePatchWithReranker`
 * are deleted as part of the production hardening overhaul. The retrieval-
 * benchmark replacement lives in:
 *
 *   - eval/retrieval-corpus.ts     — corpus types, loader, root hashing
 *   - eval/retrieval-benchmark.ts  — scorer + patch evaluator
 *   - eval/ir-metrics.ts           — IR primitives
 *   - eval/hidden-query-pack.ts    — deterministic per-epoch pack derivation
 *   - eval/bi-encoder.ts           — CPU-only bi-encoder runtime
 *   - substrate/retrieval-decoder.ts
 *
 * This file remains so external imports of `eval/corpus` resolve to the
 * new types without breaking the package barrel.
 */

export {
  type ProductionCorpusFamily,
  type ProductionCorpusEvent,
  type ProductionCorpus,
  type CorpusSplit,
  type GradedRelevance,
  type QrelEntry,
  type TruthDocument,
  type TemporalAnnotation,
  type RelationAnnotation,
  type RelationEdgeType,
  type RetrievalKeyLayout,
  type EmbeddingPayload,
  type Provenance,
  type ProvenanceSource,
  type SplitRatios,
  type CorpusFileShape,
  DEFAULT_SPLIT_RATIOS,
  splitForRecord,
  computeCorpusRoot,
  loadProductionCorpus,
  serializeProductionCorpus,
} from './retrieval-corpus.js';
