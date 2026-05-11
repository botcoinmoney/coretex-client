// @botcoin/cortex — entrypoint.
// Phase 1: state codec, merkleization, patch wire format.
// Phase 3: decoder, eval harness, worker pool, upgrade, verify-epoch.
// Phase 6: reducer, eligibility, multiplier-cap, funding-tx.
// V4 production hardening: retrieval-benchmark scorer, deterministic CPU-only
// inference, graded-qrel corpus, hidden query pack, signed corpus deltas with
// embedding payloads.
export const VERSION = '0.7.0';

export * from './state/index.js';
export * from './decoder/index.js';
export * from './eval/index.js';
export * from './workers/pool.js';
export * from './upgrade/index.js';
export * from './verify-epoch/index.js';
export * from './reducer/index.js';
export * from './rewards/index.js';
export * from './shards.js';
export * from './event-topics.js';
export * from './bundle/index.js';
export * from './replay/v4.js';
export * from './coordinator/endpoints.js';
export * from './coordinator/retrieval-data-source.js';
export * from './coordinator/base-blockhash.js';
export * from './coordinator/per-patch-evaluator.js';
export * from './eval/seed-derivation.js';
export * from './eval/live-eval-admission.js';
export * from './eval/reranker.js';
export * from './eval/bi-encoder.js';
export * from './eval/retrieval-corpus.js';
export * from './eval/retrieval-benchmark.js';
export * from './eval/ir-metrics.js';
export * from './eval/hidden-query-pack.js';
export * from './corpus/admission.js';
export * from './corpus/delta.js';
export * from './corpus/epoch-rotation.js';
export * from './substrate/slot-policy.js';
export {
  type DecodedSubstrate,
  type SubstrateFamily,
  type DecoderOptions,
  type RelationEdge,
  type TemporalRecord,
  decodeMemoryIndex,
  decodeRetrievalKeys,
  decodeRelations,
  decodeTemporal,
  decodeCodebook,
  decodeSubstrate,
  encodeMemoryIndexSlot,
  encodeRetrievalKeySlot,
  encodeRelationEdge,
  encodeTemporalRecord,
  encodeCodebookEntry,
  biEncoderModelIdHash,
} from './substrate/retrieval-decoder.js';
export type {
  MemoryIndexSlot as RetrievalMemoryIndexSlot,
  RetrievalKeySlot as RetrievalKeySlotV2,
  CodebookEntry as RetrievalCodebookEntry,
  RelationEdgeType as SubstrateRelationEdgeType,
} from './substrate/retrieval-decoder.js';
export * from './substrate/structural-validity.js';
