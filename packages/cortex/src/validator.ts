// Public validator/client entrypoint.
//
// This surface is safe for standalone validators: replay, sync, state codecs,
// corpus verification, bundle attestation, and scoring/audit helpers. It does
// not export the coordinator HTTP router, miner submit handler, receipt signer
// dependencies, or CoreTexCoordinatorCore.
export { CORTEX_CLIENT_VERSION as VERSION } from './version.js';
export { CORTEX_CLIENT_VERSION } from './version.js';

export * from './state/index.js';
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
export * from './replay/coretex-registry.js';
export * from './replay/per-patch.js';
export * from './coordinator/base-blockhash.js';
export * from './coordinator/patch-received-notice.js';
export * from './eval/seed-derivation.js';
export * from './eval/live-eval-admission.js';
export * from './eval/reranker.js';
export * from './eval/bi-encoder.js';
export * from './eval/retrieval-corpus.js';
export * from './eval/public-corpus-index.js';
export * from './eval/retrieval-benchmark.js';
export * from './eval/memory-ir-render.js';
export * from './eval/ir-metrics.js';
export * from './eval/hidden-query-pack.js';
export * from './eval/relation-qrels.js';
export * from './corpus/admission.js';
export * from './corpus/delta.js';
export * from './corpus/logical-delta-bridge.js';
export * from './corpus/epoch-rotation.js';
export * from './substrate/slot-policy.js';
export {
  type DecodedSubstrate,
  type SubstrateFamily,
  type DecoderOptions,
  type RelationEdge,
  type RelationCategoryLens,
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
  encodeRelationCategoryLens,
  encodeTemporalRecord,
  encodeCodebookEntry,
  biEncoderModelIdHash,
  checkLensDiversity,
  relationEdgeValid,
  type PolicyAtom,
  type PolicyAtomFamily,
  type PolicyAction,
  type PolicyScope,
  decodePolicyAtomRegion,
  encodePolicyAtom,
  policyReservedNonZeroWords,
  POLICY_REGIONS,
  POLICY_SELECTOR,
  POLICY_EVIDENCE_FEATURE,
  POLICY_FLAG,
  POLICY_TARGET_NONE,
} from './substrate/retrieval-decoder.js';
export { validatePolicyRegions, validateReservedBits, hasNonZeroReservedBits } from './state/validate.js';
export type {
  MemoryIndexSlot as RetrievalMemoryIndexSlot,
  RetrievalKeySlot as RetrievalKeySlotV2,
  CodebookEntry as RetrievalCodebookEntry,
  RelationEdgeType as SubstrateRelationEdgeType,
  LensDiversityCheck,
} from './substrate/retrieval-decoder.js';
export * from './substrate/structural-validity.js';
