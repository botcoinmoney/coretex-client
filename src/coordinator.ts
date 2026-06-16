// Coordinator-mounted entrypoint.
//
// The production SWCP coordinator imports this subpath. Standalone validators
// should import `@botcoinmoney/coretex-client` or `@botcoinmoney/coretex-client/validator` instead.
export * from './client.js';
export * from './coordinator/endpoints.js';
export * from './coordinator/retrieval-data-source.js';
export {
  CoreTexCoordinatorCore,
  createInProcessCoreTexSubmitQueue,
} from './coordinator/coretex-coordinator-core.js';
export type {
  ChainClient as CoreTexCoordinatorChainClient,
  CoreTexMinerCounters,
  RegistryEpochPins,
  ParentSubstrateLoader,
  RealEvaluator,
  EvalResult,
  CoreTexDualPackEvaluationProof,
  CoreTexReceiptPayload,
  CoreTexReceiptSigner,
  CoreTexSignedReceipt,
  CoreTexSubmitQueue,
  CoreTexCoordinatorConfig,
  PendingReceipt,
  ReceiptEnvelope,
  CoreTexCoordinatorMetrics,
} from './coordinator/coretex-coordinator-core.js';
export * from './coordinator/per-patch-evaluator.js';
export * from './coordinator/production-evaluator.js';
// Canonical verify-before-sign for the keyless remote scorer (the integration
// adapter imports this instead of carrying its own copy).
export * from './coordinator/remote-scorer-verify.js';
export * from './coordinator/scorer-pair-trace.js';
export * from './coordinator/epoch-frontier.js';
// Keyless GPU scorer-server handler boundary (pure, evaluator-injectable) — so
// the coordinator-side integration test can drive the REAL handler over HTTP.
export {
  handleScoreJob,
  checkScorerJobPins,
  verifyJobParentState,
  resolveJobSeedContext,
  resolveScorerAuth,
  scorerRequestAuthorized,
  DEFAULT_SCORER_BODY_LIMIT_BYTES,
  type ScorerJobRequest,
  type ScorerJobResult,
  type ScorerPublicEvalContext,
  type ScorerJobHandlerDeps,
  type ScorerJobResponse,
  type ScorerLoadedPins,
  type ScorerHealth as ScorerServerHealth,
  type ScorerExpectedPins as ScorerServerExpectedPins,
} from './scorer-server-cli.js';
