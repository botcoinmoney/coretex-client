/**
 * @botcoin/cortex — reducer module
 * Phase 6 deliverable: deterministic greedy-by-marginal-gain epoch reducer,
 * eligibility tracking, multiplier-cap computation, and funding-tx builder.
 */

// Reducer
export type {
  ReducerInputPatch,
  ReducerOutput,
  AcceptedPatch,
  RejectedPatch,
  RejectionCode,
  MarginalEvaluator,
} from './reducer.js';

export {
  reduce,
  computePatchSetRoot,
  makeReducerInput,
  stubMarginalEvaluator,
} from './reducer.js';

export type {
  LiveEpochInputPatch,
  LiveEpochOutput,
  LiveRejectedPatch,
  LiveRejectionCode,
  StateAdvance,
} from './live-epoch.js';

export {
  advanceEpochState,
  makeLiveEpochInput,
} from './live-epoch.js';

// Eligibility
export type {
  ScreenerPassedEvent,
  PatchMergedEvent,
  CreditIssuance,
  MultiplierAccrual,
  EpochEligibility,
} from './eligibility.js';

export {
  buildEpochEligibility,
  minerScreenerCredits,
  minerHasMerge,
} from './eligibility.js';

// Multiplier cap
export type {
  MinerBonusLeaf,
  MinerClaimBase,
} from './multiplier-cap.js';

export {
  MERGE_MULTIPLIER_BPS,
  BPS_DIVISOR,
  computeMinerBonus,
  buildEpochBonusLeaves,
  computeEpochTotalBonus,
  assertBonusWithinCap,
} from './multiplier-cap.js';

// Funding tx
export type {
  FundEpochCalldata,
  MinerClaimProof,
} from './funding-tx.js';

export {
  computeLeafHash,
  computeBonusMerkleRoot,
  buildFundEpochCalldata,
  buildMinerClaimProof,
  verifyMinerClaimProof,
} from './funding-tx.js';
