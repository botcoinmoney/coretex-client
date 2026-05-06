// @botcoin/cortex — entrypoint.
// Phase 1: state codec, merkleization, patch wire format.
// Phase 3: decoder, eval harness, worker pool, upgrade, verify-epoch.
// Phase 6: reducer, eligibility, multiplier-cap, funding-tx.
export const VERSION = '0.6.0';

export * from './state/index.js';
export * from './decoder/index.js';
export * from './eval/index.js';
export * from './workers/pool.js';
export * from './upgrade/index.js';
export * from './verify-epoch/index.js';
export * from './reducer/index.js';
export * from './shards.js';
export * from './event-topics.js';
