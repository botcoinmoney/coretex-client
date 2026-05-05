// @botcoin/cortex — entrypoint.
// Phase 1: state codec, merkleization, patch wire format.
// Phase 6: reducer, eligibility, multiplier-cap, funding-tx.
export const VERSION = '0.2.0';

export * from './state/index.js';
export * from './reducer/index.js';
