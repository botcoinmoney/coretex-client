// @botcoin/cortex — entrypoint.
// Phase 1: state codec, merkleization, patch wire format.
// Phase 3: decoder, eval harness, worker pool, upgrade, verify-epoch.
export const VERSION = '0.3.0';

export * from './state/index.js';
export * from './decoder/index.js';
export * from './eval/index.js';
export * from './workers/pool.js';
export * from './upgrade/index.js';
export * from './verify-epoch/index.js';
