/**
 * Canonical Solidity event topic[0] hashes for the Cortex contracts.
 *
 * Each value is `keccak256(eventSignature)` — what eth_getLogs filters as
 * `topics[0]`. Pinned constants so off-chain scripts (dry-run-epoch,
 * first-reward-audit-trail, replay-reducer) never carry placeholders.
 *
 * Cross-checked with `cast keccak <signature>`. Changing any contract event
 * MUST update both the contract and this table.
 */

export const EVENT_TOPICS = {
  // CortexRegistry
  CortexShardCommitted: '0x8b145aa1e2dd374dfe91a195e02d385d97846dcba016c588bbdbd2b8804ea317',
  CortexShardRevealed:  '0x633ed613fcb448ec56058ca9868b47e102f9955ce07965e9d30bd3caf2ea65a7',
  CortexPatchAccepted:  '0xab00c32b8051b99c7b38b9ac827b758c6ee25a4148c397b00d72584a330416dc',
  CortexEpochFinalized: '0xff2718a1f525df14d5da78a5d63b920e5fff6b92f8e463a1229c2e18f62cd2f8',
  CortexStateSnapshot:  '0x2993cbcc092846a5c58a62728dbefaaf9e84336576719e8b82f0cb8b71b009e4',
  // CortexMergeBonus
  EpochFunded:          '0xe5b8a095fb436a3843f3656aa0be2702fee71429271a51fe924a9a957b9187df',
} as const;

export type EventName = keyof typeof EVENT_TOPICS;
