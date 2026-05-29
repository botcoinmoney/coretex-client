import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  selectSubstrateSlot,
  wordIndexForSubstrateSlot,
} from '../../dist/substrate/slot-policy.js';

describe('substrate slot rotation policy', () => {
  test('selects retrieval_keys slot 0 on first advance', () => {
    const first = selectSubstrateSlot({ region: 'retrieval_keys', advanceIndex: 0 });
    assert.deepEqual(first, {
      region: 'retrieval_keys',
      slotIndex: 0,
      wordIndex: 384,
      capacity: 36,
      wrapped: false,
    });
  });

  test('wraps retrieval-key writes after 36 advances', () => {
    const wrapped = selectSubstrateSlot({ region: 'retrieval_keys', advanceIndex: 36 });
    assert.deepEqual(wrapped, {
      region: 'retrieval_keys',
      slotIndex: 0,
      wordIndex: 384,
      capacity: 36,
      wrapped: true,
    });
  });

  test('selects Tier-2 stride-1 MemoryIndex slots across all 352 words', () => {
    const first = selectSubstrateSlot({ region: 'memory_index', advanceIndex: 0 });
    assert.deepEqual(first, {
      region: 'memory_index',
      slotIndex: 0,
      wordIndex: 32,
      capacity: 352,
      wrapped: false,
    });
    const last = selectSubstrateSlot({ region: 'memory_index', advanceIndex: 351 });
    assert.equal(last.slotIndex, 351);
    assert.equal(last.wordIndex, 383);
    assert.equal(last.wrapped, false);
    const wrapped = selectSubstrateSlot({ region: 'memory_index', advanceIndex: 352 });
    assert.equal(wrapped.slotIndex, 0);
    assert.equal(wrapped.wordIndex, 32);
    assert.equal(wrapped.wrapped, true);
  });

  test('skips protected slots when wrapping or landing directly on one', () => {
    const selected = selectSubstrateSlot({
      region: 'retrieval_keys',
      advanceIndex: 36,
      protectedSlots: new Set([0, 1]),
    });
    assert.equal(selected.slotIndex, 2);
    assert.equal(selected.wordIndex, 400);
    assert.equal(selected.wrapped, true);
  });

  test('fails closed when every slot in a region is protected', () => {
    assert.throws(
      () => selectSubstrateSlot({
        region: 'retrieval_keys',
        advanceIndex: 36,
        protectedSlots: Array.from({ length: 36 }, (_v, i) => i),
      }),
      /no writable retrieval_keys slots remain/,
    );
  });

  test('computes stable word indices for both rotating regions', () => {
    assert.equal(wordIndexForSubstrateSlot('memory_index', 0), 32);
    assert.equal(wordIndexForSubstrateSlot('memory_index', 351), 383);
    assert.throws(() => wordIndexForSubstrateSlot('memory_index', 0, 1), /wordOffset out of range/);
    assert.equal(wordIndexForSubstrateSlot('retrieval_keys', 35), 664);
    assert.equal(wordIndexForSubstrateSlot('retrieval_keys', 35, 7), 671);
  });
});
