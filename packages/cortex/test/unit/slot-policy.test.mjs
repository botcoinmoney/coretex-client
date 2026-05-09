import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  selectSubstrateSlot,
  substrateRegionForFamily,
  wordIndexForSubstrateSlot,
} from '../../dist/substrate/slot-policy.js';

describe('substrate slot rotation policy', () => {
  test('routes near-collision to retrieval keys and other families to memory index', () => {
    assert.equal(substrateRegionForFamily('near_collision'), 'retrieval_keys');
    assert.equal(substrateRegionForFamily('temporal'), 'memory_index');
    assert.equal(substrateRegionForFamily('long_horizon'), 'memory_index');
  });

  test('wraps retrieval-key writes after 36 advances', () => {
    const first = selectSubstrateSlot({ family: 'near_collision', advanceIndex: 0 });
    const wrapped = selectSubstrateSlot({ family: 'near_collision', advanceIndex: 36 });
    assert.deepEqual(first, {
      region: 'retrieval_keys',
      slotIndex: 0,
      wordIndex: 384,
      capacity: 36,
      wrapped: false,
    });
    assert.deepEqual(wrapped, {
      region: 'retrieval_keys',
      slotIndex: 0,
      wordIndex: 384,
      capacity: 36,
      wrapped: true,
    });
  });

  test('skips protected slots when wrapping or landing directly on one', () => {
    const selected = selectSubstrateSlot({
      family: 'near_collision',
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
        family: 'near_collision',
        advanceIndex: 36,
        protectedSlots: Array.from({ length: 36 }, (_v, i) => i),
      }),
      /no writable retrieval_keys slots remain/,
    );
  });

  test('computes stable word indices for both rotating regions', () => {
    assert.equal(wordIndexForSubstrateSlot('memory_index', 43), 376);
    assert.equal(wordIndexForSubstrateSlot('memory_index', 43, 7), 383);
    assert.equal(wordIndexForSubstrateSlot('retrieval_keys', 35), 664);
    assert.equal(wordIndexForSubstrateSlot('retrieval_keys', 35, 7), 671);
  });
});
