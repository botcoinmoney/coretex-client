/**
 * §6.4 relation-edge domain-share predicate — drops relation edges whose
 * two endpoints don't share at least one MemoryIndex.domainBits bit.
 *
 * Spec: docs/CORETEX_SUBSTRATE_EXPANSION_HARDENING.md §6.4.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  decodeSubstrate,
  encodeMemoryIndexSlot,
  encodeRelationEdge,
  relationEdgeValid,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const ZERO_STATE = { words: new Array(1024).fill(0n) };

function withWords(state, indexed) {
  const words = [...state.words];
  for (const [i, v] of indexed) words[i] = v;
  return { words };
}

function placeMemorySlot(state, slotIndex, slot) {
  const enc = encodeMemoryIndexSlot({ ...slot, slotIndex });
  // Tier-2 stride-1: each MemoryIndex slot is ONE word (word 0); write only enc[0] at
  // START+slotIndex so adjacent slots are independent.
  return withWords(state, [[RANGES.MEMORY_INDEX_START + slotIndex, enc[0]]]);
}

function placeRelation(state, entryIndex, edge) {
  const word = encodeRelationEdge({ ...edge, entryIndex });
  return withWords(state, [[RANGES.RELATIONS_START + entryIndex, word]]);
}

function makeSlot(recordId, domainBits, valid = true) {
  return {
    recordId: BigInt(recordId),
    family: 'near_collision',
    domainBits: BigInt(domainBits),
    valid,
    revoked: false,
    protected: false,
    retrievalSlot: 0,
    expiryEpoch: 0n,
  };
}

describe('§6.4 relation-edge domain-share predicate', () => {
  test('edge with overlapping domainBits is kept', () => {
    let s = { words: [...ZERO_STATE.words] };
    s = placeMemorySlot(s, 0, makeSlot(1, 0b0011)); // domains {0,1}
    s = placeMemorySlot(s, 1, makeSlot(2, 0b0110)); // domains {1,2} — bit 1 shared
    s = placeRelation(s, 0, { weight: 100, edgeType: 'supports', sourceSlot: 0, targetSlot: 1 });

    const decoded = decodeSubstrate(s);
    assert.equal(decoded.relations.length, 1);
    assert.equal(decoded.relations[0].sourceSlot, 0);
    assert.equal(decoded.relations[0].targetSlot, 1);
    assert.equal(decoded.relationsDroppedByDomainPredicate, 0);
  });

  test('edge with disjoint domainBits is dropped and counter increments', () => {
    let s = { words: [...ZERO_STATE.words] };
    s = placeMemorySlot(s, 0, makeSlot(1, 0b0001)); // domain {0}
    s = placeMemorySlot(s, 1, makeSlot(2, 0b0010)); // domain {1} — no overlap
    s = placeRelation(s, 0, { weight: 100, edgeType: 'supports', sourceSlot: 0, targetSlot: 1 });

    const decoded = decodeSubstrate(s);
    assert.equal(decoded.relations.length, 0);
    assert.equal(decoded.relationsDroppedByDomainPredicate, 1);
  });

  test('edge where source domainBits=0 (unset) is dropped', () => {
    let s = { words: [...ZERO_STATE.words] };
    s = placeMemorySlot(s, 0, makeSlot(1, 0)); // domain unset
    s = placeMemorySlot(s, 1, makeSlot(2, 0b0001));
    s = placeRelation(s, 0, { weight: 100, edgeType: 'supports', sourceSlot: 0, targetSlot: 1 });

    const decoded = decodeSubstrate(s);
    assert.equal(decoded.relations.length, 0);
    assert.equal(decoded.relationsDroppedByDomainPredicate, 1);
  });

  test('edge to inactive (valid=false) slot is dropped', () => {
    let s = { words: [...ZERO_STATE.words] };
    s = placeMemorySlot(s, 0, makeSlot(1, 0b0001, true));
    s = placeMemorySlot(s, 1, makeSlot(2, 0b0001, false)); // inactive
    s = placeRelation(s, 0, { weight: 100, edgeType: 'supports', sourceSlot: 0, targetSlot: 1 });

    const decoded = decodeSubstrate(s);
    assert.equal(decoded.relations.length, 0);
    assert.equal(decoded.relationsDroppedByDomainPredicate, 1);
  });

  test('relationEdgeValid standalone predicate matches decodeSubstrate behavior', () => {
    // Build memoryIndex manually (slot 0: {0,1}, slot 1: {2,3} — disjoint).
    const memoryIndex = [
      {
        slotIndex: 0,
        recordId: 1n,
        family: 'near_collision',
        domainBits: 0b0011n,
        valid: true,
        revoked: false,
        protected: false,
        retrievalSlot: 0,
        expiryEpoch: 0n,
      },
      {
        slotIndex: 1,
        recordId: 2n,
        family: 'near_collision',
        domainBits: 0b1100n,
        valid: true,
        revoked: false,
        protected: false,
        retrievalSlot: 0,
        expiryEpoch: 0n,
      },
      ...new Array(42).fill(null),
    ];
    const edge = { entryIndex: 0, weight: 1, edgeType: 'supports', sourceSlot: 0, targetSlot: 1 };
    assert.equal(relationEdgeValid(edge, memoryIndex), false);

    // Flip slot 1 to share bit 1 with slot 0 (now overlap on bit 1 if we
    // set 0b0110 instead of 0b1100).
    const overlapping = [
      memoryIndex[0],
      { ...memoryIndex[1], domainBits: 0b0110n },
      ...memoryIndex.slice(2),
    ];
    assert.equal(relationEdgeValid(edge, overlapping), true);
  });

  test('mixed kept + dropped edges produce correct counts', () => {
    let s = { words: [...ZERO_STATE.words] };
    s = placeMemorySlot(s, 0, makeSlot(1, 0b0011));
    s = placeMemorySlot(s, 1, makeSlot(2, 0b0010)); // shares bit 1 with slot 0
    s = placeMemorySlot(s, 2, makeSlot(3, 0b1000)); // disjoint from 0 and 1
    // Edge 0→1 kept; edge 0→2 dropped; edge 1→2 dropped.
    s = placeRelation(s, 0, { weight: 10, edgeType: 'supports', sourceSlot: 0, targetSlot: 1 });
    s = placeRelation(s, 1, { weight: 20, edgeType: 'supports', sourceSlot: 0, targetSlot: 2 });
    s = placeRelation(s, 2, { weight: 30, edgeType: 'supports', sourceSlot: 1, targetSlot: 2 });

    const decoded = decodeSubstrate(s);
    assert.equal(decoded.relations.length, 1);
    assert.equal(decoded.relations[0].weight, 10);
    assert.equal(decoded.relationsDroppedByDomainPredicate, 2);
  });
});
