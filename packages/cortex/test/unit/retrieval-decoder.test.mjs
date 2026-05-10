import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  decodeMemoryIndex,
  decodeRetrievalKeys,
  decodeRelations,
  decodeTemporal,
  decodeCodebook,
  decodeSubstrate,
  encodeMemoryIndexSlot,
  encodeRetrievalKeySlot,
  encodeRelationEdge,
  encodeTemporalRecord,
  encodeCodebookEntry,
  biEncoderModelIdHash,
  structuralValidity,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const ZERO_STATE = { words: new Array(1024).fill(0n) };

function withWords(state, indexed) {
  const words = [...state.words];
  for (const [i, v] of indexed) words[i] = v;
  return { words };
}

function placeSlot(baseStart, slotIndex, slotWords) {
  const out = [];
  for (let i = 0; i < slotWords.length; i++) {
    out.push([baseStart + slotIndex * slotWords.length + i, slotWords[i]]);
  }
  return out;
}

describe('retrieval decoder — round-trip', () => {
  test('memory index slot encode→decode is lossless', () => {
    const slot = {
      slotIndex: 3,
      recordId: BigInt('0x' + 'ab'.repeat(16)),
      family: 'multi_hop_relation',
      domainBits: 0x1n,
      valid: true,
      revoked: false,
      protected: true,
      retrievalSlot: 17,
      expiryEpoch: 12345n,
    };
    const enc = encodeMemoryIndexSlot(slot);
    const indexed = enc.map((v, i) => [RANGES.MEMORY_INDEX_START + 3 * 8 + i, v]);
    const state = withWords(ZERO_STATE, indexed);
    const { slots } = decodeMemoryIndex(state);
    const got = slots[3];
    assert.equal(got.recordId, slot.recordId);
    assert.equal(got.family, slot.family);
    assert.equal(got.domainBits, slot.domainBits);
    assert.equal(got.valid, true);
    assert.equal(got.protected, true);
    assert.equal(got.retrievalSlot, slot.retrievalSlot);
    assert.equal(got.expiryEpoch, slot.expiryEpoch);
  });

  test('decoder zeroes memory slots with reserved bits set', () => {
    const slot = {
      slotIndex: 0,
      recordId: 1n,
      family: 'near_collision',
      domainBits: 0n,
      valid: true,
      revoked: false,
      protected: false,
      retrievalSlot: 0,
      expiryEpoch: 0n,
    };
    const enc = encodeMemoryIndexSlot(slot);
    const indexed = enc.map((v, i) => [RANGES.MEMORY_INDEX_START + i, v]);
    indexed[3][1] = 0xdeadn;          // pollute payload word 3
    const state = withWords(ZERO_STATE, indexed);
    const { slots, failures } = decodeMemoryIndex(state);
    assert.equal(slots[0], null);
    assert.equal(failures, 1);
  });

  test('retrieval key slot encode→decode preserves vector bytes', () => {
    const layout = { dim: 16, quantization: 'int8', headerBytes: 9 };
    const modelHash = biEncoderModelIdHash('BAAI/bge-m3', 'a'.repeat(40), 'dense');
    const quantized = new Uint8Array(247);
    for (let i = 0; i < quantized.length; i++) quantized[i] = (i * 7) & 0xff;
    const slot = {
      slotIndex: 2,
      modelIdHash: modelHash,
      l2Norm: 1.5,
      versionTag: 1,
      quantizedBytes: quantized,
    };
    const enc = encodeRetrievalKeySlot(slot, { retrievalKeyHeaderBytes: 9 });
    const indexed = enc.map((v, i) => [RANGES.RETRIEVAL_KEYS_START + 2 * 8 + i, v]);
    const state = withWords(ZERO_STATE, indexed);
    const { slots } = decodeRetrievalKeys(state, {
      biEncoderModelIdHash: modelHash,
      retrievalKeyHeaderBytes: 9,
    });
    assert.equal(slots[2].versionTag, 1);
    assert.equal(slots[2].modelIdHash.toLowerCase(), modelHash.toLowerCase());
    assert.ok(Math.abs(slots[2].l2Norm - 1.5) < 1e-6);
    for (let i = 0; i < quantized.length; i++) {
      assert.equal(slots[2].quantizedBytes[i], quantized[i]);
    }
    void layout;
  });

  test('retrieval key slot zeroes when modelIdHash mismatches bundle pin', () => {
    const slot = {
      slotIndex: 0,
      modelIdHash: '0xdeadbeef',
      l2Norm: 1.0,
      versionTag: 1,
      quantizedBytes: new Uint8Array(100),
    };
    const enc = encodeRetrievalKeySlot(slot, { retrievalKeyHeaderBytes: 9 });
    const indexed = enc.map((v, i) => [RANGES.RETRIEVAL_KEYS_START + i, v]);
    const state = withWords(ZERO_STATE, indexed);
    const { slots, failures } = decodeRetrievalKeys(state, { biEncoderModelIdHash: '0xcafebabe' });
    assert.equal(slots[0], null);
    assert.equal(failures, 1);
  });

  test('relation edge encode→decode round-trip', () => {
    const edge = { entryIndex: 7, weight: 1234, edgeType: 'supersedes', sourceSlot: 5, targetSlot: 12 };
    const word = encodeRelationEdge(edge);
    const state = withWords(ZERO_STATE, [[RANGES.RELATIONS_START + 7, word]]);
    const { edges } = decodeRelations(state);
    assert.equal(edges.length, 1);
    assert.equal(edges[0].weight, 1234);
    assert.equal(edges[0].edgeType, 'supersedes');
    assert.equal(edges[0].sourceSlot, 5);
    assert.equal(edges[0].targetSlot, 12);
  });

  test('relation edge zeroes when slot index >= 44', () => {
    const edge = { entryIndex: 0, weight: 100, edgeType: 'supports', sourceSlot: 10, targetSlot: 50 };
    const word = encodeRelationEdge({ ...edge, targetSlot: 10 }); // encode valid first
    // Manually set targetSlot bits to 50 (out of range)
    const polluted = (word & ~((1n << 96n) - 1n)) | 50n;
    const state = withWords(ZERO_STATE, [[RANGES.RELATIONS_START, polluted]]);
    const { edges, failures } = decodeRelations(state);
    assert.equal(edges.length, 0);
    assert.equal(failures, 1);
  });

  test('temporal record encode→decode round-trip', () => {
    const rec = {
      recordIndex: 0,
      memorySlot: 5,
      supersededBy: 10,
      validFromEpoch: 100n,
      validUntilEpoch: 200n,
      currentStaleFlag: false,
    };
    const enc = encodeTemporalRecord(rec);
    const indexed = enc.map((v, i) => [RANGES.TEMPORAL_START + i, v]);
    const state = withWords(ZERO_STATE, indexed);
    const { records } = decodeTemporal(state);
    assert.equal(records.length, 1);
    assert.equal(records[0].memorySlot, 5);
    assert.equal(records[0].validFromEpoch, 100n);
    assert.equal(records[0].validUntilEpoch, 200n);
  });

  test('codebook entry encode→decode round-trip', () => {
    const entry = {
      entryIndex: 4,
      code: 0x1234,
      codeType: 'int8_scale_zero',
      valid: true,
      payload: 0xabcdn,
      payloadCont: 0xfeedn,
    };
    const enc = encodeCodebookEntry(entry);
    const indexed = enc.map((v, i) => [RANGES.CODEBOOK_START + 4 * 2 + i, v]);
    const state = withWords(ZERO_STATE, indexed);
    const { entries } = decodeCodebook(state);
    assert.equal(entries[4].code, 0x1234);
    assert.equal(entries[4].codeType, 'int8_scale_zero');
    assert.equal(entries[4].valid, true);
  });

  test('decodeSubstrate composes with structuralValidity = 1.0 on empty state', () => {
    const decoded = decodeSubstrate(ZERO_STATE);
    assert.equal(structuralValidity(decoded), 1);
    assert.equal(decoded.decodeAttempts, 0);
  });

  test('property fuzz: 1000 random memory-index slots round-trip exactly', () => {
    let xor = 0xcafebabe;
    function nextRand() {
      xor ^= xor << 13; xor >>>= 0;
      xor ^= xor >>> 17;
      xor ^= xor << 5; xor >>>= 0;
      return xor / 0xffffffff;
    }
    for (let i = 0; i < 1000; i++) {
      const slot = {
        slotIndex: 0,
        recordId: BigInt(Math.floor(nextRand() * 0x1000000)) << 64n | BigInt(Math.floor(nextRand() * 0x1000000)),
        family: ['near_collision', 'temporal', 'long_horizon', 'multi_hop_relation'][Math.floor(nextRand() * 4)],
        domainBits: BigInt(Math.floor(nextRand() * 0xffff)),
        valid: true,
        revoked: nextRand() < 0.1,
        protected: nextRand() < 0.1,
        retrievalSlot: Math.floor(nextRand() * 36),
        expiryEpoch: BigInt(Math.floor(nextRand() * 1_000_000)),
      };
      if (slot.recordId === 0n) slot.recordId = 1n;
      const enc = encodeMemoryIndexSlot(slot);
      const indexed = enc.map((v, j) => [RANGES.MEMORY_INDEX_START + j, v]);
      const state = withWords(ZERO_STATE, indexed);
      const { slots, failures } = decodeMemoryIndex(state);
      assert.equal(failures, 0, `iteration ${i} produced decode failure`);
      const got = slots[0];
      assert.equal(got.recordId, slot.recordId);
      assert.equal(got.family, slot.family);
      assert.equal(got.retrievalSlot, slot.retrievalSlot);
      assert.equal(got.expiryEpoch, slot.expiryEpoch);
      assert.equal(got.revoked, slot.revoked);
      assert.equal(got.protected, slot.protected);
    }
  });
});
