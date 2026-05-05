/**
 * Unit tests: patch wire encode/decode and applyPatch.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  encodeLEB128, decodeLEB128,
  encodePatch, decodePatch, applyPatch,
} from '../../dist/state/patch.js';
import { merkleizeState, bytesToHex } from '../../dist/state/merkle.js';
import { RANGES, PATCH_TYPE } from '../../dist/state/types.js';

// ─── LEB128 tests ──────────────────────────────────────────────────────────────

describe('LEB128 varint', () => {
  const cases = [
    [0,    [0x00]],
    [1,    [0x01]],
    [127,  [0x7f]],
    [128,  [0x80, 0x01]],
    [300,  [0xac, 0x02]],
    [1023, [0xff, 0x07]],
  ];

  for (const [n, expected] of cases) {
    test(`encodeLEB128(${n})`, () => {
      const enc = encodeLEB128(n);
      assert.deepEqual([...enc], expected);
    });

    test(`decodeLEB128(${n})`, () => {
      const enc = encodeLEB128(n);
      const { value, bytesRead } = decodeLEB128(enc, 0);
      assert.equal(value, n);
      assert.equal(bytesRead, expected.length);
    });
  }

  test('round-trip: indices 0–1023', () => {
    for (let i = 0; i < 1024; i++) {
      const enc = encodeLEB128(i);
      const { value } = decodeLEB128(enc, 0);
      assert.equal(value, i);
    }
  });

  test('indices 0–127 encode to 1 byte', () => {
    for (let i = 0; i < 128; i++) {
      assert.equal(encodeLEB128(i).length, 1);
    }
  });

  test('indices 128–1023 encode to 2 bytes', () => {
    for (let i = 128; i <= 1023; i++) {
      assert.equal(encodeLEB128(i).length, 2);
    }
  });
});

// ─── Patch helpers ─────────────────────────────────────────────────────────────

function makePatch(overrides = {}) {
  return {
    patchType: PATCH_TYPE.KEY_UPDATE,
    wordCount: 1,
    scoreDelta: 1000000n,
    parentStateRoot: new Uint8Array(32).fill(0xab),
    indices: [400],
    newWords: [0x123456789n],
    ...overrides,
  };
}

// ─── Encode/decode tests ──────────────────────────────────────────────────────

describe('patch wire encode/decode', () => {
  test('round-trip: 1-word patch', () => {
    const patch = makePatch();
    const wire = encodePatch(patch);
    const decoded = decodePatch(wire);
    assert.equal(decoded.patchType, patch.patchType);
    assert.equal(decoded.wordCount, patch.wordCount);
    assert.equal(decoded.scoreDelta, patch.scoreDelta);
    assert.deepEqual([...decoded.parentStateRoot], [...patch.parentStateRoot]);
    assert.deepEqual(decoded.indices, patch.indices);
    assert.deepEqual(decoded.newWords, patch.newWords);
  });

  test('round-trip: 4-word patch', () => {
    const patch = makePatch({
      wordCount: 4,
      indices: [384, 400, 500, 671],
      newWords: [1n, 2n, 3n, 4n],
    });
    const wire = encodePatch(patch);
    const decoded = decodePatch(wire);
    assert.equal(decoded.wordCount, 4);
    assert.deepEqual(decoded.indices, [384, 400, 500, 671]);
    assert.deepEqual(decoded.newWords, [1n, 2n, 3n, 4n]);
  });

  test('wire size: 4-word patch, indices < 128 ≤ 174 bytes', () => {
    const patch = makePatch({
      wordCount: 4,
      indices: [32, 40, 50, 60],
      newWords: [1n, 2n, 3n, 4n],
    });
    const wire = encodePatch(patch);
    // 1+1+8+32 + 4*(1+32) = 42 + 132 = 174
    assert.equal(wire.length, 174);
  });

  test('wire size: 4-word patch, indices >= 128 = 178 bytes', () => {
    const patch = makePatch({
      wordCount: 4,
      indices: [384, 400, 500, 671],
      newWords: [1n, 2n, 3n, 4n],
    });
    const wire = encodePatch(patch);
    // 1+1+8+32 + 4*(2+32) = 42 + 136 = 178
    assert.equal(wire.length, 178);
  });

  test('encode/decode round-trip preserves score delta (negative)', () => {
    const patch = makePatch({ scoreDelta: -500000n });
    const wire = encodePatch(patch);
    const decoded = decodePatch(wire);
    assert.equal(decoded.scoreDelta, -500000n);
  });

  test('encode/decode: all patch types', () => {
    const types = Object.values(PATCH_TYPE);
    for (const t of types) {
      const patch = makePatch({ patchType: t });
      const decoded = decodePatch(encodePatch(patch));
      assert.equal(decoded.patchType, t);
    }
  });

  test('encode throws on wordCount > 4', () => {
    assert.throws(() => encodePatch(makePatch({ wordCount: 5, indices: [1,2,3,4,5], newWords: [1n,2n,3n,4n,5n] })));
  });

  test('decode throws on truncated input', () => {
    assert.throws(() => decodePatch(new Uint8Array(10)));
  });
});

// ─── applyPatch tests ──────────────────────────────────────────────────────────

function makeCleanState() {
  return { words: new Array(1024).fill(0n) };
}

describe('applyPatch', () => {
  test('E03: wordCount > 4 rejected', () => {
    const state = makeCleanState();
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 5,
      scoreDelta: 0n,
      parentStateRoot: merkleizeState(state),
      indices: [400, 401, 402, 403, 404],
      newWords: [1n, 2n, 3n, 4n, 5n],
    };
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E03');
  });

  test('E01: wrong parent root rejected', () => {
    const state = makeCleanState();
    const patch = makePatch({
      parentStateRoot: new Uint8Array(32).fill(0xff),
      indices: [400],
      newWords: [1n],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E01');
  });

  test('E05: no-op patch rejected', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      parentStateRoot: root,
      indices: [400],
      newWords: [0n], // same as current (all-zero state)
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E05');
  });

  test('E02: reserved range (word 992) rejected', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      parentStateRoot: root,
      indices: [992],
      newWords: [1n],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E02');
  });

  test('E04: resulting state with reserved bit rejected', () => {
    // Word 0 bits 191:0 are reserved — setting bit 0 should fail
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      parentStateRoot: root,
      indices: [0],
      newWords: [1n], // sets bit 0 which is reserved in word 0
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E04');
  });

  test('successful patch: KEY_UPDATE', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    // Word 400 is in RetrievalKeys range (384–671) — no reserved bits constraint
    const patch = makePatch({
      parentStateRoot: root,
      indices: [400],
      newWords: [0xdeadbeefn],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.state.words[400], 0xdeadbeefn);
    }
  });

  test('successful multi-word patch', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      wordCount: 3,
      parentStateRoot: root,
      indices: [385, 386, 387],
      newWords: [111n, 222n, 333n],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.state.words[385], 111n);
      assert.equal(result.state.words[386], 222n);
      assert.equal(result.state.words[387], 333n);
    }
  });

  test('applied patch produces correct new root', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const newWordValue = 0xdeadbeefcafebaben;
    const patch = makePatch({
      parentStateRoot: root,
      indices: [400],
      newWords: [newWordValue],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, true);
    if (result.ok) {
      // Verify the new root is different and deterministic
      const newRoot1 = merkleizeState(result.state);
      const newRoot2 = merkleizeState(result.state);
      assert.deepEqual(newRoot1, newRoot2);
      assert.notDeepEqual(newRoot1, root);
    }
  });
});
