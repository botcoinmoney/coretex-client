/**
 * Unit tests: patch wire encode/decode and applyPatch.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  encodeLEB128, decodeLEB128,
  encodePatch, decodePatch, applyPatch, applyPatchOntoCurrent, validatePatchType,
  buildAllowedPatchTypes,
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

  test('rejects non-canonical and out-of-range word-index encodings', () => {
    assert.throws(() => decodeLEB128(new Uint8Array([0x80, 0x00]), 0), /non-canonical/);
    assert.throws(() => decodeLEB128(new Uint8Array([0x80, 0x08]), 0), /out of range/);
    assert.throws(() => decodeLEB128(new Uint8Array([0x80, 0x80, 0x00]), 0), /varint too long/);
  });
});

// ─── Patch helpers ─────────────────────────────────────────────────────────────

function makePatch(overrides = {}) {
  return {
    patchType: PATCH_TYPE.KEY_UPDATE,
    wordCount: 1,
    scoreDelta: 1000000n,
    parentStateRoot: new Uint8Array(32).fill(0xab),
    indices: [401],
    newWords: [0x123456789n],
    ...overrides,
  };
}

function validIndexForPatchType(patchType) {
  switch (patchType) {
    case PATCH_TYPE.KEY_UPDATE: return 401;
    case PATCH_TYPE.SLOT_REPLACE: return 40;
    case PATCH_TYPE.TEMPORAL_UPDATE: return 805;
    case PATCH_TYPE.RELATION_UPDATE: return 700;
    case PATCH_TYPE.CODEBOOK_UPDATE: return 900;
    case PATCH_TYPE.HEADER_UPDATE: return 1;
    case PATCH_TYPE.POLICY_UPDATE: return 384; // r5 PolicyAtom region (evidence-bundle)
    case PATCH_TYPE.MIXED: return 401;
    default: throw new Error(`unknown patch type ${patchType}`);
  }
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
      patchType: PATCH_TYPE.SLOT_REPLACE,
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

  test('encode rejects scoreDelta outside the non-negative int64 wire range', () => {
    // Solidity reads the wire scoreDelta as uint64 and reverts when the top bit is set,
    // so negative (and > int64.max) values must be encode-time validity errors, not
    // silent two's-complement wraps.
    assert.throws(() => encodePatch(makePatch({ scoreDelta: -500000n })), /non-negative int64/);
    assert.throws(() => encodePatch(makePatch({ scoreDelta: 1n << 63n })), /non-negative int64/);
    const max = (1n << 63n) - 1n;
    assert.equal(decodePatch(encodePatch(makePatch({ scoreDelta: max }))).scoreDelta, max);
  });

  test('decode rejects wire scoreDelta with the top bit set', () => {
    const wire = encodePatch(makePatch());
    wire[2] |= 0x80; // set the top bit of scoreDeltaHi
    assert.throws(() => decodePatch(wire), /non-negative int64/);
  });

  test('encode/decode: all patch types', () => {
    const types = Object.values(PATCH_TYPE);
    for (const t of types) {
      const idx = validIndexForPatchType(t);
      const patch = makePatch({ patchType: t, indices: [idx] });
      const decoded = decodePatch(encodePatch(patch));
      assert.equal(decoded.patchType, t);
    }
  });

  test('encode throws on wordCount > 4', () => {
    assert.throws(() => encodePatch(makePatch({ wordCount: 5, indices: [1,2,3,4,5], newWords: [1n,2n,3n,4n,5n] })));
  });

  test('encode rejects patch type/index range mismatches', () => {
    assert.throws(() => encodePatch(makePatch({
      patchType: PATCH_TYPE.KEY_UPDATE,
      indices: [32],
    })), /patchType/);
    assert.throws(() => encodePatch(makePatch({
      patchType: PATCH_TYPE.SLOT_REPLACE,
      indices: [384],
    })), /patchType/);
    assert.throws(() => encodePatch(makePatch({
      patchType: 0x7e,
      indices: [384],
    })), /unknown patchType/);
  });

  test('duplicate word indices within one patch are a validity error', () => {
    // encode rejects
    assert.throws(() => encodePatch(makePatch({
      wordCount: 2,
      indices: [385, 385],
      newWords: [1n, 2n],
    })), /duplicate word index/);
    assert.equal(validatePatchType(PATCH_TYPE.KEY_UPDATE, [385, 385]).ok, false);

    // decode rejects: craft wire bytes with a repeated index (both indices are
    // 2-byte LEB128: word 1 index at offsets 42–43, word 2 index at 76–77)
    const wire = encodePatch(makePatch({
      wordCount: 2,
      indices: [385, 386],
      newWords: [1n, 2n],
    }));
    wire[76] = wire[42];
    wire[77] = wire[43];
    assert.throws(() => decodePatch(wire), /duplicate word index/);
  });

  test('validatePatchType accepts mixed non-reserved ranges', () => {
    assert.deepEqual(validatePatchType(PATCH_TYPE.MIXED, [40, 401, 700, 805]), { ok: true });
    assert.equal(validatePatchType(PATCH_TYPE.MIXED, [992]).ok, false);
  });

  test('decode throws on truncated input', () => {
    assert.throws(() => decodePatch(new Uint8Array(10)));
  });

  test('decode rejects trailing bytes after declared words', () => {
    const wire = encodePatch(makePatch());
    const withTrailing = new Uint8Array(wire.length + 1);
    withTrailing.set(wire);
    withTrailing[withTrailing.length - 1] = 0xff;
    assert.throws(() => decodePatch(withTrailing), /trailing bytes/);
  });

  test('decode rejects overlong LEB128 word indices before signing', () => {
    const wire = encodePatch(makePatch({
      patchType: PATCH_TYPE.SLOT_REPLACE,
      indices: [32],
      newWords: [1n],
    }));
    const malformed = new Uint8Array(wire.length + 1);
    malformed.set(wire.slice(0, 42), 0);
    malformed[42] = 0x80 | 32;
    malformed[43] = 0x00;
    malformed.set(wire.slice(43), 44);
    assert.throws(() => decodePatch(malformed), /non-canonical/);
  });

  test('decode rejects Solidity-rejected patch type/index bytes before signing', () => {
    const wire = encodePatch(makePatch({
      patchType: PATCH_TYPE.SLOT_REPLACE,
      indices: [32],
      newWords: [1n],
    }));
    const badType = new Uint8Array(wire);
    badType[0] = PATCH_TYPE.KEY_UPDATE;
    assert.throws(() => decodePatch(badType), /cannot target index 32/);
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
      indices: [401],
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
      indices: [401],
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

  test('E02: patch type/index mismatch rejected', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      patchType: PATCH_TYPE.KEY_UPDATE,
      parentStateRoot: root,
      indices: [32],
      newWords: [1n],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E02');
  });

  test('E02: duplicate word indices rejected on apply', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      wordCount: 2,
      parentStateRoot: root,
      indices: [401, 401],
      newWords: [1n, 2n],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E02');
    const onto = applyPatchOntoCurrent(state, patch);
    assert.equal(onto.ok, false);
    assert.equal(onto.code, 'E02');
  });

  test('applyPatchOntoCurrent rejects patch type/index mismatch', () => {
    const state = makeCleanState();
    const patch = makePatch({
      patchType: PATCH_TYPE.SLOT_REPLACE,
      parentStateRoot: merkleizeState(state),
      indices: [384],
      newWords: [1n],
    });
    const result = applyPatchOntoCurrent(state, patch);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'E02');
  });

  test('E04: resulting state with reserved bit rejected', () => {
    // Word 0 bits 191:0 are reserved — setting bit 0 should fail
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      patchType: PATCH_TYPE.HEADER_UPDATE,
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
    // Word 401 is in RetrievalKeys KEY_VECTOR range — no reserved bits constraint.
    const patch = makePatch({
      parentStateRoot: root,
      indices: [401],
      newWords: [0xdeadbeefn],
    });
    const result = applyPatch(state, patch);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.state.words[401], 0xdeadbeefn);
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
      indices: [401],
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

describe('r5 header freeze (policyAtomsMode)', () => {
  test('HEADER_UPDATE is rejected E02 under policyAtomsMode (header words are not minable)', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      patchType: PATCH_TYPE.HEADER_UPDATE,
      parentStateRoot: root,
      indices: [2], // word 2: full-word writable under the r4 masks
      newWords: [0x1234n],
    });
    // r4: header writes remain possible (subject to reserved masks).
    assert.equal(applyPatch(state, patch).ok, true);
    // r5: frozen — E02 regardless of value.
    const r5 = applyPatch(state, patch, true);
    assert.equal(r5.ok, false);
    assert.equal(r5.code, 'E02');
  });

  test('MIXED touching a header word is rejected E02 under policyAtomsMode', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = makePatch({
      patchType: PATCH_TYPE.MIXED,
      wordCount: 2,
      parentStateRoot: root,
      indices: [2, 40], // header word + MemoryIndex word
      newWords: [0x99n, 0x42n],
    });
    assert.equal(applyPatch(state, patch).ok, true, 'r4 unchanged');
    const r5 = applyPatch(state, patch, true);
    assert.equal(r5.ok, false);
    assert.equal(r5.code, 'E02');
  });

  test('buildAllowedPatchTypes: r5 suppresses HEADER_UPDATE and MIXED starts at the MemoryIndex region', () => {
    const r5 = buildAllowedPatchTypes({ pipelineVersion: 'coretex-retrieval-v2-policy-r5' });
    assert.equal(r5.find((t) => t.name === 'HEADER_UPDATE'), undefined);
    const mixed = r5.find((t) => t.name === 'MIXED');
    assert.deepEqual(mixed.wordIndexRange, [RANGES.MEMORY_INDEX_START, RANGES.CODEBOOK_END]);
    // r4 advertisement unchanged.
    const r4 = buildAllowedPatchTypes();
    assert.ok(r4.find((t) => t.name === 'HEADER_UPDATE'));
    assert.deepEqual(r4.find((t) => t.name === 'MIXED').wordIndexRange, [0, RANGES.CODEBOOK_END]);
  });
});
