/**
 * Unit tests: reserved-bit validation.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { hasNonZeroReservedBits, validateReservedBits } from '../../dist/state/validate.js';
import { RANGES } from '../../dist/state/types.js';

function makeState(overrides = {}) {
  const words = new Array(1024).fill(0n);
  for (const [k, v] of Object.entries(overrides)) {
    words[Number(k)] = v;
  }
  return { words };
}

describe('reserved-bit validation', () => {
  test('all-zero state passes', () => {
    const state = makeState();
    assert.equal(hasNonZeroReservedBits(state), false);
    assert.equal(validateReservedBits(state), null);
  });

  test('reserved word 992 non-zero fails', () => {
    const state = makeState({ 992: 1n });
    assert.equal(hasNonZeroReservedBits(state), true);
    const err = validateReservedBits(state);
    assert.ok(err !== null);
    assert.equal(err.code, 'E04');
  });

  test('reserved word 1023 non-zero fails', () => {
    const state = makeState({ 1023: (1n << 255n) });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('word 0: non-reserved bits can be set', () => {
    // Named bits: 255:240 (MAGIC), 239:224 (SCHEMA_VERSION), 223:208 (WORD_COUNT), 207:192 (FLAGS)
    // Set word 0 to a valid-looking value using only named field bits
    const magic = 0xC07En << 240n;
    const schemaVer = 0x0000n << 224n;
    const wordCount = 1024n << 208n;
    const flags = 0x0001n << 192n; // genesis flag set
    const state = makeState({ 0: magic | schemaVer | wordCount | flags });
    assert.equal(hasNonZeroReservedBits(state), false);
  });

  test('word 0: reserved bits 191:0 fail if set', () => {
    const state = makeState({ 0: 1n }); // bit 0 is reserved
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('word 0: FLAGS reserved bits 207:193 fail', () => {
    // FLAGS bit 1 (bit 193 in word) is reserved
    const state = makeState({ 0: (1n << 193n) });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('word 1: reserved bits 127:0 fail', () => {
    const state = makeState({ 1: 1n });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('word 1: epoch bits are fine', () => {
    const epoch = 100n << 192n;
    const state = makeState({ 1: epoch });
    assert.equal(hasNonZeroReservedBits(state), false);
  });

  test('words 11–31 are fully reserved', () => {
    for (let w = 11; w <= 31; w++) {
      const state = makeState({ [w]: 1n });
      assert.equal(hasNonZeroReservedBits(state), true, `word ${w} should fail`);
    }
  });

  test('word 8: reserved bits 63:0 fail', () => {
    const state = makeState({ 8: 1n });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('word 8: non-reserved bits pass', () => {
    const reducer = 999n << 64n;
    const state = makeState({ 8: reducer });
    assert.equal(hasNonZeroReservedBits(state), false);
  });

  test('MemoryIndex slot0 reserved bits 63:0 fail', () => {
    // word 32 is slot 0, slot-word 0; reserved = bits 63:0 + VALIDITY_FLAGS 79:67
    const state = makeState({ 32: 1n }); // bit 0 reserved
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('MemoryIndex slot0 VALIDITY_FLAGS reserved bits fail', () => {
    // VALIDITY_FLAGS reserved bits 79:67, e.g. bit 69
    const state = makeState({ 32: (1n << 69n) });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('MemoryIndex slot0 non-reserved fields pass', () => {
    // EVENT_ID: bits 255:128, DOMAIN_CODE: 127:96, OBJ_TYPE: 95:80
    // VALIDITY_FLAGS: 79:64 — only bits 79:67 reserved, bits 66:64 are named (active/stale/revoked)
    const eventId = 0x1234567890ABCDEFn << 128n;
    const validityFlags = 0x0001n << 64n; // active bit, bit 64
    const state = makeState({ 32: eventId | validityFlags });
    assert.equal(hasNonZeroReservedBits(state), false);
  });

  test('Relations entry: reserved bits 191:0 fail', () => {
    // word 672 is Relations entry 0
    const state = makeState({ 672: 1n });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('Relations entry: non-reserved bits pass', () => {
    // SRC_IDX: bits 255:240, DST_IDX: 239:224, REL_TYPE: 223:208, WEIGHT: 207:192
    const srcIdx = 5n << 240n;
    const dstIdx = 10n << 224n;
    const relType = 1n << 208n;
    const weight = 256n << 192n;
    const state = makeState({ 672: srcIdx | dstIdx | relType | weight });
    assert.equal(hasNonZeroReservedBits(state), false);
  });

  test('Temporal entry: reserved bits 31:0 fail', () => {
    // word 800 is Temporal entry 0
    const state = makeState({ 800: 1n });
    assert.equal(hasNonZeroReservedBits(state), true);
  });

  test('Codebook slot0: reserved bits 207:0 fail', () => {
    // word 896 = codebook slot 0, slot-word 0
    const state = makeState({ 896: 1n });
    assert.equal(hasNonZeroReservedBits(state), true);
  });
});
