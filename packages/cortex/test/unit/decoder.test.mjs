/**
 * Unit tests: typed-slot decoder for CortexState V0.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { decodeCortexState, isTemporallyValid } from '../../dist/decoder/index.js';
import { RANGES, MAGIC, SCHEMA_VERSION_V0, WORD_COUNT_VALUE } from '../../dist/state/types.js';
import { getField, setField } from '../../dist/state/codec.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeBlankState() {
  return { words: new Array(1024).fill(0n) };
}

/**
 * Build a valid CortexState V0 header in word 0.
 * MAGIC in bits 255:240, SCHEMA_VERSION_V0 in 239:224, WORD_COUNT_VALUE in 223:208.
 */
function makeValidState() {
  const words = new Array(1024).fill(0n);
  let w0 = 0n;
  w0 = setField(w0, 255, 240, MAGIC);
  w0 = setField(w0, 239, 224, SCHEMA_VERSION_V0);
  w0 = setField(w0, 223, 208, WORD_COUNT_VALUE);
  words[0] = w0;
  return { words };
}

// ─── Decode error cases ───────────────────────────────────────────────────────

describe('decodeCortexState — error cases', () => {
  test('DECODE_WRONG_LENGTH on 512-word state', () => {
    const state = { words: new Array(512).fill(0n) };
    const result = decodeCortexState(state);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'DECODE_WRONG_LENGTH');
  });

  test('DECODE_WRONG_MAGIC on zero state', () => {
    const result = decodeCortexState(makeBlankState());
    assert.equal(result.ok, false);
    assert.equal(result.code, 'DECODE_WRONG_MAGIC');
  });

  test('DECODE_WRONG_VERSION on wrong schema version', () => {
    const words = new Array(1024).fill(0n);
    let w0 = 0n;
    w0 = setField(w0, 255, 240, MAGIC);
    w0 = setField(w0, 239, 224, 0x0001n); // wrong version
    w0 = setField(w0, 223, 208, WORD_COUNT_VALUE);
    words[0] = w0;
    const result = decodeCortexState({ words });
    assert.equal(result.ok, false);
    assert.equal(result.code, 'DECODE_WRONG_VERSION');
  });

  test('DECODE_WRONG_WORD_COUNT on wrong word count field', () => {
    const words = new Array(1024).fill(0n);
    let w0 = 0n;
    w0 = setField(w0, 255, 240, MAGIC);
    w0 = setField(w0, 239, 224, SCHEMA_VERSION_V0);
    w0 = setField(w0, 223, 208, 512n); // wrong
    words[0] = w0;
    const result = decodeCortexState({ words });
    assert.equal(result.ok, false);
    assert.equal(result.code, 'DECODE_WRONG_WORD_COUNT');
  });
});

// ─── Decode success cases ─────────────────────────────────────────────────────

describe('decodeCortexState — success cases', () => {
  test('decodes valid state without error', () => {
    const result = decodeCortexState(makeValidState());
    assert.equal(result.ok, true);
  });

  test('header fields decoded correctly', () => {
    const state = makeValidState();
    // Set epoch and timestamp in word 1
    let w1 = 0n;
    w1 = setField(w1, 255, 192, 42n);   // EPOCH
    w1 = setField(w1, 191, 128, 9999n); // EPOCH_START_TIMESTAMP
    state.words[1] = w1;
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.header.epoch, 42n);
      assert.equal(result.decoded.header.epochStartTimestamp, 9999n);
      assert.equal(result.decoded.header.magic, Number(MAGIC));
      assert.equal(result.decoded.header.schemaVersion, Number(SCHEMA_VERSION_V0));
    }
  });

  test('genesis flag decoded from FLAGS bit 0', () => {
    const state = makeValidState();
    // Set FLAGS bit 0 = genesis
    let w0 = state.words[0];
    w0 = setField(w0, 192, 192, 1n); // bit 192 = bit 0 of FLAGS field
    state.words[0] = w0;
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.header.genesisState, true);
    }
  });

  test('memoryIndex has 44 slots', () => {
    const result = decodeCortexState(makeValidState());
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.memoryIndex.length, 44);
    }
  });

  test('retrievalKeys has 36 slots', () => {
    const result = decodeCortexState(makeValidState());
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.retrievalKeys.length, 36);
    }
  });

  test('relations has 128 entries', () => {
    const result = decodeCortexState(makeValidState());
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.relations.length, 128);
    }
  });

  test('temporal has 96 entries', () => {
    const result = decodeCortexState(makeValidState());
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.temporal.length, 96);
    }
  });

  test('codebook has 48 entries', () => {
    const result = decodeCortexState(makeValidState());
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.codebook.length, 48);
    }
  });
});

// ─── Memory index slot decoding ───────────────────────────────────────────────

describe('memoryIndex slot decoding', () => {
  test('slot 0 decodes from words 32–39', () => {
    const state = makeValidState();
    // Set EVENT_ID (bits 255:128) of word 32
    const eventId = 0xDEADBEEFCAFEBABEn;
    state.words[32] = setField(0n, 255, 128, eventId);
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      const slot = result.decoded.memoryIndex[0];
      assert.ok(slot !== undefined);
      assert.equal(slot.eventId, eventId);
      assert.equal(slot.wordBase, 32);
    }
  });

  test('VALID flag decodes from bit 64 of word 0 in slot', () => {
    const state = makeValidState();
    // validity_flags bit 0 = bit 64 of word 32
    state.words[32] = setField(state.words[32] ?? 0n, 64, 64, 1n);
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.memoryIndex[0]?.valid, true);
    }
  });
});

// ─── Retrieval key decoding ───────────────────────────────────────────────────

describe('retrievalKeys slot decoding', () => {
  test('slot 0 decodes from words 384–391', () => {
    const state = makeValidState();
    const keyId = 0x123456789ABCDEFn;
    state.words[384] = setField(0n, 255, 128, keyId);
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.retrievalKeys[0]?.keyId, keyId);
      assert.equal(result.decoded.retrievalKeys[0]?.wordBase, 384);
    }
  });

  test('active flag from bit 80 of word 384', () => {
    const state = makeValidState();
    state.words[384] = setField(state.words[384] ?? 0n, 80, 80, 1n);
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.retrievalKeys[0]?.active, true);
    }
  });
});

// ─── Temporal entry decoding ──────────────────────────────────────────────────

describe('temporal entry decoding', () => {
  test('revocation flag decoded', () => {
    const state = makeValidState();
    // Word 800: temporal entry 0. Set revoked = bit 0
    state.words[800] = setField(0n, 0, 0, 1n);
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.temporal[0]?.revoked, true);
    }
  });

  test('revokedEventIds set includes non-zero revoked event IDs', () => {
    const state = makeValidState();
    const eventId = 0xABCDn;
    // Set eventId (bits 255:96) and revoked (bit 0)
    let w = 0n;
    w = setField(w, 255, 96, eventId);
    w = setField(w, 0, 0, 1n);
    state.words[800] = w;
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.revokedEventIds.has(eventId), true);
    }
  });
});

// ─── Route building ───────────────────────────────────────────────────────────

describe('route building', () => {
  test('active key routes to valid memory slots with matching objType', () => {
    const state = makeValidState();
    // Make retrieval key slot 0 active, keyType = 5
    const k0base = RANGES.RETRIEVAL_KEYS_START; // 384
    let kw = 0n;
    kw = setField(kw, 127, 112, 5n); // keyType = 5
    kw = setField(kw, 80, 80, 1n);   // active = true
    state.words[k0base] = kw;

    // Make memory slot 0 valid, objType = 5
    const m0base = RANGES.MEMORY_INDEX_START; // 32
    let mw = 0n;
    mw = setField(mw, 95, 80, 5n); // objType = 5
    mw = setField(mw, 64, 64, 1n); // valid = true
    state.words[m0base] = mw;

    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      const route = result.decoded.routes.get(0);
      assert.ok(route !== undefined);
      assert.ok(route.includes(0));
    }
  });

  test('inactive key has no route', () => {
    const state = makeValidState();
    // Key 0 is inactive (default)
    const result = decodeCortexState(state);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.decoded.routes.has(0), false);
    }
  });
});

// ─── isTemporallyValid ────────────────────────────────────────────────────────

describe('isTemporallyValid', () => {
  function makeSlot(overrides = {}) {
    return {
      slotIndex: 0,
      wordBase: 32,
      eventId: 1n,
      domainCode: 0,
      objType: 0,
      validityFlags: 1,
      valid: true,
      revoked: false,
      checksum: 0n,
      corpusEpoch: 0n,
      expiryEpoch: 0n,
      payloadWords: [0n, 0n, 0n, 0n, 0n, 0n],
      ...overrides,
    };
  }

  test('valid, not revoked, no expiry = temporally valid', () => {
    const slot = makeSlot();
    assert.equal(isTemporallyValid(slot, 100n, new Set()), true);
  });

  test('valid=false → not valid', () => {
    assert.equal(isTemporallyValid(makeSlot({ valid: false }), 100n, new Set()), false);
  });

  test('revoked=true → not valid', () => {
    assert.equal(isTemporallyValid(makeSlot({ revoked: true }), 100n, new Set()), false);
  });

  test('eventId in revokedEventIds → not valid', () => {
    const slot = makeSlot({ eventId: 42n });
    assert.equal(isTemporallyValid(slot, 100n, new Set([42n])), false);
  });

  test('expiryEpoch in the past → not valid', () => {
    const slot = makeSlot({ expiryEpoch: 50n });
    assert.equal(isTemporallyValid(slot, 100n, new Set()), false);
  });

  test('corpusEpoch in the future → not valid', () => {
    const slot = makeSlot({ corpusEpoch: 200n });
    assert.equal(isTemporallyValid(slot, 100n, new Set()), false);
  });

  test('within validity window = valid', () => {
    const slot = makeSlot({ corpusEpoch: 50n, expiryEpoch: 200n });
    assert.equal(isTemporallyValid(slot, 100n, new Set()), true);
  });
});
