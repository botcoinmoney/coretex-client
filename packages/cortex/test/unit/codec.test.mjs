/**
 * Unit tests: pack/unpack codec.
 * Uses Node.js built-in test runner (node --test).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// We test the compiled JS. Since we're in ESM with NodeNext, we import from dist.
// But for unit tests before build, we import the source directly via --loader or
// by compiling first. The test:unit script in package.json runs on dist.
// We import from dist/ (post-build).
import { pack, unpack, PACKED_SIZE } from '../../dist/state/codec.js';
import { RANGES } from '../../dist/state/types.js';

describe('pack/unpack', () => {
  test('pack produces exactly 32768 bytes', () => {
    const state = { words: new Array(1024).fill(0n) };
    const packed = pack(state);
    assert.equal(packed.length, PACKED_SIZE);
    assert.equal(PACKED_SIZE, 32768);
  });

  test('pack zero state is all zeros', () => {
    const state = { words: new Array(1024).fill(0n) };
    const packed = pack(state);
    for (const b of packed) assert.equal(b, 0);
  });

  test('pack/unpack round-trip: known value', () => {
    const words = new Array(1024).fill(0n);
    words[0] = 0xDEADBEEFCAFEBABEn;
    words[500] = (1n << 255n);
    words[1023] = (1n << 256n) - 1n;
    const state = { words };
    const packed = pack(state);
    const unpacked = unpack(packed);
    for (let i = 0; i < 1024; i++) {
      assert.equal(unpacked.words[i], words[i], `word ${i} mismatch`);
    }
  });

  test('unpack throws on wrong length', () => {
    assert.throws(() => unpack(new Uint8Array(100)), /wrong length|expected 32768/i);
  });

  test('pack throws on wrong word count', () => {
    assert.throws(() => pack({ words: [] }), /expected 1024/i);
  });

  test('big-endian word ordering', () => {
    const words = new Array(1024).fill(0n);
    words[0] = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20n;
    const packed = pack({ words });
    // First byte of first word should be 0x01
    assert.equal(packed[0], 0x01);
    assert.equal(packed[31], 0x20);
  });

  test('word 1 is isolated in correct byte range', () => {
    const words = new Array(1024).fill(0n);
    words[0] = 0n;
    words[1] = 1n; // LSB of word 1
    const packed = pack({ words });
    // word 1 occupies bytes 32–63; LSB at byte 63
    assert.equal(packed[63], 1);
    for (let b = 32; b < 63; b++) assert.equal(packed[b], 0, `byte ${b} should be 0`);
    // word 0 bytes should all be 0
    for (let b = 0; b < 32; b++) assert.equal(packed[b], 0, `byte ${b} should be 0`);
  });

  test('pack/unpack round-trip: max value word', () => {
    const words = new Array(1024).fill(0n);
    words[7] = (1n << 256n) - 1n;
    const state = { words };
    const packed = pack(state);
    const back = unpack(packed);
    assert.equal(back.words[7], words[7]);
  });
});
