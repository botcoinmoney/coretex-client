import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  word,
  address,
  hexdata,
  bareRoot,
  rootFromWord,
  wordFromRoot,
  wide,
  narrow,
  CanonicalizationError,
  MAX_SAFE_INTEGER_BIG,
} from '../../dist/index.js';

describe('wide integers must not narrow', () => {
  test('2**53 and 2**53+1 are the SAME double — which is why decimal strings exist', () => {
    // This is the whole argument for decision 3, executed rather than asserted in a comment.
    assert.equal(Number(2n ** 53n), Number(2n ** 53n + 1n));
    // ...and the canonical rendering keeps them apart.
    assert.notEqual(wide(2n ** 53n), wide(2n ** 53n + 1n));
    assert.equal(wide(2n ** 53n + 1n), '9007199254740993');
  });

  test('a uint256 at the top of its range survives exactly', () => {
    const max = 2n ** 256n - 1n;
    assert.equal(wide(max), max.toString(10));
    assert.throws(() => wide(2n ** 256n), CanonicalizationError);
  });

  test('wide() refuses a number, because a number has already lost the precision', () => {
    // Accepting `9007199254740993` as a JS number would silently accept 9007199254740992.
    assert.throws(() => wide(9007199254740993), CanonicalizationError);
    assert.throws(() => wide(-1n), CanonicalizationError);
    assert.throws(() => wide('12x'), CanonicalizationError);
  });

  test('narrow() REFUSES rather than rounds above 2**53-1', () => {
    assert.equal(narrow(MAX_SAFE_INTEGER_BIG), 9007199254740991);
    assert.throws(() => narrow(2n ** 53n), CanonicalizationError);
    assert.throws(() => narrow(2n ** 64n), CanonicalizationError);
    assert.throws(() => narrow(-1n), CanonicalizationError);
  });
});

describe('two spellings, one boundary crossing', () => {
  const ROOT = 'ab'.repeat(32);

  test('chain words are 0x-prefixed, content roots are bare', () => {
    assert.equal(word('0x' + ROOT), '0x' + ROOT);
    assert.equal(word(ROOT), '0x' + ROOT); // accepts unprefixed input, emits prefixed
    assert.equal(bareRoot(ROOT), ROOT);
    assert.throws(() => bareRoot('0x' + ROOT), CanonicalizationError);
  });

  test('the boundary is crossed only through rootFromWord / wordFromRoot', () => {
    assert.equal(rootFromWord('0x' + ROOT), ROOT);
    assert.equal(wordFromRoot(ROOT), '0x' + ROOT);
  });

  test('a short hex string is refused, never padded', () => {
    // Guessing the padding side is how a root and a left-aligned label get confused.
    assert.throws(() => word('0xdeadbeef'), CanonicalizationError);
  });

  test('EIP-55 casing is a checksum over the same bytes, so it is lowercased', () => {
    assert.equal(
      address('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'),
      '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266',
    );
    // A left-padded address word is unwrapped; a dirty pad is refused.
    assert.equal(address('0x' + '0'.repeat(24) + 'aa'.repeat(20)), '0x' + 'aa'.repeat(20));
    assert.throws(
      () => address('0x' + '1'.repeat(24) + 'aa'.repeat(20)),
      CanonicalizationError,
    );
  });

  test('empty ABI bytes render as 0x', () => {
    assert.equal(hexdata(new Uint8Array()), '0x');
    assert.equal(hexdata(new Uint8Array([0xde, 0xad])), '0xdead');
  });
});

// The retired Python canonical.py API has no current counterpart. These are private
// TypeScript codec tests; live cross-language topic parity lives in rig-dispatch.test.mjs.
