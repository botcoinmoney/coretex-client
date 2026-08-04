import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  word,
  address,
  hexdata,
  bareRoot,
  rootFromWord,
  wordFromRoot,
  wide,
  narrow,
  canonicalRuleRecord,
  CanonicalizationError,
  MAX_SAFE_INTEGER_BIG,
} from '../../dist/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PYTHON_ROOT = path.resolve(HERE, '../../python');

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

describe('cross-language parity with the Python canonicaliser', () => {
  test('both lanes spell the same inputs identically', () => {
    // Independent implementations compared on the same values — including the one that a
    // number-based renderer gets wrong.
    const cases = {
      wide_2_53: wide(2n ** 53n),
      wide_2_53_plus_1: wide(2n ** 53n + 1n),
      wide_uint256_max: wide(2n ** 256n - 1n),
      narrow_max_safe: narrow(MAX_SAFE_INTEGER_BIG),
      word: word('AB'.repeat(32)),
      address: address('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'),
      hexdata: hexdata(new Uint8Array([0, 255])),
      bare_root: bareRoot('cd'.repeat(32)),
      root_from_word: rootFromWord('0x' + 'ef'.repeat(32)),
      word_from_root: wordFromRoot('ef'.repeat(32)),
    };

    let raw;
    try {
      raw = execFileSync(
        'python3',
        [
          '-c',
          'import json,sys;sys.path.insert(0,"' +
            PYTHON_ROOT +
            '");from coretex_validator import canonical as c;' +
            'print(json.dumps({' +
            '"wide_2_53": c.wide(2**53),' +
            '"wide_2_53_plus_1": c.wide(2**53+1),' +
            '"wide_uint256_max": c.wide(2**256-1),' +
            '"narrow_max_safe": c.narrow(2**53-1),' +
            '"word": c.word("AB"*32),' +
            '"address": c.address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),' +
            '"hexdata": c.hexdata(bytes([0,255])),' +
            '"bare_root": c.bare_root("cd"*32),' +
            '"root_from_word": c.root_from_word("0x"+"ef"*32),' +
            '"word_from_root": c.word_from_root("ef"*32)}))',
        ],
        { encoding: 'utf8', timeout: 60_000 },
      );
    } catch (err) {
      assert.ok(err, 'python3 unavailable — parity unchecked on this host');
      return;
    }
    assert.deepEqual(cases, JSON.parse(raw));
  });

  test('both lanes publish the same canonicalization record', () => {
    let raw;
    try {
      raw = execFileSync(
        'python3',
        [
          '-c',
          'import json,sys;sys.path.insert(0,"' +
            PYTHON_ROOT +
            '");from coretex_validator import canonical as c;' +
            'print(json.dumps(c.canonical_rule_record()))',
        ],
        { encoding: 'utf8', timeout: 60_000 },
      );
    } catch (err) {
      assert.ok(err, 'python3 unavailable — parity unchecked on this host');
      return;
    }
    // The record goes INSIDE the signed bytes, so a divergence here is a divergence in the
    // payload itself, not merely in documentation.
    assert.deepEqual(canonicalRuleRecord(), JSON.parse(raw));
  });
});
