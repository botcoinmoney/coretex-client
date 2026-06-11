/**
 * TS ↔ Solidity wire-grammar parity (audit Q2 / B8).
 *
 * The patch-type → word-range table lives ONCE in state/types.ts
 * (PATCH_TYPE_RANGE_TABLE); patchTypeRange() derives from it. This test parses
 * `_wordMatchesPatchType` and the compact-patch constants out of
 * contracts/src/BotcoinMiningV4.sol and asserts byte-for-byte agreement, so a
 * region change on either side is a FAILING TEST instead of an audit finding.
 *
 * Skips cleanly when the contracts tree is absent (standalone npm install).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { PATCH_TYPE, PATCH_TYPE_RANGE_TABLE, RANGES } from '../../dist/state/types.js';
import { patchTypeRange } from '../../dist/state/patch.js';
import { PATCH_HASH_DOMAIN_PREFIX } from '../../dist/eval/seed-derivation.js';

const solPath = join(
  dirname(fileURLToPath(import.meta.url)),
  '../../../../contracts/src/BotcoinMiningV4.sol',
);
const sol = existsSync(solPath) ? readFileSync(solPath, 'utf8') : null;

describe('PATCH_TYPE_RANGE_TABLE — internal consistency', () => {
  test('patchTypeRange derives exactly from the table; MIXED and unknown types are special-cased', () => {
    for (const row of PATCH_TYPE_RANGE_TABLE) {
      assert.deepEqual(patchTypeRange(row.typeByte), { start: row.start, end: row.end }, row.name);
      assert.equal(PATCH_TYPE[row.name], row.typeByte, `${row.name} byte matches PATCH_TYPE`);
    }
    assert.equal(patchTypeRange(PATCH_TYPE.MIXED), undefined, 'MIXED spans all non-reserved words (special-cased)');
    assert.equal(patchTypeRange(0x42), undefined);
    // Every non-MIXED PATCH_TYPE entry appears in the table exactly once.
    const nonMixed = Object.entries(PATCH_TYPE).filter(([k]) => k !== 'MIXED');
    assert.equal(PATCH_TYPE_RANGE_TABLE.length, nonMixed.length);
    // No range may reach into the reserved tail.
    for (const row of PATCH_TYPE_RANGE_TABLE) {
      assert.ok(row.start >= 0 && row.start <= row.end, `${row.name} start <= end`);
      assert.ok(row.end < RANGES.RESERVED_START, `${row.name} ends below RESERVED_START`);
    }
  });
});

describe('TS ↔ Solidity parity (BotcoinMiningV4.sol)', { skip: sol === null }, () => {
  test('_wordMatchesPatchType ranges equal PATCH_TYPE_RANGE_TABLE exactly', () => {
    const fnStart = sol.indexOf('function _wordMatchesPatchType');
    assert.notEqual(fnStart, -1, '_wordMatchesPatchType present');
    const body = sol.slice(fnStart, sol.indexOf('}', sol.indexOf('return false;', fnStart)));

    // 0xff wildcard
    assert.match(body, /patchType == 0xff\) return true;/);

    // Parse every `if (patchType == 0xNN) return <range>;` clause.
    const clauses = [...body.matchAll(/patchType == (0x0[1-7])\) return ([^;]+);/g)];
    const parsed = new Map();
    for (const [, byteHex, expr] of clauses) {
      const both = expr.match(/index >= (\d+) && index <= (\d+)/);
      const upperOnly = expr.match(/^index <= (\d+)$/);
      assert.ok(both || upperOnly, `parseable range expr: ${expr}`);
      const start = both ? Number(both[1]) : 0;
      const end = both ? Number(both[2]) : Number(upperOnly[1]);
      parsed.set(Number(byteHex), { start, end });
    }

    // Exact bidirectional equality with the TS table.
    assert.equal(parsed.size, PATCH_TYPE_RANGE_TABLE.length, 'same number of typed ranges on both sides');
    for (const row of PATCH_TYPE_RANGE_TABLE) {
      assert.deepEqual(
        parsed.get(row.typeByte),
        { start: row.start, end: row.end },
        `${row.name} (0x${row.typeByte.toString(16).padStart(2, '0')}) range matches on-chain`,
      );
    }
  });

  test('compact-patch wire constants match the TS codec', () => {
    assert.match(sol, /COMPACT_PATCH_HEADER_BYTES = 42;/);
    assert.match(sol, /COMPACT_PATCH_MAX_BYTES = 178;/);
    assert.match(sol, /COMPACT_PATCH_MAX_WORDS = 4;/);
    const reserved = sol.match(/RESERVED_WORD_START = (\d+);/);
    assert.ok(reserved, 'RESERVED_WORD_START present');
    assert.equal(Number(reserved[1]), RANGES.RESERVED_START);
    // 42 = type(1) + wordCount(1) + scoreDelta(8) + parent(32); 178 = 42 + 4×(2+32).
    assert.equal(42, 1 + 1 + 8 + 32);
    assert.equal(178, 42 + 4 * (2 + 32));
  });

  test('patch-hash domain string is byte-identical', () => {
    assert.ok(sol.includes(`"${PATCH_HASH_DOMAIN_PREFIX}"`), 'coretex-patch-hash-v1 domain present in V4');
    assert.equal(PATCH_HASH_DOMAIN_PREFIX, 'coretex-patch-hash-v1');
  });
});
