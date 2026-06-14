/**
 * Golden-vector lock for seed-derivation primitives.
 *
 * Hand-picked fixtures in `test/fixtures/seed-derivation-golden.json`
 * capture the canonical output bytes for representative inputs across:
 *   - all-zero / all-one extremes
 *   - launch-genesis-like values
 *   - high epoch IDs (2^40)
 *   - empty / single / 32-byte / 128-byte patch byte sequences
 *
 * Any drift in keccak primitive, byte ordering, or domain prefix
 * breaks these assertions. This is a stronger guarantee than the
 * property-style sensitivity tests in `seed-derivation.test.mjs`,
 * which only assert "changing X changes the output" without locking
 * specific bytes.
 *
 * Updating fixtures: re-run the generator script that emitted them
 * (see commit history) and explicitly commit the new bytes — never
 * silently regenerate.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  deriveGateEvalSeed,
  deriveConfirmEvalSeed,
  computePatchHash,
  computeDedupKey,
} from '../../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../fixtures/seed-derivation-golden.json');
const golden = JSON.parse(readFileSync(fixturePath, 'utf8'));

describe('seed-derivation golden vectors', () => {
  test('schema and prefix declarations are intact', () => {
    assert.equal(golden.schemaVersion, 'coretex.seed-derivation-golden.v1');
    assert.equal(golden.domainPrefixes.gate,      'coretex-eval-v1-gate');
    assert.equal(golden.domainPrefixes.confirm,   'coretex-eval-v1-confirm');
    assert.equal(golden.domainPrefixes.patchHash, 'coretex-patch-hash-v1');
    assert.equal(golden.domainPrefixes.dedupDigest, 'coretex-dedup-key-v1');
  });

  test('every seedCase reproduces gateSeed + confirmSeed byte-for-byte', () => {
    for (const c of golden.seedCases) {
      const input = {
        ...c.input,
        epochId: typeof c.input.epochId === 'string' ? BigInt(c.input.epochId) : c.input.epochId,
      };
      const gate = deriveGateEvalSeed(input);
      const confirm = deriveConfirmEvalSeed(input);
      assert.equal(gate,    c.gateSeed,    `[${c.tag}] gateSeed mismatch`);
      assert.equal(confirm, c.confirmSeed, `[${c.tag}] confirmSeed mismatch`);
    }
  });

  test('every patchHashCase reproduces patchHash + dedup digest byte-for-byte', () => {
    const parentRoot = '0x' + '77'.repeat(32);
    for (const c of golden.patchHashCases) {
      const u8 = new Uint8Array(c.bytes.length / 2);
      for (let i = 0; i < u8.length; i++) u8[i] = parseInt(c.bytes.slice(i * 2, i * 2 + 2), 16);
      assert.equal(computePatchHash(u8), c.patchHash, `[${c.tag}] patchHash mismatch`);
      assert.equal(computeDedupKey(parentRoot, u8), c.dedupDigest, `[${c.tag}] dedup digest mismatch`);
    }
  });

  test('fixtures cover the documented edge cases', () => {
    // Sanity floor — if someone removes a case by accident the suite
    // should yelp. Pin the expected tags.
    const seedTags = new Set(golden.seedCases.map((c) => c.tag));
    for (const required of ['all-zeros-except-blockhash', 'all-ones', 'launch-genesis', 'high-epoch-id-2pow40']) {
      assert.ok(seedTags.has(required), `missing fixture tag: ${required}`);
    }
    const patchTags = new Set(golden.patchHashCases.map((c) => c.tag));
    for (const required of ['empty-bytes', 'single-byte', '32-bytes-zero', '128-bytes-pattern']) {
      assert.ok(patchTags.has(required), `missing patchHash fixture tag: ${required}`);
    }
  });
});
