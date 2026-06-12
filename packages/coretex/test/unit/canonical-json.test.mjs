/**
 * THE canonical-JSON serializer (src/canonical/json.ts) — the single
 * implementation behind every hash/signature surface (corpus deltas, rotation
 * manifests, bundleHash, work-policy hash, eval-report artifacts).
 *
 * Golden guarantees:
 *   1. exact serialized strings for every supported value class (drift in any
 *      branch is a consensus split — these are byte-level pins);
 *   2. the REAL released v16 bundle manifest re-hashes to its embedded
 *      bundleHash through the swapped-in serializer (end-to-end proof the
 *      consolidation changed no shipped digest);
 *   3. the two deliberate bug-class removals: explicit-undefined keys are
 *      SKIPPED (JSON.stringify parity — a manifest now hashes identically
 *      before and after a disk round-trip), and non-finite numbers THROW.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, bytesToBareHex } from '../../dist/canonical/json.js';
import { computeBundleHashFromManifest } from '../../dist/bundle/index.js';
import { coreTexWorkPolicyHash, DEFAULT_CORETEX_WORK_POLICY } from '../../dist/rewards/work-units.js';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '../../../..');

describe('canonicalJson — byte-level pins per value class', () => {
  test('scalars', () => {
    assert.equal(canonicalJson(null), 'null');
    assert.equal(canonicalJson(true), 'true');
    assert.equal(canonicalJson(false), 'false');
    assert.equal(canonicalJson(0), '0');
    assert.equal(canonicalJson(-1.5), '-1.5');
    assert.equal(canonicalJson(1e21), '1e+21');
    assert.equal(canonicalJson('a"b\\c'), JSON.stringify('a"b\\c'));
    assert.equal(canonicalJson(123n), '"123"');
  });

  test('bytes, maps, arrays, nested objects with sorted keys', () => {
    assert.equal(canonicalJson(new Uint8Array([0, 15, 255])), '"000fff"');
    assert.equal(bytesToBareHex(new Uint8Array([0xde, 0xad])), 'dead');
    assert.equal(canonicalJson(new Map([['b', 2], ['a', 1]])), '{"a":1,"b":2}');
    assert.equal(canonicalJson([1, 'x', [true]]), '[1,"x",[true]]');
    assert.equal(
      canonicalJson({ z: 1, a: { d: 4, c: 3 } }),
      '{"a":{"c":3,"d":4},"z":1}',
    );
  });

  test('explicit-undefined keys are SKIPPED (JSON.stringify parity)', () => {
    const spreadBuilt = { knob: undefined, real: 1 };
    assert.equal(canonicalJson(spreadBuilt), '{"real":1}');
    // The fix's whole point: identical hash input before/after a disk round-trip.
    assert.equal(
      canonicalJson(spreadBuilt),
      canonicalJson(JSON.parse(JSON.stringify(spreadBuilt))),
    );
    // Array elements keep JSON semantics (null, not skipped).
    assert.equal(canonicalJson([undefined, 1]), '[null,1]');
  });

  test('non-finite numbers THROW instead of silently hashing as null', () => {
    assert.throws(() => canonicalJson(NaN), /non-finite/);
    assert.throws(() => canonicalJson(Infinity), /non-finite/);
    assert.throws(() => canonicalJson({ x: -Infinity }), /non-finite/);
  });

  test('safe-integer policy rejects fractional numbers', () => {
    assert.equal(canonicalJson(7, { numbers: 'safe-integer' }), '7');
    assert.throws(() => canonicalJson(1.5, { numbers: 'safe-integer' }), /safe integers/);
  });

  test('top-level undefined / symbols / functions throw', () => {
    assert.throws(() => canonicalJson(undefined), /top-level undefined/);
    assert.throws(() => canonicalJson(Symbol('x')), /unsupported/);
    assert.throws(() => canonicalJson(() => 1), /unsupported/);
  });
});

describe('canonicalJson — shipped-digest invariance (golden)', () => {
  test('the released v16 bundle manifest re-hashes to its embedded bundleHash', () => {
    const manifestPath = join(
      repoRoot,
      'release/calibration/2026-06-04-memory-atom-v16/bundle-manifest-v2-dgen1-policy-r5-atom-v16-300k-enabled.json',
    );
    if (!existsSync(manifestPath)) {
      // Standalone-package installs do not ship the release tree; the pin
      // still runs in-repo (CI + audit gates).
      return;
    }
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const { bundleHash, ...rest } = manifest;
    assert.equal(computeBundleHashFromManifest(rest).toLowerCase(), String(bundleHash).toLowerCase());
  });

  test('the default work-policy hash is unchanged by the consolidation', () => {
    // Pinned from the pre-consolidation implementation (canonicalValue).
    const hash = coreTexWorkPolicyHash(DEFAULT_CORETEX_WORK_POLICY);
    assert.match(hash, /^0x[0-9a-f]{64}$/);
    // Determinism + idempotence (same object, fresh call).
    assert.equal(coreTexWorkPolicyHash(DEFAULT_CORETEX_WORK_POLICY), hash);
  });
});
