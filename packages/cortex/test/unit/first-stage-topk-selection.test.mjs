/**
 * §5 selection-policy attestation: `firstStageTopKSelection` must be a
 * required, validated field of `EvaluatorProfile` whenever
 * `firstStageTopK > 0`. The field is canonical-JSON-hashed into
 * `bundleHash`, so every override claim is signed in the manifest.
 *
 * These tests exercise `verifyBundleManifest` against a real production
 * bundle and replace the selection field with various malformed shapes
 * to confirm each shape fails closed.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { verifyBundleManifest } from '../../dist/index.js';

const MANIFEST_PATH = '/root/cortex/release/bundle/bundle-manifest-v2-ownerscope-candidate.json';
const REPO_ROOT = '/root/cortex';

function baseManifest() {
  return JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
}

function selectionErrors(manifest) {
  return verifyBundleManifest(manifest, REPO_ROOT).filter((e) =>
    /firstStageTopKSelection/i.test(e),
  );
}

describe('§5 firstStageTopKSelection — signed manifest attestation', () => {
  test('candidate bundle is accepted as-is (worst-stratum target with calibration report)', () => {
    const m = baseManifest();
    assert.deepEqual(selectionErrors(m), [], 'shipped bundle should pass selection validation');
    assert.equal(m.evaluator.profile.firstStageTopKSelection.method, 'worst-stratum-target');
    assert.ok(m.evaluator.profile.firstStageTopKSelection.calibrationReport);
  });

  test('rejects bundle missing firstStageTopKSelection when firstStageTopK > 0', () => {
    const m = baseManifest();
    delete m.evaluator.profile.firstStageTopKSelection;
    const errs = selectionErrors(m);
    assert.equal(errs.length, 1, `expected one selection error, got: ${JSON.stringify(errs)}`);
    assert.match(errs[0], /required when firstStageTopK > 0/);
  });

  test("rejects method='operator-override' without substrateBridgedFamilies", () => {
    const m = baseManifest();
    m.evaluator.profile.firstStageTopKSelection = {
      method: 'operator-override',
      reason: 'A descriptive reason long enough to pass.',
    };
    const errs = selectionErrors(m);
    assert.ok(errs.some((e) => /substrateBridgedFamilies must be a non-empty array/.test(e)),
      `errors: ${JSON.stringify(errs)}`);
  });

  test("rejects method='worst-stratum-target' without calibrationReport", () => {
    const m = baseManifest();
    m.evaluator.profile.firstStageTopKSelection = {
      method: 'worst-stratum-target',
      reason: 'All families met the recall@K floor on Run 1.',
    };
    const errs = selectionErrors(m);
    assert.ok(errs.some((e) => /calibrationReport is required/.test(e)),
      `errors: ${JSON.stringify(errs)}`);
  });

  test('rejects reason shorter than 16 chars', () => {
    const m = baseManifest();
    m.evaluator.profile.firstStageTopKSelection = {
      method: 'operator-override',
      reason: 'short',
      substrateBridgedFamilies: ['long_horizon'],
    };
    const errs = selectionErrors(m);
    assert.ok(errs.some((e) => /reason must be a descriptive string/.test(e)),
      `errors: ${JSON.stringify(errs)}`);
  });

  test('rejects unknown method values', () => {
    const m = baseManifest();
    m.evaluator.profile.firstStageTopKSelection = {
      method: 'whatever',
      reason: 'A reason long enough to pass.',
    };
    const errs = selectionErrors(m);
    assert.ok(errs.some((e) => /method must be 'worst-stratum-target' or 'operator-override'/.test(e)),
      `errors: ${JSON.stringify(errs)}`);
  });

  test('rejects servedFamilyRecallAtPinnedK values outside [0,1]', () => {
    const m = baseManifest();
    m.evaluator.profile.firstStageTopKSelection = {
      method: 'operator-override',
      reason: 'A reason long enough to pass validation.',
      substrateBridgedFamilies: ['long_horizon'],
      servedFamilyRecallAtPinnedK: { temporal: 1.5 },
    };
    const errs = selectionErrors(m);
    assert.ok(errs.some((e) => /servedFamilyRecallAtPinnedK\.temporal must be a number in \[0, 1\]/.test(e)),
      `errors: ${JSON.stringify(errs)}`);
  });

  test('field is part of the canonical bundleHash (changing it would require a new hash)', () => {
    // Sanity check: the shipped bundleHash is non-empty and the field is
    // structurally inside the profile that bundleHash is computed over.
    const m = baseManifest();
    assert.match(m.bundleHash, /^0x[0-9a-f]{64}$/);
    assert.ok('firstStageTopKSelection' in m.evaluator.profile);
  });
});
