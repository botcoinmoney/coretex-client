/**
 * Launch controller pin: the difficulty-controller shape is sourced from the
 * SIGNED EvaluatorProfile (controllerParams) via controllerParamsFromProfile,
 * the single profile → controller-override path (analogous to
 * scoringOptionsFromProfile for the scorer). Guards:
 *   1. pinned controllerParams flow through to the nextMinImprovementPpm inputs;
 *   2. absent controllerParams → difficulty.ts protocol defaults (back-compat);
 *   3. validateProfile (via buildBundleManifest) rejects degenerate controllers;
 *   4. DECAY / RECOVERY SMOKE — the 2026-05-24 calibration (qualityHighThresholdMult=1)
 *      makes the decay branch reachable at honestAttempts == targetAdvances, where
 *      the pre-calibration mult=4 (and the A/B's mult=2) left it unreachable.
 *      The hardened default still takes under-target recovery instead of
 *      ratcheting upward when quality work is present.
 *      (V2_DGEN1_ENDURANCE_FINDINGS.md §Controller-calibration A/B.)
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_PROFILE,
  DEFAULT_CONTROLLER_PARAMS,
  controllerParamsFromProfile,
  nextMinImprovementPpm,
  buildBundleManifest,
  verifyBundleManifest,
  qwen3Reranker06BManifest,
  bgeM3DenseManifest,
  memRerankerManifest,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

// The pinned launch controller (2026-05-24 calibration).
const LAUNCH_CONTROLLER = {
  rampUpMaxRatio: 1.1,
  decayRatio: 0.8,
  smallDriftRatio: 1.05,
  underTargetRecoveryRatio: 0.9,
  qualityHighThresholdMult: 1,
};

const pinnedProfile = { ...DEFAULT_PROFILE, controllerParams: LAUNCH_CONTROLLER };

function biEnc() {
  return bgeM3DenseManifest({ revision: '0123456789abcdef0123456789abcdef01234567', files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }] });
}
function reranker() {
  return qwen3Reranker06BManifest({ revision: '89abcdef0123456789abcdef0123456789abcdef', files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }] });
}
function labeling() {
  return memRerankerManifest({ modelId: 'memreranker/4B', revision: 'cafebabedeadbeefcafebabedeadbeefcafebabe', files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }] });
}
function buildWith(evaluatorProfile) {
  return buildBundleManifest({
    repoRoot, corpusRoot: '0x' + '11'.repeat(32), corpusFiles: [],
    biEncoder: biEnc(), reranker: reranker(), labelingReranker: labeling(),
    ...(evaluatorProfile ? { evaluatorProfile } : {}),
  });
}

describe('controllerParamsFromProfile', () => {
  test('pinned controllerParams flow through; qualityHighThreshold = mult × targetAdvances', () => {
    const target = 3;
    const cp = controllerParamsFromProfile(pinnedProfile, target);
    assert.equal(cp.rampUpMaxRatio, 1.1);
    assert.equal(cp.decayRatio, 0.8);
    assert.equal(cp.smallDriftRatio, 1.05);
    assert.equal(cp.underTargetRecoveryRatio, 0.9);
    assert.equal(cp.qualityHighThreshold, 1 * target, 'mult=1 → threshold == target');
  });

  test('absent controllerParams → difficulty.ts protocol defaults (back-compat)', () => {
    const target = 2;
    const cp = controllerParamsFromProfile(DEFAULT_PROFILE, target);
    assert.equal(cp.rampUpMaxRatio, DEFAULT_CONTROLLER_PARAMS.rampUpMaxRatio);
    assert.equal(cp.decayRatio, DEFAULT_CONTROLLER_PARAMS.decayRatio);
    assert.equal(cp.smallDriftRatio, DEFAULT_CONTROLLER_PARAMS.smallDriftRatio);
    assert.equal(cp.underTargetRecoveryRatio, DEFAULT_CONTROLLER_PARAMS.underTargetRecoveryRatio);
    assert.equal(cp.qualityHighThreshold, DEFAULT_CONTROLLER_PARAMS.qualityHighThresholdMult * target);
  });

  test('a partially-pinned controller falls back per-field', () => {
    const cp = controllerParamsFromProfile({ ...DEFAULT_PROFILE, controllerParams: { rampUpMaxRatio: 1.2 } }, 5);
    assert.equal(cp.rampUpMaxRatio, 1.2, 'pinned field used');
    assert.equal(cp.decayRatio, DEFAULT_CONTROLLER_PARAMS.decayRatio, 'unset field defaults');
    assert.equal(cp.underTargetRecoveryRatio, DEFAULT_CONTROLLER_PARAMS.underTargetRecoveryRatio, 'unset anti-plateau field defaults');
    assert.equal(cp.qualityHighThreshold, DEFAULT_CONTROLLER_PARAMS.qualityHighThresholdMult * 5);
  });
});

describe('controllerParams validation (via buildBundleManifest → validateProfile)', () => {
  test('default-built bundle has no controllerParams and verifies clean', () => {
    const m = buildWith();
    assert.equal(m.evaluator.profile.controllerParams, undefined);
    assert.deepEqual(verifyBundleManifest(m, repoRoot), []);
  });

  test('valid launch controllerParams accepted and verifies clean', () => {
    const m = buildWith({ controllerParams: LAUNCH_CONTROLLER });
    assert.deepEqual(m.evaluator.profile.controllerParams, LAUNCH_CONTROLLER);
    assert.deepEqual(verifyBundleManifest(m, repoRoot), []);
  });

  test('rampUpMaxRatio < 1 rejected', () => {
    assert.throws(() => buildWith({ controllerParams: { rampUpMaxRatio: 0.9 } }), /rampUpMaxRatio/);
  });
  test('decayRatio >= 1 rejected (a decay that never eases difficulty)', () => {
    assert.throws(() => buildWith({ controllerParams: { decayRatio: 1.0 } }), /decayRatio/);
  });
  test('decayRatio <= 0 rejected', () => {
    assert.throws(() => buildWith({ controllerParams: { decayRatio: 0 } }), /decayRatio/);
  });
  test('smallDriftRatio < 1 rejected', () => {
    assert.throws(() => buildWith({ controllerParams: { smallDriftRatio: 0.99 } }), /smallDriftRatio/);
  });
  test('underTargetRecoveryRatio > 1 rejected', () => {
    assert.throws(() => buildWith({ controllerParams: { underTargetRecoveryRatio: 1.01 } }), /underTargetRecoveryRatio/);
  });
  test('underTargetRecoveryRatio <= 0 rejected', () => {
    assert.throws(() => buildWith({ controllerParams: { underTargetRecoveryRatio: 0 } }), /underTargetRecoveryRatio/);
  });
  test('qualityHighThresholdMult <= 0 rejected', () => {
    assert.throws(() => buildWith({ controllerParams: { qualityHighThresholdMult: 0 } }), /qualityHighThresholdMult/);
  });
});

describe('decay-branch smoke (the 2026-05-24 calibration fix)', () => {
  const target = 3;
  // The realistic per-epoch honest signal that previously starved the decay
  // branch: 0 accepted advances but honestAttempts at the target volume.
  const epoch = { current: 100_000n, observedAdvances: 0, targetAdvances: target, qualityAttempts: 3 };

  test('CALIBRATED (mult=1): decay FIRES when honestAttempts == targetAdvances → threshold eases', () => {
    const cp = controllerParamsFromProfile(pinnedProfile, target);
    const out = nextMinImprovementPpm({ ...epoch, ...cp });
    assert.equal(out.reason, 'decay', 'decay branch must engage under the launch controller');
    assert.equal(out.ratioApplied, 0.8, 'pinned decayRatio applied');
    assert.ok(out.next < epoch.current, 'threshold decays toward the floor');
  });

  test('DEFAULT (mult=4): decay is unreachable, but under-target recovery still eases', () => {
    const cp = controllerParamsFromProfile(DEFAULT_PROFILE, target); // mult=4 → threshold 12 > 3
    const out = nextMinImprovementPpm({ ...epoch, ...cp });
    assert.notEqual(out.reason, 'decay', 'mult=4 keeps decay unreachable');
    assert.equal(out.reason, 'under_target_recovery', 'the hardened default still eases under quality pressure');
    assert.ok(out.next < epoch.current, 'threshold does not ratchet upward under state-advance shortfall');
  });

  test('A/B mult=2 also leaves decay unreachable at honestAttempts=3 (threshold 6 > 3)', () => {
    const cp = controllerParamsFromProfile({ ...DEFAULT_PROFILE, controllerParams: { qualityHighThresholdMult: 2 } }, target);
    const out = nextMinImprovementPpm({ ...epoch, ...cp });
    assert.notEqual(out.reason, 'decay');
  });
});
