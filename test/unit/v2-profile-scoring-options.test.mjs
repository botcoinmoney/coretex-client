/**
 * V2-native evaluator profile → ScoringOptions round-trip.
 *
 * The signed `EvaluatorProfile` must be able to EXPRESS the winning V2 config
 * (owner-scope + non-flooding promotion + score-inheritance). This guards the
 * canonical `scoringOptionsFromProfile` mapping so production / calibration /
 * replay all derive the SAME scorer options from the profile.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DEFAULT_PROFILE, scoringOptionsFromProfile } from '../../dist/index.js';

const runtime = {
  biEncoder: { modelId: 'm', revision: 'r', layout: { dim: 8, headerBytes: 9, quantization: 'int8' }, async encode() { return new Float32Array(8); } },
  reranker: { model: 'k', async score(p) { return p.map(() => 0.5); } },
  biEncoderHash: '0xabc',
  retrievalKeyLayout: { dim: 8, headerBytes: 9, quantization: 'int8' },
};

// The V2 launch-lane profile = DEFAULT_PROFILE + the winning knobs.
const v2Profile = {
  ...DEFAULT_PROFILE,
  name: 'coretex-evaluator-v2-ownerscope',
  version: 'r1-candidate',
  ownerScopeMode: 'restrict',
  categoryLensExpansionBudget: 50,
  categoryLensFinalBonusWeight: 0,
  categoryLensScoreInheritance: 0.3,
};

describe('V2 profile → ScoringOptions', () => {
  test('the winning V2 config flows through scoringOptionsFromProfile', () => {
    const opts = scoringOptionsFromProfile(v2Profile, runtime);
    assert.equal(opts.ownerScopeMode, 'restrict', 'owner-scope expressed');
    assert.equal(opts.categoryLensFinalBonusWeight, 0, 'inclusion-only (no final lens bonus)');
    assert.equal(opts.categoryLensScoreInheritance, 0.3, 'score-inheritance alpha expressed');
    assert.equal(opts.categoryLensExpansionBudget, 50, 'lens expansion on');
    assert.equal(opts.lensDiversityFloor, DEFAULT_PROFILE.lensDiversityFloor, 'lens-diversity floor expressed');
    // runtime deps injected
    assert.equal(opts.biEncoderHash, '0xabc');
    assert.ok(typeof opts.reranker.score === 'function');
  });

  test('DEFAULT_PROFILE (legacy) does NOT enable owner-scope / inheritance (back-compat)', () => {
    const opts = scoringOptionsFromProfile(DEFAULT_PROFILE, runtime);
    assert.equal(opts.ownerScopeMode, undefined, 'legacy default is full-pool');
    assert.equal(opts.categoryLensScoreInheritance, undefined, 'legacy default has no inheritance');
  });

  test('real v16 launch profile activates the full Memory-IR reranker path through profile mapping', () => {
    const profilePath = new URL('../../release/calibration/2026-06-04-memory-atom-v16/evaluator-profile-v2-dgen1-policy-r5-atom-v16-300k-enabled.json', import.meta.url);
    const launchProfile = JSON.parse(readFileSync(profilePath, 'utf8'));
    const opts = scoringOptionsFromProfile(launchProfile, runtime);
    assert.equal(opts.rerankerMemoryIRMode, 'full');
    assert.notEqual(opts.rerankerMemoryIRFormat, 'F2');
  });
});
