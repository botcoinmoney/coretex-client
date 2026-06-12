/**
 * B6 — the single reward-active substrate-surface source of truth + the
 * advertised-vs-reward-active boot assertion.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { rewardActiveSubstrateSurfaces, assertActiveSurfacesRewardActive } from '../../dist/index.js';

describe('rewardActiveSubstrateSurfaces', () => {
  test('unions the profile list with flag-derived surfaces', () => {
    const set = rewardActiveSubstrateSurfaces({
      activeSubstrateSurfaces: ['temporal_update', 'coreference'],
      enableEvidenceBundleAtoms: true,
      enableConflictLifecycleAtoms: true,
      enableAbstentionAtoms: true,
      enableScopeAtoms: true,
      enableEntityResolutionAtoms: true,
      policyRelationTypedAdmission: true,
    });
    for (const s of ['temporal_update', 'coreference', 'evidence_bundle', 'conflict_lifecycle',
      'abstention_top1', 'scope_atom', 'entity_resolution_atom', 'relation_category_routing', 'validity_atom']) {
      assert.ok(set.has(s), `${s} reward-active`);
    }
  });

  test('validity_atom is reward-active unless enableValidityAtoms is explicitly false', () => {
    assert.ok(rewardActiveSubstrateSurfaces({}).has('validity_atom'));            // undefined → on (preserved default)
    assert.ok(!rewardActiveSubstrateSurfaces({ enableValidityAtoms: false }).has('validity_atom'));
  });

  test('disabled flags do NOT add their surface', () => {
    const set = rewardActiveSubstrateSurfaces({ enableScopeAtoms: false, enableEntityResolutionAtoms: false });
    assert.ok(!set.has('scope_atom'));
    assert.ok(!set.has('entity_resolution_atom'));
  });

  test('temporalStaleContrast:false removes temporal_update', () => {
    assert.ok(!rewardActiveSubstrateSurfaces({ temporalStaleContrast: false }).has('temporal_update'));
  });
});

describe('assertActiveSurfacesRewardActive', () => {
  const profile = { activeSubstrateSurfaces: ['temporal_update'], enableConflictLifecycleAtoms: true };

  test('passes when every advertised surface is reward-active', () => {
    assert.doesNotThrow(() => assertActiveSurfacesRewardActive(['temporal_update', 'conflict_lifecycle', 'validity_atom'], profile));
  });

  test('throws naming a surface that is NOT reward-active (operator env drift)', () => {
    assert.throws(
      () => assertActiveSurfacesRewardActive(['temporal_update', 'evidence_bundle'], profile),
      /NOT reward-active.*evidence_bundle/,
    );
  });

  test('an empty advertised list is vacuously valid', () => {
    assert.doesNotThrow(() => assertActiveSurfacesRewardActive([], profile));
  });
});
