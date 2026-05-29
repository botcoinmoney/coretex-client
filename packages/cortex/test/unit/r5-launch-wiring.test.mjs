/**
 * Launch-wiring regression tests for two r5 gaps found in the launch audit:
 *
 *  P1 — buildPolicyEntityRegistry: the canonical profile→options path carried no
 *       policyEntityRegistry, so the r5 query-conditioned admission block (guarded on
 *       opts.policyEntityRegistry) silently no-opped in production. The registry is now
 *       derived deterministically from the PUBLIC corpus.
 *
 *  P2 — apply-path PolicyAtom validation: validatePolicyRegions was never called on the
 *       acceptance path, so under r5 a patch could write nonzero words into the reserved
 *       policy region (896–991) or malformed PolicyAtoms and be ACCEPTED + committed. The
 *       apply functions now hard-fail when policyAtomsMode is set (r4 path unchanged).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { buildPolicyEntityRegistry, resolveQuerySubjects, POLICY_MAX_SELECTOR_FANOUT, encodePolicyAtom, POLICY_SELECTOR, POLICY_EVIDENCE_FEATURE, assertGradedRelevance } from '../../dist/index.js';
import { applyPatch, applyPatchOntoCurrent } from '../../dist/state/patch.js';
import { merkleizeState } from '../../dist/state/merkle.js';
import { RANGES, PATCH_TYPE } from '../../dist/state/types.js';

const zero = () => ({ words: new Array(1024).fill(0n) });
const VALID_EB = encodePolicyAtom({
  atomIndex: 0, family: 'evidence_bundle', selector: POLICY_SELECTOR.ANSWER_DENSITY,
  evidenceFeature: POLICY_EVIDENCE_FEATURE.SUPPORT_IN_DEGREE, action: 'bundle', scope: 'relation_path',
  targetSlot: 5, budget: 1000, flags: 0, validFromEpoch: 0n, expiryEpoch: 0n,
});
const mixed = (idx, word) => ({ patchType: PATCH_TYPE.MIXED, wordCount: 1, scoreDelta: 1, parentStateRoot: new Uint8Array(32), indices: [idx], newWords: [word] });

describe('P1 — buildPolicyEntityRegistry (derive public registry from corpus)', () => {
  const corpus = {
    entities: [
      { id: 'e_universe', canonicalName: 'Deep Memory Universe 0', aliases: [] },
      { id: 'e_s0', canonicalName: 'Aisha Costa', aliases: ['Aisha', 'Aisha the ER nurse'] },
      { id: 'e_s1', canonicalName: 'image-pipeline-svc-0', aliases: ['image-pipeline-svc-0'] },
    ],
    events: [
      { ownerEntityId: 'e_universe', entityIds: ['e_universe', 'e_s0'] },
      { ownerEntityId: 'e_universe', entityIds: ['e_universe', 'e_s1'] },
    ],
  };

  test('registry lowercases canonicalName + aliases, preserves entity order', () => {
    const { registry } = buildPolicyEntityRegistry(corpus);
    assert.equal(registry.length, 3);
    assert.deepEqual(registry[1], { id: 'e_s0', names: ['aisha costa', 'aisha', 'aisha the er nurse'] });
    // canonicalName + aliases are concatenated as-is (no dedup — matches the probe builder).
    assert.deepEqual(registry[2].names, ['image-pipeline-svc-0', 'image-pipeline-svc-0']);
  });

  test('generic ids = the public owner scopes, NOT subjects (no flood)', () => {
    const { genericEntityIds } = buildPolicyEntityRegistry(corpus);
    assert.deepEqual([...genericEntityIds], ['e_universe']);
  });

  test('deterministic: same corpus → identical registry + generic ids', () => {
    const a = buildPolicyEntityRegistry(corpus);
    const b = buildPolicyEntityRegistry(corpus);
    assert.deepEqual(a, b);
  });

  test('no owner field → empty generic set (safe, no over-suppression)', () => {
    const { genericEntityIds } = buildPolicyEntityRegistry({ entities: corpus.entities, events: [{ entityIds: ['e_s0'] }] });
    assert.deepEqual([...genericEntityIds], []);
  });
});

describe('P2 — apply-path hard-fails r5 forge under policyAtomsMode (r4 path unchanged)', () => {
  test('FORGE into reserved policy region (896) is ACCEPTED under r4 but REJECTED (E04) under r5', () => {
    const s = zero();
    const patch = mixed(RANGES.CODEBOOK_START, 1n); // 896 == POLICY_RESERVED_START under r5
    assert.equal(applyPatchOntoCurrent(s, patch, false).ok, true, 'r4: reclaimed-word mask is 0 → accepted (the gap)');
    const r5 = applyPatchOntoCurrent(s, patch, true);
    assert.equal(r5.ok, false);
    assert.equal(r5.code, 'E04', 'r5: reserved policy region must be zero');
  });

  test('MALFORMED PolicyAtom (384) is ACCEPTED under r4 but REJECTED (E02) under r5', () => {
    const s = zero();
    const patch = mixed(RANGES.POLICY_EVIDENCE_START, 1n); // nonzero reserved_pa bits → invalid atom
    assert.equal(applyPatchOntoCurrent(s, patch, false).ok, true);
    const r5 = applyPatchOntoCurrent(s, patch, true);
    assert.equal(r5.ok, false);
    assert.equal(r5.code, 'E02', 'r5: malformed atom fails closed');
  });

  test('VALID PolicyAtom (384) is accepted under r5', () => {
    const s = zero();
    const patch = mixed(RANGES.POLICY_EVIDENCE_START, VALID_EB);
    assert.equal(applyPatchOntoCurrent(s, patch, true).ok, true);
  });

  test('applyPatch (parent-checked path) also rejects the reserved forge under r5', () => {
    const s = zero();
    const patch = { ...mixed(RANGES.CODEBOOK_START, 1n), parentStateRoot: merkleizeState(s) };
    assert.equal(applyPatch(s, patch, false).ok, true);
    assert.equal(applyPatch(s, patch, true).code, 'E04');
  });
});

describe('Fix A — resolveQuerySubjects (collision-proof selector; 300k zero-signal fix)', () => {
  // 112 entities share the colliding canonical name "Yuki Nadar" (the 300k failure mode).
  const registry = [
    { id: 'e_universe', names: ['deep memory universe 0'] },
    ...Array.from({ length: 112 }, (_, i) => ({ id: `e_s${i}`, names: ['yuki nadar', 'yuki'] })),
    { id: 'e_other', names: ['aisha costa', 'aisha'] },
  ];
  const generic = ['e_universe'];
  const qtext = "What diet is Yuki Nadar currently following?";

  test('PUBLIC subjectEntityId grounding collapses 112-way collision to the one true subject', () => {
    const subjects = resolveQuerySubjects(qtext, 'e_s42', registry, generic);
    assert.deepEqual([...subjects], ['e_s42']);
  });

  test('name-text fallback is FAIL-CLOSED on ambiguity (>MAX_FANOUT → admit nothing, no flood)', () => {
    const subjects = resolveQuerySubjects(qtext, undefined, registry, generic);
    assert.equal(subjects.size, 0, `112-way match must admit nothing, not flood (cap=${POLICY_MAX_SELECTOR_FANOUT})`);
  });

  test('name-text fallback resolves an unambiguous (<=MAX_FANOUT) name', () => {
    const subjects = resolveQuerySubjects('what does Aisha Costa prefer?', undefined, registry, generic);
    assert.deepEqual([...subjects], ['e_other']);
  });

  test('generic owner ids are never selected', () => {
    const subjects = resolveQuerySubjects('deep memory universe 0 stuff', 'e_universe', registry, generic);
    assert.equal(subjects.size, 0);
  });

  test('word-boundary match (no substring fanout): "Ana" does not match "Anabel"', () => {
    const reg = [{ id: 'e_a', names: ['anabel'] }];
    assert.equal(resolveQuerySubjects('where is Ana?', undefined, reg, []).size, 0);
    assert.deepEqual([...resolveQuerySubjects('where is Anabel?', undefined, reg, [])], ['e_a']);
  });
});

describe('P4 — assertGradedRelevance (durable graded-relevance guard)', () => {
  test('accepts on-scale grades, rejects the off-scale 0.5 (historical bridge bug)', () => {
    for (const g of [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]) assert.equal(assertGradedRelevance(g), g);
    assert.throws(() => assertGradedRelevance(0.5), /off the GradedRelevance scale/);
    assert.throws(() => assertGradedRelevance(0.3), /off the GradedRelevance scale/);
  });
});
