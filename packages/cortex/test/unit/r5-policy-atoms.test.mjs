import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  decodeSubstrate,
  decodePolicyAtomRegion,
  encodePolicyAtom,
  policyReservedNonZeroWords,
  validatePolicyRegions,
  validateReservedBits,
  encodeRetrievalKeySlot,
  encodeCodebookEntry,
  encodeMemoryIndexSlot,
  decodeMemoryIndex,
  assertPipelineVersionMatches,
  CORETEX_PIPELINE_VERSION_THIS_BINARY,
  CORETEX_PIPELINE_VERSION_R5,
  POLICY_SELECTOR,
  POLICY_EVIDENCE_FEATURE,
  POLICY_TARGET_NONE,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const zero = () => ({ words: new Array(1024).fill(0n) });

const EB = { atomIndex: 0, family: 'evidence_bundle', selector: POLICY_SELECTOR.ANSWER_DENSITY, evidenceFeature: POLICY_EVIDENCE_FEATURE.SUPPORT_IN_DEGREE, action: 'bundle', scope: 'relation_path', targetSlot: 5, budget: 1000, flags: 0, validFromEpoch: 0n, expiryEpoch: 0n };
const CL = { atomIndex: 0, family: 'conflict_lifecycle', selector: POLICY_SELECTOR.CONFLICT_SET_MEMBER, evidenceFeature: POLICY_EVIDENCE_FEATURE.LIFECYCLE_STATE, action: 'boost', scope: 'conflict_set', targetSlot: 7, budget: 1000, flags: 0, validFromEpoch: 10n, expiryEpoch: 200n };
const AB = { atomIndex: 0, family: 'abstention', selector: POLICY_SELECTOR.MISSING_EVIDENCE, evidenceFeature: POLICY_EVIDENCE_FEATURE.NO_PUBLIC_EVIDENCE_PATH, action: 'abstain', scope: 'entity', targetSlot: POLICY_TARGET_NONE, budget: 0, flags: 0x01, validFromEpoch: 0n, expiryEpoch: 0n };

describe('r5 PolicyAtom decode/encode roundtrip', () => {
  test('each family roundtrips with expiry/validity', () => {
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom(EB);
    s.words[RANGES.POLICY_CONFLICT_START] = encodePolicyAtom(CL);
    s.words[RANGES.POLICY_ABSTENTION_START] = encodePolicyAtom(AB);
    const d = decodeSubstrate(s, { policyAtomsMode: true });
    assert.equal(d.evidenceBundleAtoms.length, 1);
    assert.equal(d.evidenceBundleAtoms[0].action, 'bundle');
    assert.equal(d.evidenceBundleAtoms[0].targetSlot, 5);
    assert.equal(d.evidenceBundleAtoms[0].budget, 1000);
    assert.equal(d.conflictLifecycleAtoms.length, 1);
    assert.equal(d.conflictLifecycleAtoms[0].action, 'boost');
    assert.equal(d.conflictLifecycleAtoms[0].validFromEpoch, 10n);
    assert.equal(d.conflictLifecycleAtoms[0].expiryEpoch, 200n);
    assert.equal(d.abstentionAtoms.length, 1);
    assert.equal(d.abstentionAtoms[0].action, 'abstain');
    assert.equal(d.abstentionAtoms[0].targetSlot, POLICY_TARGET_NONE);
    assert.equal(d.abstentionAtoms[0].flags, 0x01);
    assert.equal(d.decodeFailures, 0, 'clean r5 decode has zero failures');
  });
});

describe('r5/r4 hard gating (no silent reinterpretation)', () => {
  test('r5 atoms are zero-effect under r4 decode', () => {
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom(EB);
    const d4 = decodeSubstrate(s, { policyAtomsMode: false });
    assert.equal(d4.evidenceBundleAtoms.length, 0);
    assert.equal(d4.conflictLifecycleAtoms.length, 0);
    assert.equal(d4.abstentionAtoms.length, 0);
  });

  test('r4 RetrievalKeys + Codebook are NOT decoded under r5 (no dense-lens / codebook leak)', () => {
    const s = zero();
    // a valid r4 retrieval-key slot at slot 0 (words 384..391) + a codebook entry at 896..897
    const keyWords = encodeRetrievalKeySlot({ slotIndex: 0, modelIdHash: '0xdeadbeef', l2Norm: 1.0, versionTag: 1, quantizedBytes: new Uint8Array([1, 2, 3, 4]) });
    for (let w = 0; w < keyWords.length; w++) s.words[RANGES.RETRIEVAL_KEYS_START + w] = keyWords[w];
    const cb = encodeCodebookEntry({ entryIndex: 0, code: 7, codeType: 'int8_scale_zero', valid: true, payload: 42n, payloadCont: 0n });
    s.words[RANGES.CODEBOOK_START] = cb[0]; s.words[RANGES.CODEBOOK_START + 1] = cb[1];
    const d4 = decodeSubstrate(s, { policyAtomsMode: false });
    assert.ok(d4.retrievalKeys.some((k) => k !== null), 'r4 mode decodes the retrieval key');
    assert.ok(d4.codebook.some((c) => c !== null), 'r4 mode decodes the codebook entry');
    const d5 = decodeSubstrate(s, { policyAtomsMode: true });
    assert.equal(d5.retrievalKeys.length, 0, 'r5 mode does NOT decode RetrievalKeys as a dense lens');
    assert.equal(d5.codebook.length, 0, 'r5 mode does NOT decode the Codebook');
  });
});

describe('r5 reserved region + invalid-atom enforcement', () => {
  test('reserved r5 policy region (896-991) must be zero', () => {
    const s = zero();
    s.words[RANGES.POLICY_RESERVED_START + 4] = 123n;
    assert.equal(policyReservedNonZeroWords(s), 1);
    const v = validatePolicyRegions(s);
    assert.equal(v?.code, 'E04');
  });

  test('clean policy state validates', () => {
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom(EB);
    assert.equal(validatePolicyRegions(s), null);
  });

  test('atom with non-zero reserved bits is dropped + fails validation', () => {
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom(EB) | 1n; // bit 0 reserved
    const r = decodePolicyAtomRegion(s, 'evidence_bundle');
    assert.equal(r.atoms.length, 0);
    assert.equal(r.failures, 1);
    assert.equal(validatePolicyRegions(s)?.code, 'E02');
  });

  test('disallowed action for a family is dropped (abstain in evidence region)', () => {
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom({ ...EB, action: 'abstain', targetSlot: POLICY_TARGET_NONE });
    assert.equal(decodePolicyAtomRegion(s, 'evidence_bundle').failures, 1);
  });

  test('non-abstain atom without a public anchor is dropped', () => {
    const s = zero();
    s.words[RANGES.POLICY_CONFLICT_START] = encodePolicyAtom({ ...CL, targetSlot: POLICY_TARGET_NONE });
    assert.equal(decodePolicyAtomRegion(s, 'conflict_lifecycle').failures, 1);
  });

  test('targetSlot must be 8-bit-addressable (0..255); 256..351 rejected at encode AND decode', () => {
    // encode rejects an unaddressable anchor (256..351 is decoded by MemoryIndex but not 8-bit referenceable)
    assert.throws(() => encodePolicyAtom({ ...EB, targetSlot: 300 }), /targetSlot/);
    // and if a raw word smuggles slot 300 in, decode drops it
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = (encodePolicyAtom({ ...EB, targetSlot: 255 }) & ~(0xffffn << 216n)) | (300n << 216n);
    assert.equal(decodePolicyAtomRegion(s, 'evidence_bundle').failures, 1);
    // slot 255 is the max valid anchor
    const s2 = zero();
    s2.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom({ ...EB, targetSlot: 255 });
    assert.equal(decodePolicyAtomRegion(s2, 'evidence_bundle').atoms.length, 1);
  });

  test('static validateReservedBits stays r4-compatible for the reclaimed word ranges', () => {
    // An r5 atom sets bits in 384-671 that r4 treated as key payload (mask 0) → static
    // reserved-bit check must still pass (the r5 typed check is validatePolicyRegions).
    const s = zero();
    s.words[RANGES.POLICY_EVIDENCE_START] = encodePolicyAtom(EB);
    assert.equal(validateReservedBits(s), null);
  });
});

describe('r5 policyAnchor MemoryIndex flag', () => {
  test('policyAnchor roundtrips and defaults false', () => {
    const s = zero();
    const w = encodeMemoryIndexSlot({ slotIndex: 0, recordId: 123n, family: 'multi_hop_relation', domainBits: 1n, valid: true, revoked: false, protected: false, policyAnchor: true, retrievalSlot: 0, expiryEpoch: 0n });
    s.words[RANGES.MEMORY_INDEX_START] = w[0];
    const w2 = encodeMemoryIndexSlot({ slotIndex: 1, recordId: 456n, family: 'temporal', domainBits: 1n, valid: true, revoked: false, protected: false, retrievalSlot: 0, expiryEpoch: 0n });
    s.words[RANGES.MEMORY_INDEX_START + 1] = w2[0];
    const d = decodeMemoryIndex(s);
    assert.equal(d.slots[0].policyAnchor, true);
    assert.equal(d.slots[1].policyAnchor, false, 'defaults false when flag bit unset');
    assert.equal(d.slots[0].valid, true);
    assert.equal(d.failures, 0);
  });
});

describe('r5 pipelineVersion routing', () => {
  test('binary replays BOTH r4 and r5; rejects unknown', () => {
    assert.doesNotThrow(() => assertPipelineVersionMatches(CORETEX_PIPELINE_VERSION_THIS_BINARY));
    assert.doesNotThrow(() => assertPipelineVersionMatches(CORETEX_PIPELINE_VERSION_R5));
    assert.throws(() => assertPipelineVersionMatches('coretex-retrieval-v9-imaginary'));
  });
});
