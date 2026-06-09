/**
 * Direct lock on `evaluateRetrievalBenchmarkPatch` acceptance gating.
 *
 * The footgun the field guards against: a caller reads `result.accepted`
 * thinking it captures the full production gate, but the evaluator only
 * checks `floors.minImprovementPpm`. Production gate is
 * `computeAcceptanceThresholdPpm(profile)` =
 *   minImprovementPpm + replayTolerancePpm + production baselineVariancePpm.
 *
 * These tests pin the contract:
 *   1. When `acceptanceThresholdPpm` is omitted, the gate falls back
 *      to `minImprovementPpm` (self-eval / scoring primitive mode).
 *   2. When `acceptanceThresholdPpm` is present, IT is the gate —
 *      a deltaPpm satisfying `minImprovementPpm` but below
 *      `acceptanceThresholdPpm` MUST be rejected with
 *      `no_retrieval_improvement`.
 *
 * The scenario uses an empty corpus + minimal patch so deltaPpm = 0
 * deterministically, then varies `floors` to land on each branch.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  evaluateRetrievalBenchmarkPatch,
  evaluateRetrievalBenchmarkState,
  computeCorpusRoot,
  merkleizeState,
  DEFAULT_PROFILE,
  RANGES,
  PATCH_TYPE,
  encodePolicyAtom,
  POLICY_SELECTOR,
  POLICY_EVIDENCE_FEATURE,
} from '../../dist/index.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
const MODEL_ID = 'test/biencoder';
const REVISION = 'rev';
const MODEL_HASH = '0xdeadbeef';

function trivialBiEncoder() {
  return {
    model: { id: MODEL_ID, revision: REVISION },
    async encode() { return new Float32Array(LAYOUT.dim); },
  };
}
function constantReranker() {
  return { model: 'const', async score(pairs) { return pairs.map(() => 0.5); } };
}

const opts = {
  weights: DEFAULT_PROFILE.compositeWeights,
  retrievalKeyLayout: LAYOUT,
  biEncoder: trivialBiEncoder(),
  reranker: constantReranker(),
  biEncoderHash: MODEL_HASH,
  relationHopBudget: 2,
  abstentionThreshold: 0.001,
  rerankerTopK: 10,
  retrievalKeyTopK: 50,
  firstStageTopK: 300,
  rerankerInputTopK: 10,
  lensTopK: 36,
  lensWeight: 0.1,
  anchorWeight: 0.15,
  relationExpansionBudget: 50,
  temporalCurrentBoost: 0.1,
  temporalStaleSuppression: 0.1,
};

function makeCorpus() {
  // Empty corpus + empty pack → before === after → deltaPpm === 0.
  // We still need a valid corpus shape so loadProductionCorpus-style
  // structural checks pass inside the evaluator.
  const events = [];
  return {
    schemaVersion: 'coretex.production-corpus.v1',
    corpusEpoch: 0,
    corpusRoot: computeCorpusRoot(events),
    generatedAt: new Date().toISOString(),
    biEncoderModelId: MODEL_ID,
    biEncoderRevision: REVISION,
    biEncoderRetrievalKeyLayout: LAYOUT,
    events,
    splitRatios: { trainVisiblePct: 70, calibrationPct: 10, evalHiddenPct: 15, canaryPct: 5 },
    byId: new Map(),
  };
}

function makeState() {
  return { words: new Array(RANGES.WORD_COUNT).fill(0n) };
}

function makeNoopDeltaPatch(parentState) {
  // Smallest valid patch: write a non-zero value into a non-reserved
  // word that's NOT touched by any query (corpus is empty so nothing
  // is). before/after composites are identical → deltaPpm = 0.
  // PATCH_TYPE.SLOT_REPLACE targets the MemoryIndex range.
  const parentRoot = merkleizeState(parentState);
  return {
    patchType: PATCH_TYPE.SLOT_REPLACE,
    wordCount: 1,
    scoreDelta: 0n,
    parentStateRoot: parentRoot,
    indices: [RANGES.MEMORY_INDEX_START],
    newWords: [1n],
  };
}

const PERMISSIVE_GUARDS = {
  structuralFloor: 0,
  protectedRegressionFloor: 1,
  familyCatastrophicFloor: 0,
};

describe('evaluateRetrievalBenchmarkPatch — acceptance threshold gating', () => {
  // Probe deltaPpm once with permissive floors so each test pins floors
  // relative to the actually-observed delta. The patch contents and
  // corpus are deterministic, so this is reproducible — but it lets the
  // test target the gating semantics without coupling to the exact
  // numeric delta (which depends on internal structural-validity math).
  async function probeDelta() {
    const state = makeState();
    const patch = makeNoopDeltaPatch(state);
    const corpus = makeCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + '55'.repeat(32), events: [] };
    const probe = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: Number.MIN_SAFE_INTEGER,
    });
    return { state, patch, corpus, pack, deltaPpm: probe.deltaPpm };
  }

  test('rejects when deltaPpm < acceptanceThresholdPpm, even if deltaPpm ≥ minImprovementPpm', async () => {
    const { state, patch, corpus, pack, deltaPpm } = await probeDelta();
    const result = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: deltaPpm,         // delta clears this floor (delta >= delta) …
      acceptanceThresholdPpm: deltaPpm + 1, // … but is strictly below the production gate.
    });
    assert.equal(result.accepted, false, `must reject: deltaPpm=${deltaPpm} < acceptanceThresholdPpm=${deltaPpm + 1}`);
    assert.equal(result.reason, 'no_retrieval_improvement');
  });

  test('accepts when deltaPpm ≥ acceptanceThresholdPpm', async () => {
    const { state, patch, corpus, pack, deltaPpm } = await probeDelta();
    const result = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: deltaPpm,
      acceptanceThresholdPpm: deltaPpm,    // delta clears the full gate exactly.
    });
    assert.equal(result.accepted, true, `must accept: deltaPpm=${deltaPpm} ≥ acceptanceThresholdPpm=${deltaPpm}`);
  });

  test('falls back to minImprovementPpm when acceptanceThresholdPpm is omitted (self-eval mode)', async () => {
    const { state, patch, corpus, pack, deltaPpm } = await probeDelta();

    // Fallback-accept: delta ≥ minImprovementPpm, no override.
    const accepted = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: deltaPpm,
    });
    assert.equal(accepted.accepted, true, `fallback path must accept when delta=${deltaPpm} ≥ minImprovementPpm`);

    // Fallback-reject: delta < minImprovementPpm, no override.
    const rejected = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: deltaPpm + 1,
    });
    assert.equal(rejected.accepted, false, 'fallback path must reject when delta < minImprovementPpm');
    assert.equal(rejected.reason, 'no_retrieval_improvement');
  });

  test('precomputed-before path matches canonical patch evaluation', async () => {
    const { state, patch, corpus, pack } = await probeDelta();
    const floors = {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: Number.MIN_SAFE_INTEGER,
      acceptanceThresholdPpm: Number.MIN_SAFE_INTEGER,
    };
    const canonical = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, floors);
    const before = await evaluateRetrievalBenchmarkState(state, corpus, pack, opts);
    const cached = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, floors, before);

    assert.equal(cached.accepted, canonical.accepted);
    assert.equal(cached.reason, canonical.reason);
    assert.equal(cached.deltaPpm, canonical.deltaPpm);
    assert.deepEqual(cached.perFamilyDelta, canonical.perFamilyDelta);
    assert.deepEqual(cached.before, canonical.before);
    assert.deepEqual(cached.after, canonical.after);
  });

  test('acceptanceThresholdPpm overrides minImprovementPpm in BOTH directions', async () => {
    // The override must be *the* gate — even if minImprovementPpm would
    // accept, an unmet acceptanceThresholdPpm must reject; even if
    // minImprovementPpm would reject, a met acceptanceThresholdPpm must
    // accept. This locks the field as the source of truth.
    const { state, patch, corpus, pack, deltaPpm } = await probeDelta();

    // min would accept, but override raises bar → reject.
    const rejected = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: deltaPpm,
      acceptanceThresholdPpm: deltaPpm + 1,
    });
    assert.equal(rejected.accepted, false);

    // min would reject, but override lowers bar → accept.
    const accepted = await evaluateRetrievalBenchmarkPatch(state, patch, corpus, pack, opts, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: deltaPpm + 1,
      acceptanceThresholdPpm: deltaPpm,
    });
    assert.equal(accepted.accepted, true);
  });

  test('r5 profile rejects malformed PolicyAtom patches at apply time', async () => {
    const state = makeState();
    const corpus = makeCorpus();
    const pack = { epochId: 0, evalSeedCommit: '0x' + '55'.repeat(32), events: [] };
    const badAtomPatch = {
      patchType: PATCH_TYPE.POLICY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: merkleizeState(state),
      indices: [RANGES.POLICY_EVIDENCE_START],
      newWords: [1n], // non-zero reserved low bits, invalid r5 atom grammar
    };

    const result = await evaluateRetrievalBenchmarkPatch(state, badAtomPatch, corpus, pack, { ...opts, policyAtomsMode: true }, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: Number.MIN_SAFE_INTEGER,
    });
    assert.equal(result.accepted, false);
    assert.equal(result.reason, 'apply_failed:E02');

    const validAtomPatch = {
      ...badAtomPatch,
      newWords: [encodePolicyAtom({
        atomIndex: 0,
        family: 'evidence_bundle',
        selector: POLICY_SELECTOR.ANSWER_DENSITY,
        evidenceFeature: POLICY_EVIDENCE_FEATURE.SUPPORT_IN_DEGREE,
        action: 'include',
        scope: 'relation_path',
        targetSlot: 0,
        budget: 250,
        flags: 0,
        validFromEpoch: 0n,
        expiryEpoch: 0n,
      })],
    };
    const valid = await evaluateRetrievalBenchmarkPatch(state, validAtomPatch, corpus, pack, { ...opts, policyAtomsMode: true }, {
      ...PERMISSIVE_GUARDS,
      minImprovementPpm: Number.MIN_SAFE_INTEGER,
    });
    assert.notEqual(valid.reason, 'apply_failed:E02');
  });
});
