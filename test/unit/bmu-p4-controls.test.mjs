/**
 * P4 reward-law controls.
 *
 * These are CI-scale adversarial controls over the BMU production scoring
 * primitives: candidate patches are evaluated on gate and confirm packs using
 * the same evaluateBmuBenchmarkPatch law the coordinator consumes. The suite
 * pins the miner-facing promise:
 *   - generalized row fixes transfer gate -> confirm;
 *   - exact hidden-row anchoring dies on confirm;
 *   - no-op/random, forbidden budget floods, stale-direction inversions,
 *     protected regressions, and always-abstain patches do not advance.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  computeCorpusRoot,
  createDeterministicBiEncoder,
  biEncoderModelIdHash,
  evaluateBmuBenchmarkState,
  evaluateBmuBenchmarkPatch,
  mapBmuExternalRejectionReason,
  merkleizeState,
  PATCH_TYPE,
  RANGES,
  encodePolicyAtom,
  POLICY_SELECTOR,
  POLICY_EVIDENCE_FEATURE,
  POLICY_TARGET_NONE,
} from '../../dist/index.js';

const BI = { modelId: 'BAAI/bge-m3', revision: 'c'.repeat(40), mode: 'dense' };
const LAYOUT = { dim: 32, quantization: 'int8', headerBytes: 9 };
const ZERO_STATE = { words: new Array(1024).fill(0n) };
const EPOCH = 41;
const GATE_SEED = '0x' + '44'.repeat(32);
const CONFIRM_SEED = '0x' + '55'.repeat(32);

const FAMILIES = [
  { bmu: 'temporal', bucketed: 'temporal', logical: 'temporal_update' },
  { bmu: 'conflict_lifecycle', bucketed: 'conflict_lifecycle', logical: 'conflict_lifecycle' },
  { bmu: 'multi_hop_relation', bucketed: 'multi_hop_relation', logical: 'multi_session_bridge' },
  { bmu: 'near_collision_abstention', bucketed: 'near_collision', logical: 'abstention_missing' },
];

const WEIGHTS = {
  w_retrieval: 0.75,
  w_temporal: 0.08,
  w_relation_recall: 0.07,
  w_abstention: 0.05,
  w_structural_sanity: 0.05,
};

const FLOORS = {
  minImprovementPpm: 20_000,
  structuralFloor: 0,
  protectedRegressionFloor: 1,
  familyCatastrophicFloor: 0,
  acceptanceThresholdPpm: 20_250,
};

function row({ id, fam, protectedRow = false }) {
  const truthId = `${id}-truth`;
  const trapId = `${id}-trap`;
  const fillId = `${id}-fill`;
  return {
    id,
    family: fam.bucketed,
    domain: 'p4',
    split: 'eval_hidden',
    queryText: `q-${id}`,
    truthDocuments: [{ id: truthId, text: `truth-${id}`, isCurrent: true }],
    hardNegatives: [
      { id: trapId, text: `trap-${id}` },
      { id: fillId, text: `fill-${id}` },
    ],
    qrels: [
      { documentId: truthId, relevance: 1.0 },
      { documentId: trapId, relevance: 0.0 },
      { documentId: fillId, relevance: 0.0 },
    ],
    protected: protectedRow,
    logicalFamily: fam.logical,
    subjectEntityId: `subject-${id}`,
    bmuTask: {
      family: fam.bmu,
      budgetB: 3,
      requiredEvidence: [truthId],
      forbiddenEvidence: [trapId],
      answer: { id: truthId },
      motifGroupId: `motif-${id}`,
      templateId: `template-${id}`,
    },
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'cc'.repeat(32) },
    embeddings: {
      modelId: BI.modelId,
      revision: BI.revision,
      layout: LAYOUT,
      query: new Uint8Array(LAYOUT.dim + 4),
      perTruth: new Map([[truthId, new Uint8Array(LAYOUT.dim + 4)]]),
      perNegative: new Map([
        [trapId, new Uint8Array(LAYOUT.dim + 4)],
        [fillId, new Uint8Array(LAYOUT.dim + 4)],
      ]),
    },
  };
}

function makeRows(prefix) {
  const events = [];
  for (const fam of FAMILIES) {
    for (let i = 0; i < 16; i++) {
      events.push(row({
        id: `${prefix}-${fam.bmu}-${String(i).padStart(2, '0')}`,
        fam,
        protectedRow: prefix === 'confirm' && fam.bmu === 'temporal' && i === 0,
      }));
    }
  }
  assert.equal(events.length, 64);
  return events;
}

function makeFixture() {
  const gate = makeRows('gate');
  const confirm = makeRows('confirm');
  const events = [...gate, ...confirm];
  const corpusRoot = computeCorpusRoot(events);
  const corpus = {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot,
    corpusEpoch: 0,
    biEncoderModelId: BI.modelId,
    biEncoderRevision: BI.revision,
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: 'memreranker/4B',
    labelingModelRevision: 'd'.repeat(40),
  };
  return {
    corpus,
    gatePack: { epochId: EPOCH, evalSeedHex: GATE_SEED, corpusRoot, events: gate },
    confirmPack: { epochId: EPOCH, evalSeedHex: CONFIRM_SEED, corpusRoot, events: confirm },
  };
}

function bmuOpts(reranker, extra = {}) {
  return {
    weights: WEIGHTS,
    retrievalKeyLayout: LAYOUT,
    biEncoderHash: biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode),
    biEncoder: createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT }),
    reranker,
    relationHopBudget: 2,
    abstentionThreshold: 0.001,
    rerankerTopK: 10,
    rerankerInputTopK: 512,
    firstStageTopK: 512,
    lensTopK: 36,
    lensWeight: 0.1,
    anchorWeight: 0.15,
    relationExpansionBudget: 50,
    temporalCurrentBoost: 0.1,
    temporalStaleSuppression: 0.1,
    pipelineVersion: 'coretex-bmu-v1-r5state',
    policyAtomsMode: true,
    ...extra,
  };
}

function rerankerFor({ trapHighRows = [] } = {}) {
  const trapHigh = new Set(trapHighRows);
  return {
    model: 'p4-control-reranker',
    async score(pairs) {
      return pairs.map((p) => {
        const rid = p.query.slice(2);
        if (p.document === `truth-${rid}`) return 0.90;
        if (p.document === `trap-${rid}`) return trapHigh.has(rid) ? 0.95 : -0.50;
        if (p.document === `fill-${rid}`) return 0.35;
        return 0.01;
      });
    },
  };
}

function patchAt(index, word = 1n, patchType = PATCH_TYPE.SLOT_REPLACE) {
  return {
    patchType,
    wordCount: 1,
    scoreDelta: 0n,
    parentStateRoot: merkleizeState(ZERO_STATE),
    indices: [index],
    newWords: [word],
  };
}

function inertPatch() {
  return patchAt(RANGES.MEMORY_INDEX_START, 1n);
}

function alwaysAbstainPatch() {
  return patchAt(RANGES.POLICY_ABSTENTION_START, encodePolicyAtom({
    atomIndex: 0,
    family: 'abstention',
    selector: POLICY_SELECTOR.MISSING_EVIDENCE,
    evidenceFeature: POLICY_EVIDENCE_FEATURE.NO_PUBLIC_EVIDENCE_PATH,
    action: 'abstain',
    scope: 'entity',
    targetSlot: POLICY_TARGET_NONE,
    budget: 0,
    flags: 0x01,
    validFromEpoch: 0n,
    expiryEpoch: 0n,
  }), PATCH_TYPE.POLICY_UPDATE);
}

async function evalOne({ corpus, pack, beforeTrapRows = [], afterTrapRows = [], patch = inertPatch(), optsExtra = {} }) {
  const before = await evaluateBmuBenchmarkState(
    ZERO_STATE,
    corpus,
    pack,
    bmuOpts(rerankerFor({ trapHighRows: beforeTrapRows }), optsExtra),
  );
  return evaluateBmuBenchmarkPatch(
    ZERO_STATE,
    patch,
    corpus,
    pack,
    bmuOpts(rerankerFor({ trapHighRows: afterTrapRows }), optsExtra),
    FLOORS,
    {},
    before,
  );
}

async function evalDualControl({
  gateBeforeTrapRows = [],
  gateAfterTrapRows = [],
  confirmBeforeTrapRows = [],
  confirmAfterTrapRows = [],
  patch = inertPatch(),
  optsExtra = {},
} = {}) {
  const fixture = makeFixture();
  const gate = await evalOne({
    corpus: fixture.corpus,
    pack: fixture.gatePack,
    beforeTrapRows: gateBeforeTrapRows,
    afterTrapRows: gateAfterTrapRows,
    patch,
    optsExtra,
  });
  if (!gate.accepted) {
    return {
      accepted: false,
      stage: 'gate',
      gate,
      reason: mapBmuExternalRejectionReason({ outerCode: 'gate-acceptance-floor', innerReason: gate.reason }),
    };
  }

  const confirm = await evalOne({
    corpus: fixture.corpus,
    pack: fixture.confirmPack,
    beforeTrapRows: confirmBeforeTrapRows,
    afterTrapRows: confirmAfterTrapRows,
    patch,
    optsExtra,
  });
  if (!confirm.accepted) {
    return {
      accepted: false,
      stage: 'confirm',
      gate,
      confirm,
      reason: mapBmuExternalRejectionReason({ outerCode: 'confirm-acceptance-floor', innerReason: confirm.reason }),
    };
  }
  return { accepted: true, gate, confirm };
}

function ids(prefix, fam, indices) {
  return indices.map((i) => `${prefix}-${fam}-${String(i).padStart(2, '0')}`);
}

describe('P4 dual-pack controls over the BMU acceptance law', () => {
  for (const fam of FAMILIES) {
    test(`known-good generalized patch clears gate and confirm by at least 3x the advance threshold: ${fam.bmu}`, async () => {
      const gateTargets = ids('gate', fam.bmu, [0, 1, 2, 3]);
      const confirmTargets = ids('confirm', fam.bmu, [0, 1, 2, 3]);
      const result = await evalDualControl({
        gateBeforeTrapRows: gateTargets,
        confirmBeforeTrapRows: confirmTargets,
      });
      assert.equal(result.accepted, true);
      assert.ok(result.gate.deltaPpm >= 3 * FLOORS.acceptanceThresholdPpm, `gate delta ${result.gate.deltaPpm}`);
      assert.ok(result.confirm.deltaPpm >= 3 * FLOORS.acceptanceThresholdPpm, `confirm delta ${result.confirm.deltaPpm}`);
      assert.equal(result.gate.after.bmu.utilitySum - result.gate.before.bmu.utilitySum, 4);
      assert.equal(result.confirm.after.bmu.utilitySum - result.confirm.before.bmu.utilitySum, 4);
    });
  }

  test('exact hidden-row anchoring passes gate but dies on held-out confirm', async () => {
    const gateTargets = ids('gate', 'temporal', [4, 5, 6, 7]);
    const result = await evalDualControl({
      gateBeforeTrapRows: gateTargets,
      confirmBeforeTrapRows: [],
    });
    assert.equal(result.accepted, false);
    assert.equal(result.stage, 'confirm');
    assert.equal(result.gate.accepted, true);
    assert.equal(result.confirm.accepted, false);
    assert.equal(result.confirm.reason, 'no_retrieval_improvement');
    assert.equal(result.reason, 'failed_holdout_transfer');
  });

  test('no-op/random patch is below gate', async () => {
    const result = await evalDualControl();
    assert.equal(result.accepted, false);
    assert.equal(result.stage, 'gate');
    assert.equal(result.gate.reason, 'no_retrieval_improvement');
    assert.equal(result.reason, 'below_gate');
  });

  test('budget-flood patch is rejected even when net-positive', async () => {
    const beforeDown = [
      ...ids('gate', 'conflict_lifecycle', [0, 1, 2]),
      ...ids('gate', 'multi_hop_relation', [0, 1, 2]),
    ];
    const flooded = [
      ids('gate', 'temporal', [1])[0],
      ids('gate', 'conflict_lifecycle', [8])[0],
      ids('gate', 'near_collision_abstention', [8])[0],
    ];
    const result = await evalDualControl({
      gateBeforeTrapRows: beforeDown,
      gateAfterTrapRows: flooded,
    });
    assert.equal(result.accepted, false);
    assert.equal(result.stage, 'gate');
    assert.equal(result.gate.reason, 'regression_budget_total');
    assert.ok(result.gate.deltaPpm > FLOORS.acceptanceThresholdPpm);
    for (const rowId of flooded) {
      const row = result.gate.after.bmu.perTask.find((t) => t.recordId === rowId);
      assert.equal(row?.failure, 'forbidden_admitted', rowId);
    }
    assert.equal(result.reason, 'safety_regression');
  });

  test('shared-attribute stale/current inversion is rejected by the per-family safety budget', async () => {
    const beforeDown = ids('gate', 'multi_hop_relation', [4, 5, 6, 7, 8, 9]);
    const staleDirectionInversion = ids('gate', 'temporal', [2, 3]);
    const result = await evalDualControl({
      gateBeforeTrapRows: beforeDown,
      gateAfterTrapRows: staleDirectionInversion,
    });
    assert.equal(result.accepted, false);
    assert.equal(result.stage, 'gate');
    assert.equal(result.gate.reason, 'regression_budget_family:temporal');
    assert.ok(result.gate.deltaPpm > FLOORS.acceptanceThresholdPpm);
    assert.equal(result.reason, 'safety_regression');
  });

  test('protected-row regression vetoes a net-positive patch', async () => {
    const beforeDown = ids('confirm', 'multi_hop_relation', [10, 11, 12, 13, 14, 15]);
    const protectedRow = ids('confirm', 'temporal', [0]);
    const fixture = makeFixture();
    const result = await evalOne({
      corpus: fixture.corpus,
      pack: fixture.confirmPack,
      beforeTrapRows: beforeDown,
      afterTrapRows: protectedRow,
    });
    assert.equal(result.accepted, false);
    assert.equal(result.reason, 'protected_regression:confirm-temporal-00');
    assert.ok(result.deltaPpm > FLOORS.acceptanceThresholdPpm);
  });

  test('always-abstain policy atom fails answerable packs through the production path', async () => {
    const fixture = makeFixture();
    const result = await evalOne({
      corpus: fixture.corpus,
      pack: fixture.gatePack,
      patch: alwaysAbstainPatch(),
      optsExtra: {
        enableAbstentionAtoms: true,
        policyAbstentionTop1Threshold: 1.1,
        policyAbstentionMarginThreshold: 2.0,
      },
    });
    assert.equal(result.accepted, false);
    assert.ok(result.reason?.startsWith('regression_budget_family:'));
    assert.equal(result.after.bmu.perTask.every((t) => t.failure === 'false_abstain'), true);
    assert.equal(result.after.bmu.utilitySum, 0);
  });
});
