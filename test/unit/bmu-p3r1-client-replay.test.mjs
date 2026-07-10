/**
 * P3-R1 MAJOR-2 — validator SCORE REPLAY runs the BMU law on BMU artifacts
 * (BMU_SPEC §9 LAW site 18, rev3.3):
 *   - an HONEST BMU artifact (receipt scores produced by the production BMU
 *     path) replays GREEN end-to-end through
 *     verifyPostRevealEvalReportArtifact + scorerForParent;
 *   - the version-pairing guard REFUSES a BMU artifact under an r5 bundle and
 *     an r5 artifact under a BMU bundle (fail-closed both directions);
 *   - an R5-SCORED BMU artifact — receipt scores produced the way the
 *     pre-fix code replayed them (r5 pack law + r5 composite) — is REJECTED
 *     beyond replay tolerance (the exact wrong-law failure MAJOR-2 named).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { scorerForParent } from '../../dist/client-sync-cli.js';
import {
  computeDedupKey,
  verifyPostRevealEvalReportArtifact,
  buildPostRevealEvalReportArtifact,
  scoreBmuAgainstSeed,
  deriveGateEvalSeed,
  deriveConfirmEvalSeed,
  computePatchHash,
  deriveScoredQueryPack,
  evaluateRetrievalBenchmarkPatch,
  computeCorpusRoot,
  createDeterministicBiEncoder,
  biEncoderModelIdHash,
  merkleizeState,
  encodePatch,
  decodePatch,
  bytesToHex,
  keccak256,
  hexToBytes,
  PATCH_TYPE,
  RANGES,
  encodeMemoryIndexSlot,
  encodePolicyAtom,
  POLICY_SELECTOR,
  POLICY_EVIDENCE_FEATURE,
  stableRecordIdFor,
} from '../../dist/index.js';

const B32 = (b) => '0x' + b.repeat(32);
const ZERO_STATE = { words: new Array(1024).fill(0n) };
const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40), mode: 'dense' };
const LAYOUT = { dim: 32, quantization: 'int8', headerBytes: 9 };
const EPOCH = 137;
const EPOCH_SECRET = B32('0e');
const BLOCKHASH = B32('ab');
const BUNDLE_HASH = B32('dd');
const T_ID = 'q_conflict_lifecycle_00'; // the anchor event whose truth doc is every row's trap
const T_DOC = `${T_ID}-t`;

const FAMS = [
  { bmu: 'temporal', bucketed: 'temporal', logical: 'temporal_update' },
  { bmu: 'conflict_lifecycle', bucketed: 'conflict_lifecycle', logical: 'conflict_lifecycle' },
  { bmu: 'multi_hop_relation', bucketed: 'multi_hop_relation', logical: 'multi_session_bridge' },
  { bmu: 'near_collision_abstention', bucketed: 'near_collision', logical: 'abstention_missing' },
];

/** Row-distinguishable embeddings: query k and its own docs share a one-hot
 *  direction; T's trap doc is all-ones so it lands in EVERY query's stage-1
 *  pool at moderate cosine. */
function emb(fill) {
  const bytes = new Uint8Array(LAYOUT.dim + 4);
  if (typeof fill === 'number') bytes[4 + (fill % LAYOUT.dim)] = 100;
  else bytes.fill(50, 4);
  return bytes;
}

function bmuEvent({ rid, fam, k }) {
  const truthId = `${rid}-t`;
  const isT = rid === T_ID;
  const trapId = isT ? `${rid}-x` : T_DOC; // every non-T row's forbidden trap IS T's truth doc
  return {
    id: rid,
    family: fam.bucketed,
    domain: 'companies',
    split: 'eval_hidden',
    queryText: `q-${rid}`,
    truthDocuments: [{ id: truthId, text: `truth-${rid}`, isCurrent: true }],
    hardNegatives: isT ? [{ id: trapId, text: `trap-${rid}` }] : [],
    qrels: [{ documentId: truthId, relevance: 1 }],
    protected: false,
    logicalFamily: fam.logical,
    subjectEntityId: `ent-${rid}`,
    bmuTask: {
      family: fam.bmu, budgetB: 3, requiredEvidence: [truthId], forbiddenEvidence: [trapId],
      answer: { id: truthId }, motifGroupId: `mg-${rid}`, templateId: `tt-${rid}`,
    },
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
    embeddings: {
      modelId: BI.modelId, revision: BI.revision, layout: LAYOUT,
      query: emb(k),
      perTruth: new Map([[truthId, isT ? emb('ones') : emb(k)]]),
      perNegative: new Map(isT ? [[trapId, emb(k)]] : []),
    },
  };
}

function makeCorpus() {
  const events = [];
  let k = 0;
  for (const fam of FAMS) {
    for (let i = 0; i < 34; i++) events.push(bmuEvent({ rid: `q_${fam.bmu}_${String(i).padStart(2, '0')}`, fam, k: k++ }));
    for (let i = 0; i < 6; i++) events.push(bmuEvent({ rid: `zz_e${String(EPOCH).padStart(12, '0')}_q_${fam.bmu}_${i}`, fam, k: k++ }));
  }
  return {
    events, byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events), corpusEpoch: 0,
    biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision, biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: 'lm', labelingModelRevision: 'lr',
  };
}

const HIDDEN_PACK = {
  packSize: 64,
  quotas: [
    { stratum: 'family=temporal', minCount: 10 },
    { stratum: 'family=conflict_lifecycle', minCount: 15 },
    { stratum: 'family=multi_hop_relation', minCount: 15 },
    { stratum: 'family=near_collision', minCount: 10 },
  ],
};
const LAW = {
  limit: 12,
  familyPriority: ['temporal_update', 'conflict_lifecycle', 'multi_session_bridge', 'abstention_missing'],
  familySlots: { temporal: 3, conflict_lifecycle: 3, multi_hop_relation: 3, near_collision_abstention: 3 },
  freshWindow: 2,
};

function bmuProfile(over = {}) {
  return {
    pipelineVersion: 'coretex-bmu-v1-r5state',
    hiddenPack: HIDDEN_PACK,
    patchAcceptanceFloors: { minImprovementPpm: 20_000, structuralFloor: 0, protectedRegressionFloor: 1, familyCatastrophicFloor: 0 },
    replayTolerancePpm: 250,
    epochFrontier: {
      mode: 'C3', activeWindow: 9639, seed: 's', baselineRecompute: 'activeRootChanged', majorDeltaPolicy: 'corpusRootChanged',
      maxRootDeltaPerEpoch: 24, maxAge: 32, liveEvalPack: LAW,
    },
    ...over,
  };
}

const reranker = {
  model: 'unit-test-reranker',
  async score(pairs) {
    return pairs.map((p) => {
      const rid = p.query.slice(2);
      if (p.document === `truth-${rid}`) return 0.9;
      if (p.document === `trap-${T_ID}` || p.document === `truth-${T_ID}`) {
        return rid === T_ID && p.document === `truth-${T_ID}` ? 0.9 : 0.08;
      }
      return 0.1;
    });
  },
};

function scoringOpts(pipelineVersion = 'coretex-bmu-v1-r5state') {
  return {
    weights: { w_retrieval: 0.75, w_temporal: 0.08, w_relation_recall: 0.07, w_abstention: 0.05, w_structural_sanity: 0.05 },
    retrievalKeyLayout: LAYOUT,
    biEncoderHash: biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode),
    biEncoder: createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT }),
    reranker,
    relationHopBudget: 2, abstentionThreshold: 0.001, rerankerTopK: 10, rerankerInputTopK: 128,
    firstStageTopK: 64, lensTopK: 36, lensWeight: 0.1, anchorWeight: 0.15, relationExpansionBudget: 50,
    temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1,
    pipelineVersion, policyAtomsMode: true,
  };
}

const corpus = makeCorpus();
const activeIds = new Set(corpus.events.map((e) => e.id));
const parentRootBytes = merkleizeState(ZERO_STATE);
const parentRoot = bytesToHex(parentRootBytes).toLowerCase();

function ctxFor(profile) {
  return {
    corpus,
    profile,
    scoringOpts: scoringOpts(profile.pipelineVersion),
    thresholdPpm: 0,
    reranker: { model: 'unit-test-reranker' },
    activeFrontierIdsResolver: () => activeIds,
  };
}

/** The MIXED patch that anchors event T and stacks one conflict BOOST atom on
 *  it — flips forbidden-trap admission on many BMU rows while leaving every
 *  r5 nDCG position unchanged (truths stay rank 1; T's doc is relevance-0
 *  everywhere else) — the law-divergence carrier. */
function boostPatchBytes() {
  const SLOT = 5;
  const anchorWord = encodeMemoryIndexSlot({
    slotIndex: SLOT, recordId: stableRecordIdFor(T_ID), family: 'near_collision',
    domainBits: 0n, valid: true, revoked: false, protected: false, retrievalSlot: 0, expiryEpoch: 0n,
  })[0];
  const atomWord = encodePolicyAtom({
    atomIndex: 0, family: 'conflict_lifecycle', selector: POLICY_SELECTOR.CONFLICT_SET_MEMBER,
    evidenceFeature: POLICY_EVIDENCE_FEATURE.LIFECYCLE_STATE, action: 'boost', scope: 'conflict_set',
    targetSlot: SLOT, budget: 500, flags: 0, validFromEpoch: 0n, expiryEpoch: 0n,
  });
  return encodePatch({
    patchType: PATCH_TYPE.MIXED, wordCount: 2, scoreDelta: 0n, parentStateRoot: parentRootBytes,
    indices: [RANGES.MEMORY_INDEX_START + SLOT, RANGES.POLICY_CONFLICT_START],
    newWords: [anchorWord, atomWord],
  });
}

function noopPatchBytes() {
  return encodePatch({
    patchType: PATCH_TYPE.SLOT_REPLACE, wordCount: 1, scoreDelta: 0n, parentStateRoot: parentRootBytes,
    indices: [RANGES.MEMORY_INDEX_START], newWords: [1n],
  });
}

function seedsFor(patchBytes) {
  const patchHash = computePatchHash(patchBytes);
  const seedInput = {
    epochSecret: EPOCH_SECRET, blockhash: BLOCKHASH, epochId: EPOCH,
    patchHash, parentRoot, corpusRoot: corpus.corpusRoot, bundleHash: BUNDLE_HASH,
  };
  return { patchHash, gateSeed: deriveGateEvalSeed(seedInput), confirmSeed: deriveConfirmEvalSeed(seedInput) };
}

function artifactFor({ patchBytes, patchHash, gateSeed, confirmSeed, gateScorePpm, confirmScorePpm, version, scoringPipelineVersion }) {
  const receipt = {
    patchHash, dedupKey: computeDedupKey(parentRoot, patchBytes), parentRoot, minerAddress: '0x' + '11'.repeat(20),
    epochId: EPOCH, receivedAtBlock: 10, targetBlock: 25, blockhash: BLOCKHASH,
    gateSeed, confirmSeed, gateScorePpm, confirmScorePpm, accepted: true,
  };
  return buildPostRevealEvalReportArtifact({
    version,
    epochId: EPOCH,
    minerAddress: '0x' + '11'.repeat(20),
    outcome: 'SCREENER_PASS',
    compactPatchBytesHex: bytesToHex(patchBytes).toLowerCase(),
    thresholdPpm: 0,
    seedDerivation: {
      mode: 'future_blockhash_dual_pack', epochId: EPOCH, receivedAtBlock: 10, targetBlock: 25, targetBlockOffset: 15,
      blockhash: BLOCKHASH, patchHash, parentStateRoot: parentRoot, corpusRoot: corpus.corpusRoot, bundleHash: BUNDLE_HASH,
    },
    receipt,
    context: {
      parentStateRoot: parentRoot, corpusRoot: corpus.corpusRoot, coreVersionHash: BUNDLE_HASH,
      hiddenSeedCommit: bytesToHex(keccak256(hexToBytes(EPOCH_SECRET))).toLowerCase(),
      replayTolerancePpm: 250,
      ...(scoringPipelineVersion !== undefined ? { scoringPipelineVersion } : {}),
      activeFrontierRoot: B32('08'),
    },
  });
}

async function bmuScore(patchBytes, seed, which, gateSeed) {
  const res = await scoreBmuAgainstSeed({
    epochId: EPOCH, parent: ZERO_STATE, patch: decodePatch(patchBytes), corpus,
    profile: bmuProfile(), evalSeed: seed, which, gateSeedHex: gateSeed,
    scoringOpts: scoringOpts(), thresholdPpm: 0,
    activeLiveEval: { activeIds, law: LAW }, bmuScoring: {},
  });
  return res.deltaPpm;
}

const rpcClient = { getBlockHash: async () => BLOCKHASH, getLatestBlockNumber: async () => 25, waitForBlock: async () => ({ number: 25, blockhash: BLOCKHASH, timestamp: 0 }) };

describe('MAJOR-2: validator score replay under the BMU law (§9 site 18)', () => {
  test('an HONEST BMU artifact replays GREEN through scorerForParent', { timeout: 120_000 }, async () => {
    const patchBytes = noopPatchBytes();
    const { patchHash, gateSeed, confirmSeed } = seedsFor(patchBytes);
    const gatePpm = await bmuScore(patchBytes, gateSeed, 'gate', gateSeed);
    const confirmPpm = await bmuScore(patchBytes, confirmSeed, 'confirm', gateSeed);
    const artifact = artifactFor({
      patchBytes, patchHash, gateSeed, confirmSeed,
      gateScorePpm: gatePpm, confirmScorePpm: confirmPpm,
      version: 'coretex-bmu-post-reveal-eval-report-v1',
    });
    const result = await verifyPostRevealEvalReportArtifact(artifact, {
      rpcClient, epochSecret: EPOCH_SECRET,
      scorer: scorerForParent(ctxFor(bmuProfile()), ZERO_STATE, artifact),
    });
    assert.equal(result.ok, true, result.ok ? '' : `${result.code}: ${result.detail}`);
  });

  test('version pairing fails CLOSED both directions', () => {
    const patchBytes = noopPatchBytes();
    const { patchHash, gateSeed, confirmSeed } = seedsFor(patchBytes);
    const bmuArtifact = artifactFor({ patchBytes, patchHash, gateSeed, confirmSeed, gateScorePpm: 0, confirmScorePpm: 0, version: 'coretex-bmu-post-reveal-eval-report-v1' });
    const r5Artifact = artifactFor({ patchBytes, patchHash, gateSeed, confirmSeed, gateScorePpm: 0, confirmScorePpm: 0, version: 'coretex-post-reveal-eval-report-v1' });
    // BMU artifact under an r5-law bundle: REFUSED before any rescore.
    assert.throws(
      () => scorerForParent(ctxFor(bmuProfile({ pipelineVersion: 'coretex-retrieval-v2-policy-r5' })), ZERO_STATE, bmuArtifact),
      /does not pair with the loaded bundle's scoring law/,
    );
    // r5 artifact under a BMU-law bundle: REFUSED too.
    assert.throws(
      () => scorerForParent(ctxFor(bmuProfile()), ZERO_STATE, r5Artifact),
      /does not pair with the loaded bundle's scoring law/,
    );
  });

  test('BMU v2 replay requires an exact artifact scoringPipelineVersion while historical v1 remains replayable', () => {
    const patchBytes = noopPatchBytes();
    const { patchHash, gateSeed, confirmSeed } = seedsFor(patchBytes);
    const common = {
      patchBytes, patchHash, gateSeed, confirmSeed,
      gateScorePpm: 0, confirmScorePpm: 0,
      version: 'coretex-bmu-post-reveal-eval-report-v1',
    };
    const v1Ctx = ctxFor(bmuProfile());
    const v2Ctx = ctxFor(bmuProfile({ pipelineVersion: 'coretex-bmu-v2-r5state' }));
    const historicalV1 = artifactFor(common);
    const v1Pinned = artifactFor({ ...common, scoringPipelineVersion: 'coretex-bmu-v1-r5state' });
    const v2Pinned = artifactFor({ ...common, scoringPipelineVersion: 'coretex-bmu-v2-r5state' });

    assert.doesNotThrow(() => scorerForParent(v1Ctx, ZERO_STATE, historicalV1));
    assert.doesNotThrow(() => scorerForParent(v1Ctx, ZERO_STATE, v1Pinned));
    assert.doesNotThrow(() => scorerForParent(v2Ctx, ZERO_STATE, v2Pinned));
    assert.throws(() => scorerForParent(v2Ctx, ZERO_STATE, historicalV1), /scoringPipelineVersion 'absent'/);
    assert.throws(() => scorerForParent(v2Ctx, ZERO_STATE, v1Pinned), /does not match loaded bundle/);
    assert.throws(() => scorerForParent(v1Ctx, ZERO_STATE, v2Pinned), /does not match loaded bundle/);
  });

  test('an R5-SCORED BMU artifact (the pre-fix wrong-law behavior) is REJECTED beyond tolerance', { timeout: 240_000 }, async () => {
    const patchBytes = boostPatchBytes();
    const { patchHash, gateSeed, confirmSeed } = seedsFor(patchBytes);
    // Receipt scores the way the PRE-FIX validator computed them: r5 pack law
    // (newest-first overlay, frontier-blind broad rows, no bmuTask
    // eligibility, no exclusion) + the r5 composite objective.
    const r5Opts = { ...scoringOpts(), pipelineVersion: 'coretex-retrieval-v2-policy-r5' };
    const r5Floors = { minImprovementPpm: 0, structuralFloor: 0, protectedRegressionFloor: 1, familyCatastrophicFloor: 0, acceptanceThresholdPpm: 0 };
    const legacyActive = { activeIds, law: { limit: LAW.limit, familyPriority: LAW.familyPriority } };
    const r5Gate = await evaluateRetrievalBenchmarkPatch(
      ZERO_STATE, decodePatch(patchBytes), corpus,
      deriveScoredQueryPack(EPOCH, gateSeed, corpus, HIDDEN_PACK, legacyActive),
      r5Opts, r5Floors);
    // The BMU-law replay of the SAME (patch, gate seed):
    const bmuGate = await bmuScore(patchBytes, gateSeed, 'gate', gateSeed);
    // Law divergence precondition: the boost patch flips forbidden-trap rows
    // under BMU (quantized flips) while r5 nDCG stays ~flat.
    assert.ok(Math.abs(r5Gate.deltaPpm - bmuGate) > 500,
      `expected law divergence > 500ppm (r5=${r5Gate.deltaPpm}, bmu=${bmuGate})`);
    const artifact = artifactFor({
      patchBytes, patchHash, gateSeed, confirmSeed,
      gateScorePpm: r5Gate.deltaPpm, confirmScorePpm: r5Gate.deltaPpm,
      version: 'coretex-bmu-post-reveal-eval-report-v1',
    });
    const result = await verifyPostRevealEvalReportArtifact(artifact, {
      rpcClient, epochSecret: EPOCH_SECRET,
      scorer: scorerForParent(ctxFor(bmuProfile()), ZERO_STATE, artifact),
    });
    assert.equal(result.ok, false, 'r5-scored BMU artifact must NOT replay green under the BMU law');
    assert.match(result.code, /SCORE_BEYOND_TOLERANCE/);
  });
});
