import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { createRetrievalDataSource, handleCoreTexCoordinatorRoute } from '../../dist/index.js';

const BUNDLE_HASH = `0x${'ab'.repeat(32)}`;
const ALT_BUNDLE_HASH = `0x${'cd'.repeat(32)}`;
const ROOT = `0x${'22'.repeat(32)}`;
const PATCH_HASH = `0x${'33'.repeat(32)}`;
const V4 = `0x${'44'.repeat(20)}`;
const FORBIDDEN_PUBLIC_KEY_RE = /qrel|truthdoc|hardnegativ|answerid|answer_id|answerlabel|answer_label|epochsecret|epoch_secret|gateseed|gate_seed|confirmseed|confirm_seed|evalseed(?!commit)|eval_seed(?!_commit)|hiddenpack|hidden_pack|truthdocuments|relevance|failurestat|perfamilydelta/i;
const FORBIDDEN_VALUE_SENTINELS = [
  'hidden-event-id',
  'hidden-answer-id',
  'hidden-answer-label',
  'hidden-qrel-doc',
  'hidden-family-telemetry',
  `0x${'ee'.repeat(32)}`,
  `0x${'ef'.repeat(32)}`,
];

function scanForbiddenPublicKeys(obj, path = '') {
  const hits = [];
  if (obj && typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) {
      if (FORBIDDEN_PUBLIC_KEY_RE.test(k)) hits.push(`${path}${k}`);
      hits.push(...scanForbiddenPublicKeys(v, `${path}${k}.`));
    }
  }
  return hits;
}

function assertNoHiddenMaterial(body) {
  const keyHits = scanForbiddenPublicKeys(body);
  assert.deepEqual(keyHits, []);
  const json = JSON.stringify(body);
  for (const sentinel of FORBIDDEN_VALUE_SENTINELS) {
    assert.equal(json.includes(sentinel), false, `leaked sentinel ${sentinel}`);
  }
}

function fixtureManifest(bundleHash = BUNDLE_HASH) {
  return { bundleHash };
}

function makeFactoryOpts(overrides = {}) {
  return {
    bundleManifest: fixtureManifest(),
    bundleHash: BUNDLE_HASH,
    submit: () => ({
      status: 'accepted',
      patchHash: PATCH_HASH,
      evalReportHash: `0x${'55'.repeat(32)}`,
      receipt: { sig: '0xabc' },
      transaction: { to: V4, chainId: 8453, value: '0', data: '0x1234' },
      scoreAfterPpm: 999_999,
    }),
    getStatus: () => ({
      lane: 'coretex',
      epochId: 7,
      currentStateRoot: ROOT,
      wordCount: 1024,
      confirmedTransitionCount: 12,
      rulesVersion: 192,
      workPolicyHash: `0x${'66'.repeat(32)}`,
      parentStateRoot: `0x${'21'.repeat(32)}`,
      corpusRoot: `0x${'77'.repeat(32)}`,
      activeFrontierRoot: `0x${'78'.repeat(32)}`,
      baselineManifestHash: `0x${'79'.repeat(32)}`,
      rotationManifestHash: `0x${'79'.repeat(32)}`,
      corpusDeltaHash: `0x${'7a'.repeat(32)}`,
      rotationManifestUrl: 'https://coretex-launch-artifacts-429971482539-us-east-2-an.s3.us-east-2.amazonaws.com/coretex/launch/v16/epoch-rotations/epoch-rotation-7.json',
      corpusDeltaUrl: 'https://coretex-launch-artifacts-429971482539-us-east-2-an.s3.us-east-2.amazonaws.com/coretex/launch/v16/epoch-rotations/corpus-delta-epoch-7.json',
      epochSigningPublicKeyId: 'coretex-epoch-operator',
      epochSigningPublicKeyFingerprint: `0x${'7b'.repeat(32)}`,
      currentEpoch: 7,
      bundleHash: BUNDLE_HASH,
      coreVersionHash: BUNDLE_HASH,
      minImprovementPpm: 2500,
      replayTolerancePpm: 250,
      screenerThresholdPpm: 347,
      baselineParentScorePpm: 288438,
      baselineVarianceSource: 'unavailable',
      fixedPackRepeatabilityPpm: 0,
      recentNoiseFloorPpm: 12,
      patchWordBudget: 4,
      perMinerScreenerCap: 50,
      qualifiedScreenerPassesSinceLastStateAdvance: 3,
      nextStateAdvanceWorkBps: 30_000,
      activeSubstrateSurfaces: ['temporal_update', 'evidence_bundle'],
      allowedPatchTypes: [{ name: 'MEMORY_INDEX_UPDATE', byte: 2, wordIndexRange: [32, 383] }],
      patchWordRanges: [{ surface: 'temporal_update', patchType: 'MIXED', wordRanges: [[32, 383], [800, 895]] }],
      exampleValidPatch: { patchType: 4, wordCount: 1, indexRange: [672, 799], encodedHex: '0x04' },
      pins: { corpusRoot: `0x${'77'.repeat(32)}`, activeFrontierRoot: `0x${'78'.repeat(32)}` },
      difficultyController: { reason: 'under_target_recovery', output: { next: '2500' } },
      runwayTelemetry: {
        updatedAtEpoch: 7,
        activeLivePackFamilyDistribution: { temporal_update: 12, validity_atom: 8, scope_atom: 6 },
        strictMinableRatioPpm: 528_000,
        alreadySolvedRatioPpm: 250_000,
        tooHardRatioPpm: 222_000,
        acceptedFamilyEntropyPpm: 812_000,
        acceptedFingerprintReusePpm: 675_000,
        acceptedSelectorReusePpm: 640_000,
        familyAttempts: { temporal_update: 24, validity_atom: 18 },
        familyAccepts: { temporal_update: 14, validity_atom: 7 },
        familyRejects: { threshold_block: 3, qwen_no_recovery: 5 },
        fingerprintAttempts: { 'temporal_update:current_stale': 12 },
        fingerprintAccepts: { 'temporal_update:current_stale': 7 },
        randomControlAccepts: 0,
        randomControlAttempts: 32,
        noopControlAccepts: 0,
        noopControlAttempts: 8,
        hillControlAccepts: 0,
        hillControlAttempts: 16,
        reserveRemaining: 6909,
        reserveAdded: 98,
        activeChurn: 12,
        oldCorpusDamageRejects: 4,
        goldDamageRejects: 5,
        acceptedOldCorpusDamageCount: 0,
        acceptedGoldDamageCount: 0,
      },
      nextEpochReadiness: { ready: true, blockers: [], checked: ['signed_corpus_delta'] },
      lastEvolveDecision: {
        chosenChurnFraction: 0.15,
        reasons: ['base_churn', 'high_fingerprint_reuse'],
        metrics: { strictMinableRatioPpm: 528_000, acceptedFingerprintReusePpm: 780_000 },
      },
      acceptingSubmissions: true,
      substrate: { uri: `/coretex/substrate/${ROOT}` },
      perMiner: {
        address: `0x${'11'.repeat(20)}`,
        screenersThisEpoch: 1,
        remaining: 49,
        cap: 50,
        nextIndex: 8,
        lastReceiptHash: `0x${'00'.repeat(32)}`,
      },
      hiddenEvalWarning: 'hidden qrels / eval pack / epochSecret are NOT public',
      perMinerCap: 999,
    }),
    getSubstrate: (root) => ({ stateRoot: root, wordCount: 1024, packedBytes: 32768, packedHex: '0x' + '00'.repeat(32768) }),
    getReceipt: (hash) => ({ status: 200, body: { status: 'accepted', patchHash: hash, confirmedOnChain: true } }),
    ...overrides,
  };
}

describe('createRetrievalDataSource — v0 canonical surface', () => {
  test('refuses bundle hash that disagrees with manifest', () => {
    assert.throws(
      () => createRetrievalDataSource({
        ...makeFactoryOpts(),
        bundleManifest: fixtureManifest(ALT_BUNDLE_HASH),
      }),
      /bundle manifest hash/,
    );
  });

  test('passes status/submit/substrate/receipt through canonical callbacks', async () => {
    const seen = [];
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getStatus: (query) => { seen.push(['status', query]); return makeFactoryOpts().getStatus(); },
      submit: (body) => { seen.push(['submit', body]); return { status: 'rejected', patchHash: PATCH_HASH, score: 42 }; },
      getSubstrate: (root) => { seen.push(['substrate', root]); return { stateRoot: root, wordCount: 1024, packedHex: '0x' + '00'.repeat(32768) }; },
      getReceipt: (hash) => { seen.push(['receipt', hash]); return { status: 409, body: { code: 'PendingReceiptStale' } }; },
    }));

    const st = await ds.getStatus({ miner: `0x${'11'.repeat(20)}` });
    const s = await ds.submit({ patchBytesHex: '0x1234' });
    const sub = await ds.getSubstrate?.(ROOT);
    const rec = await ds.getReceipt?.(PATCH_HASH);

    assert.deepEqual(seen, [
      ['status', { miner: `0x${'11'.repeat(20)}` }],
      ['submit', { patchBytesHex: '0x1234' }],
      ['substrate', ROOT],
      ['receipt', PATCH_HASH],
    ]);
    assert.equal(st.bundleHash, BUNDLE_HASH);
    assert.equal(st.coreVersionHash, BUNDLE_HASH);
    assert.deepEqual(s, { status: 'rejected', code: 'rejected', patchHash: PATCH_HASH });
    assert.equal(sub.stateRoot, ROOT);
    assert.equal(sub.wordCount, 1024);
    assert.equal(sub.packedBytes, 32768);
    assert.deepEqual(rec, { status: 409, body: { status: 'rejected', code: 'PendingReceiptStale' } });
  });

  test('preserves launch-shaped public status fields through the sanitizer', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const st = await ds.getStatus({ miner: `0x${'11'.repeat(20)}` });

    assert.equal(st.currentStateRoot, ROOT);
    assert.equal(st.currentEpoch, 7);
    assert.equal(st.stateRoot, undefined);
    assert.equal(st.parentStateRoot, `0x${'21'.repeat(32)}`);
    assert.equal(st.corpusRoot, `0x${'77'.repeat(32)}`);
    assert.equal(st.activeFrontierRoot, `0x${'78'.repeat(32)}`);
    assert.equal(st.baselineManifestHash, `0x${'79'.repeat(32)}`);
    assert.equal(st.rotationManifestHash, `0x${'79'.repeat(32)}`);
    assert.equal(st.corpusDeltaHash, `0x${'7a'.repeat(32)}`);
    assert.match(st.rotationManifestUrl, /epoch-rotation-7\.json$/);
    assert.match(st.corpusDeltaUrl, /corpus-delta-epoch-7\.json$/);
    assert.equal(st.epochSigningPublicKeyId, 'coretex-epoch-operator');
    assert.equal(st.epochSigningPublicKeyFingerprint, `0x${'7b'.repeat(32)}`);
    assert.equal(st.confirmedTransitionCount, 12);
    assert.equal(st.transitionCount, undefined);
    assert.equal(st.patchWordBudget, 4);
    assert.equal(st.baselineParentScorePpm, 288438);
    assert.equal(st.baselineVariancePpm, undefined);
    assert.equal(st.baselineVarianceSource, 'unavailable');
    assert.equal(st.fixedPackRepeatabilityPpm, 0);
    assert.equal(st.recentNoiseFloorPpm, 12);
    assert.equal(st.perMinerScreenerCap, 50);
    assert.equal(st.perMinerCap, undefined);
    assert.equal(st.allowedPatchTypes[0].byte, 2);
    assert.equal(st.patchWordRanges[0].surface, 'temporal_update');
    assert.equal(st.exampleValidPatch.patchType, 4);
    assert.equal(st.pins.corpusRoot, `0x${'77'.repeat(32)}`);
    assert.equal(st.difficultyController.reason, 'under_target_recovery');
    assert.deepEqual(st.activeSubstrateSurfaces, ['temporal_update', 'evidence_bundle']);
    assert.equal(st.runwayTelemetry.strictMinableRatioPpm, 528_000);
    assert.equal(st.runwayTelemetry.activeLivePackFamilyDistribution, undefined);
    assert.equal(st.runwayTelemetry.familyAttempts, undefined);
    assert.equal(st.runwayTelemetry.fingerprintAttempts, undefined);
    assert.equal(st.runwayTelemetry.randomControlAccepts, 0);
    assert.equal(st.runwayTelemetry.acceptedOldCorpusDamageCount, 0);
    assert.equal(st.nextEpochReadiness.ready, true);
    assert.equal(st.lastEvolveDecision.chosenChurnFraction, 0.15);
    assert.equal(st.acceptingSubmissions, true);
    assert.deepEqual(st.substrate, { uri: `/coretex/substrate/${ROOT}` });
    assert.ok(typeof st.statusVersion === 'string' && st.statusVersion.startsWith('0x'));
  });

  test('fails closed on malformed status response', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getStatus: () => ({ lane: 'coretex' }),
    }));
    assert.deepEqual(await ds.getStatus({}), { error: 'coretex-status-malformed' });
  });

  test('fails closed if removed status aliases resurface', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getStatus: () => ({
        lane: 'coretex',
        epochId: 9,
        currentStateRoot: ROOT,
        stateRoot: ROOT,
      }),
    }));
    assert.deepEqual(await ds.getStatus({}), { error: 'coretex-status-malformed' });

    const ds2 = createRetrievalDataSource(makeFactoryOpts({
      getStatus: () => ({
        lane: 'coretex',
        epochId: 9,
        currentStateRoot: ROOT,
        transitionCount: 1,
      }),
    }));
    assert.deepEqual(await ds2.getStatus({}), { error: 'coretex-status-malformed' });
  });

  test('submit response preserves safe rejection codes and accepted contract fields', async () => {
    const rejected = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({ status: 'rejected', code: 'W03_DETERMINISTIC_DELTA_TOO_LOW', deterministicDeltaPpm: 12, requiredDeltaPpm: 347, perFamilyDelta: { temporal: -0.9 } }),
    }));
    assert.deepEqual(await rejected.submit({}), { status: 'rejected', code: 'W03_DETERMINISTIC_DELTA_TOO_LOW', deterministicDeltaPpm: 12, requiredDeltaPpm: 347 });

    const accepted = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({
        status: 'accepted',
        outcome: 'STATE_ADVANCE',
        patchHash: `0x${'99'.repeat(32)}`,
        newStateRoot: `0x${'98'.repeat(32)}`,
        evalReportHash: `0x${'aa'.repeat(32)}`,
        workUnitsBps: 30000,
        receipt: {
          sig: '0xdeadbeef',
          epochId: '7',
          patchHash: `0x${'99'.repeat(32)}`,
          newStateRoot: `0x${'98'.repeat(32)}`,
          compactPatchBytes: '0x1234',
          perFamilyDelta: { temporal: -0.9 },
        },
        transaction: { to: V4.toUpperCase(), chainId: 8453, value: '0', data: '0xDEADBEEF' },
        scoreBeforePpm: 10,
        scoreAfterPpm: 999999,
      }),
    }));
    assert.deepEqual(await accepted.submit({}), {
      status: 'accepted',
      outcome: 'STATE_ADVANCE',
      patchHash: `0x${'99'.repeat(32)}`,
      newStateRoot: `0x${'98'.repeat(32)}`,
      evalReportHash: `0x${'aa'.repeat(32)}`,
      workUnitsBps: 30000,
      receipt: {
        sig: '0xdeadbeef',
        epochId: '7',
        patchHash: `0x${'99'.repeat(32)}`,
        newStateRoot: `0x${'98'.repeat(32)}`,
        compactPatchBytes: '0x1234',
      },
      transaction: { to: V4, chainId: 8453, value: '0', data: '0xdeadbeef' },
    });
  });

  test('receipt envelope strips non-signature fields', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({
        status: 'accepted',
        patchHash: `0x${'99'.repeat(32)}`,
        receipt: {
          keyId: 'coordinator-mainnet-v1',
          algorithm: 'ECDSA-SHA256',
          signature: '0xdeadbeefcafe',
          signedFields: ['patchHash', 'receivedAtBlock'],
          scoreAfterPpm: 999_999,
          perFamilyDelta: { temporal: -0.9 },
        },
      }),
    }));
    const out = await ds.submit({});
    assert.deepEqual(out.receipt, {
      keyId: 'coordinator-mainnet-v1',
      algorithm: 'ECDSA-SHA256',
      signature: '0xdeadbeefcafe',
      signedFields: ['patchHash', 'receivedAtBlock'],
      scoreAfterPpm: 999999,
    });
  });

  test('receipt lookup is sanitized before returning cached envelopes', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getReceipt: () => ({
        status: 200,
        body: {
          status: 'accepted',
          outcome: 'STATE_ADVANCE',
          patchHash: `0x${'99'.repeat(32)}`,
          newStateRoot: `0x${'98'.repeat(32)}`,
          evalReportHash: `0x${'aa'.repeat(32)}`,
          workUnitsBps: 30000,
          confirmedOnChain: true,
          pendingState: 'confirmed',
          receipt: {
            signature: '0xdeadbeef',
            patchHash: `0x${'99'.repeat(32)}`,
            compactPatchBytes: '0x1234',
            scoreBeforePpm: 100,
            scoreAfterPpm: 3100,
            qrels: [{ documentId: 'hidden-answer', relevance: 1 }],
            hiddenPackIds: ['ev-hidden-1'],
            epochSecret: `0x${'ee'.repeat(32)}`,
          },
          transaction: { to: V4, chainId: 8453, value: '0', data: '0xdeadbeef' },
          evalSeed: `0x${'ef'.repeat(32)}`,
          hiddenPack: ['ev-hidden-1'],
        },
      }),
    }));
    const out = await ds.getReceipt(PATCH_HASH);
    assert.deepEqual(out, {
      status: 200,
      body: {
        status: 'accepted',
        outcome: 'STATE_ADVANCE',
        patchHash: `0x${'99'.repeat(32)}`,
        newStateRoot: `0x${'98'.repeat(32)}`,
        evalReportHash: `0x${'aa'.repeat(32)}`,
        workUnitsBps: 30000,
        receipt: {
          signature: '0xdeadbeef',
          patchHash: `0x${'99'.repeat(32)}`,
          compactPatchBytes: '0x1234',
          scoreBeforePpm: 100,
          scoreAfterPpm: 3100,
        },
        transaction: { to: V4, chainId: 8453, value: '0', data: '0xdeadbeef' },
        confirmedOnChain: true,
        pendingState: 'confirmed',
      },
    });
  });

  test('public route bodies do not expose hidden eval material through sanitized data source', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      health: () => ({
        ok: true,
        service: 'coretex',
        bundleHash: BUNDLE_HASH,
        epochPins: { hiddenSeedCommit: `0x${'80'.repeat(32)}` },
        epochSecret: `0x${'ee'.repeat(32)}`,
        hiddenPackIds: ['hidden-event-id'],
      }),
      getStatus: () => ({
        ...makeFactoryOpts().getStatus(),
        evalSeed: `0x${'ef'.repeat(32)}`,
        gateSeed: `0x${'ef'.repeat(32)}`,
        hiddenPack: [{ id: 'hidden-event-id' }],
        truthDocuments: [{ id: 'hidden-answer-id' }],
        answerLabels: ['hidden-answer-label'],
        runwayTelemetry: {
          strictMinableRatioPpm: 528_000,
          familyAttempts: { hidden_family: 1 },
          fingerprintAttempts: { 'hidden-family-telemetry': 1 },
        },
      }),
      getSubstrate: (root) => ({
        stateRoot: root,
        wordCount: 1024,
        packedBytes: 32768,
        packedHex: '0x' + '00'.repeat(32768),
        hiddenPackIds: ['hidden-event-id'],
      }),
      submit: () => ({
        status: 'accepted',
        outcome: 'STATE_ADVANCE',
        patchHash: PATCH_HASH,
        newStateRoot: ROOT,
        evalReportHash: `0x${'aa'.repeat(32)}`,
        workUnitsBps: 30000,
        receipt: {
          signature: '0xdeadbeef',
          patchHash: PATCH_HASH,
          qrels: [{ documentId: 'hidden-qrel-doc', relevance: 1 }],
          answerId: 'hidden-answer-id',
          scoreBeforePpm: 1,
          scoreAfterPpm: 2,
          perFamilyDelta: { temporal: 1 },
        },
        transaction: { to: V4, chainId: 8453, value: '0', data: '0xdeadbeef' },
        evalSeed: `0x${'ef'.repeat(32)}`,
      }),
      getReceipt: (hash) => ({
        status: 200,
        body: {
          status: 'accepted',
          outcome: 'STATE_ADVANCE',
          patchHash: hash,
          newStateRoot: ROOT,
          evalReportHash: `0x${'aa'.repeat(32)}`,
          workUnitsBps: 30000,
          receipt: {
            signature: '0xdeadbeef',
            patchHash: hash,
            hiddenPackIds: ['hidden-event-id'],
            epochSecret: `0x${'ee'.repeat(32)}`,
          },
          transaction: { to: V4, chainId: 8453, value: '0', data: '0xdeadbeef' },
        },
      }),
    }));

    for (const req of [
      { method: 'GET', path: '/coretex/health' },
      { method: 'GET', path: '/coretex/status', query: { miner: `0x${'11'.repeat(20)}` } },
      { method: 'GET', path: `/coretex/substrate/${ROOT}` },
      { method: 'POST', path: '/coretex/submit', body: { patchBytesHex: '0x1234' } },
      { method: 'GET', path: `/coretex/receipt/${PATCH_HASH}` },
    ]) {
      const res = await handleCoreTexCoordinatorRoute(req, ds);
      assert.equal(res.handled, true);
      assertNoHiddenMaterial(res.body);
    }
  });

  test('status URI envelope only allows /coretex/substrate/:root', async () => {
    const staleRoutes = [
      `/coretex/bundle/${BUNDLE_HASH}`,
      `/coretex/patch/${PATCH_HASH}`,
      `/coretex/eval-report/${PATCH_HASH}`,
      '/coretex/corpus-delta/7',
      '/coretex/admin-dashboard',
    ];

    for (const uri of staleRoutes) {
      const ds = createRetrievalDataSource(makeFactoryOpts({
        getStatus: () => ({
          lane: 'coretex',
          epochId: 9,
          currentStateRoot: ROOT,
          substrate: { uri },
        }),
      }));
      assert.deepEqual(await ds.getStatus({}), { error: 'coretex-status-malformed' }, uri);
    }
  });

  test('default health response carries bundleHash + serverTime', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const out = await ds.health();
    assert.equal(out.ok, true);
    assert.equal(out.service, 'coretex');
    assert.equal(out.bundleHash, BUNDLE_HASH);
    assert.ok(typeof out.serverTime === 'string' && out.serverTime.includes('T'));
  });

  test('custom health response is sanitized', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      health: () => ({
        ok: false,
        service: 'coretex',
        version: 'v0',
        epoch: 7,
        chainId: 8453,
        confirmationDepth: 4,
        chainLiveRoot: ROOT,
        confirmedLiveRoot: ROOT,
        finalityLagBlocks: 3,
        acceptingSubmissions: false,
        reason: 'CoordEpochMismatch',
        epochPins: {
          parentStateRoot: ROOT,
          coreVersionHash: BUNDLE_HASH,
          corpusRoot: `0x${'77'.repeat(32)}`,
          activeFrontierRoot: `0x${'78'.repeat(32)}`,
          baselineManifestHash: `0x${'79'.repeat(32)}`,
          hiddenSeedCommit: `0x${'80'.repeat(32)}`,
        },
        hiddenPack: ['leak'],
        perMiner: { address: `0x${'11'.repeat(20)}` },
      }),
    }));
    const out = await ds.health();
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'CoordEpochMismatch');
    assert.equal(out.epochPins.hiddenSeedCommit, `0x${'80'.repeat(32)}`);
    assert.equal(out.hiddenPack, undefined);
    assert.equal(out.perMiner, undefined);
  });
});
