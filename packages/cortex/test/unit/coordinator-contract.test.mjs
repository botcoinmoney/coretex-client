/**
 * v0 launch coordinator data-source contract test.
 *
 * Every public CoreTex route delegates to a CoreTexCoordinatorDataSource
 * (`packages/cortex/src/coordinator/endpoints.ts`). This test pins the CONTRACT
 * a production data source must satisfy:
 *
 *  - the canonical 5 endpoints (health, status, substrate/:root, submit,
 *    receipt/:hash) return 200 + structured responses;
 *  - no response leaks hidden qrels / eval-pack / answer IDs / epochSecret /
 *    evalSeed;
 *  - removed v0 routes (`/coretex/challenge`, `/coretex/patch/:hash`,
 *    `/coretex/patch-received/:hash`, `/coretex/eval-report/:hash`,
 *    `/coretex/corpus-delta/:epoch`, `/coretex/bundle/*`) consistently return
 *    404 `coretex-not-found`.
 *
 * The status payload carries all dynamic miner context plus per-miner counters;
 * the canonical naming is `perMinerScreenerCap` (`perMinerCap` is removed).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { createCoreTexCoordinatorRouteHandler } from '../../dist/coordinator/endpoints.js';

const PARENT_ROOT = '0x04d107ad97465d9fbdb448d4ff2d21131bf2ee38ce72de641b7c17dedec72146';
const BUNDLE_HASH = '0x474cd8851eebd097a7f1480818c1ccdb0dd473c5da08cd6909b071ac8c101715';
const CORPUS_ROOT = '0x15bab3a8e0d6fdb8df4d525e49aa7e22c815e749c8d95301a89e54de933beb33';
const PATCH_HASH = '0x82a2e24dc19e166c4a12f2c86b73cb3bde3f54b6cc9f4479a9a392aec45b1573';
const MINER = '0x' + '11'.repeat(20);

const ds = {
  health: () => ({
    ok: true, service: 'coretex', version: 'v0',
    epoch: 106, chainId: 8453, confirmationDepth: 4,
    chainLiveRoot: PARENT_ROOT, confirmedLiveRoot: PARENT_ROOT,
    finalityLagBlocks: 0, acceptingSubmissions: true,
    epochPins: { parentStateRoot: PARENT_ROOT, coreVersionHash: BUNDLE_HASH, corpusRoot: CORPUS_ROOT,
                 activeFrontierRoot: '0x' + '09'.repeat(32), baselineManifestHash: '0x' + 'ba'.repeat(32),
                 hiddenSeedCommit: '0x' + 'cc'.repeat(32) },
  }),
  // status folds in challenge content + per-miner counters
  getStatus: (query) => ({
    epochId: 0, currentStateRoot: PARENT_ROOT, confirmedTransitionCount: 7,
    bundleHash: BUNDLE_HASH, coreVersionHash: BUNDLE_HASH, corpusRoot: CORPUS_ROOT,
    activeFrontierRoot: '0x' + '09'.repeat(32),
    pipelineVersion: 'coretex-retrieval-v2-policy-r5-atom-v16-300k',
    allowedPatchTypes: [{ name: 'MEMORY_INDEX_UPDATE', byte: 2, wordIndexRange: [32, 383] }],
    patchWordRanges: [{ surface: 'temporal_update', patchType: 'MIXED', wordRanges: [[32, 383], [800, 895]] }],
    exampleValidPatch: { patchType: 4, wordCount: 1, indexRange: [672, 799], encodedHex: '0x04' },
    patchWordBudget: 4,
    minImprovementPpm: 2500, replayTolerancePpm: 250, screenerThresholdPpm: 347,
    baselineParentScorePpm: 288438, baselineVarianceSource: 'unavailable', fixedPackRepeatabilityPpm: 0, recentNoiseFloorPpm: 12,
    pins: { corpusRoot: CORPUS_ROOT, activeFrontierRoot: '0x' + '09'.repeat(32), baselineManifestHash: '0x' + 'ba'.repeat(32) },
    difficultyController: { reason: 'under_target_recovery', output: { next: '2500' } },
    perMinerScreenerCap: 50, qualifiedScreenerPassesSinceLastStateAdvance: 0,
    memoryIRSchemaVersion: 'memory_ir.v1',
    activeSubstrateSurfaces: ['temporal_update', 'conflict_lifecycle', 'relation_category_routing',
                              'abstention_top1', 'evidence_bundle', 'validity_atom', 'scope_atom',
                              'entity_resolution_atom'],
    runwayTelemetry: {
      updatedAtEpoch: 0,
      strictMinableRatioPpm: 528000,
      alreadySolvedRatioPpm: 250000,
      tooHardRatioPpm: 222000,
      acceptedFamilyEntropyPpm: 812000,
      acceptedFingerprintReusePpm: 675000,
      acceptedSelectorReusePpm: 640000,
      randomControlAccepts: 0,
      randomControlAttempts: 32,
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
    acceptingSubmissions: true,
    perMiner: query.miner ? {
      address: query.miner, screenersThisEpoch: 0, remaining: 50, cap: 50,
      nextIndex: 0, lastReceiptHash: '0x' + '00'.repeat(32),
    } : null,
    hiddenEvalWarning: 'hidden qrels/pack/epochSecret are NOT public',
  }),
  getSubstrate: (root) => ({ stateRoot: root, wordCount: 1024, packedBytes: 32768, packedHex: '0x' + '00'.repeat(32768) }),
  submit: (body) => ({ status: 'accepted', patchHash: PATCH_HASH, evalReportHash: '0x' + 'ef'.repeat(32),
                       echo: body ? 'ok' : 'empty' }),
  getReceipt: (hash) => ({ status: 200, body: { status: 'accepted', patchHash: hash, confirmedOnChain: true } }),
};

const handle = createCoreTexCoordinatorRouteHandler(ds);
const FORBIDDEN = /qrel|truthdoc|hardnegativ|answerid|answer_id|answerlabel|answer_label|epochsecret|epoch_secret|gateseed|gate_seed|confirmseed|confirm_seed|evalseed(?!commit)|eval_seed(?!_commit)|hiddenpack|hidden_pack|relevance|truthDocuments|scorebeforeppm|scoreafterppm|perfamilydelta|failurestat/i;
function scanLeak(obj, path = '') {
  const hits = [];
  if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN.test(k)) hits.push(`${path}${k}`);
    hits.push(...scanLeak(v, `${path}${k}.`));
  }
  return hits;
}

function scanSourceFiles(dirUrl, out = []) {
  for (const entry of readdirSync(dirUrl, { withFileTypes: true })) {
    const url = new URL(entry.name, dirUrl);
    if (entry.isDirectory()) {
      scanSourceFiles(new URL(`${entry.name}/`, dirUrl), out);
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      out.push(url);
    }
  }
  return out;
}

describe('v0 coordinator data-source contract', () => {
  const canonical = [
    ['GET', '/coretex/health'],
    ['GET', '/coretex/status'],
    ['GET', `/coretex/substrate/${PARENT_ROOT}`],
    ['POST', '/coretex/submit'],
    ['GET', `/coretex/receipt/${PATCH_HASH}`],
  ];

  for (const [method, path] of canonical) {
    test(`${method} ${path} → 200 + handled + no hidden leakage`, async () => {
      const res = await handle({
        method, path, query: { miner: MINER },
        body: method === 'POST' ? { patchBytesHex: '0xff010000', parentStateRoot: PARENT_ROOT, minerAddress: MINER } : undefined,
      });
      assert.equal(res.handled, true, 'route handled');
      assert.equal(res.status, 200, `expected 200, got ${res.status} body=${JSON.stringify(res.body)}`);
      const leaks = scanLeak(res.body);
      assert.equal(leaks.length, 0, `no hidden leakage, got: ${leaks.join(',')}`);
    });
  }

  test('status carries dynamic miner context + per-miner counters', async () => {
    const r = await handle({ method: 'GET', path: '/coretex/status', query: { miner: MINER } });
    for (const k of [
      'epochId', 'currentStateRoot', 'bundleHash', 'coreVersionHash', 'corpusRoot',
      'activeFrontierRoot', 'pipelineVersion', 'allowedPatchTypes', 'patchWordBudget',
      'minImprovementPpm', 'screenerThresholdPpm', 'perMinerScreenerCap',
      'qualifiedScreenerPassesSinceLastStateAdvance', 'activeSubstrateSurfaces',
      'patchWordRanges', 'exampleValidPatch', 'memoryIRSchemaVersion',
      'baselineParentScorePpm', 'baselineVarianceSource', 'recentNoiseFloorPpm',
      'pins', 'difficultyController', 'runwayTelemetry', 'acceptingSubmissions', 'perMiner',
    ]) {
      assert.ok(r.body[k] !== undefined, `status.${k} present`);
    }
    assert.equal(r.body.runwayTelemetry.strictMinableRatioPpm, 528000);
    assert.equal(r.body.runwayTelemetry.activeLivePackFamilyDistribution, undefined);
    assert.equal(r.body.runwayTelemetry.familyAttempts, undefined);
    for (const k of ['address', 'screenersThisEpoch', 'remaining', 'cap', 'nextIndex', 'lastReceiptHash']) {
      assert.ok(r.body.perMiner[k] !== undefined, `status.perMiner.${k} present`);
    }
    assert.equal(r.body.perMinerScreenerCap, r.body.perMiner.cap, 'cap matches across status surfaces');
  });

  test('status NEVER exposes the removed perMinerCap alias', async () => {
    const r = await handle({ method: 'GET', path: '/coretex/status', query: { miner: MINER } });
    assert.equal(r.body.perMinerCap, undefined, 'no perMinerCap key in status body');
    assert.equal(r.body.stateRoot, undefined, 'no stateRoot alias in status body');
    assert.equal(r.body.transitionCount, undefined, 'no transitionCount alias in status body');
  });

  test('health exposes coord version + epoch + chain + pins (no miner-specific data)', async () => {
    const r = await handle({ method: 'GET', path: '/coretex/health' });
    for (const k of ['version', 'epoch', 'chainId', 'confirmationDepth', 'chainLiveRoot',
                     'confirmedLiveRoot', 'finalityLagBlocks', 'acceptingSubmissions', 'epochPins']) {
      assert.ok(r.body[k] !== undefined, `health.${k} present`);
    }
    for (const pin of ['parentStateRoot', 'coreVersionHash', 'corpusRoot', 'activeFrontierRoot',
                       'baselineManifestHash', 'hiddenSeedCommit']) {
      assert.ok(r.body.epochPins[pin] !== undefined, `health.epochPins.${pin} present`);
    }
    assert.equal(r.body.perMiner, undefined, 'no miner-specific data on /health');
  });

  test('removed v0 routes all 404 with coretex-not-found', async () => {
    for (const stale of [
      ['GET', '/coretex/challenge'],
      ['GET', `/coretex/patch/${PATCH_HASH}`],
      ['GET', `/coretex/patch-received/${PATCH_HASH}`],
      ['GET', `/coretex/eval-report/${PATCH_HASH}`],
      ['GET', '/coretex/corpus-delta/0'],
      ['GET', `/coretex/bundle/${BUNDLE_HASH}`],
      ['GET', `/coretex/bundle/by-core-version/${BUNDLE_HASH}`],
    ]) {
      const r = await handle({ method: stale[0], path: stale[1] });
      assert.equal(r.handled, true);
      assert.equal(r.status, 404, `${stale.join(' ')} should 404`);
      assert.deepEqual(r.body, { error: 'coretex-not-found' });
    }
  });

  test('unconfigured endpoint returns a stable 503 not-configured (not a crash)', async () => {
    const empty = createCoreTexCoordinatorRouteHandler({});
    const r = await empty({ method: 'GET', path: '/coretex/status' });
    assert.equal(r.handled, true);
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: 'coretex-route-not-configured', route: 'status' });
  });

  test('production source does not contain harness-only runway acceptance caps', () => {
    const forbidden = [
      'weak-family',
      'weakFamily',
      'fingerprint-quota',
      'fingerprintQuota',
      'slot-pacing',
      'slotPacing',
      'hardness-conditioned',
      'hardnessConditioned',
      'already_solved',
      'too_hard',
      'qwen_no_recovery',
    ];
    const hits = [];
    for (const url of scanSourceFiles(new URL('../../src/', import.meta.url))) {
      const body = readFileSync(url, 'utf8');
      for (const token of forbidden) {
        if (body.includes(token)) hits.push(`${url.pathname}:${token}`);
      }
    }
    assert.deepEqual(hits, [], 'stress-harness caps/classifiers must not become production rejection logic');
  });

  test('validator sync CLI does not import coordinator-only control-plane modules', () => {
    const body = readFileSync(new URL('../../../../scripts/coretex-validator-sync.mjs', import.meta.url), 'utf8');
    const imports = body.split('\n').filter((line) => /^\s*import\s/.test(line)).join('\n');
    for (const forbidden of [
      'coretex-coordinator',
      '/coordinator/',
      '@aws-sdk',
      'child_process',
      'coretex-pin-epoch-context',
      'coretex-epoch-evolve',
    ]) {
      assert.equal(
        imports.includes(forbidden),
        false,
        `validator sync import boundary must not include ${forbidden}`,
      );
    }
  });
});
