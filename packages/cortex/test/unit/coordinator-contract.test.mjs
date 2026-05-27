/**
 * Coordinator data-source contract test  (Launch hardening L20).
 *
 * The production coordinator server is external, but every route delegates to a
 * CoreTexCoordinatorDataSource (endpoints.ts). This pins the CONTRACT a production
 * data source must satisfy: each launch endpoint returns a well-formed shape through
 * the real route handler, AND no response leaks hidden qrels / eval-pack / answer IDs /
 * epochSecret / evalSeed. A representative data source (canonical launch shapes) is
 * wired through createCoreTexCoordinatorRouteHandler exactly as a server would.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createCoreTexCoordinatorRouteHandler } from '../../dist/coordinator/endpoints.js';

const PARENT_ROOT = '0x04d107ad97465d9fbdb448d4ff2d21131bf2ee38ce72de641b7c17dedec72146';
const BUNDLE_HASH = '0x474cd8851eebd097a7f1480818c1ccdb0dd473c5da08cd6909b071ac8c101715';
const CORPUS_ROOT = '0x15bab3a8e0d6fdb8df4d525e49aa7e22c815e749c8d95301a89e54de933beb33';
const PATCH_HASH = '0x82a2e24dc19e166c4a12f2c86b73cb3bde3f54b6cc9f4479a9a392aec45b1573';

// A representative production data source returning canonical launch shapes (public-only).
const ds = {
  getChallenge: () => ({
    epochId: 0, parentStateRoot: PARENT_ROOT, currentStateRoot: PARENT_ROOT,
    bundleHash: BUNDLE_HASH, coreVersionHash: BUNDLE_HASH, pipelineVersion: 'coretex-retrieval-v2-policy-r5',
    corpusRoot: CORPUS_ROOT, activeFrontierRoot: '0x9150a9aaee8d4dea',
    allowedPatchTypes: ['TEMPORAL_UPDATE', 'RELATION_UPDATE', 'POLICY_UPDATE'], patchWordBudget: 4,
    minImprovementPpm: 2500, replayTolerancePpm: 250, screenerThresholdPpm: 347, perMinerCap: 8,
    memoryIRSchemaVersion: 'memory_ir.v1',
    activeSubstrateSurfaces: ['temporal', 'relation_typed_routing', 'evidence_bundle', 'guarded_abstention', 'conflict_state'],
    hiddenEvalWarning: 'hidden qrels/pack/epochSecret are NOT public',
  }),
  // current state + active frontier / corpus metadata
  getStatus: () => ({
    epochId: 0, currentStateRoot: PARENT_ROOT, corpusRoot: CORPUS_ROOT, bundleHash: BUNDLE_HASH,
    activeFrontier: { activeRoot: '0x9150a9aaee8d4dea', activeEvalHiddenCount: 141, reserveRemaining: 0, churnMode: 'C3' },
    corpus: { evalHiddenCount: 141, familyCounts: { near_collision: 46, temporal: 61, multi_hop_relation: 34 } },
    minImprovementPpm: 2500, screenerThresholdPpm: 347,
  }),
  // current substrate by root — full 1024 words (public; the state IS public by root)
  getSubstrate: (root) => ({ stateRoot: root, wordCount: 1024, packedBytes: 32768, wordsHex: '0x' + '00'.repeat(32) }),
  getPatch: (hash) => ({ patchHash: hash, patchBytesHex: '0x07010000', wordCount: 1 }),
  getPatchReceivedNotice: (hash) => ({ patchHash: hash, receivedAtBlock: 21_000_000, epochId: 0, noticeHash: '0xabc' }),
  // screener result + state-advance receipt (post-reveal-safe; no qrels)
  getEvalReport: (hash) => ({
    patchHash: hash, outcome: 'state_advance', accepted: true,
    gateScorePpm: 310158, confirmScorePpm: 309758, parentStateRoot: PARENT_ROOT, childStateRoot: '0xbbbf82a2',
    workUnitsBps: 30000, blockhash: '0x' + 'bb'.repeat(32),
  }),
  submit: (body) => ({ accepted: true, patchHash: PATCH_HASH, dedupKey: '0xdedup', receivedAtBlock: 21_000_000, echo: body ? 'ok' : 'empty' }),
  getCorpusDelta: (epoch) => ({ epoch: Number(epoch), corpusRootChanged: false, addedEvalHidden: 0 }),
  getBundle: (h) => ({ bundleHash: h, schemaVersion: 'coretex.client-bundle.v2' }),
  getBundleByCoreVersionHash: (h) => ({ coreVersionHash: h, bundleHash: BUNDLE_HASH }),
  health: () => ({ ok: true, service: 'coretex' }),
};

const handle = createCoreTexCoordinatorRouteHandler(ds);
const FORBIDDEN = /qrel|truthdoc|hardnegativ|answerid|answer_id|epochsecret|epoch_secret|evalseed|eval_seed|hiddenpack|hidden_pack|relevance|truthDocuments/i;
function scanLeak(obj, path = '') {
  const hits = [];
  if (obj && typeof obj === 'object') for (const [k, v] of Object.entries(obj)) {
    if (FORBIDDEN.test(k)) hits.push(`${path}${k}`);
    hits.push(...scanLeak(v, `${path}${k}.`));
  }
  return hits;
}

describe('coordinator data-source contract', () => {
  const cases = [
    ['GET', '/coretex/health'],
    ['GET', '/coretex/challenge'],
    ['GET', '/coretex/status'],
    ['GET', `/coretex/substrate/${PARENT_ROOT}`],
    ['GET', `/coretex/patch/${PATCH_HASH}`],
    ['GET', `/coretex/patch-received/${PATCH_HASH}`],
    ['GET', `/coretex/eval-report/${PATCH_HASH}`],
    ['GET', '/coretex/corpus-delta/0'],
    ['GET', `/coretex/bundle/${BUNDLE_HASH}`],
    ['POST', '/coretex/submit'],
  ];

  for (const [method, path] of cases) {
    test(`${method} ${path} → 200 + handled + no hidden leakage`, async () => {
      const res = await handle({ method, path, body: method === 'POST' ? { patchBytesHex: '0x07010000', minerAddress: '0x' + '11'.repeat(20) } : undefined });
      assert.equal(res.handled, true, 'route handled');
      assert.equal(res.status, 200, 'status 200');
      const leaks = scanLeak(res.body);
      assert.equal(leaks.length, 0, `no hidden leakage, got: ${leaks.join(',')}`);
    });
  }

  test('challenge exposes required public fields + active surfaces incl conflict_state', async () => {
    const r = await handle({ method: 'GET', path: '/coretex/challenge' });
    for (const k of ['epochId', 'parentStateRoot', 'bundleHash', 'corpusRoot', 'pipelineVersion', 'allowedPatchTypes', 'minImprovementPpm', 'screenerThresholdPpm', 'activeSubstrateSurfaces', 'hiddenEvalWarning']) {
      assert.ok(r.body[k] !== undefined, `challenge.${k} present`);
    }
    assert.ok(r.body.activeSubstrateSurfaces.includes('conflict_state'), 'conflict_state is an active launch surface');
  });

  test('status exposes active-frontier + corpus metadata (no eval pack)', async () => {
    const r = await handle({ method: 'GET', path: '/coretex/status' });
    assert.ok(r.body.activeFrontier?.activeRoot, 'activeFrontier.activeRoot present');
    assert.equal(r.body.corpus?.evalHiddenCount, 141);
    assert.ok(!('events' in r.body) && !('pack' in r.body) && !('qrels' in r.body), 'no eval pack embedded');
  });

  test('eval-report is replay-sufficient without leaking qrels', async () => {
    const r = await handle({ method: 'GET', path: `/coretex/eval-report/${PATCH_HASH}` });
    for (const k of ['patchHash', 'outcome', 'gateScorePpm', 'confirmScorePpm', 'childStateRoot', 'blockhash']) {
      assert.ok(r.body[k] !== undefined, `eval-report.${k} present`);
    }
    assert.equal(scanLeak(r.body).length, 0);
  });

  test('unconfigured endpoint returns a stable not-configured (not a crash)', async () => {
    const empty = createCoreTexCoordinatorRouteHandler({});
    const r = await empty({ method: 'GET', path: '/coretex/challenge' });
    assert.equal(r.handled, true);
    assert.notEqual(r.status, 200);
  });
});
