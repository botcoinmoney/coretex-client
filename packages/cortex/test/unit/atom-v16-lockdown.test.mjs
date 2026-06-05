import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_PROFILE,
  BGE_M3_DEFAULT_LAYOUT,
  buildBundleManifest,
  scoringOptionsFromProfile,
  qwen3Reranker06BManifest,
  bgeM3DenseManifest,
  memRerankerManifest,
  serializeProductionCorpus,
  bridgeLogicalDeltaToProductionEvents,
} from '../../dist/index.js';
import { buildMemoryEventByDocId } from '../../../../scripts/lib/v2-patch-families.mjs';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));

const REV_A = '0123456789abcdef0123456789abcdef01234567';
const REV_B = '89abcdef0123456789abcdef0123456789abcdef';
const REV_C = 'cafebabedeadbeefcafebabedeadbeefcafebabe';
const layout = { dim: 8, headerBytes: 9, quantization: 'int8' };
const emb = new Uint8Array(12);

function runtime() {
  return {
    biEncoder: { modelId: 'm', revision: 'r', layout, async encode() { return new Float32Array(8); } },
    reranker: { model: 'k', async score(pairs) { return pairs.map(() => 0.5); } },
    biEncoderHash: '0xabc',
    retrievalKeyLayout: layout,
  };
}

function modelFixtures() {
  return {
    biEncoder: bgeM3DenseManifest({ revision: REV_A, files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }] }),
    reranker: qwen3Reranker06BManifest({ revision: REV_B, files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }] }),
    labelingReranker: memRerankerManifest({ modelId: 'memreranker/4B', revision: REV_C, files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }] }),
  };
}

function event(overrides = {}) {
  return {
    id: 'mem_d1',
    family: 'near_collision',
    domain: 'deep',
    split: 'train_visible',
    queryText: 'Doc text',
    truthDocuments: [{ id: 'd1', text: 'Doc text', isCurrent: true }],
    hardNegatives: [],
    qrels: [{ documentId: 'd1', relevance: 1 }],
    protected: false,
    relations: [],
    provenance: { source: 'synthetic_challenge', sourceHash: `0x${'00'.repeat(32)}` },
    embeddings: { modelId: 'BAAI/bge-m3', revision: REV_A, layout: BGE_M3_DEFAULT_LAYOUT, query: emb, perTruth: new Map([['d1', emb]]), perNegative: new Map() },
    ...overrides,
  };
}

describe('atom v16 lockdown wiring', () => {
  test('atom flags and budgets flow through profile options and bundle hash', () => {
    const atomProfile = {
      ...DEFAULT_PROFILE,
      pipelineVersion: 'coretex-retrieval-v2-policy-r5',
      enableValidityAtoms: true,
      enableScopeAtoms: true,
      enableEntityResolutionAtoms: true,
      policyMaxBudgetEntity: 111,
      policyMaxBudgetScope: 222,
      policyEntityMaxDocs: 3,
      policyScopeMaxDocs: 5,
    };
    const opts = scoringOptionsFromProfile(atomProfile, runtime());
    assert.equal(opts.enableValidityAtoms, true);
    assert.equal(opts.enableScopeAtoms, true);
    assert.equal(opts.enableEntityResolutionAtoms, true);
    assert.equal(opts.policyMaxBudgetEntity, 111);
    assert.equal(opts.policyMaxBudgetScope, 222);
    assert.equal(opts.policyEntityMaxDocs, 3);
    assert.equal(opts.policyScopeMaxDocs, 5);

    const fixtures = modelFixtures();
    const enabled = buildBundleManifest({
      repoRoot,
      generatedAt: '2026-06-04T00:00:00.000Z',
      corpusRoot: `0x${'11'.repeat(32)}`,
      corpusFiles: [],
      ...fixtures,
      evaluatorProfile: atomProfile,
    });
    const disabled = buildBundleManifest({
      repoRoot,
      generatedAt: '2026-06-04T00:00:00.000Z',
      corpusRoot: `0x${'11'.repeat(32)}`,
      corpusFiles: [],
      ...fixtures,
      evaluatorProfile: { ...atomProfile, enableValidityAtoms: false, enableScopeAtoms: false, enableEntityResolutionAtoms: false },
    });
    assert.notEqual(enabled.bundleHash, disabled.bundleHash);
    assert.equal(enabled.evaluator.profile.enableValidityAtoms, true);
    assert.equal(enabled.evaluator.profile.enableScopeAtoms, true);
    assert.equal(enabled.evaluator.profile.enableEntityResolutionAtoms, true);
  });

  test('production corpus serialization preserves public atom metadata', () => {
    const scope = { projectId: 'proj-a', sessionId: 'sess-a', topicId: 'topic-a', taskId: 'task-a', userScopeId: 'user-a' };
    const validity = { subjectEntityId: 'e1', attribute: 'api endpoint', validFrom: '2026-01-01', observedAt: '2026-06-04' };
    const corpus = {
      events: [event({
        scope,
        validity,
        aliases: ['Alias A'],
        roleAliases: ['backend lead'],
        publicIntent: { atom: 'scope_atom', ...scope },
      })],
      byId: new Map(),
      entities: [{ id: 'e1', canonicalName: 'Sam Rivera', aliases: ['Sam'], roleAliases: ['backend lead'] }],
      corpusRoot: `0x${'22'.repeat(32)}`,
      corpusEpoch: 0,
      biEncoderModelId: 'BAAI/bge-m3',
      biEncoderRevision: REV_A,
      biEncoderRetrievalKeyLayout: BGE_M3_DEFAULT_LAYOUT,
      labelingModelId: 'memreranker/4B',
      labelingModelRevision: REV_C,
    };
    const out = serializeProductionCorpus(corpus);
    assert.deepEqual(out.events[0].scope, scope);
    assert.deepEqual(out.events[0].validity, validity);
    assert.deepEqual(out.events[0].aliases, ['Alias A']);
    assert.deepEqual(out.events[0].roleAliases, ['backend lead']);
    assert.deepEqual(out.events[0].publicIntent, { atom: 'scope_atom', ...scope });
    assert.deepEqual(out.entities[0].roleAliases, ['backend lead']);
  });

  test('live delta bridge preserves atom doc/query metadata', () => {
    const scope = { projectId: 'proj-a', sessionId: 'sess-a', topicId: 'topic-a', taskId: 'task-a', userScopeId: 'user-a' };
    const validity = { subjectEntityId: 'e1', attribute: 'api endpoint', validFrom: '2026-01-01', observedAt: '2026-06-04' };
    const previousCorpus = {
      events: [],
      byId: new Map(),
      corpusRoot: `0x${'33'.repeat(32)}`,
      corpusEpoch: 0,
      biEncoderModelId: 'BAAI/bge-m3',
      biEncoderRevision: REV_A,
      biEncoderRetrievalKeyLayout: BGE_M3_DEFAULT_LAYOUT,
      labelingModelId: 'memreranker/4B',
      labelingModelRevision: REV_C,
    };
    const logicalDelta = {
      epoch: 2,
      seed: 'seed',
      churnFraction: 0.01,
      addedDocs: [{
        id: 'd_live',
        lane: 'deep',
        text: 'Sam set the current API endpoint.',
        entityIds: ['e1'],
        scope,
        validity,
        aliases: ['Sam'],
        roleAliases: ['backend lead'],
        liveUpdateEpoch: 2,
      }],
      addedRelations: [],
      addedQueries: [{
        id: 'q_live',
        lane: 'deep',
        family: 'validity_atom',
        queryText: 'What is Sam current API endpoint?',
        qrels: [{ docId: 'd_live', relevance: 1, role: 'direct' }],
        scope,
        publicIntent: { atom: 'validity_atom', subjectEntityId: 'e1', attribute: 'api endpoint', ...scope },
        liveUpdateEpoch: 2,
      }],
      churnedSubjects: ['e1'],
      liveChurnRate: 0.01,
    };
    const events = bridgeLogicalDeltaToProductionEvents({
      previousCorpus,
      logicalDelta,
      addedDocEmbeddings: new Map([['d_live', emb]]),
      addedQueryEmbeddings: new Map([['q_live', emb]]),
      biEncoder: { modelId: 'BAAI/bge-m3', revision: REV_A, layout: BGE_M3_DEFAULT_LAYOUT },
    });
    const mem = events.find((e) => e.id.includes('_mem_'));
    const query = events.find((e) => e.id.includes('_q_'));
    assert.deepEqual(mem.scope, scope);
    assert.deepEqual(mem.validity, validity);
    assert.deepEqual(mem.aliases, ['Sam']);
    assert.deepEqual(mem.roleAliases, ['backend lead']);
    assert.deepEqual(query.scope, scope);
    assert.deepEqual(query.publicIntent, { atom: 'validity_atom', subjectEntityId: 'e1', attribute: 'api endpoint', ...scope });
  });

  test('live event lookup maps doc ids to memory-doc events, not query events', () => {
    const mem = event({ id: 'zz_e000000000002_mem_d_live', truthDocuments: [{ id: 'd_live', text: 'Live doc', isCurrent: true }] });
    const query = event({ id: 'zz_e000000000002_q_q_live', split: 'eval_hidden', truthDocuments: [{ id: 'd_live', text: 'Live doc', isCurrent: true }] });
    const index = buildMemoryEventByDocId({ events: [mem, query] });
    assert.equal(index.get('d_live').id, mem.id);
    assert.equal(index.get('mem_d_live').id, mem.id);
    assert.equal(index.get(query.id).id, query.id);
  });
});
