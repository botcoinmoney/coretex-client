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
  decodeSubstrate,
  applyPatch,
  merkleizeState,
  stableRecordIdFor,
  RANGES,
  PATCH_TYPE,
} from '../../dist/index.js';
import {
  atomAnchorUnits,
  buildMemoryEventByDocId,
  evidenceBundleUnits,
  noiseSuppressionUnits,
  relationUnitsForEdges,
} from '../../../../scripts/lib/v2-patch-families.mjs';
import { baselineAtomHardness } from '../../../../scripts/lib/atom-hardness.mjs';

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

  test('multi-anchor atom patches compile disjoint in-family MemoryIndex slots', () => {
    const scope = { projectId: 'proj-a', sessionId: 'sess-a', topicId: 'topic-a', taskId: 'task-a', userScopeId: 'user-a' };
    const queries = Array.from({ length: 4 }, (_, i) => event({
      id: `q_scope_${i}`,
      family: 'scope_atom',
      logicalFamily: 'scope_atom',
      split: 'eval_hidden',
      queryText: `scope query ${i}`,
      truthDocuments: [{ id: `d_scope_${i}`, text: `scope doc ${i}`, isCurrent: true }],
      qrels: [{ documentId: `d_scope_${i}`, relevance: 1 }],
      scope,
    }));
    const logicalQById = new Map(queries.map((q, i) => [q.id, {
      id: q.id,
      family: 'scope_atom',
      qrels: [{ docId: `d_scope_${i}`, relevance: 1, role: 'direct' }],
      liveUpdateEpoch: i,
    }]));
    const memEvents = queries.map((q, i) => event({
      id: `mem_d_scope_${i}`,
      split: 'train_visible',
      truthDocuments: [{ id: `d_scope_${i}`, text: `scope doc ${i}`, isCurrent: true }],
      qrels: [{ documentId: `d_scope_${i}`, relevance: 1 }],
      scope,
    }));
    const units = atomAnchorUnits({
      pack: { events: queries },
      logicalQById,
      eventByDocId: buildMemoryEventByDocId({ events: memEvents }),
      atomFamily: 'scope_atom',
      memorySlot: 220,
      skipDocIds: new Set(),
      maxRecords: 4,
    });

    assert.equal(units.recordsCompiled, 4);
    assert.deepEqual(units.slots, [220, 221, 222, 223]);
    assert.equal(new Set(units.indices).size, 4);
    assert.ok(units.indices.every((idx) => idx >= RANGES.MEMORY_INDEX_START + 192 && idx < RANGES.MEMORY_INDEX_START + 256));

    const state = { words: new Array(RANGES.WORD_COUNT).fill(0n) };
    const applied = applyPatch(state, {
      patchType: PATCH_TYPE.MIXED,
      wordCount: units.indices.length,
      scoreDelta: 0n,
      parentStateRoot: merkleizeState(state),
      indices: units.indices,
      newWords: units.newWords,
    }, true);
    assert.equal(applied.ok, true);
    const decoded = decodeSubstrate(applied.state, { policyAtomsMode: true });
    for (let i = 0; i < units.slots.length; i++) {
      const slot = decoded.memoryIndex[units.slots[i]];
      assert.equal(slot.policyAnchor, true);
      assert.equal(slot.recordId, stableRecordIdFor(units.eventIds[i]));
    }
  });

  test('runway patch helpers keep relation/evidence/noise slots disjoint', () => {
    const relationA = relationUnitsForEdges(['supports', 'causes'], 0);
    const relationB = relationUnitsForEdges(['supersedes'], 2);
    assert.equal(new Set([...relationA.indices, ...relationB.indices]).size, 3);

    const relationQuery = event({
      id: 'q_relation',
      family: 'multi_hop_relation',
      logicalFamily: 'multi_hop_relation',
      split: 'eval_hidden',
      truthDocuments: [{ id: 'd_relation', text: 'relation doc', isCurrent: true }],
      hardNegatives: [{ id: 'd_noise', text: 'noise doc', category: 'wrong_relation' }],
      qrels: [
        { documentId: 'd_relation', relevance: 1, role: 'direct' },
        { documentId: 'd_noise', relevance: 0, role: 'wrong_relation' },
      ],
    });
    const logicalQById = new Map([['q_relation', {
      id: 'q_relation',
      family: 'multi_hop_relation',
      qrels: [
        { docId: 'd_relation', relevance: 1, role: 'direct' },
        { docId: 'd_noise', relevance: 0, role: 'wrong_relation' },
      ],
    }]]);
    const memRelation = event({
      id: 'mem_d_relation',
      truthDocuments: [{ id: 'd_relation', text: 'relation doc', isCurrent: true }],
      qrels: [{ documentId: 'd_relation', relevance: 1 }],
    });
    const memNoise = event({
      id: 'mem_d_noise',
      truthDocuments: [{ id: 'd_noise', text: 'noise doc', isCurrent: true }],
      qrels: [{ documentId: 'd_noise', relevance: 1 }],
    });
    const eventByDocId = buildMemoryEventByDocId({ events: [memRelation, memNoise] });

    const evidence = evidenceBundleUnits({
      pack: { events: [relationQuery] },
      logicalQById,
      eventByDocId,
      memorySlot: 224,
      skipDocIds: new Set(),
    });
    const noise = noiseSuppressionUnits({
      pack: { events: [relationQuery] },
      logicalQById,
      eventByDocId,
      memorySlot: 240,
      skipDocIds: new Set(),
    });

    assert.deepEqual(evidence.indices, [RANGES.MEMORY_INDEX_START + 224, RANGES.POLICY_EVIDENCE_START]);
    assert.deepEqual(noise.indices, [RANGES.MEMORY_INDEX_START + 240, RANGES.POLICY_EVIDENCE_START + 16]);
    assert.equal(evidence.minedDocId, 'd_relation');
    assert.equal(noise.minedDocId, 'd_noise');
    assert.equal(new Set([...evidence.indices, ...noise.indices]).size, 4);

    const state = { words: new Array(RANGES.WORD_COUNT).fill(0n) };
    const applied = applyPatch(state, {
      patchType: PATCH_TYPE.MIXED,
      wordCount: 4,
      scoreDelta: 0n,
      parentStateRoot: merkleizeState(state),
      indices: [...evidence.indices, ...noise.indices],
      newWords: [...evidence.newWords, ...noise.newWords],
    }, true);
    assert.equal(applied.ok, true);
    const decoded = decodeSubstrate(applied.state, { policyAtomsMode: true });
    assert.equal(decoded.memoryIndex[224].recordId, stableRecordIdFor('mem_d_relation'));
    assert.equal(decoded.memoryIndex[240].recordId, stableRecordIdFor('mem_d_noise'));
    assert.equal(decoded.evidenceBundleAtoms.find((a) => a.atomIndex === 0)?.action, 'bundle');
    assert.equal(decoded.evidenceBundleAtoms.find((a) => a.atomIndex === 16)?.action, 'suppress');
  });

  test('atom anchor compiler refuses slots outside the atom family range', () => {
    const units = atomAnchorUnits({
      pack: { events: [] },
      logicalQById: new Map(),
      eventByDocId: new Map(),
      atomFamily: 'entity_resolution_atom',
      memorySlot: 192,
      skipDocIds: new Set(),
      maxRecords: 4,
    });
    assert.equal(units.reason, 'entity_resolution_atom_slot_exhausted');
    assert.deepEqual(units.indices, []);
  });

  test('atom hardness filter distinguishes solved from hard active targets', () => {
    const pack = { events: [event({
      id: 'q_atom',
      family: 'validity_atom',
      logicalFamily: 'validity_atom',
      split: 'eval_hidden',
      truthDocuments: [{ id: 'd_current', text: 'current', isCurrent: true }],
      hardNegatives: [{ id: 'd_stale', text: 'stale' }],
      qrels: [{ documentId: 'd_current', relevance: 1 }, { documentId: 'd_stale', relevance: 0 }],
    })] };
    const solved = baselineAtomHardness({
      targetDocIds: ['d_current'],
      pack,
      baselineScore: { perQuery: [{ recordId: 'q_atom', nDCG10: 1, finalRankingTop20: [{ docId: 'd_current', rank: 1 }, { docId: 'd_stale', rank: 2 }] }] },
    });
    assert.equal(solved.hard, false);
    assert.equal(solved.reason, 'already_solved_by_qwen');

    const hard = baselineAtomHardness({
      targetDocIds: ['d_current'],
      pack,
      baselineScore: { perQuery: [{ recordId: 'q_atom', nDCG10: 0.5, finalRankingTop20: [{ docId: 'd_stale', rank: 1 }, { docId: 'd_current', rank: 2 }] }] },
    });
    assert.equal(hard.hard, true);
    assert.equal(hard.reason, 'hard_candidate');
    assert.equal(hard.rows[0].hardNegativeAboveTarget, true);
  });
});
