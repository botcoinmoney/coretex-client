/**
 * Unit tests: §9 corpus pipeline — V3 bridge, admission policy, corpus delta.
 *
 * Run: npm run build && node --test test/unit/corpus-pipeline.test.mjs
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  bridgeV3ToV4,
  bridgeV3Batch,
  routeV3Family,
  computeHardnessSignal,
  computeNoveltyBucket,
} from '../../dist/corpus/v3-bridge.js';

import {
  admitCorpusBatch,
  DEFAULT_ADMISSION_POLICY,
} from '../../dist/corpus/admission.js';

import {
  buildCorpusDelta,
  applyCorpusDelta,
} from '../../dist/corpus/delta.js';

import { computeProductionCorpusRoot } from '../../dist/eval/corpus.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeV3Record(overrides = {}) {
  return {
    challengeId: 'chal-abc123',
    worldSeed: 'seed-xyz',
    domain: 'domain_reasoning',
    rulesVersion: 'v1',
    manifestHash: 'manifest' + 'a'.repeat(56),
    docHash: 'doc' + 'b'.repeat(61),
    questionsHash: 'questions' + 'c'.repeat(55),
    constraintsHash: 'constraints' + 'd'.repeat(53),
    selectedQuestionIndices: [0, 1, 2],
    answerHashes: ['ans1' + 'e'.repeat(60), 'ans2' + 'f'.repeat(60)],
    sourceVersionHash: 'srcver' + 'g'.repeat(58),
    coreCommitHash: 'core' + 'h'.repeat(60),
    ...overrides,
  };
}

function makeV4Event(overrides = {}) {
  return {
    id: 'test-event-001',
    family: 'long_horizon',
    taskType: 'domain_reasoning',
    isProtected: false,
    epochCommitted: 1,
    sourceRef: 'botcoin-domain-library:test:001',
    queryText: 'What is the answer?',
    truthText: 'The answer is 42.',
    isStaleTruth: false,
    relevant: true,
    distractors: ['wrong answer A', 'wrong answer B'],
    relations: [],
    expectedStateRegions: ['memory_index', 'retrieval_keys'],
    validFromEpoch: 1,
    expiresAtEpoch: 0,
    noveltyBucket: 'medium',
    hardnessSignal: 0.5,
    ...overrides,
  };
}

function makeMinimalCorpus(events = []) {
  const byFamily = { near_collision: [], temporal: [], long_horizon: [] };
  for (const e of events) byFamily[e.family].push(e);

  // Compute a valid corpus root using the same algorithm.
  // For an empty corpus the root is the zero hash.
  const corpusRoot = '0x' + '00'.repeat(32);
  return { events: byFamily, sources: {}, corpusRoot };
}

// ── bridgeV3ToV4 ──────────────────────────────────────────────────────────────

describe('bridgeV3ToV4 — §9 required fields', () => {
  test('produces a record with all §9 required fields populated', () => {
    const record = makeV3Record();
    const result = bridgeV3ToV4(record, { epochCommitted: 5 });

    // Core identity fields
    assert.ok(typeof result.id === 'string' && result.id.length > 0, 'id must be non-empty string');
    assert.ok(['near_collision', 'temporal', 'long_horizon'].includes(result.family), 'family must be valid');
    assert.ok(typeof result.taskType === 'string' && result.taskType.length > 0, 'taskType must be non-empty');
    assert.equal(result.epochCommitted, 5);
    assert.ok(typeof result.sourceRef === 'string' && result.sourceRef.length > 0, 'sourceRef must be non-empty');

    // §9 extension fields
    assert.ok(Array.isArray(result.distractors), 'distractors must be array');
    assert.ok(Array.isArray(result.relations), 'relations must be array');
    assert.ok(Array.isArray(result.expectedStateRegions) && result.expectedStateRegions.length > 0, 'expectedStateRegions must be non-empty array');
    assert.equal(typeof result.validFromEpoch, 'number');
    assert.equal(typeof result.expiresAtEpoch, 'number');
    assert.ok(['low', 'medium', 'high'].includes(result.noveltyBucket), 'noveltyBucket must be low/medium/high');
    assert.ok(typeof result.hardnessSignal === 'number' && result.hardnessSignal >= 0 && result.hardnessSignal <= 1, 'hardnessSignal must be in [0,1]');
    assert.equal(result.validFromEpoch, 5);
  });

  test('sourceRef contains challengeId, manifestHash, and other hashes', () => {
    const record = makeV3Record({ challengeId: 'chal-XYZ', manifestHash: 'mfst' + 'a'.repeat(60) });
    const result = bridgeV3ToV4(record, { epochCommitted: 1 });
    assert.ok(result.sourceRef.includes('v3-challenge:chal-XYZ'));
    assert.ok(result.sourceRef.includes('manifest:mfst' + 'a'.repeat(60)));
  });

  test('relations are derived from answerHashes', () => {
    const record = makeV3Record({ answerHashes: ['hash1', 'hash2'] });
    const result = bridgeV3ToV4(record, { epochCommitted: 1 });
    assert.ok(result.relations.some((r) => r.includes('hash1')));
    assert.ok(result.relations.some((r) => r.includes('hash2')));
  });

  test('mintHardNegatives hook populates distractors', () => {
    const record = makeV3Record();
    const result = bridgeV3ToV4(record, {
      epochCommitted: 1,
      mintHardNegatives: () => ['distractor-A', 'distractor-B'],
    });
    assert.deepEqual(result.distractors, ['distractor-A', 'distractor-B']);
  });
});

// ── Domain routing ────────────────────────────────────────────────────────────

describe('bridgeV3ToV4 — domain routing', () => {
  test('temporal domain routes to temporal family', () => {
    assert.equal(routeV3Family('temporal_stale_knowledge'), 'temporal');
    assert.equal(routeV3Family('time_series_reasoning'), 'temporal');
    assert.equal(routeV3Family('TEMPORAL_UPDATE'), 'temporal');
  });

  test('collision/similar domain routes to near_collision family', () => {
    assert.equal(routeV3Family('near_collision_retrieval'), 'near_collision');
    assert.equal(routeV3Family('semantic_similar_docs'), 'near_collision');
    assert.equal(routeV3Family('SIMILAR_ENTITY'), 'near_collision');
  });

  test('other domains route to long_horizon', () => {
    assert.equal(routeV3Family('domain_reasoning'), 'long_horizon');
    assert.equal(routeV3Family('multi_hop_project'), 'long_horizon');
    assert.equal(routeV3Family('tool_api_fact'), 'long_horizon');
    assert.equal(routeV3Family('codebook_compression'), 'long_horizon');
  });

  test('bridgeV3ToV4 uses routing when family not overridden', () => {
    const temporal = bridgeV3ToV4(makeV3Record({ domain: 'temporal_events' }), { epochCommitted: 1 });
    assert.equal(temporal.family, 'temporal');

    const collision = bridgeV3ToV4(makeV3Record({ domain: 'near_collision_test' }), { epochCommitted: 1 });
    assert.equal(collision.family, 'near_collision');

    const horizon = bridgeV3ToV4(makeV3Record({ domain: 'reasoning' }), { epochCommitted: 1 });
    assert.equal(horizon.family, 'long_horizon');
  });

  test('family override takes precedence over domain routing', () => {
    const result = bridgeV3ToV4(makeV3Record({ domain: 'temporal_knowledge' }), {
      epochCommitted: 1,
      family: 'near_collision',
    });
    assert.equal(result.family, 'near_collision');
  });

  test('near_collision family gets memory_index default region', () => {
    const result = bridgeV3ToV4(makeV3Record(), { epochCommitted: 1, family: 'near_collision' });
    assert.deepEqual([...result.expectedStateRegions], ['memory_index']);
  });

  test('temporal family gets memory_index+temporal default regions', () => {
    const result = bridgeV3ToV4(makeV3Record(), { epochCommitted: 1, family: 'temporal' });
    assert.deepEqual([...result.expectedStateRegions], ['memory_index', 'temporal']);
  });

  test('long_horizon family gets memory_index+retrieval_keys default regions', () => {
    const result = bridgeV3ToV4(makeV3Record(), { epochCommitted: 1, family: 'long_horizon' });
    assert.deepEqual([...result.expectedStateRegions], ['memory_index', 'retrieval_keys']);
  });
});

// ── Hardness signal determinism ───────────────────────────────────────────────

describe('hardness signal', () => {
  test('is deterministic for same inputs', () => {
    const record = makeV3Record({ challengeId: 'chal-DET', manifestHash: 'mfst' + 'b'.repeat(60) });
    const r1 = bridgeV3ToV4(record, { epochCommitted: 3 });
    const r2 = bridgeV3ToV4(record, { epochCommitted: 3 });
    assert.equal(r1.hardnessSignal, r2.hardnessSignal);
  });

  test('differs for different challengeId', () => {
    const s1 = computeHardnessSignal('chal-A', 'manifest' + 'x'.repeat(56));
    const s2 = computeHardnessSignal('chal-B', 'manifest' + 'x'.repeat(56));
    // Very unlikely to be equal for different inputs
    assert.notEqual(s1, s2);
  });

  test('is in [0, 1] range', () => {
    for (let i = 0; i < 20; i++) {
      const v = computeHardnessSignal(`chal-${i}`, `manifest-${i}` + 'z'.repeat(50));
      assert.ok(v >= 0 && v <= 1, `hardnessSignal out of range: ${v}`);
    }
  });

  test('noveltyBucket is deterministic', () => {
    const m = 'manifest' + 'q'.repeat(56);
    assert.equal(computeNoveltyBucket(m), computeNoveltyBucket(m));
  });
});

// ── bridgeV3Batch ─────────────────────────────────────────────────────────────

describe('bridgeV3Batch', () => {
  test('maps each record and preserves count', () => {
    const records = [makeV3Record({ challengeId: 'c1' }), makeV3Record({ challengeId: 'c2' })];
    const results = bridgeV3Batch(records, { epochCommitted: 7 });
    assert.equal(results.length, 2);
    assert.ok(results.every((r) => r.epochCommitted === 7));
  });
});

// ── admitCorpusBatch — insufficient_distractors ───────────────────────────────

describe('admitCorpusBatch — distractor rejection', () => {
  test('rejects records below minDistractorsPerRecord with reason insufficient_distractors', () => {
    const event = makeV4Event({ distractors: ['only one'] }); // 1 < 2 (default)
    const decision = admitCorpusBatch([event], DEFAULT_ADMISSION_POLICY);
    assert.equal(decision.admitted.length, 0);
    assert.equal(decision.rejected.length, 1);
    assert.equal(decision.rejected[0].reason, 'insufficient_distractors');
  });

  test('admits records with exactly minDistractorsPerRecord distractors', () => {
    const event = makeV4Event({ distractors: ['d1', 'd2'] }); // exactly 2
    const decision = admitCorpusBatch([event], DEFAULT_ADMISSION_POLICY);
    assert.equal(decision.admitted.length, 1);
    assert.equal(decision.rejected.length, 0);
  });
});

// ── admitCorpusBatch — missing_source_provenance ──────────────────────────────

describe('admitCorpusBatch — source provenance rejection', () => {
  test('rejects when sourceRef is empty under requireSourceProvenance', () => {
    const event = makeV4Event({ sourceRef: '' });
    const decision = admitCorpusBatch([event], DEFAULT_ADMISSION_POLICY);
    assert.equal(decision.admitted.length, 0);
    assert.equal(decision.rejected.length, 1);
    assert.equal(decision.rejected[0].reason, 'missing_source_provenance');
  });

  test('admits when sourceRef is empty if requireSourceProvenance=false', () => {
    const policy = { ...DEFAULT_ADMISSION_POLICY, requireSourceProvenance: false };
    const event = makeV4Event({ sourceRef: '' });
    const decision = admitCorpusBatch([event], policy);
    assert.equal(decision.admitted.length, 1);
  });
});

// ── admitCorpusBatch — per-domain cap ─────────────────────────────────────────

describe('admitCorpusBatch — perDomainCap', () => {
  test('admits first N records per domain and rejects overflow with per_domain_cap_exceeded', () => {
    const policy = { ...DEFAULT_ADMISSION_POLICY, perDomainCap: 2 };
    const events = [
      makeV4Event({ id: 'e1', taskType: 'domain_x' }),
      makeV4Event({ id: 'e2', taskType: 'domain_x' }),
      makeV4Event({ id: 'e3', taskType: 'domain_x' }), // overflow
    ];
    const decision = admitCorpusBatch(events, policy);
    assert.equal(decision.admitted.length, 2);
    assert.equal(decision.rejected.length, 1);
    assert.equal(decision.rejected[0].reason, 'per_domain_cap_exceeded');
  });

  test('tracks domain counts across multiple domains', () => {
    const policy = { ...DEFAULT_ADMISSION_POLICY, perDomainCap: 1 };
    const events = [
      makeV4Event({ id: 'a1', taskType: 'alpha' }),
      makeV4Event({ id: 'a2', taskType: 'alpha' }), // overflow alpha
      makeV4Event({ id: 'b1', taskType: 'beta' }),  // new domain, admitted
    ];
    const decision = admitCorpusBatch(events, policy);
    assert.equal(decision.admitted.length, 2);
    assert.equal(decision.perDomainCounts['alpha'], 1);
    assert.equal(decision.perDomainCounts['beta'], 1);
    assert.equal(decision.rejected[0].reason, 'per_domain_cap_exceeded');
  });
});

// ── admitCorpusBatch — hardness signal ───────────────────────────────────────

describe('admitCorpusBatch — hardness signal', () => {
  test('rejects records below minHardnessSignal with hardness_signal_too_low', () => {
    const policy = { ...DEFAULT_ADMISSION_POLICY, minHardnessSignal: 0.5 };
    const event = makeV4Event({ hardnessSignal: 0.1 });
    const decision = admitCorpusBatch([event], policy);
    assert.equal(decision.rejected[0].reason, 'hardness_signal_too_low');
  });
});

// ── admitCorpusBatch — total cap ──────────────────────────────────────────────

describe('admitCorpusBatch — totalCap', () => {
  test('enforces totalCap and rejects overflow with total_cap_exceeded', () => {
    const policy = { ...DEFAULT_ADMISSION_POLICY, totalCap: 2 };
    const events = [
      makeV4Event({ id: 'x1' }),
      makeV4Event({ id: 'x2' }),
      makeV4Event({ id: 'x3' }),
    ];
    const decision = admitCorpusBatch(events, policy);
    assert.equal(decision.admitted.length, 2);
    assert.equal(decision.rejected[0].reason, 'total_cap_exceeded');
  });
});

// ── buildCorpusDelta — determinism ────────────────────────────────────────────

describe('buildCorpusDelta', () => {
  test('produces a deterministic root for the same input', () => {
    const corpus = makeMinimalCorpus();
    const additions = [makeV4Event({ id: 'new-1' }), makeV4Event({ id: 'new-2' })];
    const delta1 = buildCorpusDelta(corpus, additions, [], 5);
    const delta2 = buildCorpusDelta(corpus, additions, [], 5);
    assert.equal(delta1.nextRoot, delta2.nextRoot);
  });

  test('previousRoot matches corpus.corpusRoot', () => {
    const corpus = makeMinimalCorpus();
    const delta = buildCorpusDelta(corpus, [makeV4Event({ id: 'n1' })], [], 1);
    assert.equal(delta.previousRoot, corpus.corpusRoot);
  });

  test('addedIds lists bridged record ids', () => {
    const corpus = makeMinimalCorpus();
    const additions = [makeV4Event({ id: 'added-abc' })];
    const delta = buildCorpusDelta(corpus, additions, [], 2);
    assert.ok(delta.addedIds.includes('added-abc'));
  });

  test('removedIds are captured', () => {
    const existing = makeV4Event({ id: 'to-remove' });
    const rawItems = [{
      id: existing.id, family: existing.family, task: existing.taskType,
      query: existing.queryText, truth: existing.truthText,
      is_stale: existing.isStaleTruth, epoch_committed: existing.epochCommitted,
      source_ref: existing.sourceRef,
    }];
    const corpusRoot = computeProductionCorpusRoot(rawItems);
    const corpus = {
      events: { near_collision: [], temporal: [], long_horizon: [existing] },
      sources: {},
      corpusRoot,
    };
    const delta = buildCorpusDelta(corpus, [], ['to-remove'], 3);
    assert.ok(delta.removedIds.includes('to-remove'));
  });

  test('nextRoot changes when additions are non-empty', () => {
    const corpus = makeMinimalCorpus();
    const emptyDelta = buildCorpusDelta(corpus, [], [], 1);
    const withAddDelta = buildCorpusDelta(corpus, [makeV4Event({ id: 'add-unique-xyz' })], [], 1);
    assert.notEqual(emptyDelta.nextRoot, withAddDelta.nextRoot);
  });
});

// ── applyCorpusDelta — hash continuity ───────────────────────────────────────

describe('applyCorpusDelta', () => {
  test('throws if previousRoot does not match corpus.corpusRoot', () => {
    const corpus = makeMinimalCorpus();
    const delta = {
      previousRoot: '0x' + 'ff'.repeat(32), // wrong root
      nextRoot: '0x' + '00'.repeat(32),
      addedIds: [],
      removedIds: [],
      epoch: 1,
      generatedAt: new Date().toISOString(),
    };
    assert.throws(
      () => applyCorpusDelta(corpus, delta),
      /hash continuity check failed/,
    );
  });

  test('applies a removal delta and returns corpus without removed id', () => {
    // Build a corpus with one event and a real root.
    const event = makeV4Event({ id: 'to-remove-test' });
    const rawItem = {
      id: event.id, family: event.family, task: event.taskType,
      query: event.queryText, truth: event.truthText,
      is_stale: event.isStaleTruth, epoch_committed: event.epochCommitted,
      source_ref: event.sourceRef,
    };
    const corpusRoot = computeProductionCorpusRoot([rawItem]);
    const corpus = {
      events: { near_collision: [], temporal: [], long_horizon: [event] },
      sources: {},
      corpusRoot,
    };

    const delta = buildCorpusDelta(corpus, [], ['to-remove-test'], 1);
    const updated = applyCorpusDelta(corpus, delta);

    assert.equal(updated.corpusRoot, delta.nextRoot);
    const allIds = [
      ...updated.events.near_collision,
      ...updated.events.temporal,
      ...updated.events.long_horizon,
    ].map((e) => e.id);
    assert.ok(!allIds.includes('to-remove-test'));
  });
});
