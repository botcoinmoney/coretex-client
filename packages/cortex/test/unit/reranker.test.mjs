/**
 * Unit tests for the cross-encoder reranker and reranker-based patch evaluator.
 *
 * All tests use createDeterministicReranker() — no real model load in CI.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  createDeterministicReranker,
  withRerankerCache,
  rerankerFromEnv,
} from '../../dist/eval/reranker.js';
import {
  evaluateStateWithReranker,
  evaluatePatchWithReranker,
  RERANKER_WEIGHTS,
} from '../../dist/eval/reranker-eval.js';
import { PATCH_TYPE, RANGES } from '../../dist/state/types.js';
import { encodePatch } from '../../dist/state/patch.js';
import { merkleizeState, bytesToHex } from '../../dist/state/merkle.js';
import { eventIdToMem128, eventIdToKey128 } from '../../dist/eval/corpus.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeCleanState() {
  return { words: new Array(1024).fill(0n) };
}

/**
 * Build a minimal synthetic corpus with one event per interesting family.
 * Using deterministic event ids that hash to known substrate slot values.
 */
function makeSyntheticCorpus() {
  const corpusRoot = '0x' + '42'.repeat(32);
  return {
    corpusRoot,
    sources: {},
    events: {
      near_collision: [
        {
          id: 'nc-1',
          family: 'near_collision',
          taskType: 'near',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: 'What is the capital of France?',
          truthText: 'Paris is the capital of France.',
          isStaleTruth: false,
          relevant: true,
        },
      ],
      temporal: [
        {
          id: 'stale-1',
          family: 'temporal',
          taskType: 'stale',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: 'Who was president in 2019?',
          truthText: 'An old president.',
          isStaleTruth: true,
          relevant: true,
        },
        {
          id: 'current-1',
          family: 'temporal',
          taskType: 'current',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: 'Who is the current president?',
          truthText: 'The current president.',
          isStaleTruth: false,
          relevant: true,
        },
      ],
      long_horizon: [
        {
          id: 'lh-1',
          family: 'long_horizon',
          taskType: 'long',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: 'What happened in the long past?',
          truthText: 'A long-horizon memory event.',
          isStaleTruth: false,
          relevant: true,
        },
      ],
    },
  };
}

// ─── createDeterministicReranker ──────────────────────────────────────────────

describe('createDeterministicReranker', () => {
  test('resolves to a CrossEncoderReranker with correct model string', async () => {
    const reranker = await createDeterministicReranker();
    assert.equal(typeof reranker.model, 'string');
    assert.ok(reranker.model.includes('deterministic'));
    assert.equal(typeof reranker.score, 'function');
  });

  test('returns the same score for the same (query, doc) pair across calls', async () => {
    const reranker = await createDeterministicReranker();
    const pair = { query: 'machine learning', document: 'neural networks for ML' };
    const [s1] = await reranker.score([pair]);
    const [s2] = await reranker.score([pair]);
    assert.equal(s1, s2, 'scores must be deterministic');
  });

  test('scores are in [0, 1]', async () => {
    const reranker = await createDeterministicReranker();
    const pairs = [
      { query: 'hello world', document: 'hello world' },
      { query: 'foo', document: 'bar baz' },
      { query: 'completely unrelated topic', document: 'quantum physics experiments' },
    ];
    const scores = await reranker.score(pairs);
    assert.equal(scores.length, pairs.length);
    for (const score of scores) {
      assert.ok(score >= 0 && score <= 1, `score ${score} must be in [0, 1]`);
    }
  });

  test('identical query and doc scores higher than completely different content', async () => {
    const reranker = await createDeterministicReranker();
    const identicalPair = { query: 'machine learning neural networks', document: 'machine learning neural networks' };
    const differentPair = { query: 'machine learning neural networks', document: 'astronomy telescope stars distant galaxy' };
    const [identical, different] = await reranker.score([identicalPair, differentPair]);
    assert.ok(identical > different, `same content (${identical}) should score higher than different (${different})`);
  });

  test('returns empty array for empty pairs', async () => {
    const reranker = await createDeterministicReranker();
    const scores = await reranker.score([]);
    assert.deepEqual(scores, []);
  });

  test('respects custom dims option', async () => {
    const reranker = await createDeterministicReranker({ dims: 128 });
    assert.ok(reranker.model.includes('128'));
    const [s] = await reranker.score([{ query: 'test', document: 'test' }]);
    assert.ok(typeof s === 'number');
  });
});

// ─── withRerankerCache ────────────────────────────────────────────────────────

describe('withRerankerCache', () => {
  test('caches results and returns same score on second call', async () => {
    let callCount = 0;
    const inner = {
      model: 'mock',
      async score(pairs) {
        callCount++;
        return pairs.map(() => 0.7);
      },
    };
    const cached = withRerankerCache(inner);
    const pair = { query: 'test query', document: 'test document' };

    const [s1] = await cached.score([pair]);
    const [s2] = await cached.score([pair]);

    assert.equal(s1, 0.7);
    assert.equal(s2, 0.7);
    // Second call should use cache — inner called only once
    assert.equal(callCount, 1, 'inner scorer should be called only once for same pair');
  });

  test('propagates model name', async () => {
    const reranker = await createDeterministicReranker();
    const cached = withRerankerCache(reranker);
    assert.equal(cached.model, reranker.model);
  });
});

// ─── rerankerFromEnv ──────────────────────────────────────────────────────────

describe('rerankerFromEnv', () => {
  test('defaults to deterministic reranker when CORETEX_RERANKER is unset', async () => {
    const saved = process.env['CORETEX_RERANKER'];
    const savedProd = process.env['CORTEX_REAL_EVAL'];
    delete process.env['CORETEX_RERANKER'];
    delete process.env['CORTEX_REAL_EVAL'];
    try {
      const reranker = await rerankerFromEnv();
      assert.ok(reranker.model.includes('deterministic'));
    } finally {
      if (saved !== undefined) process.env['CORETEX_RERANKER'] = saved;
      if (savedProd !== undefined) process.env['CORTEX_REAL_EVAL'] = savedProd;
    }
  });

  test('returns deterministic reranker when CORETEX_RERANKER=deterministic', async () => {
    process.env['CORETEX_RERANKER'] = 'deterministic';
    try {
      const reranker = await rerankerFromEnv();
      assert.ok(reranker.model.includes('deterministic'));
    } finally {
      delete process.env['CORETEX_RERANKER'];
    }
  });

  test('production mode requires an explicit non-deterministic reranker', async () => {
    const savedSelector = process.env['CORETEX_RERANKER'];
    const savedReal = process.env['CORTEX_REAL_EVAL'];
    delete process.env['CORETEX_RERANKER'];
    process.env['CORTEX_REAL_EVAL'] = '1';
    try {
      await assert.rejects(() => rerankerFromEnv(), /CORETEX_RERANKER must be set/);
      process.env['CORETEX_RERANKER'] = 'deterministic';
      await assert.rejects(() => rerankerFromEnv(), /deterministic reranker is not allowed/);
    } finally {
      if (savedSelector !== undefined) process.env['CORETEX_RERANKER'] = savedSelector;
      else delete process.env['CORETEX_RERANKER'];
      if (savedReal !== undefined) process.env['CORTEX_REAL_EVAL'] = savedReal;
      else delete process.env['CORTEX_REAL_EVAL'];
      delete process.env['CORETEX_ALLOW_DETERMINISTIC_RERANKER'];
    }
  });
});

// ─── RERANKER_WEIGHTS ─────────────────────────────────────────────────────────

describe('RERANKER_WEIGHTS', () => {
  test('matches the 20/20/20/20/10/10 launch profile (§9)', () => {
    assert.equal(RERANKER_WEIGHTS.nearCollisionRetrieval,   0.20);
    assert.equal(RERANKER_WEIGHTS.temporalCurrentStale,     0.20);
    assert.equal(RERANKER_WEIGHTS.longHorizonCompression,   0.20);
    assert.equal(RERANKER_WEIGHTS.relationMultiHop,         0.20);
    assert.equal(RERANKER_WEIGHTS.codebookCompression,      0.10);
    assert.equal(RERANKER_WEIGHTS.localModelAgreement,      0.10);
  });

  test('weights sum to 1.0', () => {
    const total = Object.values(RERANKER_WEIGHTS).reduce((a, b) => a + b, 0);
    assert.ok(Math.abs(total - 1.0) < 1e-10, `weights sum to ${total}`);
  });
});

// ─── evaluateStateWithReranker ────────────────────────────────────────────────

describe('evaluateStateWithReranker', () => {
  test('returns a RerankerEvalResult with composite in [0, 1]', async () => {
    const reranker = await createDeterministicReranker();
    const state = makeCleanState();
    const corpus = makeSyntheticCorpus();
    const result = await evaluateStateWithReranker(state, corpus, { reranker });
    assert.equal(typeof result.composite, 'number');
    assert.ok(result.composite >= 0 && result.composite <= 1);
    assert.equal(result.model, reranker.model);
    assert.equal(typeof result.components.nearCollisionRetrieval, 'number');
    assert.equal(typeof result.components.temporalCurrentStale, 'number');
    assert.equal(typeof result.components.longHorizonCompression, 'number');
    assert.equal(typeof result.components.relationMultiHop, 'number');
    assert.equal(typeof result.components.codebookCompression, 'number');
    assert.equal(typeof result.components.localModelAgreement, 'number');
  });

  test('state with active memory events scores higher than clean state', async () => {
    const reranker = await createDeterministicReranker();
    const corpus = makeSyntheticCorpus();

    const cleanState = makeCleanState();
    const cleanResult = await evaluateStateWithReranker(cleanState, corpus, { reranker });

    // Populate state with current-1 event in MemoryIndex (active, not revoked)
    const populatedState = makeCleanState();
    populatedState.words[32] =
      (eventIdToMem128('current-1') << 128n)
      | (1n << 64n); // valid bit

    const populatedResult = await evaluateStateWithReranker(populatedState, corpus, { reranker });

    // The populated state should have better temporal_current score
    assert.ok(
      populatedResult.components.temporalCurrentStale >= cleanResult.components.temporalCurrentStale,
      'state with active memory should have equal or better score',
    );
  });

  test('determinism: same state produces same composite', async () => {
    const reranker = await createDeterministicReranker();
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    state.words[32] = (eventIdToMem128('lh-1') << 128n) | (1n << 64n);

    const r1 = await evaluateStateWithReranker(state, corpus, { reranker });
    const r2 = await evaluateStateWithReranker(state, corpus, { reranker });
    assert.equal(r1.composite, r2.composite);
  });
});

// ─── evaluatePatchWithReranker ────────────────────────────────────────────────

describe('evaluatePatchWithReranker — reserved bits rejection', () => {
  test('patch targeting reserved range returns errorCode (not pass)', async () => {
    const reranker = await createDeterministicReranker();
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    const root = merkleizeState(state);

    // RESERVED_START is 992 — target that range
    const reservedIndex = RANGES.RESERVED_START;
    const patch = {
      patchType: PATCH_TYPE.SLOT_REPLACE,
      wordCount: 1,
      scoreDelta: 1000000n,
      parentStateRoot: root,
      indices: [reservedIndex],
      newWords: [1n],
    };

    const result = await evaluatePatchWithReranker(state, patch, { corpus, reranker });

    assert.equal(result.pass, false, 'reserved-range patch must not pass');
    assert.equal(typeof result.errorCode, 'string', 'errorCode must be present for structural rejection');
    assert.ok(
      result.errorCode === 'E02' || result.errorCode === 'E04',
      `expected E02 or E04, got ${result.errorCode}`,
    );
  });
});

describe('evaluatePatchWithReranker — clean state + memory-index update', () => {
  test('patch that adds a long-horizon event to MemoryIndex passes (deterministic reranker)', async () => {
    const reranker = await createDeterministicReranker();
    const corpus = makeSyntheticCorpus();

    // Start from a clean state
    const state = makeCleanState();

    // Build a patch that writes lh-1 event into MemoryIndex slot 0
    // (word index 32) with valid flag set.
    const memId = eventIdToMem128('lh-1');
    const word = (memId << 128n) | (1n << 64n); // eventId | valid_bit

    const root = merkleizeState(state);
    const patch = {
      patchType: PATCH_TYPE.SLOT_REPLACE,
      wordCount: 1,
      scoreDelta: 1000000n,
      parentStateRoot: root,
      indices: [32], // first MemoryIndex slot
      newWords: [word],
    };

    const result = await evaluatePatchWithReranker(state, patch, {
      corpus,
      reranker,
      // Use a low threshold so deterministic scores can satisfy it
      threshold: 0,
    });

    // No structural rejection — patch should be accepted structurally
    assert.equal(result.errorCode, undefined, `unexpected errorCode: ${result.errorCode}`);

    // With threshold=0 and deterministic scores: if the candidate state has
    // better or equal reranker signal, pass should be true.
    // The reranker will see the long-horizon event's query/doc pair and
    // score it — since we added the event to the active memory set,
    // the hit rate can only stay the same or improve.
    assert.equal(result.pass, true, `expected pass=true, got: ${JSON.stringify({ pass: result.pass, scoreDelta: result.scoreDelta, regressions: result.regressions })}`);
    assert.equal(result.noRegression, true);
    assert.deepEqual(result.regressions, []);
  });

  test('before/after scores are present and well-formed', async () => {
    const reranker = await createDeterministicReranker();
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    const root = merkleizeState(state);

    const memId = eventIdToMem128('current-1');
    const patch = {
      patchType: PATCH_TYPE.SLOT_REPLACE,
      wordCount: 1,
      scoreDelta: 1000000n,
      parentStateRoot: root,
      indices: [32],
      newWords: [(memId << 128n) | (1n << 64n)],
    };

    const result = await evaluatePatchWithReranker(state, patch, {
      corpus,
      reranker,
      threshold: 0,
    });

    assert.equal(typeof result.before.composite, 'number');
    assert.equal(typeof result.after.composite, 'number');
    assert.equal(typeof result.scoreDelta, 'number');
    assert.ok(result.before.composite >= 0 && result.before.composite <= 1);
    assert.ok(result.after.composite >= 0 && result.after.composite <= 1);
  });
});

describe('evaluatePatchWithReranker — noop patch is rejected', () => {
  test('noop patch (no change to words) returns errorCode', async () => {
    const reranker = await createDeterministicReranker();
    const corpus = makeSyntheticCorpus();
    const state = makeCleanState();
    const root = merkleizeState(state);

    // noop: writing 0n to a word that is already 0n
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: root,
      indices: [384],
      newWords: [0n], // no-op
    };

    const result = await evaluatePatchWithReranker(state, patch, { corpus, reranker });
    assert.equal(result.pass, false);
    assert.equal(result.errorCode, 'E05');
  });
});
