/**
 * Keyless GPU scorer-server unit tests (BUILD A).
 *
 * Exercises the pure job handler `handleScoreJob` + pin check `checkScorerJobPins`
 * with a FAKE evaluator and a FAKE traced reranker — no real Qwen3 load, no CUDA,
 * no signing material in scope (keyless). Covers:
 *   - pin-mismatch jobs are REFUSED (4xx) without running the evaluator;
 *   - a happy job returns the full result shape incl. pairTraceHash /
 *     scoreArrayHash / scorerHealth / scores;
 *   - reject results return accepted=false with the reason and zeroed scores;
 *   - the pair-trace TS port produces hashes byte-identical to the CPU parity
 *     harness (scripts/lib/instrumented-reranker.mjs).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  handleScoreJob,
  checkScorerJobPins,
  verifyJobParentState,
} from '../../dist/scorer-server-cli.js';
import { wrapRerankerWithPairTrace } from '../../dist/coordinator/scorer-pair-trace.js';
import { pack, merkleizeState, bytesToHex, RANGES, PACKED_SIZE } from '../../dist/index.js';
import { DEFAULT_SCORER_BODY_LIMIT_BYTES } from '../../dist/scorer-server-cli.js';
import { makeInstrumentedReranker } from '../../../../scripts/lib/instrumented-reranker.mjs';

const B32 = (seed) => `0x${seed.repeat(Math.ceil(64 / seed.length)).slice(0, 64)}`;
const MODEL_ID = 'Qwen/Qwen3-Reranker-0.6B';
const REVISION = 'e61197ed45024b0ed8a2d74b80b4d909f1255473';

// A REAL parent substrate the scorer can verify: a full-size (1024-word) state,
// its canonical packing (PACKED_SIZE = 32768 bytes), and the merkle root it
// hashes to. The scorer refuses any job whose packed state does not merkle to
// the job's parentStateRoot.
function makeParentState() {
  const words = new Array(RANGES.WORD_COUNT).fill(0n);
  words[0] = 0x1234n;
  words[7] = (1n << 200n) | 99n;
  words[RANGES.WORD_COUNT - 1] = 0x5678n;
  return { words };
}
const PARENT_STATE = makeParentState();
const PARENT_PACKED_HEX = bytesToHex(pack(PARENT_STATE));
const PARENT_ROOT = bytesToHex(merkleizeState(PARENT_STATE)).toLowerCase();

const LOADED_PINS = {
  modelId: MODEL_ID,
  revision: REVISION,
  promptTemplateHash: B32('ab'),
  bundleHash: B32('dd'),
  corpusRoot: B32('cc'),
  coreVersionHash: B32('dd'),
};

const HEALTH = {
  commit: 'deadbee',
  modelId: MODEL_ID,
  revision: REVISION,
  promptTemplateHash: B32('ab'),
  dtype: 'fp32',
  tf32: false,
  cuda: true,
  device: 'NVIDIA GeForce RTX 4090',
  torch: '2.3.0',
  transformers: '4.44.0',
  python: '3.11.9',
};

function baseJob(over = {}) {
  return {
    jobId: 'job-1',
    epochId: 7,
    parentStateRoot: PARENT_ROOT,
    packedParentStateHex: PARENT_PACKED_HEX,
    patchHash: B32('22'),
    corpusRoot: LOADED_PINS.corpusRoot,
    bundleHash: LOADED_PINS.bundleHash,
    coreVersionHash: LOADED_PINS.coreVersionHash,
    compactPatchBytesHex: '0x1234',
    miner: `0x${'10'.repeat(20)}`,
    expectedScorerPins: {
      modelId: MODEL_ID,
      revision: REVISION,
      promptTemplateHash: LOADED_PINS.promptTemplateHash,
      bundleHash: LOADED_PINS.bundleHash,
      corpusRoot: LOADED_PINS.corpusRoot,
    },
    ...over,
  };
}

/** Fake traced reranker — fixed snapshot, no model. */
function fakeTracedReranker({ pairTraceHash = B32('aa'), scoreArrayHash = B32('bb'), count = 12 } = {}) {
  let reset = 0;
  return {
    resetTrace() { reset += 1; },
    traceSnapshot() { return { totalScoredPairCount: count, pairTraceHash, scoreArrayHash }; },
    resets: () => reset,
  };
}

function fakeEvaluator(result, counter = { calls: 0 }) {
  return {
    async scorePatch(input) {
      counter.calls += 1;
      counter.lastInput = input;
      return result;
    },
  };
}

function stateAdvanceResult() {
  return {
    outcome: 'state_advance',
    deterministicDeltaPpm: 42_000,
    evalReportHash: B32('e1'),
    artifactHash: B32('e1'),
    scoreBeforePpm: 400_000,
    scoreAfterPpm: 442_000,
    rewrittenPatchBytesHex: '0x1234',
    evaluationProof: {
      kind: 'coretex-dual-pack-v1',
      mode: 'future_blockhash_dual_pack',
      gate: { domain: 'gate', seedCommit: B32('a1'), accepted: true, scorePpm: 45_000 },
      confirm: { domain: 'confirm', seedCommit: B32('a2'), accepted: true, scorePpm: 42_000 },
    },
  };
}

describe('scorer-server — pin enforcement', () => {
  test('matching pins pass', () => {
    assert.equal(checkScorerJobPins(baseJob(), LOADED_PINS), null);
  });

  for (const [field, val] of [
    ['modelId', 'Qwen/Other'],
    ['revision', 'cafef00d'],
    ['promptTemplateHash', B32('99')],
    ['bundleHash', B32('99')],
    ['corpusRoot', B32('99')],
  ]) {
    test(`expectedScorerPins.${field} mismatch is refused`, () => {
      const job = baseJob({ expectedScorerPins: { ...baseJob().expectedScorerPins, [field]: val } });
      const reason = checkScorerJobPins(job, LOADED_PINS);
      assert.ok(reason, `expected refusal for ${field}`);
      assert.match(reason, new RegExp(field));
    });
  }

  test('job-level corpusRoot / bundleHash / coreVersionHash mismatch is refused', () => {
    assert.match(checkScorerJobPins(baseJob({ corpusRoot: B32('99') }), LOADED_PINS), /corpusRoot/);
    assert.match(checkScorerJobPins(baseJob({ bundleHash: B32('99') }), LOADED_PINS), /bundleHash/);
    assert.match(checkScorerJobPins(baseJob({ coreVersionHash: B32('99') }), LOADED_PINS), /coreVersionHash/);
  });
});

describe('scorer-server — parent-state verification', () => {
  test('verifyJobParentState accepts a packed state that merkles to parentStateRoot', () => {
    const v = verifyJobParentState({ parentStateRoot: PARENT_ROOT, packedParentStateHex: PARENT_PACKED_HEX });
    assert.equal(v.ok, true);
    assert.deepEqual(v.state.words, PARENT_STATE.words);
  });

  test('verifyJobParentState refuses a packed state that hashes to a DIFFERENT root', () => {
    const other = { words: PARENT_STATE.words.slice() };
    other.words[3] = 0xdeadn; // perturb -> different merkle root
    const v = verifyJobParentState({ parentStateRoot: PARENT_ROOT, packedParentStateHex: bytesToHex(pack(other)) });
    assert.equal(v.ok, false);
    assert.match(v.reason, /merkles to .* != job\.parentStateRoot/);
  });

  test('happy job passes the VERIFIED parent state through to the evaluator', async () => {
    const counter = { calls: 0 };
    const res = await handleScoreJob(baseJob(), {
      evaluator: fakeEvaluator(stateAdvanceResult(), counter),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 200);
    assert.equal(counter.calls, 1);
    // The evaluator must receive the unpacked, verified parent state (NOT just
    // the root hash) so it scores against the attested substrate.
    assert.ok(counter.lastInput.parentState, 'parentState must be supplied to the evaluator');
    assert.deepEqual(counter.lastInput.parentState.words, PARENT_STATE.words);
    assert.equal(counter.lastInput.parentStateRoot, PARENT_ROOT);
  });

  test('mismatched packedParentStateHex is REFUSED (422) and the evaluator NEVER runs', async () => {
    const other = { words: PARENT_STATE.words.slice() };
    other.words[10] = 0xbeefn;
    const counter = { calls: 0 };
    const res = await handleScoreJob(
      baseJob({ packedParentStateHex: bytesToHex(pack(other)) }),
      {
        evaluator: fakeEvaluator(stateAdvanceResult(), counter),
        tracedReranker: fakeTracedReranker(),
        loadedPins: LOADED_PINS,
        scorerHealth: HEALTH,
      },
    );
    assert.equal(res.status, 422);
    assert.equal(res.body.error, 'SCORER_PARENT_STATE_MISMATCH');
    assert.equal(counter.calls, 0, 'evaluator must not run when the parent state does not match the pin');
  });

  test('wrong-length packedParentStateHex is rejected (400) before any eval', async () => {
    const counter = { calls: 0 };
    const res = await handleScoreJob(baseJob({ packedParentStateHex: '0x1234' }), {
      evaluator: fakeEvaluator(stateAdvanceResult(), counter),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 400);
    assert.equal(counter.calls, 0);
  });

  test('a job at the realistic substrate size scores (full PACKED_SIZE body accepted by the handler)', async () => {
    // The packed parent is the largest field on the wire (PACKED_SIZE bytes).
    assert.equal((PARENT_PACKED_HEX.length - 2) / 2, PACKED_SIZE);
    const counter = { calls: 0 };
    const res = await handleScoreJob(baseJob(), {
      evaluator: fakeEvaluator(stateAdvanceResult(), counter),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 200);
    assert.equal(counter.calls, 1);
  });

  test('the HTTP body limit comfortably fits a realistic job (packed substrate + patch + context)', () => {
    // A serialized job at realistic size must fit under the raised default
    // body limit (the old 64 KB default was smaller than the packed substrate
    // alone, which is the bug this guards against).
    const realisticJobBytes = JSON.stringify(baseJob()).length;
    assert.ok(realisticJobBytes > PACKED_SIZE, 'sanity: the packed substrate dominates the body');
    assert.ok(
      DEFAULT_SCORER_BODY_LIMIT_BYTES > realisticJobBytes * 2,
      `default body limit ${DEFAULT_SCORER_BODY_LIMIT_BYTES} must comfortably exceed a realistic job body ${realisticJobBytes}`,
    );
  });
});

describe('scorer-server — handleScoreJob', () => {
  test('pin mismatch returns 409 and NEVER runs the evaluator', async () => {
    const counter = { calls: 0 };
    const res = await handleScoreJob(baseJob({ bundleHash: B32('99') }), {
      evaluator: fakeEvaluator(stateAdvanceResult(), counter),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 409);
    assert.equal(res.body.error, 'pin-mismatch');
    assert.equal(counter.calls, 0, 'evaluator must not run on a pin mismatch');
  });

  test('malformed job returns 400 without eval', async () => {
    const counter = { calls: 0 };
    const res = await handleScoreJob({ jobId: '', epochId: 'x' }, {
      evaluator: fakeEvaluator(stateAdvanceResult(), counter),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 400);
    assert.equal(counter.calls, 0);
  });

  test('happy state_advance returns the full result shape', async () => {
    const traced = fakeTracedReranker({ pairTraceHash: B32('aa'), scoreArrayHash: B32('bb'), count: 9 });
    const counter = { calls: 0 };
    const res = await handleScoreJob(baseJob(), {
      evaluator: fakeEvaluator(stateAdvanceResult(), counter),
      tracedReranker: traced,
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
      telemetry: () => ({ rerankerCache: { hits: 1, misses: 2 } }),
      now: (() => { let t = 1000; return () => (t += 5); })(),
    });
    assert.equal(res.status, 200);
    assert.equal(counter.calls, 1);
    assert.equal(traced.resets(), 1, 'trace reset once per job');
    const b = res.body;
    assert.equal(b.jobId, 'job-1');
    assert.equal(b.accepted, true);
    assert.equal(b.scoreBeforePpm, 400_000);
    assert.equal(b.scoreAfterPpm, 442_000);
    assert.equal(b.deltaPpm, 42_000);
    assert.equal(b.gateScorePpm, 45_000);
    assert.equal(b.confirmScorePpm, 42_000);
    assert.equal(b.evalReportHash, B32('e1'));
    assert.equal(b.artifactHash, B32('e1'));
    assert.equal(b.pairTraceHash, B32('aa'));
    assert.equal(b.scoreArrayHash, B32('bb'));
    assert.equal(b.totalScoredPairCount, 9);
    assert.ok(b.wallMs >= 0);
    assert.deepEqual(b.telemetry, { rerankerCache: { hits: 1, misses: 2 } });
    // scorerHealth carries the runtime fingerprint, NO signing material.
    assert.deepEqual(b.scorerHealth, HEALTH);
    assert.equal('signature' in b, false);
    assert.equal('signingKey' in b, false);
  });

  test('reject result returns accepted=false with reason and zeroed scores', async () => {
    const res = await handleScoreJob(baseJob(), {
      evaluator: fakeEvaluator({ outcome: 'reject', code: 'no_retrieval_improvement', reason: 'dual-pack rejected' }),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.accepted, false);
    assert.equal(res.body.rejectionReason, 'no_retrieval_improvement');
    assert.equal(res.body.scoreBeforePpm, null);
    assert.equal(res.body.scoreAfterPpm, null);
    assert.equal(res.body.gateScorePpm, 0);
    assert.equal(res.body.confirmScorePpm, 0);
    // The trace is still emitted (proves the input set scored), keyless.
    assert.equal(typeof res.body.pairTraceHash, 'string');
  });

  test('screener_pass returns accepted=true with null before/after scores', async () => {
    const res = await handleScoreJob(baseJob(), {
      evaluator: fakeEvaluator({
        outcome: 'screener_pass',
        deterministicDeltaPpm: 1_500,
        evalReportHash: B32('f0'),
        artifactHash: B32('f0'),
        evaluationProof: {
          gate: { scorePpm: 1_600 }, confirm: { scorePpm: 1_500 },
        },
      }),
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.body.accepted, true);
    assert.equal(res.body.scoreBeforePpm, null);
    assert.equal(res.body.deltaPpm, 1_500);
    assert.equal(res.body.gateScorePpm, 1_600);
    assert.equal(res.body.confirmScorePpm, 1_500);
  });

  test('evaluator throw returns 500 eval-failure (no score leak)', async () => {
    const res = await handleScoreJob(baseJob(), {
      evaluator: { async scorePatch() { throw new Error('cuda oom'); } },
      tracedReranker: fakeTracedReranker(),
      loadedPins: LOADED_PINS,
      scorerHealth: HEALTH,
    });
    assert.equal(res.status, 500);
    assert.equal(res.body.error, 'eval-failure');
  });
});

describe('scorer-server — pair-trace parity with the CPU harness', () => {
  test('wrapRerankerWithPairTrace produces hashes byte-identical to instrumented-reranker.mjs', async () => {
    // A deterministic fake backend so both wrappers score the same pairs.
    const backend = {
      model: `${MODEL_ID}@${REVISION}`,
      async score(pairs) { return pairs.map((p, i) => (p.query.length + p.document.length + i) / 100); },
    };
    const pairsBatch1 = [
      { query: 'alpha', document: 'doc one' },
      { query: 'beta', document: 'doc two' },
    ];
    const pairsBatch2 = [{ query: 'gamma', document: 'doc three' }];

    const traced = wrapRerankerWithPairTrace({
      model: backend.model,
      score: (p) => backend.score(p),
    });
    const instrumented = makeInstrumentedReranker({ reranker: backend, modelId: MODEL_ID, revision: REVISION });

    await traced.score(pairsBatch1);
    await instrumented.score(pairsBatch1);
    await traced.score(pairsBatch2);
    await instrumented.score(pairsBatch2);

    const a = traced.traceSnapshot();
    const b = instrumented.traceSnapshot();
    assert.equal(a.pairTraceHash, b.pairTraceHash, 'pairTraceHash must match the CPU parity harness');
    assert.equal(a.scoreArrayHash, b.scoreArrayHash, 'scoreArrayHash must match the CPU parity harness');
    assert.equal(a.totalScoredPairCount, b.totalScoredPairCount);

    // resetTrace yields a clean slate (empty-chain digest) on both.
    traced.resetTrace();
    instrumented.resetTrace();
    assert.equal(traced.traceSnapshot().pairTraceHash, instrumented.traceSnapshot().pairTraceHash);
  });
});
