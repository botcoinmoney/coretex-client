import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  bridgeDacrBatch,
  bridgeDacrSession,
  bridgeDacrBookendPair,
  admitCorpusBatch,
  DEFAULT_ADMISSION_POLICY,
} from '../../dist/index.js';

function baseAttempt(overrides = {}) {
  return {
    split: 'train',
    challenge_id: '0x' + '12'.repeat(32),
    challenge_seed: 'seed-1',
    challenge_domain: 'computational_biology',
    questions: ['What marker is retained?'],
    question_metadata: [{ id: 'q01', coretex_family: 'near_collision' }],
    submitted_answers: { q01: { value: 'OCT4-high', expected: 'OCT4-high', correct: true } },
    answer_verification: {
      correct: 1,
      total: 1,
      per_question: { q01: { submitted: 'OCT4-high', expected: 'OCT4-high', correct: true } },
    },
    pass: true,
    reasoning_depth: { reasoning_depth_score: 0.8 },
    trap_metadata: { traps: [] },
    ...overrides,
  };
}

describe('DACR corpus bridge hardening', () => {
  test('bridgeDacrBatch mines cross-miner wrong answers for sparse trap metadata', () => {
    const good = baseAttempt();
    const wrongA = baseAttempt({
      record_id: 'wrong-a',
      pass: false,
      submitted_answers: { q01: { value: 'NANOG-high', expected: 'OCT4-high', correct: false } },
      answer_verification: { correct: 0, total: 1, per_question: { q01: { submitted: 'NANOG-high', expected: 'OCT4-high', correct: false } } },
    });
    const wrongB = baseAttempt({
      record_id: 'wrong-b',
      pass: false,
      submitted_answers: { q01: { value: 'SOX2-high', expected: 'OCT4-high', correct: false } },
      answer_verification: { correct: 0, total: 1, per_question: { q01: { submitted: 'SOX2-high', expected: 'OCT4-high', correct: false } } },
    });

    const events = bridgeDacrBatch([good, wrongA, wrongB], [], { epochCommitted: 3, maxDistractors: 4 });
    assert.equal(events.length, 1);
    assert.equal(events[0].family, 'near_collision');
    assert.deepEqual(events[0].distractors.sort(), ['NANOG-high', 'SOX2-high']);

    const decision = admitCorpusBatch(events, {
      ...DEFAULT_ADMISSION_POLICY,
      minDistractorsPerRecord: 2,
    });
    assert.equal(decision.rejected.length, 0);
    assert.equal(decision.admitted.length, 1);
  });

  test('bridgeDacrSession emits long-horizon session events with multi-step relations', () => {
    const session = {
      challenge_id: '0x' + '34'.repeat(32),
      challenge_seed: 'seed-session',
      challenge_domain: 'scrna_imputation',
      questions: ['Which imputation method wins after the final correction?'],
      question_metadata: [{ id: 'q01' }],
      session: { nonce: 'n-1', attempts_total: 3, final_status: 'pass', pass_record_id: 'pass-1' },
      trap_metadata: { traps: [{ decoy: 'MAGIC' }] },
      attempts: [
        baseAttempt({
          challenge_id: '0x' + '34'.repeat(32),
          record_id: 'fail-1',
          pass: false,
          submitted_answers: { q01: { value: 'ALRA', expected: 'SAVER', correct: false } },
          answer_verification: { correct: 0, total: 1, per_question: { q01: { submitted: 'ALRA', expected: 'SAVER', correct: false } } },
        }),
        baseAttempt({
          challenge_id: '0x' + '34'.repeat(32),
          record_id: 'pass-1',
          pass: true,
          submitted_answers: { q01: { value: 'SAVER', expected: 'SAVER', correct: true } },
          answer_verification: { correct: 1, total: 1, per_question: { q01: { submitted: 'SAVER', expected: 'SAVER', correct: true } } },
        }),
      ],
      final_submitted_answers: { q01: { value: 'SAVER', expected: 'SAVER', correct: true } },
    };

    const events = bridgeDacrSession(session, { epochCommitted: 4, maxDistractors: 4 });
    assert.equal(events.length, 1);
    assert.equal(events[0].family, 'long_horizon');
    assert.ok(events[0].relations.includes('attempts:3'));
    assert.ok(events[0].expectedStateRegions.includes('relations'));
    assert.deepEqual(events[0].distractors.sort(), ['ALRA', 'MAGIC']);
  });

  test('bridgeDacrBookendPair emits current/stale temporal pairs that survive admission', () => {
    const bookend = {
      challenge_id: '0x' + '56'.repeat(32),
      challenge_seed: 'seed-bookend',
      challenge_domain: 'quantum_physics',
      pair_quality: { dataset_export_eligible: true, rejection_reasons: [] },
      questions: ['Which code is current after revision?'],
      question_metadata: [{ id: 'q01' }],
      trap_metadata: { traps: [{ decoy: 'Surface-7' }] },
      chosen: {
        submitted_answers: { q01: { value: 'Surface-9', expected: 'Surface-9', correct: true } },
        answer_verification: { correct: 1, total: 1, per_question: { q01: { submitted: 'Surface-9', expected: 'Surface-9', correct: true } } },
        pass: true,
      },
      rejected: {
        submitted_answers: { q01: { value: 'Surface-5', expected: 'Surface-9', correct: false } },
        answer_verification: { correct: 0, total: 1, per_question: { q01: { submitted: 'Surface-5', expected: 'Surface-9', correct: false } } },
        pass: false,
      },
    };

    const events = bridgeDacrBookendPair(bookend, { epochCommitted: 5, maxDistractors: 4 });
    assert.equal(events.length, 2);
    assert.ok(events.every((event) => event.family === 'temporal'));
    assert.ok(events.every((event) => event.distractors.length >= 2));
    const decision = admitCorpusBatch(events, {
      ...DEFAULT_ADMISSION_POLICY,
      minDistractorsPerRecord: 2,
    });
    assert.equal(decision.rejected.length, 0);
  });
});
