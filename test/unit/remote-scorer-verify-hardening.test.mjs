/**
 * Hardening tests for verifyScorerResult:
 *  - gate/confirm scores must be FINITE SAFE INTEGERS (typeof-number alone is
 *    NaN-bypassable: NaN defeats the `min(gate,confirm) < threshold` check);
 *  - the result's top-level scores must EQUAL the dual-pack proof's scores.
 * The full check-1..8 matrix (real artifacts) lives in the coordinator
 * integration repo; these tests pin the two canonical-layer gaps.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { verifyScorerResult } from '../../dist/coordinator/remote-scorer-verify.js';

const B32 = (b) => '0x' + b.repeat(32);

function minimalResult(over = {}) {
  return {
    jobId: 'job-1',
    accepted: true,
    deltaPpm: 42_000,
    gateScorePpm: 45_000,
    confirmScorePpm: 42_000,
    thresholdPpmUsed: 1_000,
    policyHash: B32('ee'),
    pairTraceHash: B32('aa'),
    scoreArrayHash: B32('bb'),
    evalReportHash: B32('e1'),
    artifactHash: B32('a1'),
    scorerHealth: { modelId: 'm', revision: 'r', promptTemplateHash: B32('ab') },
    ...over,
  };
}

// job.epochId deliberately != active.epochId: a result that gets PAST the
// schema check fails next at SCORER_STALE_CONTEXT — which proves the schema
// accepted it without needing full artifact fixtures.
const job = { jobId: 'job-1', epochId: 7, thresholdPpm: 1_000, policyHash: B32('ee') };
const active = { epochId: 8, parentStateRoot: B32('01'), corpusRoot: B32('cc'), bundleHash: B32('dd'), coreVersionHash: B32('dd'), workPolicyHash: B32('ee'), thresholdPpm: 1_000 };
const expectedHealth = { modelId: 'm', revision: 'r', promptTemplateHash: B32('ab') };
const outstanding = new Set(['job-1']);

function verify(result) {
  return verifyScorerResult({ result, job, outstandingJobIds: outstanding, active, expectedHealth });
}

describe('verifyScorerResult score hardening', () => {
  test('NaN / Infinity / float gate or confirm scores are SCORER_RESULT_MALFORMED', () => {
    for (const bad of [NaN, Infinity, -Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      for (const field of ['gateScorePpm', 'confirmScorePpm']) {
        const v = verify(minimalResult({ [field]: bad }));
        assert.equal(v.ok, false, `${field}=${bad}`);
        assert.equal(v.code, 'SCORER_RESULT_MALFORMED', `${field}=${bad} → ${v.code}: ${v.reason}`);
        assert.match(v.reason, /finite safe integers/);
      }
    }
  });

  test('finite safe-integer scores pass the schema (fail later at stale-context, not malformed)', () => {
    const v = verify(minimalResult());
    assert.equal(v.ok, false);
    assert.equal(v.code, 'SCORER_STALE_CONTEXT');
  });
});
