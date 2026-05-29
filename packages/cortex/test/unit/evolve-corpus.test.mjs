/**
 * Fix B — evolveCorpusDelta: deterministic live-update churn fuel.
 * CPU gates (the production embedding + corpusRoot-replay gate is the A100/pipeline step):
 *   - replay determinism: same (base, epoch, seed) → byte-identical delta;
 *   - live_churn_rate > 0 and tracks churnFraction;
 *   - distinct epochs produce distinct (new) structure;
 *   - delta queries are subject-grounded (subjectEntityId) and supersede/contradict held facts.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { evolveCorpusDelta } from '../../../../scripts/lib/evolve-corpus.mjs';

// minimal base logical corpus: 1 universe + 40 subjects, each with one prior temporal doc.
const baseLogical = {
  entities: [
    { id: 'e_universe', canonicalName: 'Deep Memory Universe 0', aliases: [] },
    ...Array.from({ length: 40 }, (_, i) => ({ id: `e_universe_s${i}`, canonicalName: i % 3 === 0 ? `svc-${i}-pipeline-svc-${i}` : `First${i} Last${i}`, aliases: [] })),
  ],
  docs: Array.from({ length: 40 }, (_, i) => ({ id: `d${i}`, kind: 'temporal_city', entityIds: ['e_universe', `e_universe_s${i}`], currentStaleFlag: false, text: 'prior' })),
  relations: [],
  queries: [],
};

describe('Fix B — evolveCorpusDelta (deterministic live-update churn)', () => {
  test('replay determinism: same inputs → byte-identical delta', () => {
    const a = evolveCorpusDelta({ baseLogical, epoch: 3, seed: 'launch-frontier', churnFraction: 0.25 });
    const b = evolveCorpusDelta({ baseLogical, epoch: 3, seed: 'launch-frontier', churnFraction: 0.25 });
    assert.equal(JSON.stringify(a), JSON.stringify(b));
  });

  test('live_churn_rate > 0 and approximates churnFraction', () => {
    const d = evolveCorpusDelta({ baseLogical, epoch: 1, seed: 's', churnFraction: 0.25 });
    assert.ok(d.liveChurnRate > 0, 'live churn must be > 0 (the static-corpus failure was ~0)');
    assert.ok(d.churnedSubjects.length >= 4 && d.churnedSubjects.length <= 18, `~25% of 40 expected, got ${d.churnedSubjects.length}`);
    assert.ok(d.addedDocs.length > 0 && d.addedQueries.length > 0);
  });

  test('distinct epochs produce distinct new structure (fresh minable work each epoch)', () => {
    const e1 = evolveCorpusDelta({ baseLogical, epoch: 1, seed: 's', churnFraction: 0.5 });
    const e2 = evolveCorpusDelta({ baseLogical, epoch: 2, seed: 's', churnFraction: 0.5 });
    const ids1 = new Set(e1.addedDocs.map((d) => d.id));
    const overlap = e2.addedDocs.filter((d) => ids1.has(d.id));
    assert.equal(overlap.length, 0, 'epoch deltas must not collide on doc ids');
    assert.notEqual(JSON.stringify(e1.churnedSubjects), JSON.stringify(e2.churnedSubjects));
  });

  test('delta is subject-grounded and revises held facts (supersedes / contradicts)', () => {
    const d = evolveCorpusDelta({ baseLogical, epoch: 5, seed: 's', churnFraction: 1.0 });
    assert.ok(d.addedQueries.every((q) => typeof q.subjectEntityId === 'string' && q.subjectEntityId !== 'e_universe'), 'every delta query is subject-grounded');
    const edgeLabels = new Set(d.addedRelations.map((r) => r.label));
    assert.ok(edgeLabels.has('supersedes') || edgeLabels.has('contradicts'), 'delta must revise held facts via supersedes/contradicts edges');
    // supersedes edges point at a prior (held) doc id from the base corpus
    const baseDocIds = new Set(baseLogical.docs.map((x) => x.id));
    assert.ok(d.addedRelations.filter((r) => r.label === 'supersedes').every((r) => baseDocIds.has(r.dst)), 'supersedes targets a held base fact');
  });
});
