/**
 * CPU-trivial multi-epoch evolve mechanics probe (smallest scale, mock-free generator level).
 *
 * Threads the logical state across 4 epochs exactly like scripts/coretex-epoch-evolve.mjs
 * (retracted docs + retired hidden rows removed, additions appended) and verifies PER EPOCH:
 *   conflicts, stale facts, superseding facts, entity collisions, retractions,
 *   hidden-pool turnover (fresh mints + aged retirements), live surface expansion.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { evolveCorpusDelta } from '../../scripts/lib/evolve-corpus.mjs';
import { liveTailQueryId, splitForRecord } from '../../dist/index.js';

const CORPUS_EPOCH = 0;
const splitOf = (id, liveUpdateEpoch) => splitForRecord(
  liveUpdateEpoch !== undefined && liveUpdateEpoch !== null ? liveTailQueryId(id, liveUpdateEpoch) : id,
  CORPUS_EPOCH,
);

function genesisLogical() {
  const subjects = Array.from({ length: 40 }, (_, i) => ({
    id: `e_universe_s${i}`,
    canonicalName: i % 3 === 0 ? `svc-${i}-pipeline-svc-${i}` : `First${i} Last${i}`,
    aliases: [i % 3 === 0 ? `svc${i}` : `First${i}`],
  }));
  const genesisHiddenIds = [];
  for (let i = 0; genesisHiddenIds.length < 5 && i < 20_000; i++) {
    const id = `q_genesis_${i}`;
    if (splitOf(id) === 'eval_hidden') genesisHiddenIds.push(id);
  }
  return {
    dgen1: { atomV16Metadata: true },
    entities: [
      { id: 'e_universe', canonicalName: 'Deep Memory Universe 0', aliases: [] },
      ...subjects,
      // duplicate-name pair → entity-collision supply for entity_resolution_atom
      { id: 'e_dup_backend', canonicalName: 'Jordan Vale', aliases: ['Jordan Vale the API migration lead'], roleAliases: ['API migration lead', 'backend lead'] },
      { id: 'e_dup_design', canonicalName: 'Jordan Vale', aliases: ['Jordan Vale the design lead'], roleAliases: ['design lead'] },
    ],
    docs: subjects.map((s, i) => ({
      id: `d${i}`, kind: 'temporal_city', entityIds: ['e_universe', s.id], currentStaleFlag: false, text: `prior fact ${i}`,
    })),
    relations: [],
    queries: genesisHiddenIds.map((id) => ({ id, family: 'temporal_update' })),
  };
}

describe('evolve mechanics probe — per-epoch live structure at trivial scale', () => {
  test('4 chained epochs supply every mechanic each epoch', () => {
    let logical = genesisLogical();
    const HORIZON = 2;
    const QUOTA = 3;
    let priorQueryCount = logical.queries.length;

    for (let epoch = 1; epoch <= 4; epoch++) {
      const heldDocIds = new Set(logical.docs.map((d) => d.id));
      const activeExclusion = new Set(logical.queries.slice(0, 2).map((q) => q.id)); // simulated frontier-active rows
      const d = evolveCorpusDelta({
        baseLogical: logical, epoch, seed: 'mechanics-probe', churnFraction: 1.0,
        retractionFraction: 0.15,
        evalHiddenPolicy: {
          splitOf, minFreshPerEpoch: QUOTA, retireAfterEpochs: HORIZON, maxRetiredPerEpoch: 24,
          excludeRetireIds: activeExclusion,
        },
      });

      // 1. conflicts: contradicts edges + conflict_lifecycle queries
      assert.ok(d.addedRelations.some((r) => r.label === 'contradicts'), `epoch ${epoch}: contradicts edges`);
      assert.ok(d.addedQueries.some((q) => q.family === 'conflict_lifecycle'), `epoch ${epoch}: conflict queries`);

      // 2. stale facts: records flagged non-current (stale shadows / closed-validity facts)
      assert.ok(d.addedDocs.some((doc) => doc.currentStaleFlag === false), `epoch ${epoch}: stale facts`);

      // 3. superseding facts: supersedes edges, at least one pointing at a HELD (pre-epoch) doc
      const supersedes = d.addedRelations.filter((r) => r.type === 'supersedes');
      assert.ok(supersedes.length > 0, `epoch ${epoch}: supersedes edges`);
      assert.ok(supersedes.some((r) => heldDocIds.has(r.dst)), `epoch ${epoch}: supersession revises a held fact`);

      // 4. entity collisions: duplicate-name routing traps
      const collisions = d.addedQueries.filter((q) => q.family === 'entity_resolution_atom');
      assert.ok(collisions.length > 0, `epoch ${epoch}: entity-collision queries`);
      assert.ok(collisions.every((q) => q.hardNegatives.some((n) => n.category === 'duplicate_name_wrong_role')), `epoch ${epoch}: collision hard negatives`);

      // 5. retractions: removals + one tombstone each
      assert.ok(d.retractedDocIds.length > 0, `epoch ${epoch}: retractions emitted`);
      assert.equal(
        d.addedDocs.filter((doc) => doc.kind === 'retraction_record').length,
        d.retractedDocIds.length,
        `epoch ${epoch}: one tombstone per retraction`,
      );

      // 6. hidden-pool turnover: fresh quota met every epoch; aged rows retire once past the horizon
      assert.ok(d.freshEvalHiddenQueryIds.length >= QUOTA, `epoch ${epoch}: fresh eval_hidden quota (${d.freshEvalHiddenQueryIds.length} >= ${QUOTA})`);
      for (const id of d.freshEvalHiddenQueryIds) assert.equal(splitOf(id, epoch), 'eval_hidden');
      if (epoch >= HORIZON) {
        assert.ok(d.retiredQueryIds.length > 0, `epoch ${epoch}: aged hidden rows retired`);
        for (const id of d.retiredQueryIds) assert.ok(!activeExclusion.has(id), `epoch ${epoch}: active rows protected`);
      } else {
        assert.equal(d.retiredQueryIds.length, 0, `epoch ${epoch}: nothing inside the horizon retires`);
      }

      // thread the state exactly like the production script
      const retracted = new Set(d.retractedDocIds);
      const retired = new Set(d.retiredQueryIds);
      logical = {
        ...logical,
        docs: [...logical.docs.filter((doc) => !retracted.has(doc.id)), ...d.addedDocs],
        relations: [...logical.relations.filter((r) => !retracted.has(r.src) && !retracted.has(r.dst)), ...d.addedRelations],
        queries: [...logical.queries.filter((q) => !retired.has(q.id)), ...d.addedQueries],
      };

      // 7. live surface expansion: the query surface grows net of retirement, across >= 4 families
      assert.ok(logical.queries.length > priorQueryCount, `epoch ${epoch}: live query surface expands (${priorQueryCount} -> ${logical.queries.length})`);
      const families = new Set(d.addedQueries.map((q) => q.family));
      assert.ok(families.size >= 4, `epoch ${epoch}: >= 4 live families supplied (${[...families].join(', ')})`);
      priorQueryCount = logical.queries.length;
    }
  });
});
