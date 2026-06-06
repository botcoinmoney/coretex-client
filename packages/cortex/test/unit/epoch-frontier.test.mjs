import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { makeEpochFrontier } from '../../dist/index.js';

describe('epoch frontier live reserve injection', () => {
  const familyOf = (id) => id.split(':')[0];

  test('C3 zero-attempt epochs do not churn without injected work', () => {
    const f = makeEpochFrontier({
      evalHiddenIds: ['base:a', 'base:b', 'base:c', 'base:d', 'base:e', 'base:f'],
      familyOf,
      mode: 'C3',
      activeWindow: 4,
      minChurn: 2,
      maxChurn: 4,
      seed: 'frontier-test',
    });
    const s0 = f.stepEpoch(0, null, null);
    const s1 = f.stepEpoch(1, 0, 0);

    assert.equal(s1.churnRate, 0);
    assert.equal(s1.activated, 0);
    assert.equal(s1.retired, 0);
    assert.deepEqual([...s1.activeIds].sort(), [...s0.activeIds].sort());
  });

  test('C3 zero-attempt epochs activate newly injected live evals instead of deadlocking reserve', () => {
    const f = makeEpochFrontier({
      evalHiddenIds: ['base:a', 'base:b', 'base:c', 'base:d', 'base:e', 'base:f'],
      familyOf,
      mode: 'C3',
      activeWindow: 4,
      minChurn: 2,
      maxChurn: 4,
      seed: 'frontier-test',
    });
    f.stepEpoch(0, null, null);
    assert.equal(f.addReserveIds(['validity_atom:1', 'scope_atom:1', 'entity_resolution_atom:1'], familyOf), 3);
    const s1 = f.stepEpoch(1, 0, 0);

    assert.equal(s1.churnRate, 3);
    assert.equal(s1.activated, 3);
    assert.equal(s1.retired, 3);
    assert.ok(s1.activeIds.has('validity_atom:1'));
    assert.ok(s1.activeIds.has('scope_atom:1'));
    assert.ok(s1.activeIds.has('entity_resolution_atom:1'));
  });
});
