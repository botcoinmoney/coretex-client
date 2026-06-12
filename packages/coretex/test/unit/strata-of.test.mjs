import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { strataOf, eventSatisfiesStratum, stratumOf } from '../../dist/index.js';

function ev(opts = {}) {
  return {
    id: opts.id ?? 'ev-0',
    family: opts.family ?? 'near_collision',
    domain: opts.domain ?? 'companies',
    split: opts.split ?? 'eval_hidden',
    queryText: opts.queryText ?? 'q',
    truthDocuments: opts.truthDocuments ?? [{ id: 'truth', text: 't', isCurrent: true }],
    hardNegatives: opts.hardNegatives ?? [],
    qrels: opts.qrels ?? [
      { documentId: 'truth', relevance: 1.0 },
    ],
    protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'a'.repeat(64) },
    embeddings: { modelId: 'x', revision: 'y', layout: { dim: 1, quantization: 'int8', headerBytes: 0 }, query: new Uint8Array(), perTruth: new Map(), perNegative: new Map() },
    causalDepth: opts.causalDepth,
    relationHopDepth: opts.relationHopDepth,
  };
}

describe('strataOf', () => {
  test('previous event without depth fields emits 3 base strata', () => {
    const e = ev({ family: 'near_collision' });
    const s = strataOf(e);
    assert.deepEqual(s.sort(), [
      'bucket=easy',
      'family=near_collision',
      'family=near_collision,bucket=easy',
    ].sort());
  });

  test('depth field >1 emits depth strata + family-combined depth strata', () => {
    const e = ev({ family: 'multi_hop_relation', causalDepth: 3 });
    const s = strataOf(e);
    assert.ok(s.includes('depth>=2'), 'has depth>=2');
    assert.ok(s.includes('depth>=3'), 'has depth>=3');
    assert.ok(s.includes('family=multi_hop_relation,depth>=3'), 'has combined');
    assert.ok(!s.includes('depth>=4'), 'never above stated depth');
  });

  test('relationHopDepth field emits relationHop strata', () => {
    const e = ev({ family: 'multi_hop_relation', relationHopDepth: 2 });
    const s = strataOf(e);
    assert.ok(s.includes('relationHop>=2'));
    assert.ok(s.includes('family=multi_hop_relation,relationHop>=2'));
    assert.ok(!s.includes('relationHop>=3'));
  });

  test('depth=1 (default) does not emit depth strata', () => {
    const e = ev({ causalDepth: 1, relationHopDepth: 1 });
    const s = strataOf(e);
    assert.ok(!s.some((x) => x.includes('depth>=')));
  });

  test('previous stratumOf is contained in strataOf for backward compat', () => {
    const e = ev({ family: 'temporal' });
    const previous = stratumOf(e);
    assert.ok(strataOf(e).includes(previous));
  });
});

describe('eventSatisfiesStratum', () => {
  test('exact previous stratum matches', () => {
    const e = ev({ family: 'temporal' });
    assert.equal(eventSatisfiesStratum(e, 'family=temporal,bucket=easy'), true);
  });

  test('depth predicate matches when synthesizer set the depth', () => {
    const e = ev({ family: 'multi_hop_relation', causalDepth: 3 });
    assert.equal(eventSatisfiesStratum(e, 'depth>=2'), true);
    assert.equal(eventSatisfiesStratum(e, 'depth>=3'), true);
    assert.equal(eventSatisfiesStratum(e, 'depth>=4'), false);
  });

  test('combined family+depth predicate matches', () => {
    const e = ev({ family: 'multi_hop_relation', causalDepth: 3 });
    assert.equal(eventSatisfiesStratum(e, 'family=multi_hop_relation,depth>=3'), true);
    assert.equal(eventSatisfiesStratum(e, 'family=temporal,depth>=3'), false);
  });

  test('unknown stratum returns false (fail-closed)', () => {
    const e = ev({});
    assert.equal(eventSatisfiesStratum(e, 'made_up=42'), false);
  });
});
