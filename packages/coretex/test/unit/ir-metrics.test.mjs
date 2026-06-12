import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  ndcgAtK,
  mrrAtK,
  recallAtK,
  temporalCurrentStaleHit,
  temporalCurrentStaleAccuracy,
  multiHopRelationHit,
  multiHopRelationRecallAtK,
  abstentionHit,
  abstentionAccuracy,
} from '../../dist/index.js';

describe('IR metrics', () => {
  test('nDCG@k matches a hand-computed value with exponential gain', () => {
    const ranked = [
      { documentId: 'a', relevance: 1.0 },
      { documentId: 'b', relevance: 0.0 },
      { documentId: 'c', relevance: 0.6 },
    ];
    const ideal = [1.0, 0.6, 0.0];
    const dcg = (Math.pow(2, 1.0) - 1) / Math.log2(2)
              + (Math.pow(2, 0.0) - 1) / Math.log2(3)
              + (Math.pow(2, 0.6) - 1) / Math.log2(4);
    const idcg = (Math.pow(2, 1.0) - 1) / Math.log2(2)
               + (Math.pow(2, 0.6) - 1) / Math.log2(3);
    const expected = dcg / idcg;
    assert.ok(Math.abs(ndcgAtK(ranked, ideal, 10) - expected) < 1e-9);
  });

  test('nDCG@k returns 0 when IDCG is 0 (no relevant docs)', () => {
    assert.equal(ndcgAtK([{ documentId: 'a', relevance: 0 }], [], 10), 0);
  });

  test('MRR@k is 1/rank-of-first-relevant', () => {
    const ranked = [
      { documentId: 'a', relevance: 0 },
      { documentId: 'b', relevance: 0.4 },
      { documentId: 'c', relevance: 1.0 },
    ];
    assert.equal(mrrAtK(ranked, 10), 1 / 2);
    assert.equal(mrrAtK([{ documentId: 'a', relevance: 0 }], 10), 0);
  });

  test('Recall@k counts relevant within cutoff over total relevant', () => {
    const ranked = [
      { documentId: 'a', relevance: 1.0 },
      { documentId: 'b', relevance: 0 },
      { documentId: 'c', relevance: 0.4 },
    ];
    assert.equal(recallAtK(ranked, 3, 2), 1 / 3);
    assert.equal(recallAtK(ranked, 3, 10), 2 / 3);
    assert.equal(recallAtK([], 0, 10), null);
  });

  test('temporalCurrentStaleHit requires top-1 == current and no stale in top-3', () => {
    assert.equal(temporalCurrentStaleHit(
      [
        { documentId: 'cur', relevance: 1.0 },
        { documentId: 'other', relevance: 0.4 },
        { documentId: 'noise', relevance: 0 },
      ], 'cur', ['stale1']), true);
    assert.equal(temporalCurrentStaleHit(
      [
        { documentId: 'cur', relevance: 1.0 },
        { documentId: 'stale1', relevance: 0.4 },
      ], 'cur', ['stale1']), false);
    assert.equal(temporalCurrentStaleHit(
      [
        { documentId: 'other', relevance: 0.6 },
        { documentId: 'cur', relevance: 1.0 },
      ], 'cur', []), false);
    assert.equal(temporalCurrentStaleHit([], null, []), null);
  });

  test('temporalCurrentStaleAccuracy averages over non-null hits', () => {
    assert.equal(temporalCurrentStaleAccuracy([true, false, null, true]), 2 / 3);
    assert.equal(temporalCurrentStaleAccuracy([null, null]), 0);
  });

  test('multiHopRelationHit: BFS over relation graph within hop budget', () => {
    const graph = new Map([
      [0, [1]],
      [1, [2]],
      [2, [3]],
      [5, [6]],
    ]);
    assert.equal(multiHopRelationHit([0], new Set([3]), graph, 3), true);
    assert.equal(multiHopRelationHit([0], new Set([3]), graph, 2), false);
    assert.equal(multiHopRelationHit([0], new Set([6]), graph, 5), false);
    assert.equal(multiHopRelationHit([5], new Set([6]), graph, 1), true);
    assert.equal(multiHopRelationHit([], new Set([3]), graph, 5), false);
  });

  test('multiHopRelationRecallAtK averages non-null hits', () => {
    assert.equal(multiHopRelationRecallAtK([true, true, null, false]), 2 / 3);
  });

  test('abstentionHit fires when top1 below threshold', () => {
    assert.equal(abstentionHit(0.0005, 0.001), true);
    assert.equal(abstentionHit(0.002, 0.001), false);
  });

  test('abstentionAccuracy averages non-null', () => {
    assert.equal(abstentionAccuracy([true, true, false, null]), 2 / 3);
  });
});
