/**
 * Unit tests for the Phase 6 reducer module.
 *
 * These tests run against the compiled dist/reducer/ exports.
 * Run: npm run build && node --test test/unit/reducer.test.mjs
 *
 * When Phase 4 lands, remove the TODO(phase-4) stubs in:
 *   - dist/reducer/reducer.js (stubMarginalEvaluator)
 *   - dist/reducer/eligibility.js (no changes needed — pure logic)
 *   - dist/reducer/multiplier-cap.js (no changes needed — pure math)
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// Import from dist/ (requires `npm run build` first)
let reducer, eligibility, multiplierCap, fundingTx, state;
try {
  reducer = await import('../../dist/reducer/reducer.js');
  eligibility = await import('../../dist/reducer/eligibility.js');
  multiplierCap = await import('../../dist/reducer/multiplier-cap.js');
  fundingTx = await import('../../dist/reducer/funding-tx.js');
  state = await import('../../dist/state/index.js');
} catch (e) {
  console.error('Could not import from dist/. Run `npm run build` first.');
  console.error('Error:', e.message);
  process.exit(1);
}

const {
  reduce,
  makeReducerInput,
  stubMarginalEvaluator,
  computePatchSetRoot,
} = reducer;

const {
  buildEpochEligibility,
  minerScreenerCredits,
  minerHasMerge,
} = eligibility;

const {
  MERGE_MULTIPLIER_BPS,
  BPS_DIVISOR,
  computeMinerBonus,
  buildEpochBonusLeaves,
  computeEpochTotalBonus,
  assertBonusWithinCap,
} = multiplierCap;

const {
  computeLeafHash,
  computeBonusMerkleRoot,
  buildFundEpochCalldata,
  buildMinerClaimProof,
} = fundingTx;

const {
  merkleizeState,
  bytesToHex,
  hexToBytes,
  applyPatch,
  encodePatch,
  RANGES,
} = state;

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeZeroState() {
  return { words: new Array(RANGES.WORD_COUNT).fill(0n) };
}

function makeTestState(seed = 1) {
  let s = (seed >>> 0) || 1;
  const rng = () => { s^=s<<13;s>>>=0;s^=s>>>17;s>>>=0;s^=s<<5;s>>>=0;return s; };
  const words = new Array(1024).fill(0n);
  words[0] = (0xC07En << 240n) | (1024n << 208n);
  for (let i = 1; i < 992; i++) {
    words[i] = BigInt(rng()) | (BigInt(rng()) << 32n);
    words[i] = BigInt.asUintN(256, words[i]);
  }
  return { words };
}

function makePatch(parentState, indices, newWords, scoreDelta) {
  const parentStateRoot = merkleizeState(parentState);
  const patch = {
    patchType: 0x01,
    wordCount: indices.length,
    scoreDelta: BigInt(scoreDelta),
    parentStateRoot,
    indices,
    newWords: newWords.map(BigInt),
  };
  return makeReducerInput(patch);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Reducer tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('reduce()', () => {
  test('empty patch set returns parent state unchanged', () => {
    const s = makeTestState(1);
    const result = reduce(s, []);
    assert.equal(bytesToHex(result.newStateRoot), bytesToHex(merkleizeState(s)));
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejected.length, 0);
  });

  test('single patch is accepted and applied', () => {
    const s = makeTestState(2);
    const newWord = (s.words[100] ?? 0n) ^ 1n;
    const p = makePatch(s, [100], [newWord], 500);
    const result = reduce(s, [p]);
    assert.equal(result.accepted.length, 1);
    assert.equal(result.rejected.length, 0);
    assert.equal(result.newState.words[100], newWord);
  });

  test('target-overlap: higher score wins', () => {
    const s = makeTestState(3);
    const idx = 200;
    const pHigh = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 1n], 1000);
    const pLow = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 2n], 500);
    const result = reduce(s, [pLow, pHigh]); // submit low first
    assert.equal(result.accepted.length, 1);
    assert.equal(result.accepted[0].patch.scoreDelta, 1000n);
    assert.equal(result.rejected[0].reason, 'R01_TARGET_OVERLAP');
  });

  test('patches with distinct indices both accepted', () => {
    const s = makeTestState(4);
    const p1 = makePatch(s, [100], [(s.words[100] ?? 0n) ^ 1n], 100);
    const p2 = makePatch(s, [200], [(s.words[200] ?? 0n) ^ 1n], 200);
    const result = reduce(s, [p1, p2]);
    assert.equal(result.accepted.length, 2);
    assert.equal(result.rejected.length, 0);
  });

  test('threshold=10 rejects score=5 patch with R02_SEMANTIC_CONFLICT', () => {
    const s = makeTestState(5);
    const p = makePatch(s, [300], [(s.words[300] ?? 0n) ^ 1n], 5);
    const result = reduce(s, [p], 10n);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejected[0].reason, 'R02_SEMANTIC_CONFLICT');
  });

  test('determinism: shuffled input → same output', () => {
    const s = makeTestState(6);
    const patches = [];
    for (let i = 0; i < 5; i++) {
      patches.push(makePatch(s, [100 + i * 50], [(s.words[100 + i * 50] ?? 0n) ^ BigInt(i + 1)], 100 + i * 11));
    }
    const ref = reduce(s, patches);
    // Test 10 shuffles
    for (let sh = 0; sh < 10; sh++) {
      const shuffled = [...patches].sort(() => Math.sin(sh * 137.5) - 0.5);
      const r = reduce(s, shuffled);
      assert.equal(bytesToHex(r.patchSetRoot), bytesToHex(ref.patchSetRoot));
      assert.equal(bytesToHex(r.newStateRoot), bytesToHex(ref.newStateRoot));
    }
  });

  test('sort tiebreak: smaller wordCount wins', () => {
    const s = makeTestState(7);
    const idx = 400;
    const p1word = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 1n], 1000);
    // p2 has wordCount=2, same score
    const p2 = makePatch(s, [idx, idx + 1], [(s.words[idx] ?? 0n) ^ 2n, (s.words[idx + 1] ?? 0n) ^ 1n], 1000);
    const result = reduce(s, [p2, p1word]);
    assert.equal(result.accepted[0].patch.wordCount, 1, 'wordCount=1 should win tiebreak');
  });

  test('computePatchSetRoot is empty-safe', () => {
    const root = computePatchSetRoot([]);
    assert.equal(root.length, 32);
  });

  test('stubMarginalEvaluator returns patch.scoreDelta', () => {
    const s = makeZeroState();
    const patch = { scoreDelta: 42n };
    assert.equal(stubMarginalEvaluator(s, patch), 42n);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Eligibility tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('buildEpochEligibility()', () => {
  const epoch = 1n;
  const minerA = '0xaaaa';
  const minerB = '0xbbbb';
  const hash1 = '0x1111';
  const hash2 = '0x2222';

  test('unique screener events produce credit issuances', () => {
    const elig = buildEpochEligibility(
      [{ epoch, miner: minerA, patchHash: hash1 }, { epoch, miner: minerA, patchHash: hash2 }],
      [],
      () => 5n,
    );
    assert.equal(elig.creditIssuances.length, 2);
    assert.equal(elig.multiplierAccruals.length, 0);
  });

  test('duplicate screener event skipped', () => {
    const elig = buildEpochEligibility(
      [{ epoch, miner: minerA, patchHash: hash1 }, { epoch, miner: minerA, patchHash: hash1 }],
      [],
      () => 5n,
    );
    assert.equal(elig.creditIssuances.length, 1);
    assert.equal(elig.duplicatesSkipped.length, 1);
  });

  test('valid merge produces multiplier accrual', () => {
    const elig = buildEpochEligibility(
      [{ epoch, miner: minerA, patchHash: hash1 }],
      [{ epoch, miner: minerA, patchHash: hash1 }],
      () => 5n,
    );
    assert.equal(elig.multiplierAccruals.length, 1);
  });

  test('merge without screener pass is skipped', () => {
    const elig = buildEpochEligibility(
      [],
      [{ epoch, miner: minerA, patchHash: hash1 }],
      () => 5n,
    );
    assert.equal(elig.multiplierAccruals.length, 0);
    assert.equal(elig.duplicatesSkipped.length, 1);
  });

  test('duplicate merge skipped', () => {
    const elig = buildEpochEligibility(
      [{ epoch, miner: minerA, patchHash: hash1 }],
      [{ epoch, miner: minerA, patchHash: hash1 }, { epoch, miner: minerA, patchHash: hash1 }],
      () => 5n,
    );
    assert.equal(elig.multiplierAccruals.length, 1);
    assert.equal(elig.duplicatesSkipped.length, 1);
  });

  test('minerScreenerCredits and minerHasMerge helpers', () => {
    const elig = buildEpochEligibility(
      [{ epoch, miner: minerA, patchHash: hash1 }, { epoch, miner: minerB, patchHash: hash2 }],
      [{ epoch, miner: minerA, patchHash: hash1 }],
      () => 10n,
    );
    assert.equal(minerScreenerCredits(elig, minerA), 10n);
    assert.equal(minerScreenerCredits(elig, minerB), 10n);
    assert.ok(minerHasMerge(elig, minerA));
    assert.ok(!minerHasMerge(elig, minerB));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Multiplier cap tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('multiplier-cap', () => {
  test('MERGE_MULTIPLIER_BPS = 15000 (1.5×)', () => {
    assert.equal(MERGE_MULTIPLIER_BPS, 15_000n);
  });

  test('computeMinerBonus gives 0.5× claimBase', () => {
    const bonus = computeMinerBonus('0xaaaa', 1_000_000n);
    assert.equal(bonus.bonusBotcoin, 500_000n);
    assert.equal(bonus.capBotcoin, bonus.bonusBotcoin);
  });

  test('bonus cap equals bonus (single-uplift)', () => {
    const bonus = computeMinerBonus('0xbbbb', 2_000_000n);
    assert.equal(bonus.bonusBotcoin, bonus.capBotcoin);
  });

  test('assertBonusWithinCap passes when bonus=cap', () => {
    const leaf = computeMinerBonus('0xcccc', 1_000_000n);
    assert.doesNotThrow(() => assertBonusWithinCap(leaf));
  });

  test('assertBonusWithinCap throws when bonus > cap', () => {
    const leaf = { miner: '0xdddd', bonusBotcoin: 1000n, capBotcoin: 500n };
    assert.throws(() => assertBonusWithinCap(leaf), /cap violation/);
  });

  test('buildEpochBonusLeaves: single leaf per miner (cap enforced)', () => {
    const epoch = 1n;
    const miner = '0xeeee';
    const hash1 = '0x1111'; const hash2 = '0x2222';
    const elig = buildEpochEligibility(
      [{ epoch, miner, patchHash: hash1 }, { epoch, miner, patchHash: hash2 }],
      [{ epoch, miner, patchHash: hash1 }, { epoch, miner, patchHash: hash2 }],
      () => 10n,
    );
    const leaves = buildEpochBonusLeaves(elig, [{ miner, claimBase: 1_000_000n }]);
    assert.equal(leaves.length, 1, 'exactly one leaf per miner');
    assert.equal(leaves[0].bonusBotcoin, 500_000n);
  });

  test('computeEpochTotalBonus sums correctly', () => {
    const leaves = [
      { miner: '0xaaaa', bonusBotcoin: 100n, capBotcoin: 100n },
      { miner: '0xbbbb', bonusBotcoin: 200n, capBotcoin: 200n },
    ];
    assert.equal(computeEpochTotalBonus(leaves), 300n);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Funding-tx tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('funding-tx', () => {
  test('computeLeafHash returns 32 bytes', () => {
    const leaf = { miner: '0x' + 'aa'.repeat(20), bonusBotcoin: 1000n, capBotcoin: 1000n };
    const hash = computeLeafHash(leaf);
    assert.equal(hash.length, 32);
  });

  test('computeBonusMerkleRoot is stable (same leaves → same root)', () => {
    const leaves = [
      { miner: '0x' + 'aa'.repeat(20), bonusBotcoin: 500n, capBotcoin: 500n },
      { miner: '0x' + 'bb'.repeat(20), bonusBotcoin: 700n, capBotcoin: 700n },
    ];
    const r1 = computeBonusMerkleRoot(leaves);
    const r2 = computeBonusMerkleRoot(leaves);
    assert.ok(r1.every((b, i) => b === r2[i]), 'Root must be deterministic');
  });

  test('buildFundEpochCalldata returns correct structure', () => {
    const epoch = 42n;
    const leaves = [
      { miner: '0x' + 'cc'.repeat(20), bonusBotcoin: 1000n, capBotcoin: 1000n },
    ];
    const tx = buildFundEpochCalldata(epoch, leaves);
    assert.equal(tx.merkleRoot.length, 32);
    assert.equal(tx.totalBonus, 1000n);
    assert.ok(tx.calldata.length > 4, 'Calldata must have selector + args');
    // Selector = first 4 bytes
    assert.ok(tx.calldataHex.startsWith('0x'));
  });

  test('buildMinerClaimProof returns correct leaf index', () => {
    const miner1 = '0x' + 'aa'.repeat(20);
    const miner2 = '0x' + 'bb'.repeat(20);
    const leaves = [
      { miner: miner1, bonusBotcoin: 100n, capBotcoin: 100n },
      { miner: miner2, bonusBotcoin: 200n, capBotcoin: 200n },
    ];
    // Note: leaves are sorted by miner address in buildEpochBonusLeaves,
    // but here we test with unsorted leaves for index lookup
    const proof = buildMinerClaimProof(leaves, miner1);
    assert.ok(proof !== null, 'Proof should be found');
    assert.equal(proof.miner, miner1.toLowerCase());
    assert.equal(proof.bonusBotcoin, 100n);
  });

  test('buildMinerClaimProof returns null for unknown miner', () => {
    const leaves = [
      { miner: '0x' + 'aa'.repeat(20), bonusBotcoin: 100n, capBotcoin: 100n },
    ];
    const proof = buildMinerClaimProof(leaves, '0x' + 'ff'.repeat(20));
    assert.equal(proof, null);
  });
});
