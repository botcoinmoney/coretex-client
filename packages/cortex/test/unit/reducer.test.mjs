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
let reducer, liveEpoch, eligibility, multiplierCap, fundingTx, state;
try {
  reducer = await import('../../dist/reducer/reducer.js');
  liveEpoch = await import('../../dist/reducer/live-epoch.js');
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
  advanceEpochState,
  makeLiveEpochInput,
} = liveEpoch;

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
  verifyMinerClaimProof,
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
  // Reserved-bit-clean state. Only header word 0 (magic) + RetrievalKeys
  // payload words (slot offset 1..7 of each 8-word slot) and Codebook
  // CODE_DATA words (offset 1) carry random data — every other position
  // either has reserved-bit constraints we'd need to satisfy or is reserved
  // entirely. For reducer tests we only need writable, reserved-bit-safe
  // indices that patches can target without triggering E04 on apply.
  let s = (seed >>> 0) || 1;
  const rng = () => { s^=s<<13;s>>>=0;s^=s>>>17;s>>>=0;s^=s<<5;s>>>=0;return s; };
  const words = new Array(1024).fill(0n);
  words[0] = (0xC07En << 240n) | (1024n << 208n);
  // RetrievalKeys range 384..671: 36 slots × 8 words. Words slot+1..slot+7
  // are payload (no reserved bits). Word slot+0 has reserved tail in bits
  // 79:0 — leave it zero for the test.
  for (let slot = 0; slot < 36; slot++) {
    const base = 384 + slot * 8;
    for (let w = 1; w < 8; w++) {
      words[base + w] = BigInt.asUintN(256, BigInt(rng()) | (BigInt(rng()) << 32n));
    }
  }
  return { words };
}

// Pick a target index known to be reserved-bit-safe for word writes.
// Slot k (0..35) word offset 1..7 is payload of a RetrievalKeys slot;
// these positions accept arbitrary 256-bit values without triggering E04.
function safeTarget(slot, off) {
  return 384 + slot * 8 + off;
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

function makeLivePatch(miner, parentState, indices, newWords, scoreDelta, marginalEvaluator) {
  const parentStateRoot = merkleizeState(parentState);
  const patch = {
    patchType: 0x01,
    wordCount: indices.length,
    scoreDelta: BigInt(scoreDelta),
    parentStateRoot,
    indices,
    newWords: newWords.map(BigInt),
  };
  return makeLiveEpochInput(miner, patch, encodePatch(patch), marginalEvaluator);
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
    const idx = safeTarget(0, 1);
    const newWord = (s.words[idx] ?? 0n) ^ 1n;
    const p = makePatch(s, [idx], [newWord], 500);
    const result = reduce(s, [p]);
    assert.equal(result.accepted.length, 1);
    assert.equal(result.rejected.length, 0);
    assert.equal(result.newState.words[idx], newWord);
  });

  test('target-overlap: higher score wins', () => {
    const s = makeTestState(3);
    const idx = safeTarget(1, 2);
    const pHigh = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 1n], 1000);
    const pLow = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 2n], 500);
    const result = reduce(s, [pLow, pHigh]); // submit low first
    assert.equal(result.accepted.length, 1);
    assert.equal(result.accepted[0].patch.scoreDelta, 1000n);
    assert.equal(result.rejected[0].reason, 'R01_TARGET_OVERLAP');
  });

  test('patches with distinct indices both accepted', () => {
    const s = makeTestState(4);
    const i1 = safeTarget(2, 1), i2 = safeTarget(3, 1);
    const p1 = makePatch(s, [i1], [(s.words[i1] ?? 0n) ^ 1n], 100);
    const p2 = makePatch(s, [i2], [(s.words[i2] ?? 0n) ^ 1n], 200);
    const result = reduce(s, [p1, p2]);
    assert.equal(result.accepted.length, 2);
    assert.equal(result.rejected.length, 0);
  });

  test('threshold=10 rejects score=5 patch with R02_SEMANTIC_CONFLICT', () => {
    const s = makeTestState(5);
    const idx = safeTarget(4, 1);
    const p = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 1n], 5);
    const result = reduce(s, [p], 10n);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejected[0].reason, 'R02_SEMANTIC_CONFLICT');
  });

  test('determinism: shuffled input → same output', () => {
    const s = makeTestState(6);
    const patches = [];
    for (let i = 0; i < 5; i++) {
      const idx = safeTarget(i, 1);
      patches.push(makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ BigInt(i + 1)], 100 + i * 11));
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

  // ── NEW: reducer regression test for stale-parent bug ─────────────────────
  // Before the fix, applyPatch(current, p) inside the loop rejected every
  // patch after the first because `current` had advanced past the epoch
  // parent root. This test pins the fix: 5 distinct-index patches that all
  // share the same epoch parent root must all be accepted in the same
  // reducer run.
  test('multi-patch: 5 non-overlapping patches at same epoch parent all accepted', () => {
    const s = makeTestState(99);
    const patches = [];
    for (let i = 0; i < 5; i++) {
      const idx = safeTarget(10 + i, 3); // payload words; reserved-bit-safe
      patches.push(makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ (1n << BigInt(50 + i))], 1000 - i));
    }
    const result = reduce(s, patches);
    assert.equal(result.accepted.length, 5, `expected 5 accepted, got ${result.accepted.length}`);
    assert.equal(result.rejected.length, 0);
    // All 5 distinct word writes must show up in the new state.
    for (let i = 0; i < 5; i++) {
      const idx = safeTarget(10 + i, 3);
      assert.equal(result.newState.words[idx], (s.words[idx] ?? 0n) ^ (1n << BigInt(50 + i)));
    }
  });

  // ── NEW: reducer rejects patches with wrong parent root ───────────────────
  test('R03_WRONG_PARENT_ROOT: patch with stale parentStateRoot rejected', () => {
    const s = makeTestState(101);
    const idx = safeTarget(20, 1);
    const goodPatch = makePatch(s, [idx], [(s.words[idx] ?? 0n) ^ 7n], 500);
    // Forge a stale parent — corrupt it so it can't match the epoch parent.
    const bad = {
      ...goodPatch,
      patch: { ...goodPatch.patch, parentStateRoot: new Uint8Array(32).fill(0xff) },
    };
    const result = reduce(s, [bad]);
    assert.equal(result.accepted.length, 0);
    assert.equal(result.rejected.length, 1);
    assert.equal(result.rejected[0].reason, 'R03_WRONG_PARENT_ROOT');
  });

  test('sort tiebreak: smaller wordCount wins', () => {
    const s = makeTestState(7);
    const ia = safeTarget(5, 1);
    const ib = safeTarget(5, 2);
    const p1word = makePatch(s, [ia], [(s.words[ia] ?? 0n) ^ 1n], 1000);
    // p2 has wordCount=2, same score
    const p2 = makePatch(s, [ia, ib], [(s.words[ia] ?? 0n) ^ 2n, (s.words[ib] ?? 0n) ^ 1n], 1000);
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

describe('advanceEpochState()', () => {
  test('mid-epoch accepts two different-area improvements regardless of relative score', () => {
    const s = makeTestState(301);
    const i1 = safeTarget(1, 1);
    const first = makeLivePatch('0xaaaa', s, [i1], [(s.words[i1] ?? 0n) ^ 1n], 10);
    const afterFirst = applyPatch(s, first.patch);
    assert.equal(afterFirst.ok, true);

    const i2 = safeTarget(2, 1);
    const second = makeLivePatch('0xbbbb', afterFirst.state, [i2], [(afterFirst.state.words[i2] ?? 0n) ^ 2n], 100);

    const result = advanceEpochState(s, [first, second], 0n);
    assert.equal(result.advances.length, 2);
    assert.equal(result.rejected.length, 0);
    assert.equal(result.newState.words[i1], first.patch.newWords[0]);
    assert.equal(result.newState.words[i2], second.patch.newWords[0]);
    assert.equal(result.advances[0].creditUnits, 10n);
    assert.equal(result.advances[1].creditUnits, 100n);
  });

  test('stale-parent same-epoch patch is rejected until rebased on live root', () => {
    const s = makeTestState(302);
    const i1 = safeTarget(3, 1);
    const i2 = safeTarget(4, 1);
    const first = makeLivePatch('0xaaaa', s, [i1], [(s.words[i1] ?? 0n) ^ 1n], 10);
    const staleSecond = makeLivePatch('0xbbbb', s, [i2], [(s.words[i2] ?? 0n) ^ 2n], 100);

    const result = advanceEpochState(s, [first, staleSecond], 0n);
    assert.equal(result.advances.length, 1);
    assert.equal(result.rejected.length, 1);
    assert.equal(result.rejected[0].reason, 'R03_WRONG_PARENT_ROOT');
  });

  test('screener-looking patch with no marginal improvement earns no credits', () => {
    const s = makeTestState(303);
    const idx = safeTarget(5, 1);
    const candidate = makeLivePatch('0xaaaa', s, [idx], [(s.words[idx] ?? 0n) ^ 1n], 1_000, () => 0n);

    const result = advanceEpochState(s, [candidate], 0n);
    assert.equal(result.advances.length, 0);
    assert.equal(result.rejected.length, 1);
    assert.equal(result.rejected[0].reason, 'L01_NOT_IMPROVEMENT');
    assert.equal(bytesToHex(result.newStateRoot), bytesToHex(merkleizeState(s)));
  });

  test('overlapping later patch can advance if it improves current live state', () => {
    const s = makeTestState(304);
    const idx = safeTarget(6, 1);
    const first = makeLivePatch('0xaaaa', s, [idx], [(s.words[idx] ?? 0n) ^ 1n], 10);
    const afterFirst = applyPatch(s, first.patch);
    assert.equal(afterFirst.ok, true);

    const second = makeLivePatch('0xbbbb', afterFirst.state, [idx], [(afterFirst.state.words[idx] ?? 0n) ^ 2n], 20);

    const result = advanceEpochState(s, [first, second], 0n);
    assert.equal(result.advances.length, 2);
    assert.equal(result.rejected.length, 0);
    assert.equal(result.newState.words[idx], second.patch.newWords[0]);
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

describe('legacy multiplier-cap', () => {
  test('MERGE_MULTIPLIER_BPS = 10000 (1.0×, no separate uplift)', () => {
    assert.equal(MERGE_MULTIPLIER_BPS, 10_000n);
  });

  test('computeMinerBonus gives zero uplift at the V0 default', () => {
    const bonus = computeMinerBonus('0xaaaa', 1_000_000n);
    assert.equal(bonus.bonusBotcoin, 0n);
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

  test('buildEpochBonusLeaves: default no-uplift setting emits no funding leaves', () => {
    const epoch = 1n;
    const miner = '0xeeee';
    const hash1 = '0x1111'; const hash2 = '0x2222';
    const elig = buildEpochEligibility(
      [{ epoch, miner, patchHash: hash1 }, { epoch, miner, patchHash: hash2 }],
      [{ epoch, miner, patchHash: hash1 }, { epoch, miner, patchHash: hash2 }],
      () => 10n,
    );
    const leaves = buildEpochBonusLeaves(elig, [{ miner, claimBase: 1_000_000n }]);
    assert.equal(leaves.length, 0);
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

  // ── 3-leaf binary Merkle round-trip (mirrors the on-chain forge test) ──
  test('3-leaf Merkle: each miner proof verifies against the same root', () => {
    const leaves = [
      { miner: '0x' + '05'.padEnd(40, '0'), bonusBotcoin: 30_000_000_000_000_000_000n, capBotcoin: 30_000_000_000_000_000_000n },
      { miner: '0x' + '06'.padEnd(40, '0'), bonusBotcoin: 50_000_000_000_000_000_000n, capBotcoin: 50_000_000_000_000_000_000n },
      { miner: '0x' + '07'.padEnd(40, '0'), bonusBotcoin: 20_000_000_000_000_000_000n, capBotcoin: 20_000_000_000_000_000_000n },
    ];
    const root = computeBonusMerkleRoot(leaves);
    for (const leaf of leaves) {
      const p = buildMinerClaimProof(leaves, leaf.miner);
      assert.ok(p, `proof for ${leaf.miner}`);
      assert.equal(p.bonusBotcoin, leaf.bonusBotcoin);
      const ok = verifyMinerClaimProof(leaf, p.proof, root);
      assert.ok(ok, `proof must verify for ${leaf.miner}`);
    }
  });

  test('3-leaf Merkle: swapped proof must fail verification', () => {
    const leaves = [
      { miner: '0x' + '05'.padEnd(40, '0'), bonusBotcoin: 30n, capBotcoin: 30n },
      { miner: '0x' + '06'.padEnd(40, '0'), bonusBotcoin: 50n, capBotcoin: 50n },
      { miner: '0x' + '07'.padEnd(40, '0'), bonusBotcoin: 20n, capBotcoin: 20n },
    ];
    const root = computeBonusMerkleRoot(leaves);
    const proofA = buildMinerClaimProof(leaves, leaves[0].miner);
    // miner B presenting A's proof against B's leaf must fail
    const okSwap = verifyMinerClaimProof(leaves[1], proofA.proof, root);
    assert.equal(okSwap, false, 'swapped proof must reject');
  });

  test('Single-leaf root === leaf hash (matches MerkleProof.verify)', () => {
    const leaf = { miner: '0x' + '05'.padEnd(40, '0'), bonusBotcoin: 50n, capBotcoin: 50n };
    const root = computeBonusMerkleRoot([leaf]);
    const expected = computeLeafHash(leaf);
    assert.ok(root.every((b, i) => b === expected[i]), 'single-leaf root must equal leaf hash');
    // empty proof verifies for single-leaf tree
    const ok = verifyMinerClaimProof(leaf, [], root);
    assert.ok(ok);
  });
});
