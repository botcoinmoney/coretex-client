/**
 * Validator eval-verification backlog auto-drain after a pre-reveal sync.
 *
 * These exercise the EXPORTED pure primitives the auto-drain flow is built from,
 * deterministically (no live RPC, no real scorer, no torch):
 *   - Fix #2: per-advance PARENT substrate snapshots — write, merkle-verify-
 *     before-use, refuse a non-verifying snapshot, GC orphans. The drain path
 *     (loadVerifiedParentSnapshot) has NO dependence on the current replay
 *     window: a fresh process whose cursor already moved past the advance loads
 *     the persisted snapshot, it merkle-verifies to the entry's parent root, and
 *     the rescore proceeds.
 *   - Fix #5: per-epoch corpus/bundle context resolution for cross-rotation
 *     entries — matches-loaded rescores, a differing-but-resolvable corpus is
 *     resolved, and an unresolvable corpus stays pending 'epoch-context-
 *     unavailable' (NEVER rescored with the wrong corpus).
 *   - assertArtifactBoundToEntry: the snapshot-drain binding gate.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  EVAL_PARENT_SNAPSHOT_DIR,
  evalParentSnapshotRef,
  evalParentSnapshotPath,
  loadVerifiedParentSnapshot,
  gcEvalParentSnapshots,
  resolveScorerContextDecision,
  assertArtifactBoundToEntry,
  evalBacklogEntryFromAdvance,
  evalBacklogKey,
  upsertEvalBacklog,
  removeFromEvalBacklog,
  TrustedStateStaging,
} from '../../dist/validator-sync-cli.js';
import { pack, unpack, merkleizeState, bytesToHex, PACKED_SIZE, computePatchHash, semanticPatchHash, encodePatch, PATCH_TYPE } from '../../dist/index.js';

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-backlog-drain-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const b32 = (byte) => `0x${byte.repeat(32)}`;
const addr = (byte) => `0x${byte.repeat(20)}`;

const EPOCH = 7;
const MINER = addr('a1');
const CORPUS = b32('22');
const CORE_VERSION = b32('33');
// A REAL compact patch in the coordinator-rewritten on-chain form (scoreDelta
// = the real ppm delta). The eval artifact binds via the SEMANTIC hash.
const PATCH_BYTES = encodePatch({
  patchType: PATCH_TYPE.SLOT_REPLACE,
  wordCount: 1,
  scoreDelta: 1000n,
  parentStateRoot: new Uint8Array(32).fill(0x11),
  indices: [40],
  newWords: [0x42n],
});
const PATCH_HASH = computePatchHash(PATCH_BYTES);            // literal on-chain hash
const SEMANTIC_PATCH_HASH = semanticPatchHash(PATCH_BYTES);  // artifact / backlog-entry hash
const EVAL_HASH = b32('cd');

/** A packed CortexState whose first byte is `seed` (a non-blank substrate). */
function stateWithSeed(seed) {
  const bytes = new Uint8Array(PACKED_SIZE);
  bytes[0] = seed;
  return unpack(bytes);
}
function rootOf(state) {
  return bytesToHex(merkleizeState(state)).toLowerCase();
}

/** A decoded-advance-shaped event with a self-consistent patchHash. */
function makeAdvance(parentRoot, overrides = {}) {
  return {
    epoch: BigInt(EPOCH),
    transitionIndex: 0n,
    miner: MINER,
    parentStateRoot: parentRoot,
    newStateRoot: b32('99'),
    patchHash: PATCH_HASH,
    evalReportHash: EVAL_HASH,
    coreVersionHash: CORE_VERSION,
    corpusRoot: CORPUS,
    activeFrontierRoot: b32('44'),
    improvementCredits: 0n,
    wordCount: 0,
    compactPatchBytes: PATCH_BYTES,
    ...overrides,
  };
}

function makeArtifact(parentRoot, overrides = {}) {
  return {
    artifactHash: EVAL_HASH,
    evalReportHash: EVAL_HASH,
    epochId: EPOCH,
    minerAddress: MINER,
    outcome: 'STATE_ADVANCE',
    seedDerivation: { patchHash: SEMANTIC_PATCH_HASH },
    context: { parentStateRoot: parentRoot, corpusRoot: CORPUS, coreVersionHash: CORE_VERSION },
    ...overrides,
  };
}

// ── Fix #2: per-advance parent snapshots ──────────────────────────────────────

describe('Fix #2 — parent-substrate snapshot store', () => {
  test('snapshot ref/path are deterministic and live under the snapshot dir', () => {
    const entry = { epochId: EPOCH, artifactHash: EVAL_HASH };
    const ref = evalParentSnapshotRef(entry);
    assert.ok(ref.startsWith(`${EVAL_PARENT_SNAPSHOT_DIR}/`));
    assert.ok(ref.endsWith('.bin'));
    // 1:1 with the backlog key (epochId + artifactHash).
    assert.equal(ref, evalParentSnapshotRef({ epochId: EPOCH, artifactHash: EVAL_HASH }));
    assert.notEqual(ref, evalParentSnapshotRef({ epochId: EPOCH, artifactHash: b32('ee') }));
    assert.equal(evalParentSnapshotPath('/s', ref), join('/s', ref));
  });

  test('an advance left pending writes a parent snapshot; a fresh sync (cursor moved past it) loads + merkle-verifies it', () => withTmpDir((dir) => {
    const parentState = stateWithSeed(0x42);
    const parentRoot = rootOf(parentState);
    // sync 1 (pre-reveal): build the backlog entry + persist the parent snapshot
    // atomically via the staging pattern, EXACTLY as runSync does.
    const base = evalBacklogEntryFromAdvance(makeAdvance(parentRoot), 1000, 'awaiting_epoch_secret_reveal');
    const ref = evalParentSnapshotRef(base);
    const entry = { ...base, parentSnapshotRef: ref };
    const staging = new TrustedStateStaging();
    staging.stage(evalParentSnapshotPath(dir, ref), pack(parentState));
    staging.commit();
    assert.ok(existsSync(evalParentSnapshotPath(dir, ref)));

    // sync 2 (a FRESH process; the replay window/cursor has moved past this
    // advance — there is NO in-window parent). Drain purely from the snapshot.
    const loaded = loadVerifiedParentSnapshot(dir, entry);
    assert.equal(loaded.ok, true);
    // The loaded state merkle-verified to the entry's parentStateRoot → usable.
    assert.equal(rootOf(loaded.state), parentRoot);
    assert.equal(entry.parentStateRoot, parentRoot);
  }));

  test('a snapshot that does NOT merkle-verify to the entry parent root is REFUSED (never used)', () => withTmpDir((dir) => {
    const realParent = stateWithSeed(0x42);
    const wrongParent = stateWithSeed(0x77); // different state → different root
    const entry = {
      ...evalBacklogEntryFromAdvance(makeAdvance(rootOf(realParent)), 1000, 'awaiting_epoch_secret_reveal'),
    };
    const ref = evalParentSnapshotRef(entry);
    const e = { ...entry, parentSnapshotRef: ref };
    // Write a snapshot whose bytes merkleize to a DIFFERENT root than pinned.
    mkdirSync(join(dir, EVAL_PARENT_SNAPSHOT_DIR), { recursive: true });
    const staging = new TrustedStateStaging();
    staging.stage(evalParentSnapshotPath(dir, ref), pack(wrongParent));
    staging.commit();

    const loaded = loadVerifiedParentSnapshot(dir, e);
    assert.equal(loaded.ok, false);
    assert.match(loaded.reason, /merkleizes to .* != entry parentStateRoot .* refusing to use/);
  }));

  test('a missing or unreferenced snapshot is refused, not used', () => withTmpDir((dir) => {
    const entry = { ...evalBacklogEntryFromAdvance(makeAdvance(b32('11')), 1, 'awaiting_epoch_secret_reveal') };
    // no parentSnapshotRef at all (legacy entry)
    assert.equal(loadVerifiedParentSnapshot(dir, entry).ok, false);
    // ref recorded but file absent
    const ref = evalParentSnapshotRef(entry);
    const withRef = { ...entry, parentSnapshotRef: ref };
    const r = loadVerifiedParentSnapshot(dir, withRef);
    assert.equal(r.ok, false);
    assert.match(r.reason, /missing/);
  }));

  test('GC removes orphan snapshots whose backlog entry is gone, keeps live ones', () => withTmpDir((dir) => {
    const live = { ...evalBacklogEntryFromAdvance(makeAdvance(b32('11')), 1, 'awaiting_epoch_secret_reveal') };
    const gone = { ...evalBacklogEntryFromAdvance(makeAdvance(b32('22'), { evalReportHash: b32('ee') }), 2, 'awaiting_epoch_secret_reveal') };
    const liveRef = evalParentSnapshotRef(live);
    const goneRef = evalParentSnapshotRef(gone);
    mkdirSync(join(dir, EVAL_PARENT_SNAPSHOT_DIR), { recursive: true });
    const staging = new TrustedStateStaging();
    staging.stage(evalParentSnapshotPath(dir, liveRef), pack(stateWithSeed(1)));
    staging.stage(evalParentSnapshotPath(dir, goneRef), pack(stateWithSeed(2)));
    staging.commit();
    assert.equal(readdirSync(join(dir, EVAL_PARENT_SNAPSHOT_DIR)).length, 2);

    // backlog now only references `live`; `gone` has drained.
    const removed = gcEvalParentSnapshots(dir, [{ ...live, parentSnapshotRef: liveRef }]);
    assert.equal(removed.length, 1);
    assert.ok(removed[0].endsWith(goneRef.split('/').pop()));
    assert.ok(existsSync(evalParentSnapshotPath(dir, liveRef)));
    assert.equal(existsSync(evalParentSnapshotPath(dir, goneRef)), false);
  }));

  test('GC on an empty backlog clears the whole store; missing dir is a no-op', () => withTmpDir((dir) => {
    assert.deepEqual(gcEvalParentSnapshots(dir, []), []); // no dir yet
    mkdirSync(join(dir, EVAL_PARENT_SNAPSHOT_DIR), { recursive: true });
    const e = { ...evalBacklogEntryFromAdvance(makeAdvance(b32('11')), 1, 'awaiting_epoch_secret_reveal') };
    const ref = evalParentSnapshotRef(e);
    const staging = new TrustedStateStaging();
    staging.stage(evalParentSnapshotPath(dir, ref), pack(stateWithSeed(3)));
    staging.commit();
    const removed = gcEvalParentSnapshots(dir, []);
    assert.equal(removed.length, 1);
    assert.equal(readdirSync(join(dir, EVAL_PARENT_SNAPSHOT_DIR)).length, 0);
  }));

  test('upsert preserves a previously-persisted parentSnapshotRef across re-observation', () => {
    const base = evalBacklogEntryFromAdvance(makeAdvance(b32('11')), 100, 'awaiting_epoch_secret_reveal');
    const ref = evalParentSnapshotRef(base);
    const withRef = { ...base, parentSnapshotRef: ref };
    // sync 1 records the ref.
    const backlog = upsertEvalBacklog([], [withRef]);
    assert.equal(backlog[0].parentSnapshotRef, ref);
    // sync 2 re-observes the SAME advance but (e.g. cross-window) without a ref —
    // the persisted ref survives so the snapshot stays drainable.
    const reobs = upsertEvalBacklog(backlog, [{ ...base, reason: 'epoch-context-unavailable' }]);
    const same = reobs.find((x) => evalBacklogKey(x) === evalBacklogKey(base));
    assert.equal(same.parentSnapshotRef, ref);
    assert.equal(same.reason, 'epoch-context-unavailable');
    // and removal still drains it.
    assert.equal(removeFromEvalBacklog(reobs, base).length, 0);
  });
});

// ── Fix #2 binding gate: snapshot-drain artifact binding ──────────────────────

describe('Fix #2 — assertArtifactBoundToEntry (snapshot-drain binding)', () => {
  const PARENT = b32('11');
  const entry = { ...evalBacklogEntryFromAdvance(makeAdvance(PARENT), 100, 'awaiting_epoch_secret_reveal') };

  test('a matching artifact binds cleanly to the persisted entry pins', () => {
    assert.doesNotThrow(() => assertArtifactBoundToEntry(makeArtifact(PARENT), entry));
  });
  test('a wrong epoch is rejected', () => {
    assert.throws(() => assertArtifactBoundToEntry(makeArtifact(PARENT, { epochId: 8 }), entry), /epochId 8 != backlog entry epoch 7/);
  });
  test('a wrong patchHash is rejected', () => {
    assert.throws(() => assertArtifactBoundToEntry(makeArtifact(PARENT, { seedDerivation: { patchHash: b32('ee') } }), entry), /seedDerivation\.patchHash .* != backlog entry patchHash/);
  });
  test('a wrong parentStateRoot is rejected', () => {
    assert.throws(() => assertArtifactBoundToEntry(makeArtifact(b32('ab')), entry), /context\.parentStateRoot .* != backlog entry parentStateRoot/);
  });
  test('a wrong corpusRoot is rejected', () => {
    assert.throws(() => assertArtifactBoundToEntry(makeArtifact(PARENT, { context: { parentStateRoot: PARENT, corpusRoot: b32('ab'), coreVersionHash: CORE_VERSION } }), entry), /context\.corpusRoot .* != backlog entry corpusRoot/);
  });
  test('a wrong miner is rejected', () => {
    assert.throws(() => assertArtifactBoundToEntry(makeArtifact(PARENT, { minerAddress: addr('bb') }), entry), /minerAddress .* != backlog entry miner/);
  });
});

// ── Fix #5: per-epoch corpus/bundle context resolution ────────────────────────

describe('Fix #5 — resolveScorerContextDecision', () => {
  const loaded = { corpusRoot: CORPUS, coreVersionHash: CORE_VERSION };
  const OTHER_CORPUS = b32('ab');

  test('an entry whose pins MATCH the loaded context rescores with it', () => {
    const d = resolveScorerContextDecision({ corpusRoot: CORPUS, coreVersionHash: CORE_VERSION }, loaded, new Set([CORPUS.toLowerCase()]));
    assert.deepEqual(d, { action: 'matches-loaded' });
  });

  test('an entry whose corpus DIFFERS but is RESOLVABLE materializes the right context', () => {
    const resolvable = new Set([CORPUS.toLowerCase(), OTHER_CORPUS.toLowerCase()]);
    const d = resolveScorerContextDecision({ corpusRoot: OTHER_CORPUS, coreVersionHash: CORE_VERSION }, loaded, resolvable);
    assert.equal(d.action, 'resolve-context');
  });

  test('an entry whose corpus is UNRESOLVABLE stays pending epoch-context-unavailable and is NOT rescored', () => {
    // OTHER_CORPUS is NOT in the resolvable set (not published/available).
    const d = resolveScorerContextDecision({ corpusRoot: OTHER_CORPUS, coreVersionHash: CORE_VERSION }, loaded, new Set([CORPUS.toLowerCase()]));
    assert.equal(d.action, 'unavailable');
    assert.equal(d.reason, 'epoch-context-unavailable');
    assert.match(d.detail, /no corpus matching corpusRoot .* is resolvable/);
    assert.match(d.detail, /rescoring with the wrong corpus/);
  });

  test('a differing coreVersion with a resolvable corpus still resolves (not silently mismatched)', () => {
    const d = resolveScorerContextDecision({ corpusRoot: OTHER_CORPUS, coreVersionHash: b32('ef') }, loaded, new Set([OTHER_CORPUS.toLowerCase()]));
    assert.equal(d.action, 'resolve-context');
  });

  test('a differing coreVersion with an UNresolvable corpus stays unavailable', () => {
    const d = resolveScorerContextDecision({ corpusRoot: OTHER_CORPUS, coreVersionHash: b32('ef') }, loaded, new Set([CORPUS.toLowerCase()]));
    assert.equal(d.action, 'unavailable');
  });
});
