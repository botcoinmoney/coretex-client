/**
 * Validator sync-client hardening (Findings 4–8 + runtime-pin assertion).
 *
 * These exercise the EXPORTED pure primitives the hardened sync flow is built
 * from — deterministically, with no live RPC, no real scorer, and no torch
 * install. The orchestration in runSync() composes exactly these primitives:
 *   - Finding 4: assertArtifactBoundToAdvance
 *   - Finding 5: eval-backlog upsert/remove + state-file fields
 *   - Finding 6: readChainContext at one injected confirmed block tag
 *   - Finding 7: TrustedStateStaging atomic commit / dispose
 *   - Finding 8: selectScorerContextForAdvance
 *   - runtime-pin: scorerRuntimeMatchesBundle + bundle-pin reader
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  assertArtifactBoundToAdvance,
  selectScorerContextForAdvance,
  evalBacklogEntryFromAdvance,
  evalBacklogKey,
  upsertEvalBacklog,
  removeFromEvalBacklog,
  scorerRuntimeBundlePinsFromManifest,
  TrustedStateStaging,
  serializeMergedValidatorState,
  serializeTofuKeyPin,
  readChainContext,
} from '../../dist/client-sync-cli.js';
import {
  scorerRuntimeMatchesBundle,
  scorerVersionMatchesRange,
} from '../../dist/client-runtime.js';
import { computePatchHash, semanticPatchHash, encodePatch, PATCH_TYPE } from '../../dist/index.js';

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-sync-hardening-'));
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
const PARENT = b32('11');
const CORPUS = b32('22');
const CORE_VERSION = b32('33');
const FRONTIER = b32('44');
// A REAL compact patch (SLOT_REPLACE, one word). The coordinator REWRITES
// scoreDelta to the real ppm delta before signing, so the on-chain bytes carry
// scoreDelta=1000 while the artifact was scored over the scoreDelta=0 form.
const PATCH_BASE = {
  patchType: PATCH_TYPE.SLOT_REPLACE,
  wordCount: 1,
  scoreDelta: 0n,
  parentStateRoot: hexToBytes(PARENT),
  indices: [40],
  newWords: [0x42n],
};
const PATCH_BYTES = encodePatch({ ...PATCH_BASE, scoreDelta: 1000n }); // on-chain rewritten form
const PATCH_HASH = computePatchHash(PATCH_BYTES);                       // literal on-chain patchHash
const SEMANTIC_PATCH_HASH = semanticPatchHash(PATCH_BYTES);             // artifact seedDerivation hash
const EVAL_HASH = b32('cd');

function hexToBytes(hex) {
  const h = hex.replace(/^0x/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A decoded-advance-shaped event with a self-consistent patchHash. */
function makeAdvance(overrides = {}) {
  return {
    epoch: BigInt(EPOCH),
    transitionIndex: 0n,
    miner: MINER,
    parentStateRoot: PARENT,
    newStateRoot: b32('99'),
    patchHash: PATCH_HASH,
    evalReportHash: EVAL_HASH,
    coreVersionHash: CORE_VERSION,
    corpusRoot: CORPUS,
    activeFrontierRoot: FRONTIER,
    improvementCredits: 0n,
    wordCount: 0,
    compactPatchBytes: PATCH_BYTES,
    ...overrides,
  };
}

/** An eval-report-artifact-shaped object the binding check inspects. */
function makeArtifact(overrides = {}) {
  return {
    artifactHash: EVAL_HASH,
    evalReportHash: EVAL_HASH,
    epochId: EPOCH,
    minerAddress: MINER,
    outcome: 'STATE_ADVANCE',
    seedDerivation: { patchHash: SEMANTIC_PATCH_HASH },
    context: { parentStateRoot: PARENT, corpusRoot: CORPUS, coreVersionHash: CORE_VERSION },
    ...overrides,
  };
}

// ── Finding 4: bind eval artifact to the decoded on-chain advance ─────────────

describe('Finding 4 — assertArtifactBoundToAdvance', () => {
  test('a fully matching artifact + advance binds cleanly', () => {
    assert.doesNotThrow(() => assertArtifactBoundToAdvance(makeArtifact(), makeAdvance()));
  });

  test('a wrong epoch is rejected before scoring', () => {
    assert.throws(
      () => assertArtifactBoundToAdvance(makeArtifact({ epochId: 8 }), makeAdvance()),
      /epochId 8 != advance epoch 7/,
    );
  });

  test('a wrong seedDerivation.patchHash is rejected', () => {
    assert.throws(
      () => assertArtifactBoundToAdvance(makeArtifact({ seedDerivation: { patchHash: b32('ee') } }), makeAdvance()),
      /seedDerivation\.patchHash .* != semantic advance patchHash/,
    );
  });

  test('B1: the artifact binds via the SEMANTIC hash across the coordinator scoreDelta rewrite', () => {
    // Same word writes, a DIFFERENT rewritten scoreDelta → different literal
    // on-chain patchHash, but the SAME semantic hash → binds to the same artifact.
    const rewritten2 = encodePatch({ ...PATCH_BASE, scoreDelta: 7777n });
    const advance2 = makeAdvance({
      compactPatchBytes: rewritten2,
      patchHash: computePatchHash(rewritten2),
    });
    assert.notEqual(computePatchHash(rewritten2).toLowerCase(), PATCH_HASH.toLowerCase());
    assert.doesNotThrow(() => assertArtifactBoundToAdvance(makeArtifact(), advance2));
    // The literal on-chain hash must NOT be what the artifact carries.
    assert.notEqual(SEMANTIC_PATCH_HASH.toLowerCase(), PATCH_HASH.toLowerCase());
  });

  test('an advance whose patchHash does not match its compactPatchBytes is rejected', () => {
    // event.patchHash is a lie (not the hash of compactPatchBytes).
    assert.throws(
      () => assertArtifactBoundToAdvance(makeArtifact({ seedDerivation: { patchHash: b32('ee') } }), makeAdvance({ patchHash: b32('ee') })),
      /advance patchHash .* != recomputed .* from event compactPatchBytes/,
    );
  });

  test('a wrong corpusRoot is rejected', () => {
    assert.throws(
      () => assertArtifactBoundToAdvance(makeArtifact({ context: { parentStateRoot: PARENT, corpusRoot: b32('ab'), coreVersionHash: CORE_VERSION } }), makeAdvance()),
      /context\.corpusRoot .* != advance corpusRoot/,
    );
  });

  test('a wrong miner is rejected', () => {
    assert.throws(
      () => assertArtifactBoundToAdvance(makeArtifact({ minerAddress: addr('bb') }), makeAdvance()),
      /minerAddress .* != advance miner/,
    );
  });
});

// ── Finding 8: per-epoch context selection ────────────────────────────────────

describe('Finding 8 — selectScorerContextForAdvance', () => {
  const loaded = { corpusRoot: CORPUS, coreVersionHash: CORE_VERSION };

  test('rescore when the advance pins match the loaded context', () => {
    assert.deepEqual(
      selectScorerContextForAdvance({ corpusRoot: CORPUS, coreVersionHash: CORE_VERSION }, loaded),
      { action: 'rescore' },
    );
  });

  test('a differing pinned corpus is NOT rescored — left pending with a clear reason', () => {
    const sel = selectScorerContextForAdvance({ corpusRoot: b32('ab'), coreVersionHash: CORE_VERSION }, loaded);
    assert.equal(sel.action, 'pending');
    assert.equal(sel.reason, 'epoch-context-unavailable');
    assert.match(sel.detail, /corpusRoot .* != loaded/);
  });

  test('a differing pinned coreVersion is NOT rescored — left pending', () => {
    const sel = selectScorerContextForAdvance({ corpusRoot: CORPUS, coreVersionHash: b32('ef') }, loaded);
    assert.equal(sel.action, 'pending');
    assert.match(sel.detail, /coreVersionHash .* != loaded/);
  });
});

// ── Finding 5: persisted pending-eval backlog ─────────────────────────────────

describe('Finding 5 — eval-verification backlog', () => {
  test('an advance is converted to a pending backlog entry', () => {
    const entry = evalBacklogEntryFromAdvance(makeAdvance(), 1000, 'awaiting_epoch_secret_reveal');
    assert.equal(entry.epochId, EPOCH);
    assert.equal(entry.advanceBlock, 1000);
    assert.equal(entry.artifactHash, EVAL_HASH);
    assert.equal(entry.reason, 'awaiting_epoch_secret_reveal');
    assert.equal(entry.parentStateRoot, PARENT);
    assert.equal(entry.corpusRoot, CORPUS);
  });

  test('upsert preserves existing entries and never drops them', () => {
    const a = evalBacklogEntryFromAdvance(makeAdvance(), 100, 'awaiting_epoch_secret_reveal');
    const b = evalBacklogEntryFromAdvance(makeAdvance({ evalReportHash: b32('ee'), epoch: 8n }), 200, 'awaiting_epoch_secret_reveal');
    const merged = upsertEvalBacklog([a], [b]);
    assert.equal(merged.length, 2);
    // re-observing 'a' with a different advanceBlock keeps the original block.
    const reobs = upsertEvalBacklog(merged, [{ ...a, advanceBlock: 999, reason: 'epoch-context-unavailable' }]);
    assert.equal(reobs.length, 2);
    const stillA = reobs.find((e) => evalBacklogKey(e) === evalBacklogKey(a));
    assert.equal(stillA.advanceBlock, 100);
    assert.equal(stillA.reason, 'epoch-context-unavailable');
  });

  test('an entry is removed ONLY by an explicit (passing-replay) removal', () => {
    const a = evalBacklogEntryFromAdvance(makeAdvance(), 100, 'awaiting_epoch_secret_reveal');
    const b = evalBacklogEntryFromAdvance(makeAdvance({ evalReportHash: b32('ee') }), 200, 'awaiting_epoch_secret_reveal');
    const backlog = upsertEvalBacklog([], [a, b]);
    const afterPass = removeFromEvalBacklog(backlog, a);
    assert.equal(afterPass.length, 1);
    assert.equal(evalBacklogKey(afterPass[0]), evalBacklogKey(b));
    // removing a not-present key is a no-op (never throws / never drops others).
    assert.equal(removeFromEvalBacklog(afterPass, a).length, 1);
  });

  test('pending entries round-trip through the persisted state file', () => withTmpDir((dir) => {
    const statePath = join(dir, 'client-sync-state.json');
    const entry = evalBacklogEntryFromAdvance(makeAdvance(), 100, 'awaiting_epoch_secret_reveal');
    // sync 1 leaves an advance pending (secret unrevealed) → persisted to backlog.
    writeFileSync(statePath, serializeMergedValidatorState(statePath, {
      evalBacklog: [entry],
      evalVerifiedThroughBlock: -1,
    }));
    const reloaded = JSON.parse(readFileSync(statePath, 'utf8'));
    assert.equal(reloaded.evalBacklog.length, 1);
    assert.equal(reloaded.evalBacklog[0].artifactHash, EVAL_HASH);
    assert.equal(reloaded.evalVerifiedThroughBlock, -1);
    // sync 2 after reveal drains it (passing replay) and advances the cursor.
    const drained = removeFromEvalBacklog(reloaded.evalBacklog, entry);
    writeFileSync(statePath, serializeMergedValidatorState(statePath, {
      evalBacklog: drained,
      evalVerifiedThroughBlock: 100,
    }));
    const after = JSON.parse(readFileSync(statePath, 'utf8'));
    assert.equal(after.evalBacklog.length, 0);
    assert.equal(after.evalVerifiedThroughBlock, 100);
  }));
});

// ── Finding 6: confirmed-tag consistency ──────────────────────────────────────

describe('Finding 6 — readChainContext reads everything at ONE confirmed tag', () => {
  const REGISTRY = addr('11');
  const MINING = addr('22');
  const COMMIT = b32('33');
  const CONFIRMED_LIVE_ROOT = b32('aa'); // matches the confirmed-head logs
  const LATEST_LIVE_ROOT = b32('bb'); // a new advance landed at 'latest'
  const CONFIRMED_TAG = '0x64'; // block 100

  function addressWord(a) {
    return `0x${'00'.repeat(12)}${a.slice(2).toLowerCase()}`;
  }

  // A fake chain whose liveStateRoot at 'latest' is AHEAD of the confirmed head.
  function fakeCaller({ secret = b32('55') } = {}) {
    return async ({ to, signature, blockTag }) => {
      if (to.toLowerCase() === MINING) {
        if (signature === 'coreTexRegistry()') return addressWord(REGISTRY);
        if (signature === 'coreTexEpochContextSet(uint64)') return `0x${'00'.repeat(31)}01`;
        if (signature === 'epochCommit(uint64)') return COMMIT;
        if (signature === 'epochSecret(uint64)') return secret;
      }
      if (to.toLowerCase() === REGISTRY) {
        if (signature === 'liveStateRoot(uint64)') {
          // The race: 'latest' is ahead of the confirmed head.
          return blockTag === 'latest' ? LATEST_LIVE_ROOT : CONFIRMED_LIVE_ROOT;
        }
        if (signature === 'epochParentStateRoot(uint64)') return PARENT;
        if (signature === 'transitionCount(uint64)') return `0x${'00'.repeat(31)}01`;
        if (signature === 'epochCoreVersionHash(uint64)') return CORE_VERSION;
        if (signature === 'epochCorpusRoot(uint64)') return CORPUS;
        if (signature === 'epochActiveFrontierRoot(uint64)') return FRONTIER;
        if (signature === 'epochBaselineManifestHash(uint64)') return b32('66');
        if (signature === 'epochHiddenSeedCommit(uint64)') return COMMIT;
      }
      throw new Error(`unexpected call ${to} ${signature} @ ${blockTag}`);
    };
  }

  test('liveStateRoot is read at the confirmed head, NOT at the ahead-of-head latest', async () => {
    const chain = await readChainContext(fakeCaller({ secret: `0x${'00'.repeat(32)}` }), REGISTRY, MINING, EPOCH, CONFIRMED_TAG);
    // The value the replayed root will be compared against matches the
    // confirmed-head logs — a new 'latest' advance does NOT cause a false drift.
    assert.equal(chain.liveStateRoot, CONFIRMED_LIVE_ROOT);
    assert.notEqual(chain.liveStateRoot, LATEST_LIVE_ROOT);
  });

  test('every pin comes from the confirmed tag (no read leaks to latest)', async () => {
    const tagsSeen = new Set();
    const wrapped = async (input) => {
      tagsSeen.add(input.blockTag);
      return fakeCaller({ secret: `0x${'00'.repeat(32)}` })(input);
    };
    await readChainContext(wrapped, REGISTRY, MINING, EPOCH, CONFIRMED_TAG);
    assert.deepEqual([...tagsSeen], [CONFIRMED_TAG]);
  });
});

// ── Finding 7: atomic trust/state writes ──────────────────────────────────────

describe('Finding 7 — TrustedStateStaging atomic commit/dispose', () => {
  test('a failed mandatory check (dispose without commit) leaves prior files byte-unchanged', () => withTmpDir((dir) => {
    const pinPath = join(dir, 'epoch-signing-key.pin.json');
    const statePath = join(dir, 'client-sync-state.json');
    const snapPath = join(dir, 'substrate-state.bin');
    // Prior trusted state on disk.
    const priorPin = serializeTofuKeyPin('-----BEGIN PUBLIC KEY-----\nPRIOR\n-----END PUBLIC KEY-----\n').body;
    const priorState = '{"schema":"coretex.client-sync-state.v1","prior":true}\n';
    const priorSnap = Buffer.from([9, 9, 9]);
    writeFileSync(pinPath, priorPin);
    writeFileSync(statePath, priorState);
    writeFileSync(snapPath, priorSnap);

    const staging = new TrustedStateStaging();
    staging.stage(pinPath, serializeTofuKeyPin('-----BEGIN PUBLIC KEY-----\nNEW\n-----END PUBLIC KEY-----\n').body);
    staging.stage(snapPath, Buffer.from([1, 2, 3]));
    staging.stage(statePath, '{"schema":"coretex.client-sync-state.v1","new":true}\n');
    // Simulate a mandatory check throwing BEFORE commit: dispose only.
    staging.dispose();

    // Nothing in trusted state was mutated.
    assert.equal(readFileSync(pinPath, 'utf8'), priorPin);
    assert.equal(readFileSync(statePath, 'utf8'), priorState);
    assert.deepEqual(readFileSync(snapPath), priorSnap);
    // No leftover temp files.
    assert.equal(existsSync(`${pinPath}.tmp-${process.pid}-0`), false);
  }));

  test('commit applies every staged write together', () => withTmpDir((dir) => {
    const pinPath = join(dir, 'pin.json');
    const statePath = join(dir, 'state.json');
    const snapPath = join(dir, 'snap.bin');
    const staging = new TrustedStateStaging();
    staging.stage(pinPath, 'PIN');
    staging.stage(snapPath, Buffer.from([7, 7]));
    staging.stage(statePath, 'STATE');
    // Before commit, nothing exists at the destinations.
    assert.equal(existsSync(pinPath), false);
    assert.equal(existsSync(statePath), false);
    staging.commit();
    assert.equal(readFileSync(pinPath, 'utf8'), 'PIN');
    assert.equal(readFileSync(statePath, 'utf8'), 'STATE');
    assert.deepEqual(readFileSync(snapPath), Buffer.from([7, 7]));
  }));

  test('dispose after commit is a safe no-op', () => withTmpDir((dir) => {
    const p = join(dir, 'x');
    const staging = new TrustedStateStaging();
    staging.stage(p, 'A');
    staging.commit();
    assert.doesNotThrow(() => staging.dispose());
    assert.equal(readFileSync(p, 'utf8'), 'A');
  }));
});

// ── Runtime-pin assertion ─────────────────────────────────────────────────────

describe('runtime-pin — scorer fingerprint must match the bundle reranker pins', () => {
  const PINS = {
    modelId: 'Qwen/Qwen3-Reranker-0.6B',
    revision: 'e61197ed45024b0ed8a2d74b80b4d909f1255473',
    torchRange: '2.6.*',
    transformersRange: '4.55.*',
    buildFlags: ['cpu-only'],
  };
  const RESOLVED = {
    modelId: PINS.modelId,
    revision: PINS.revision,
    promptTemplateHash: b32('77'),
  };
  const HEALTH = { torch: '2.6.0+cpu', transformers: '4.55.0', cuda: false, dtype: 'fp32', tf32: false };

  test('scorerVersionMatchesRange accepts wheel build suffixes against X.Y.*', () => {
    assert.equal(scorerVersionMatchesRange('2.6.0+cpu', '2.6.*'), true);
    assert.equal(scorerVersionMatchesRange('4.55.0', '4.55.*'), true);
    assert.equal(scorerVersionMatchesRange('2.7.0', '2.6.*'), false);
    assert.equal(scorerVersionMatchesRange('4.56.0', '4.55.*'), false);
  });

  test('a matching runtime + resolved identity passes', () => {
    assert.deepEqual(scorerRuntimeMatchesBundle(HEALTH, PINS, RESOLVED), { ok: true });
  });

  test('a missing health probe is a hard mismatch', () => {
    const v = scorerRuntimeMatchesBundle(null, PINS, RESOLVED);
    assert.equal(v.ok, false);
    assert.match(v.reason, /--health probe failed/);
  });

  test('a wrong torch version is rejected', () => {
    const v = scorerRuntimeMatchesBundle({ ...HEALTH, torch: '2.7.0' }, PINS, RESOLVED);
    assert.equal(v.ok, false);
    assert.match(v.reason, /torch 2\.7\.0 does not match bundle runtimePin 2\.6\.\*/);
  });

  test('active CUDA against a cpu-only bundle is rejected', () => {
    const v = scorerRuntimeMatchesBundle({ ...HEALTH, cuda: true }, PINS, RESOLVED);
    assert.equal(v.ok, false);
    assert.match(v.reason, /CUDA is active but the bundle runtimePin is cpu-only/);
  });

  test('TF32 enabled is rejected (fp32-exact contract)', () => {
    const v = scorerRuntimeMatchesBundle({ ...HEALTH, tf32: true }, PINS, RESOLVED);
    assert.equal(v.ok, false);
    assert.match(v.reason, /TF32 matmul is enabled/);
  });

  test('a non-fp32 dtype is rejected', () => {
    const v = scorerRuntimeMatchesBundle({ ...HEALTH, dtype: 'bf16' }, PINS, RESOLVED);
    assert.equal(v.ok, false);
    assert.match(v.reason, /dtype bf16 != fp32/);
  });

  test('a wrong resolved model revision is rejected', () => {
    const v = scorerRuntimeMatchesBundle(HEALTH, PINS, { ...RESOLVED, revision: 'deadbeef' });
    assert.equal(v.ok, false);
    assert.match(v.reason, /resolved reranker revision deadbeef != bundle pin/);
  });

  test('a pinned promptTemplateHash mismatch is rejected', () => {
    const v = scorerRuntimeMatchesBundle(HEALTH, { ...PINS, promptTemplateHash: b32('88') }, RESOLVED);
    assert.equal(v.ok, false);
    assert.match(v.reason, /prompt-template hash .* != bundle pin/);
  });

  test('scorerRuntimeBundlePinsFromManifest reads torch/transformers ranges + reranker pins', () => {
    const pins = scorerRuntimeBundlePinsFromManifest({
      model: { reranker: { modelId: PINS.modelId, revision: PINS.revision } },
      evaluator: { profile: { runtimePin: { versions: { torch: '2.6.*', transformers: '4.55.*' }, buildFlags: ['cpu-only'] } } },
    });
    assert.equal(pins.modelId, PINS.modelId);
    assert.equal(pins.torchRange, '2.6.*');
    assert.equal(pins.transformersRange, '4.55.*');
    assert.deepEqual(pins.buildFlags, ['cpu-only']);
  });

  test('a bundle without a runtimePin is a hard error (no unpinned runtime)', () => {
    assert.throws(
      () => scorerRuntimeBundlePinsFromManifest({ model: { reranker: { modelId: 'x', revision: 'y' } } }),
      /no runtimePin\.versions\.torch\/transformers/,
    );
  });
});
