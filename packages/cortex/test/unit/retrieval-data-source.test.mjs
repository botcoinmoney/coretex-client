import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { createRetrievalDataSource } from '../../dist/index.js';

const BUNDLE_HASH = `0x${'ab'.repeat(32)}`;
const ALT_BUNDLE_HASH = `0x${'cd'.repeat(32)}`;

function fixtureManifest(bundleHash = BUNDLE_HASH) {
  return { bundleHash };
}

function makeFactoryOpts(overrides = {}) {
  return {
    bundleManifest: fixtureManifest(),
    bundleHash: BUNDLE_HASH,
    getChallenge: () => ({
      lane: 'coretex',
      challengeId: `0x${'11'.repeat(32)}`,
      expiresAt: 1_760_000_000,
      epochId: 7,
      parentStateRoot: `0x${'22'.repeat(32)}`,
      substrate: {
        encoding: 'coretex-packed-substrate-v1',
        uri: `/coretex/substrate/0x${'22'.repeat(32)}`,
      },
    }),
    submit: () => ({
      status: 'accepted',
      patchHash: `0x${'33'.repeat(32)}`,
      evalReportHash: `0x${'44'.repeat(32)}`,
      receipt: { sig: '0xabc' },
      scoreAfterPpm: 999_999, // must be stripped by sanitizer
    }),
    getStatus: () => ({
      lane: 'coretex',
      epochId: 7,
      stateRoot: `0x${'55'.repeat(32)}`,
      wordCount: 1024,
      transitionCount: 12,
      rulesVersion: 192,
      workPolicyHash: `0x${'66'.repeat(32)}`,
      corpusRoot: `0x${'77'.repeat(32)}`,
      minImprovementPpm: 2500,
      evalSeedCommit: `0x${'88'.repeat(32)}`,
      substrate: { uri: `/coretex/substrate/0x${'55'.repeat(32)}` },
      bundle: { uri: `/coretex/bundle/${BUNDLE_HASH}` },
    }),
    ...overrides,
  };
}

describe('createRetrievalDataSource', () => {
  test('refuses bundle hash that disagrees with manifest', () => {
    assert.throws(
      () => createRetrievalDataSource({
        ...makeFactoryOpts(),
        bundleManifest: fixtureManifest(ALT_BUNDLE_HASH),
      }),
      /bundle manifest hash/,
    );
  });

  test('passes challenge/submit/status through to host callbacks', async () => {
    const seen = [];
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getChallenge: () => {
        seen.push(['challenge']);
        return {
          lane: 'coretex',
          challengeId: `0x${'aa'.repeat(32)}`,
          expiresAt: 1_760_000_000,
          epochId: 8,
          parentStateRoot: `0x${'bb'.repeat(32)}`,
          coreVersionHash: BUNDLE_HASH,
          substrate: {
            encoding: 'coretex-packed-substrate-v1',
            bytes: '0x1234',
          },
        };
      },
      submit: (body) => { seen.push(['submit', body]); return { accepted: false, patchHash: `0x${'cc'.repeat(32)}`, score: 42 }; },
      getStatus: () => {
        seen.push(['status']);
        return {
          lane: 'coretex',
          epochId: 8,
          stateRoot: `0x${'dd'.repeat(32)}`,
          wordCount: 1024,
          transitionCount: 13,
          rulesVersion: 192,
          workPolicyHash: `0x${'ee'.repeat(32)}`,
          corpusRoot: `0x${'ff'.repeat(32)}`,
          coreVersionHash: BUNDLE_HASH,
          minImprovementPpm: 2500,
          evalSeedCommit: `0x${'01'.repeat(32)}`,
          substrate: { uri: `/coretex/substrate/0x${'dd'.repeat(32)}` },
          bundle: { uri: `/coretex/bundle/${BUNDLE_HASH}` },
        };
      },
    }));
    const c = await ds.getChallenge();
    const s = await ds.submit({ patch: '0x1234' });
    const st = await ds.getStatus();
    assert.deepEqual(seen, [
      ['challenge'],
      ['submit', { patch: '0x1234' }],
      ['status'],
    ]);
    assert.equal(c.bundleHash, BUNDLE_HASH);
    assert.equal(c.coreVersionHash, BUNDLE_HASH);
    assert.deepEqual(s, { status: 'rejected', code: 'rejected', patchHash: `0x${'cc'.repeat(32)}` });
    assert.equal(st.bundleHash, BUNDLE_HASH);
    assert.equal(st.coreVersionHash, BUNDLE_HASH);
    assert.ok(typeof st.statusVersion === 'string' && st.statusVersion.startsWith('0x'));
  });

  test('fails closed on malformed challenge/status responses', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getChallenge: () => ({ lane: 'coretex' }),
      getStatus: () => ({ lane: 'coretex' }),
    }));
    assert.deepEqual(await ds.getChallenge(), { error: 'coretex-challenge-malformed' });
    assert.deepEqual(await ds.getStatus(), { error: 'coretex-status-malformed' });
  });

  test('submit response collapses to opaque rejection/accepted envelope', async () => {
    const rejected = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({ status: 'rejected', reason: 'too-low', perFamilyDelta: { temporal: -0.9 } }),
    }));
    assert.deepEqual(await rejected.submit({}), { status: 'rejected', code: 'rejected' });

    const accepted = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({
        status: 'accepted',
        patchHash: `0x${'99'.repeat(32)}`,
        evalReportHash: `0x${'aa'.repeat(32)}`,
        receipt: { sig: '0xdeadbeef' },
        scoreBeforePpm: 10,
        scoreAfterPpm: 999999,
      }),
    }));
    assert.deepEqual(await accepted.submit({}), {
      status: 'accepted',
      patchHash: `0x${'99'.repeat(32)}`,
      evalReportHash: `0x${'aa'.repeat(32)}`,
      receipt: { sig: '0xdeadbeef' },
    });
  });

  test('receipt envelope strips non-signature fields (anti-leak)', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({
        status: 'accepted',
        patchHash: `0x${'99'.repeat(32)}`,
        receipt: {
          // legitimate signature envelope
          keyId: 'coordinator-mainnet-v1',
          algorithm: 'ECDSA-SHA256',
          signature: '0xdeadbeefcafe',
          signedFields: ['patchHash', 'receivedAtBlock'],
          // ALL of these must be stripped — they leak retrieval signals
          scoreAfterPpm: 999_999,
          perFamilyDelta: { temporal: -0.9 },
          rawScore: 0.8732,
          retrievalConfidence: 0.42,
        },
      }),
    }));
    const out = await ds.submit({});
    assert.equal(out.status, 'accepted');
    assert.deepEqual(out.receipt, {
      keyId: 'coordinator-mainnet-v1',
      algorithm: 'ECDSA-SHA256',
      signature: '0xdeadbeefcafe',
      signedFields: ['patchHash', 'receivedAtBlock'],
    });
  });

  test('receipt with invalid algorithm/signature is dropped (not raw-passthrough)', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      submit: () => ({
        status: 'accepted',
        patchHash: `0x${'99'.repeat(32)}`,
        receipt: {
          algorithm: 'MD5', // not in allow-list
          signature: 'not-hex',
        },
      }),
    }));
    const out = await ds.submit({});
    assert.equal(out.status, 'accepted');
    assert.equal(out.receipt, undefined);
  });

  test('getPatchReceivedNotice enforces strict field shape (replay-watcher safety)', async () => {
    const goodNotice = {
      patchHash: `0x${'aa'.repeat(32)}`,
      receivedAtBlock: 12345,
      receivedAtTimestamp: 1_760_000_000,
      coordinatorAddress: `0x${'bb'.repeat(20)}`,
      // host may attach signer envelope; allowed but limited to sig fields
      signer: { keyId: 'k1', algorithm: 'ECDSA-SHA256', signature: '0xdead' },
      // any other field stripped (e.g. score-leaking detail)
      perFamilyDelta: { temporal: -0.1 },
    };
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getPatchReceivedNotice: () => goodNotice,
    }));
    const out = await ds.getPatchReceivedNotice('0x' + '11'.repeat(32));
    assert.deepEqual(out, {
      patchHash: `0x${'aa'.repeat(32)}`,
      receivedAtBlock: 12345,
      receivedAtTimestamp: 1_760_000_000,
      coordinatorAddress: `0x${'bb'.repeat(20)}`,
      signer: { keyId: 'k1', algorithm: 'ECDSA-SHA256', signature: '0xdead' },
    });

    const dsMalformed = createRetrievalDataSource(makeFactoryOpts({
      getPatchReceivedNotice: () => ({ patchHash: '0xbad' }),
    }));
    const out2 = await dsMalformed.getPatchReceivedNotice('0x' + '11'.repeat(32));
    assert.deepEqual(out2, { error: 'coretex-patch-received-notice-malformed' });
  });

  test('status URI envelope rejects arbitrary /coretex/* paths (no host-side redirects)', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getStatus: () => ({
        lane: 'coretex',
        epochId: 9,
        stateRoot: `0x${'55'.repeat(32)}`,
        wordCount: 1024,
        transitionCount: 1,
        rulesVersion: 192,
        workPolicyHash: `0x${'66'.repeat(32)}`,
        corpusRoot: `0x${'77'.repeat(32)}`,
        minImprovementPpm: 2500,
        evalSeedCommit: `0x${'88'.repeat(32)}`,
        substrate: { uri: `/coretex/admin-dashboard` }, // not an immutable artifact
        bundle: { uri: `/coretex/bundle/${BUNDLE_HASH}` },
      }),
    }));
    const out = await ds.getStatus();
    assert.deepEqual(out, { error: 'coretex-status-malformed' });
  });

  test('default health response carries bundleHash + serverTime', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const out = await ds.health();
    assert.equal(out.ok, true);
    assert.equal(out.service, 'coretex');
    assert.equal(out.bundleHash, BUNDLE_HASH);
    assert.ok(typeof out.serverTime === 'string' && out.serverTime.includes('T'));
  });

  test('returns the bundle manifest only for the matching hash', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const ok = await ds.getBundle(BUNDLE_HASH);
    assert.equal(ok.bundleHash, BUNDLE_HASH);
    const ok2 = await ds.getBundle(BUNDLE_HASH.toUpperCase());
    assert.equal(ok2.bundleHash, BUNDLE_HASH);

    const wrong = await ds.getBundle(ALT_BUNDLE_HASH);
    assert.deepEqual(wrong, { error: 'coretex-bundle-not-found', bundleHash: ALT_BUNDLE_HASH });
  });

  test('resolves bundle by coreVersionHash with default alias', async () => {
    const ds = createRetrievalDataSource(makeFactoryOpts());
    const ok = await ds.getBundleByCoreVersionHash(BUNDLE_HASH);
    assert.equal(ok.bundleHash, BUNDLE_HASH);
    const miss = await ds.getBundleByCoreVersionHash(ALT_BUNDLE_HASH);
    assert.deepEqual(miss, { error: 'coretex-bundle-not-found', coreVersionHash: ALT_BUNDLE_HASH });
  });

  test('forwards optional immutable artifact hooks when configured', async () => {
    const validNoticePatch = `0x${'cc'.repeat(32)}`;
    const ds = createRetrievalDataSource(makeFactoryOpts({
      getSubstrate: (root) => ({ stateRoot: root }),
      getPatch: (h) => ({ patch: h }),
      getPatchReceivedNotice: (h) => ({
        patchHash: h,
        receivedAtBlock: 123,
        receivedAtTimestamp: 1_760_000_000,
        coordinatorAddress: `0x${'dd'.repeat(20)}`,
      }),
      getEvalReport: (h) => ({ report: h }),
      getCorpusDelta: (epoch) => ({ delta: epoch.toString() }),
      getBundleByCoreVersionHash: (h) => ({ bundleByCoreVersion: h }),
      health: () => ({ ok: true }),
    }));
    assert.deepEqual(await ds.getSubstrate('0xabc'), { stateRoot: '0xabc' });
    assert.deepEqual(await ds.getPatch('0x111'), { patch: '0x111' });
    assert.deepEqual(await ds.getPatchReceivedNotice(validNoticePatch), {
      patchHash: validNoticePatch,
      receivedAtBlock: 123,
      receivedAtTimestamp: 1_760_000_000,
      coordinatorAddress: `0x${'dd'.repeat(20)}`,
    });
    assert.deepEqual(await ds.getEvalReport('0x222'), { report: '0x222' });
    assert.deepEqual(await ds.getCorpusDelta(8n), { delta: '8' });
    assert.deepEqual(await ds.getBundleByCoreVersionHash('0xc0re'), { bundleByCoreVersion: '0xc0re' });
    assert.deepEqual(await ds.health(), { ok: true });
  });
});
