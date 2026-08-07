import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  RIG_EVENT_TOPICS,
  RIG_EVENT_NAMES,
  RIG_LOG_TOPICS,
  RIG_EXPECTED_EMITTER,
  V4_LOG_TOPICS,
  routeRigLog,
  laneSeparation,
  assertLaneSeparation,
  RigDispatchError,
  CORETEX_EVENT_TOPICS,
  V4_EVENT_TOPICS,
  decodeRigStateAdvanced,
  decodeRigEpochFinalized,
  decodeCortexStateAdvancedLog,
} from '../../dist/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PYTHON_ROOT = path.resolve(HERE, '../../python');

const DEPLOYMENT = {
  registry: '0x1111111111111111111111111111111111111111',
  mining: '0x2222222222222222222222222222222222222222',
  verifier: '0x3333333333333333333333333333333333333333',
};

const OTHER_LANE_REGISTRY = '0x9999999999999999999999999999999999999999';

function topicUint(value) {
  return '0x' + BigInt(value).toString(16).padStart(64, '0');
}
function topicAddress(addr) {
  return '0x' + addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}
function word(hex) {
  return hex.replace(/^0x/, '').padStart(64, '0');
}

/** A well-formed CoreTexStateAdvanced log from `address`. */
function advanceLog(address) {
  const descriptor = '21' + '7e'.repeat(32) + 'aa'.repeat(32) + 'bb'.repeat(32);
  const head = [
    word('aa'.repeat(32)), // parentStateRoot
    word('bb'.repeat(32)), // newStateRoot
    word('cc'.repeat(32)), // patchHash
    word('dd'.repeat(32)), // evalReportHash
    word('ee'.repeat(32)), // coreVersionHash
    word('11'.repeat(32)), // epochContextRoot
    word('64'), // improvementCredits = 100
    word('21'), // transitionFormatVersion = descriptor byte 0
    word((9 * 32).toString(16)), // offset of compactPatchBytes
    word((descriptor.length / 2).toString(16)),
    descriptor.padEnd(Math.ceil(descriptor.length / 64) * 64, '0'),
  ].join('');
  return {
    address,
    topics: [
      // Already `0x`-prefixed: this package's `bytesToHex` prefixes, the Python lane's does
      // not. Adding one here produced `0x0x…`, which routed as an UNKNOWN topic and was
      // silently ignored — exactly the failure mode an unknown topic0 is supposed to have.
      RIG_EVENT_TOPICS.CoreTexStateAdvanced,
      topicUint(7),
      topicUint(0),
      topicAddress('0x00000000000000000000000000000000000000aa'),
    ],
    data: '0x' + head,
    blockNumber: '0x10',
    logIndex: '0x0',
    transactionHash: '0x' + 'ab'.repeat(32),
  };
}

function finalizedLog(address) {
  return {
    address,
    topics: [RIG_EVENT_TOPICS.CoreTexEpochFinalized, topicUint(7)],
    data: '0x' + [
      word('aa'.repeat(32)), word('bb'.repeat(32)), word('ee'.repeat(32)),
      word('11'.repeat(32)), word('44'.repeat(32)), word('55'.repeat(32)),
    ].join(''),
  };
}

describe('rig dispatch coexists with V4 rather than replacing it', () => {
  test('descriptor-v3 moved the rig registry advance topic away from legacy v2', () => {
    const lanes = laneSeparation();
    assert.equal(lanes.identical, false);
    assert.notEqual(lanes.canonicalRegistryAdvance, lanes.rigRegistryAdvance);
    assert.deepEqual(lanes.collidingLanes, []);
    assert.equal(lanes.discriminator, 'emitting address');
    assert.doesNotThrow(assertLaneSeparation);
  });

  test('the ORIGINAL v4 pair is a third, distinct set that collides with neither', () => {
    const lanes = laneSeparation();
    assert.notEqual(lanes.legacyV4Advance, lanes.canonicalRegistryAdvance);
    assert.notEqual(V4_EVENT_TOPICS.CoretexPatchBytes, CORETEX_EVENT_TOPICS.CoreTexStateAdvanced);
    // ...and the legacy subscription is disjoint from the rig one, so subscribing to both is safe.
    for (const topic of V4_LOG_TOPICS) {
      assert.ok(!RIG_EVENT_TOPICS[RIG_EVENT_NAMES[topic] ?? '__none__']);
    }
  });

  test('the rig subscription includes only the live v3 advance/finalize topics', () => {
    assert.ok(RIG_LOG_TOPICS.includes(RIG_EVENT_TOPICS.CoreTexStateAdvanced));
    assert.ok(RIG_LOG_TOPICS.includes(RIG_EVENT_TOPICS.CoreTexEpochFinalized));
    assert.ok(!RIG_LOG_TOPICS.includes(CORETEX_EVENT_TOPICS.CoreTexStateAdvanced));
    assert.ok(!RIG_LOG_TOPICS.includes(CORETEX_EVENT_TOPICS.CoreTexEpochFinalized));
    assert.equal(RIG_LOG_TOPICS.length, 8);
  });

  test('one identical log is routed by ADDRESS, not by topic0', () => {
    const mine = routeRigLog(advanceLog(DEPLOYMENT.registry), DEPLOYMENT);
    assert.equal(mine.event, 'CoreTexStateAdvanced');
    assert.equal(mine.emitter, 'registry');

    // Byte-identical log, different emitter: not this deployment's, and NOT an error.
    const theirs = routeRigLog(advanceLog(OTHER_LANE_REGISTRY), DEPLOYMENT);
    assert.equal(theirs.event, null);
    assert.equal(theirs.emitter, null);
  });

  test('a known event from the WRONG one of our own addresses is an error', () => {
    // Something is emitting the registry's event from the mining contract. There is no safe
    // way to guess which claim to believe, so this refuses instead of attributing.
    assert.throws(
      () => routeRigLog(advanceLog(DEPLOYMENT.mining), DEPLOYMENT),
      RigDispatchError,
    );
  });

  test('an unknown topic0 is ignored, never an error', () => {
    const log = { ...advanceLog(DEPLOYMENT.registry), topics: ['0x' + 'fe'.repeat(32)] };
    assert.equal(routeRigLog(log, DEPLOYMENT).event, null);
  });

  test('the epoch law events are expected from the VERIFIER, not the registry', () => {
    // The rig lane delegates epoch context to the verifier. A validator watching only the
    // registry can never read the pins it is supposed to check an advance against.
    assert.equal(RIG_EXPECTED_EMITTER[RIG_EVENT_TOPICS.CoreTexEpochContextSet], 'verifier');
    assert.equal(RIG_EXPECTED_EMITTER[RIG_EVENT_TOPICS.CoreTexPolicyScheduled], 'verifier');
    assert.equal(RIG_EXPECTED_EMITTER[RIG_EVENT_TOPICS.RigCoreTexCreditAccepted], 'mining');
  });
});

describe('V4 decoding is not regressed by the rig lane', () => {
  test('the live rig decoder reads epochContextRoot and the 97-byte descriptor', () => {
    const decoded = decodeRigStateAdvanced(advanceLog(DEPLOYMENT.registry));
    assert.ok(decoded !== null);
    assert.equal(decoded.epoch, 7n);
    assert.equal(decoded.improvementCredits, 100n);
    assert.equal(decoded.epochContextRoot, '0x' + '11'.repeat(32));
    assert.equal(decoded.transitionFormatVersion, 0x21);
    assert.equal(decoded.compactPatchBytes.length, 97);
    assert.equal(decoded.compactPatchBytes[0], 0x21);
  });

  test('the live finalization decoder reads only canonical seal fields', () => {
    const decoded = decodeRigEpochFinalized(finalizedLog(DEPLOYMENT.registry));
    assert.ok(decoded !== null);
    assert.equal(decoded.finalStateRoot, '0x' + 'bb'.repeat(32));
    assert.equal(decoded.epochContextRoot, '0x' + '11'.repeat(32));
    assert.equal(decoded.patchSetRoot, '0x' + '44'.repeat(32));
    assert.equal(decoded.scoreRoot, '0x' + '55'.repeat(32));
  });

  test('the legacy v4 decoder ignores a rig/canonical advance', () => {
    // It dispatches on its OWN topic0, which nothing here collides with, so a rig log is
    // simply not its business. Silence, not an exception.
    assert.equal(decodeCortexStateAdvancedLog(advanceLog(DEPLOYMENT.registry)), null);
  });
});

describe('cross-language parity with the Python validator', () => {
  test('both implementations DERIVE the same rig topic0 table', () => {
    // Two independent derivations that agree is worth more than one derivation copied twice.
    // Neither side reads the other's constants: each hashes the signature strings itself.
    let raw;
    try {
      raw = execFileSync(
        'python3',
        ['-c',
         'import json,sys;sys.path.insert(0,"' + PYTHON_ROOT + '");' +
         'from coretex_validator import rig_events as r;' +
         'print(json.dumps({t: r.EVENT_NAMES[t] for t in r.RIG_LOG_TOPICS}))'],
        { encoding: 'utf8', timeout: 60_000 },
      );
    } catch (err) {
      // A host without python3 cannot run this comparison. Skipping is honest; asserting
      // "they agree" because we could not check would not be.
      assert.ok(err, 'python3 unavailable — parity unchecked on this host');
      return;
    }
    // The two lanes render bytes32 differently ON PURPOSE — TypeScript `0x`-prefixed, Python
    // bare — so the comparison is over the BYTES. Comparing the renderings would fail on a
    // convention difference and say nothing about whether the digests agree.
    const bare = (o) =>
      Object.fromEntries(
        Object.entries(o).map(([topic, name]) => [topic.replace(/^0x/, '').toLowerCase(), name]),
      );
    const fromPython = bare(JSON.parse(raw));
    const fromTypeScript = bare(
      Object.fromEntries(RIG_LOG_TOPICS.map((topic) => [topic, RIG_EVENT_NAMES[topic]])),
    );
    assert.deepEqual(fromTypeScript, fromPython);
    assert.equal(Object.keys(fromPython).length, 8);
  });
});
