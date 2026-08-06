/**
 * TS ↔ Solidity chain-mirror parity (cleanup-audit R2).
 *
 * Two hand-maintained mirrors of on-chain truth had no automated guard:
 *
 *   1. CORETEX_EVENT_TOPICS (replay/coretex-registry.ts) — topic hashes the
 *      client uses to decode CoreTexRegistry logs. Recomputed here from the
 *      event declarations parsed out of CoreTexRegistry.sol.
 *
 *   2. The CoreTexReceipt EIP-712 type string vs the CoreTexReceipt struct in
 *      BotcoinMiningV4.sol vs the field set the coordinator signs
 *      (CoreTexReceiptPayload in coordinator/coretex-coordinator-core.ts). Field
 *      ORDER in the type string is consensus-critical: drift = unredeemable
 *      receipts. The expected list below is the reviewed pin of the TS payload
 *      shape — update it ONLY together with CoreTexReceiptPayload, the struct,
 *      and the type string (a signing-domain migration, not a cleanup).
 *
 * WHY THIS FILE WAS REWRITTEN (review L-6). It resolved its two targets to
 * `join(here, '../../../../contracts/src/…')` — two levels ABOVE the repo root,
 * at `/home/ubuntu/contracts/src/…`, which exists on no host. Both describes
 * were `{ skip: … === null }`, so the runner printed
 *
 *     ok 1 - CORETEX_EVENT_TOPICS ↔ CoreTexRegistry.sol # SKIP
 *     ok 2 - CoreTexReceipt EIP-712 mirror ↔ BotcoinMiningV4.sol # SKIP
 *     # tests 0 … # pass 0 # fail 0
 *
 * A parity guard that reports `ok` and `fail 0` having executed ZERO assertions
 * is not a guard. Two things change:
 *
 *   * resolution is an explicit env override, then a list of candidate absolute
 *     paths, so the sources are actually found where they actually live;
 *   * a missing source FAILS LOUDLY by default. Skipping is available, but only
 *     under an explicit opt-out (`CORETEX_ALLOW_MISSING_SOLIDITY_PARITY=1`), so
 *     "I could not check it" can never again look like "I checked it".
 *
 * NOTE ON SCOPE: these targets are the V4 lane — the `CoreTexRegistry` /
 * `BotcoinMiningV4` pair, whose `CoreTexReceipt` still carries `uint16
 * stateWordCount`. That is CORRECT here and is not the rig lane's migrated
 * `RigCoreTexReceipt` (`uint16 transitionFormatVersion`, typehash 0x70419dc5…),
 * which `python/coretex_validator/rig_receipt_binding.py` mirrors and
 * `test_rig_lane.py::TestGeneratedBindingParity` guards. Two lanes, two receipt
 * structs, one shared event topic0 — see `src/replay/rig-dispatch.ts`.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

import { keccak256 } from '../../dist/state/keccak256.js';
import { bytesToHex } from '../../dist/state/merkle.js';
import { CORETEX_EVENT_TOPICS } from '../../dist/replay/coretex-registry.js';

/** Explicit opt-out. Set only on a host that genuinely has no contracts tree. */
const ALLOW_MISSING = process.env.CORETEX_ALLOW_MISSING_SOLIDITY_PARITY === '1';

/**
 * Candidate absolute paths, in preference order. The V4 CoreTex contracts are not
 * vendored in this repo (it ships a client, not the chain), so parity is checked
 * against whichever checkout of them is present on the build host.
 */
const REGISTRY_CANDIDATES = [
  '/home/ubuntu/coretex-ga5-work/contracts/src/CoreTexRegistry.sol',
  '/home/ubuntu/botcoin-coordinator/contracts/src/CoreTexRegistry.sol',
  '/home/ubuntu/coretex-p5-work/contracts/src/CoreTexRegistry.sol',
  '/home/ubuntu/coretex-p3-work/contracts/src/CoreTexRegistry.sol',
];
const MINING_CANDIDATES = [
  // The vendored copy of the DEPLOYED V4 — the strongest authority available here.
  '/home/ubuntu/botcoin-mining-rigs/vendor/live-v4/BotcoinMiningV4.sol',
  '/home/ubuntu/coretex-ga5-work/contracts/src/BotcoinMiningV4.sol',
  '/home/ubuntu/botcoin-coordinator/contracts/src/BotcoinMiningV4.sol',
];

function resolveSource(label, envVar, candidates) {
  const override = process.env[envVar];
  if (override) {
    assert.ok(
      existsSync(override),
      `${envVar}=${override} does not exist; point it at ${label} or unset it`,
    );
    return readFileSync(override, 'utf8');
  }
  const found = candidates.find((p) => existsSync(p));
  if (found) return readFileSync(found, 'utf8');
  assert.ok(
    ALLOW_MISSING,
    `${label} was not found on this host. Looked at:\n  ${candidates.join('\n  ')}\n` +
      `Set ${envVar} to its absolute path, or set ` +
      'CORETEX_ALLOW_MISSING_SOLIDITY_PARITY=1 to skip this guard DELIBERATELY. ' +
      'It does not skip by default: a parity guard that has never executed is the defect ' +
      'this test was rewritten to remove.',
  );
  return null;
}

/** Parse `event Name(type [indexed] name, ...)` out of Solidity source into
 * the canonical `Name(type1,type2,...)` signature string. */
function parseEventSignature(sol, name) {
  const m = sol.match(new RegExp(`event ${name}\\(([^)]*)\\)`, 's'));
  if (!m) return null;
  const types = m[1]
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => p.split(/\s+/)[0]);
  return `${name}(${types.join(',')})`;
}

const topicOf = (sig) => bytesToHex(keccak256(new TextEncoder().encode(sig)));

describe('CORETEX_EVENT_TOPICS ↔ CoreTexRegistry.sol', () => {
  test('every pinned topic hash matches the keccak256 of the declared event signature', () => {
    const registrySol = resolveSource(
      'CoreTexRegistry.sol',
      'CORETEX_V4_REGISTRY_SOL',
      REGISTRY_CANDIDATES,
    );
    if (registrySol === null) return; // opted out explicitly; the assert above proved that
    const names = Object.keys(CORETEX_EVENT_TOPICS);
    assert.ok(names.length > 0, 'CORETEX_EVENT_TOPICS must not be empty');
    for (const name of names) {
      const sig = parseEventSignature(registrySol, name);
      assert.notEqual(sig, null, `event ${name} declared in CoreTexRegistry.sol`);
      assert.equal(
        CORETEX_EVENT_TOPICS[name],
        topicOf(sig),
        `${name}: pinned topic must equal keccak256("${sig}")`,
      );
    }
  });
});

// The reviewed pin of the signed receipt shape. Mirrors, in order:
//   - CoreTexReceiptPayload (coordinator/coretex-coordinator-core.ts) with the
//     contract's signing rule applied: `miner` prepended, and the dynamic
//     `compactPatchBytes`/`signature` tail excluded from the EIP-712 hash.
//
// `uint16 stateWordCount` at index 19 is the V4 lane's member and is CORRECT here.
// The RIG lane renamed its equivalent to `transitionFormatVersion` under
// coretex.transition-descriptor/v2; that is a DIFFERENT struct in a DIFFERENT
// contract with a DIFFERENT typehash, and conflating the two is exactly the
// name-keyed drift the rename exists to make loud.
const EXPECTED_SIGNED_RECEIPT_FIELDS = [
  ['address', 'miner'],
  ['uint64', 'epochId'],
  ['uint64', 'solveIndex'],
  ['bytes32', 'prevReceiptHash'],
  ['uint8', 'outcome'],
  ['bytes32', 'challengeId'],
  ['bytes32', 'parentStateRoot'],
  ['bytes32', 'newStateRoot'],
  ['bytes32', 'corpusRoot'],
  ['bytes32', 'activeFrontierRoot'],
  ['bytes32', 'coreVersionHash'],
  ['bytes32', 'evalReportHash'],
  ['bytes32', 'patchHash'],
  ['bytes32', 'artifactHash'],
  ['uint128', 'worldSeed'],
  ['uint32', 'rulesVersion'],
  ['bytes32', 'workPolicyHash'],
  ['uint256', 'workUnitsBps'],
  ['uint256', 'difficultyCountSnapshot'],
  ['uint16', 'stateWordCount'],
  ['uint32', 'scoreBeforePpm'],
  ['uint32', 'scoreAfterPpm'],
  ['uint64', 'issuedAt'],
  ['uint64', 'expiresAt'],
];

describe('CoreTexReceipt EIP-712 mirror ↔ BotcoinMiningV4.sol', () => {
  function miningSource() {
    return resolveSource('BotcoinMiningV4.sol', 'CORETEX_V4_MINING_SOL', MINING_CANDIDATES);
  }
  function parseTypeString(miningSol) {
    const m = miningSol.match(/CORETEX_RECEIPT_TYPEHASH = keccak256\(\s*"CoreTexReceipt\(([^)]*)\)"/s);
    assert.notEqual(m, null, 'CORETEX_RECEIPT_TYPEHASH preimage present');
    return m[1].split(',').map((f) => f.trim().split(/\s+/));
  }
  function parseStructFields(miningSol) {
    const m = miningSol.match(/struct CoreTexReceipt \{([^}]*)\}/s);
    assert.notEqual(m, null, 'struct CoreTexReceipt present');
    return m[1]
      .split(';')
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
      .map((l) => l.split(/\s+/));
  }

  test('EIP-712 type string fields match the reviewed pin exactly (order, types, names)', () => {
    const miningSol = miningSource();
    if (miningSol === null) return;
    assert.deepEqual(parseTypeString(miningSol), EXPECTED_SIGNED_RECEIPT_FIELDS);
  });

  test('struct CoreTexReceipt = signed fields minus miner, plus the dynamic tail, in the same order', () => {
    const miningSol = miningSource();
    if (miningSol === null) return;
    const structFields = parseStructFields(miningSol);
    const expectedStruct = [
      ...EXPECTED_SIGNED_RECEIPT_FIELDS.slice(1), // struct has no `miner` field
      ['bytes', 'compactPatchBytes'],
      ['bytes', 'signature'],
    ];
    assert.deepEqual(structFields, expectedStruct);
  });

  test('the reviewed pin round-trips back into the source verbatim', () => {
    const miningSol = miningSource();
    if (miningSol === null) return;
    // Rebuild the type string FROM THE PIN and require the source to contain it byte for byte.
    // The deepEqual above proves the parse matches the pin; this proves the pin can regenerate
    // the exact preimage the contract hashes, so a whitespace or ordering difference the token
    // parse would smooth over is still caught.
    const preimage = `CoreTexReceipt(${EXPECTED_SIGNED_RECEIPT_FIELDS.map(([t, n]) => `${t} ${n}`).join(',')})`;
    assert.ok(
      miningSol.includes(preimage),
      'the reviewed pin must reconstruct the CORETEX_RECEIPT_TYPEHASH preimage exactly',
    );
    // And the V4 typehash is NOT the rig lane's — different struct, different contract, and
    // there is no dual-accept window between them.
    assert.notEqual(
      bytesToHex(keccak256(new TextEncoder().encode(preimage))),
      '0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf',
    );
  });
});
