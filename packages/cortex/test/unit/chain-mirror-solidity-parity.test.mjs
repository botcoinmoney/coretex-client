/**
 * TS ↔ Solidity chain-mirror parity (cleanup-audit R2).
 *
 * Two hand-maintained mirrors of on-chain truth had no automated guard:
 *
 *   1. CORETEX_EVENT_TOPICS (replay/coretex-registry.ts) — topic hashes the
 *      validator uses to decode CoreTexRegistry logs. Recomputed here from the
 *      event declarations parsed out of contracts/src/CoreTexRegistry.sol.
 *
 *   2. The CoreTexReceipt EIP-712 type string vs the CoreTexReceipt struct in
 *      contracts/src/BotcoinMiningV4.sol vs the field set the coordinator signs
 *      (CoreTexReceiptPayload in coordinator/coretex-coordinator-core.ts). Field
 *      ORDER in the type string is consensus-critical: drift = unredeemable
 *      receipts. The expected list below is the reviewed pin of the TS payload
 *      shape — update it ONLY together with CoreTexReceiptPayload, the struct,
 *      and the type string (a signing-domain migration, not a cleanup).
 *
 * Follows the patch-type-solidity-parity pattern: parse the .sol source and
 * assert byte-for-byte agreement; skip cleanly when the contracts tree is
 * absent (standalone npm install).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { keccak256 } from '../../dist/state/keccak256.js';
import { bytesToHex } from '../../dist/state/merkle.js';
import { CORETEX_EVENT_TOPICS } from '../../dist/replay/coretex-registry.js';

const here = dirname(fileURLToPath(import.meta.url));
const registrySolPath = join(here, '../../../../contracts/src/CoreTexRegistry.sol');
const miningSolPath = join(here, '../../../../contracts/src/BotcoinMiningV4.sol');
const registrySol = existsSync(registrySolPath) ? readFileSync(registrySolPath, 'utf8') : null;
const miningSol = existsSync(miningSolPath) ? readFileSync(miningSolPath, 'utf8') : null;

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

describe('CORETEX_EVENT_TOPICS ↔ CoreTexRegistry.sol', { skip: registrySol === null }, () => {
  test('every pinned topic hash matches the keccak256 of the declared event signature', () => {
    for (const name of Object.keys(CORETEX_EVENT_TOPICS)) {
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

describe('CoreTexReceipt EIP-712 mirror ↔ BotcoinMiningV4.sol', { skip: miningSol === null }, () => {
  function parseTypeString() {
    const m = miningSol.match(/CORETEX_RECEIPT_TYPEHASH = keccak256\(\s*"CoreTexReceipt\(([^)]*)\)"/s);
    assert.notEqual(m, null, 'CORETEX_RECEIPT_TYPEHASH preimage present');
    return m[1].split(',').map((f) => f.trim().split(/\s+/));
  }
  function parseStructFields() {
    const m = miningSol.match(/struct CoreTexReceipt \{([^}]*)\}/s);
    assert.notEqual(m, null, 'struct CoreTexReceipt present');
    return m[1]
      .split(';')
      .map((l) => l.trim())
      .filter((l) => l.length > 0)
      .map((l) => l.split(/\s+/));
  }

  test('EIP-712 type string fields match the reviewed pin exactly (order, types, names)', () => {
    assert.deepEqual(parseTypeString(), EXPECTED_SIGNED_RECEIPT_FIELDS);
  });

  test('struct CoreTexReceipt = signed fields minus miner, plus the dynamic tail, in the same order', () => {
    const structFields = parseStructFields();
    const expectedStruct = [
      ...EXPECTED_SIGNED_RECEIPT_FIELDS.slice(1), // struct has no `miner` field
      ['bytes', 'compactPatchBytes'],
      ['bytes', 'signature'],
    ];
    assert.deepEqual(structFields, expectedStruct);
  });
});
