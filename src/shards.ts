/**
 * Canonical hidden-shard derivation for Cortex.
 *
 * Mirrors deriveWorldSeedU128 from /root/botcoin-coordinator/packages/coordinator/src/epoch.ts:257
 * (the SWCP coordinator). The Cortex variant uses parentStateRoot in the
 * position of prevReceiptHash and rulesVersion = 0xC0 (§6 receipt mapping).
 *
 * ABI packing order (matches ethers solidityPacked of these fields):
 *   bytes32  epochSecret      (32 bytes, big-endian)
 *   address  miner            (20 bytes)
 *   uint64   epochId          (8 bytes, big-endian)
 *   uint64   solveIndex       (8 bytes, big-endian)
 *   bytes32  parentStateRoot  (32 bytes)
 *   uint32   rulesVersion     (4 bytes, big-endian)
 *
 * Total packed: 32 + 20 + 8 + 8 + 32 + 4 = 104 bytes.
 *
 * shardId = lower 128 bits of keccak256(packed); 16 bytes; '0x' + hex.
 *
 * This module is the single source of truth for shard derivation across:
 *   - coordinator route shim challenge endpoint
 *   - benchmark/shards.ts (re-exported)
 *   - coretex-client CLI verify-epoch path
 *   - any external auditor
 *
 * Changing the packing order, hash, or rulesVersion changes consensus.
 */

import { keccak256 } from './state/keccak256.js';

/** rulesVersion = 0xC0 for all Cortex receipts (§6 receipt field mapping). */
export const CORTEX_RULES_VERSION = 0xC0;

export interface DeriveShardIdInput {
  /** 32-byte epoch secret (revealed at epoch end). */
  readonly epochSecret: Uint8Array;
  /** 0x-prefixed 20-byte miner address. */
  readonly miner: string;
  /** Epoch number (uint64). */
  readonly epochId: bigint;
  /** Solve index for this miner within this epoch (uint64). */
  readonly solveIndex: bigint;
  /** 32-byte parent state root. */
  readonly parentStateRoot: Uint8Array;
  /** Defaults to CORTEX_RULES_VERSION (0xC0). */
  readonly rulesVersion?: number;
}

function addressToBytes20(addr: string): Uint8Array {
  const s = addr.startsWith('0x') ? addr.slice(2) : addr;
  if (s.length !== 40) throw new RangeError(`miner address must be 20 bytes, got ${s.length / 2}`);
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function writeBigUint64BE(buf: Uint8Array, off: number, value: bigint): void {
  let v = BigInt.asUintN(64, value);
  for (let i = 7; i >= 0; i--) {
    buf[off + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * Derive the canonical Cortex shardId. Returns the lower 128 bits of
 * keccak256 over the packed fields, as a bigint.
 *
 * Used by coordinator route shim, benchmark loaders, replay scripts, and verifiers.
 */
export function deriveShardIdU128(input: DeriveShardIdInput): bigint {
  const { epochSecret, miner, epochId, solveIndex, parentStateRoot,
          rulesVersion = CORTEX_RULES_VERSION } = input;

  if (epochSecret.length !== 32) {
    throw new RangeError(`epochSecret must be 32 bytes, got ${epochSecret.length}`);
  }
  if (parentStateRoot.length !== 32) {
    throw new RangeError(`parentStateRoot must be 32 bytes, got ${parentStateRoot.length}`);
  }

  const minerBytes = addressToBytes20(miner);

  const packed = new Uint8Array(104);
  let off = 0;
  packed.set(epochSecret, off);     off += 32;
  packed.set(minerBytes, off);      off += 20;
  writeBigUint64BE(packed, off, epochId);   off += 8;
  writeBigUint64BE(packed, off, solveIndex); off += 8;
  packed.set(parentStateRoot, off); off += 32;
  packed[off + 0] = (rulesVersion >>> 24) & 0xff;
  packed[off + 1] = (rulesVersion >>> 16) & 0xff;
  packed[off + 2] = (rulesVersion >>> 8)  & 0xff;
  packed[off + 3] =  rulesVersion         & 0xff;

  const h = keccak256(packed);
  let result = 0n;
  for (let i = 16; i < 32; i++) {
    result = (result << 8n) | BigInt(h[i] ?? 0);
  }
  return result;
}

/** Convenience: returns the shardId as 0x-prefixed 16-byte hex (32 hex chars). */
export function deriveShardIdHex(input: DeriveShardIdInput): string {
  const u128 = deriveShardIdU128(input);
  return '0x' + u128.toString(16).padStart(32, '0');
}

/**
 * Derive worldSeed (uint128) for the §6 receipt mapping. Same value as
 * deriveShardIdU128 — the receipt's worldSeed and the challenge's shardId are
 * the same bigint by construction.
 */
export const deriveWorldSeedU128 = deriveShardIdU128;
