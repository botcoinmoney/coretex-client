/**
 * Coordinator funding-tx builder for CortexMergeBonus.fundEpoch().
 *
 * Builds the Merkle root of (miner, bonusBOTCOIN, capBOTCOIN) leaves and
 * produces the ABI-encoded calldata for:
 *   CortexMergeBonus.fundEpoch(uint64 epoch, bytes32 root, uint256 totalBonus)
 *
 * The Merkle tree follows the same leaf-hash pattern as CortexMergeBonus.sol:
 *   leaf = keccak256(abi.encodePacked(miner, bonusBOTCOIN, capBOTCOIN))
 *   root = keccak256(concat(sorted-leaves))  [V0: flat concat of all leaf hashes]
 *
 * No external dependencies. Pure functions.
 */

import type { MinerBonusLeaf } from './multiplier-cap.js';
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex, hexToBytes } from '../state/merkle.js';

// ── ABI encoding helpers ──────────────────────────────────────────────────────

/** Encode a uint256 (bigint) as 32 big-endian bytes. */
function encodeUint256(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = BigInt.asUintN(256, value);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Encode a uint64 (bigint) as 32 big-endian bytes (left-padded). */
function encodeUint64(value: bigint): Uint8Array {
  return encodeUint256(BigInt.asUintN(64, value));
}

/** Encode an address (0x-prefixed hex string) as 32 bytes (left-padded with 12 zero bytes). */
function encodeAddress(addr: string): Uint8Array {
  const raw = hexToBytes(addr.startsWith('0x') ? addr : `0x${addr}`);
  if (raw.length !== 20) {
    throw new RangeError(`encodeAddress: expected 20 bytes, got ${raw.length} for ${addr}`);
  }
  const out = new Uint8Array(32);
  out.set(raw, 12);
  return out;
}

/** Encode a bytes32 value as 32 bytes. */
function encodeBytes32(value: Uint8Array): Uint8Array {
  if (value.length !== 32) throw new RangeError(`encodeBytes32: expected 32 bytes, got ${value.length}`);
  return value.slice();
}

/** Concatenate multiple Uint8Arrays. */
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

// ── Merkle leaf encoding ──────────────────────────────────────────────────────

/**
 * Compute a single Merkle leaf hash for a MinerBonusLeaf.
 *
 * leaf = keccak256(abi.encodePacked(address miner, uint256 bonusBOTCOIN, uint256 capBOTCOIN))
 *
 * Uses abi.encodePacked: address is 20 bytes, uint256 is 32 bytes each.
 */
export function computeLeafHash(leaf: MinerBonusLeaf): Uint8Array {
  const addrBytes = hexToBytes(
    leaf.miner.startsWith('0x') ? leaf.miner : `0x${leaf.miner}`,
  );
  if (addrBytes.length !== 20) {
    throw new RangeError(`computeLeafHash: address must be 20 bytes, got ${addrBytes.length}`);
  }

  const bonusBytes = encodeUint256(leaf.bonusBotcoin);
  const capBytes = encodeUint256(leaf.capBotcoin);

  // abi.encodePacked: address (20) + uint256 (32) + uint256 (32) = 84 bytes
  const packed = concat(addrBytes, bonusBytes, capBytes);
  return keccak256(packed);
}

/**
 * Compute the Merkle root for the epoch bonus tree.
 *
 * V0: root = keccak256(concat(leaf_hash_0 ‖ leaf_hash_1 ‖ ... ‖ leaf_hash_n))
 * Leaves are sorted by miner address (done in buildEpochBonusLeaves).
 *
 * If leaves is empty, root = keccak256(empty).
 */
export function computeBonusMerkleRoot(leaves: MinerBonusLeaf[]): Uint8Array {
  if (leaves.length === 0) {
    return keccak256(new Uint8Array(0));
  }
  const leafHashes = leaves.map(computeLeafHash);
  const combined = new Uint8Array(leafHashes.length * 32);
  for (let i = 0; i < leafHashes.length; i++) {
    combined.set(leafHashes[i]!, i * 32);
  }
  return keccak256(combined);
}

// ── Calldata builder ──────────────────────────────────────────────────────────

/** Encoded funding transaction for CortexMergeBonus.fundEpoch(). */
export interface FundEpochCalldata {
  /** ABI-encoded calldata bytes. */
  readonly calldata: Uint8Array;
  /** Human-readable hex of calldata. */
  readonly calldataHex: string;
  /** The Merkle root (bytes32). */
  readonly merkleRoot: Uint8Array;
  /** Human-readable hex of Merkle root. */
  readonly merkleRootHex: string;
  /** Total BOTCOIN to transfer (must match sum of bonusBotcoin across all leaves). */
  readonly totalBonus: bigint;
}

/**
 * Build the calldata for CortexMergeBonus.fundEpoch(uint64 epoch, bytes32 root, uint256 totalBonus).
 *
 * Selector: keccak256("fundEpoch(uint64,bytes32,uint256)")[0:4]
 *
 * ABI encoding: (uint64, bytes32, uint256) — each padded to 32 bytes.
 */
export function buildFundEpochCalldata(
  epoch: bigint,
  leaves: MinerBonusLeaf[],
): FundEpochCalldata {
  const merkleRoot = computeBonusMerkleRoot(leaves);
  const totalBonus = leaves.reduce((sum, l) => sum + l.bonusBotcoin, 0n);

  // Function selector: keccak256("fundEpoch(uint64,bytes32,uint256)")[0:4]
  const selectorInput = new TextEncoder().encode('fundEpoch(uint64,bytes32,uint256)');
  const selectorFull = keccak256(selectorInput);
  const selector = selectorFull.slice(0, 4);

  // ABI-encoded arguments (standard 32-byte slots)
  const epochEncoded  = encodeUint64(epoch);
  const rootEncoded   = encodeBytes32(merkleRoot);
  const totalEncoded  = encodeUint256(totalBonus);

  const calldata = concat(selector, epochEncoded, rootEncoded, totalEncoded);

  return {
    calldata,
    calldataHex: bytesToHex(calldata),
    merkleRoot,
    merkleRootHex: bytesToHex(merkleRoot),
    totalBonus,
  };
}

/**
 * Build a Merkle proof for a miner's claim.
 *
 * V0 uses a flat-concat root (not a binary tree), so "proof" is the full leaf
 * set minus the claimed leaf — the contract recomputes the root from all leaves.
 *
 * In a real deployment, upgrade to a standard binary Merkle tree for gas efficiency.
 * TODO(v1): Replace flat-concat with binary Merkle tree for on-chain claim gas efficiency.
 */
export interface MinerClaimProof {
  readonly miner: string;
  readonly bonusBotcoin: bigint;
  readonly capBotcoin: bigint;
  /** All leaf hashes (for flat-concat proof verification). */
  readonly allLeafHashes: string[];
  /** The miner's leaf index. */
  readonly leafIndex: number;
}

export function buildMinerClaimProof(
  leaves: MinerBonusLeaf[],
  miner: string,
): MinerClaimProof | null {
  const idx = leaves.findIndex((l) => l.miner.toLowerCase() === miner.toLowerCase());
  if (idx === -1) return null;
  const leaf = leaves[idx]!;
  return {
    miner: leaf.miner,
    bonusBotcoin: leaf.bonusBotcoin,
    capBotcoin: leaf.capBotcoin,
    allLeafHashes: leaves.map((l) => bytesToHex(computeLeafHash(l))),
    leafIndex: idx,
  };
}
