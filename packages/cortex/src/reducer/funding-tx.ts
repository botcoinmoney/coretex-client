/**
 * Coordinator funding-tx builder for CortexMergeBonus.fundEpoch().
 *
 * Builds the OZ-compatible binary Merkle root over (miner, bonusBOTCOIN,
 * capBOTCOIN) leaves and emits ABI-encoded calldata for:
 *   CortexMergeBonus.fundEpoch(uint64 epoch, bytes32 root, uint256 totalBonus)
 *
 * Tree shape — exactly what OpenZeppelin MerkleProof.verify expects:
 *   leaf  = keccak256(abi.encodePacked(miner, bonusBOTCOIN, capBOTCOIN))
 *   pair  = keccak256(min(left, right) || max(left, right))         (sorted-pair)
 *   tree  = bottom-up; odd-length levels carry the unpaired leaf up unchanged
 *
 * No external runtime deps. Pure functions. Compatible with
 * @openzeppelin/contracts/utils/cryptography/MerkleProof.sol verify().
 */

import type { MinerBonusLeaf } from './multiplier-cap.js';
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex, hexToBytes } from '../state/merkle.js';

// ── ABI encoding helpers ──────────────────────────────────────────────────────

function encodeUint256(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = BigInt.asUintN(256, value);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function encodeUint64(value: bigint): Uint8Array {
  return encodeUint256(BigInt.asUintN(64, value));
}

function encodeBytes32(value: Uint8Array): Uint8Array {
  if (value.length !== 32) throw new RangeError(`encodeBytes32: expected 32 bytes, got ${value.length}`);
  return value.slice();
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

function bytesLessOrEq(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    const av = a[i] ?? 0, bv = b[i] ?? 0;
    if (av !== bv) return av < bv;
  }
  return true;
}

/**
 * Hash a pair of 32-byte siblings in OZ's `_hashPair` order:
 *   keccak256( min(a,b) || max(a,b) )
 * This is what MerkleProof.verify uses by default and what
 * MerkleProof._processProof reconstructs.
 */
function hashPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  const [lo, hi] = bytesLessOrEq(a, b) ? [a, b] : [b, a];
  return keccak256(concat(lo, hi));
}

// ── Merkle leaf encoding ──────────────────────────────────────────────────────

/**
 * Compute a single Merkle leaf hash.
 *
 * leaf = keccak256(abi.encodePacked(address miner, uint256 bonusBOTCOIN, uint256 capBOTCOIN))
 *
 * abi.encodePacked: address is 20 bytes, uint256 is 32 bytes → 84 bytes total.
 *
 * NOTE: OZ MerkleProof relies on leaves being unique. Production code should
 * either hash the leaf twice (`keccak256(leaf)`) per OZ's recommendation, or
 * guarantee uniqueness via the (miner, epoch) tuple. CortexMergeBonus uses
 * (miner, bonusBotcoin, capBotcoin) which is unique per epoch funding tx;
 * the on-chain `claimed[epoch][miner]` mapping prevents double claims so
 * second-preimage between leaf and node-pair is not exploitable.
 */
export function computeLeafHash(leaf: MinerBonusLeaf): Uint8Array {
  const addrBytes = hexToBytes(
    leaf.miner.startsWith('0x') ? leaf.miner : `0x${leaf.miner}`,
  );
  if (addrBytes.length !== 20) {
    throw new RangeError(`computeLeafHash: address must be 20 bytes, got ${addrBytes.length}`);
  }
  const bonusBytes = encodeUint256(leaf.bonusBotcoin);
  const capBytes   = encodeUint256(leaf.capBotcoin);
  // abi.encodePacked: 20 + 32 + 32 = 84 bytes
  const packed = concat(addrBytes, bonusBytes, capBytes);
  return keccak256(packed);
}

// ── Binary Merkle tree (OZ-compatible) ────────────────────────────────────────

/**
 * Build the full binary Merkle tree from leaf hashes (bottom up). Returns
 * the levels array where levels[0] = leaves and levels[levels.length-1] = [root].
 *
 * Odd-sized levels carry the unpaired tail node up unchanged (NOT duplicated).
 * This matches OZ's MerkleProof default reconstruction.
 *
 * Empty input → root is keccak256(empty); a single leaf → root === leaf.
 */
function buildLevels(leafHashes: Uint8Array[]): Uint8Array[][] {
  if (leafHashes.length === 0) {
    return [[keccak256(new Uint8Array(0))]];
  }
  const levels: Uint8Array[][] = [leafHashes.slice()];
  while (levels[levels.length - 1]!.length > 1) {
    const cur = levels[levels.length - 1]!;
    const next: Uint8Array[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      if (i + 1 === cur.length) {
        next.push(cur[i]!); // unpaired tail carries up unchanged
      } else {
        next.push(hashPair(cur[i]!, cur[i + 1]!));
      }
    }
    levels.push(next);
  }
  return levels;
}

/**
 * Compute the OZ-compatible binary Merkle root from MinerBonusLeaf entries.
 * Single-leaf trees have root === leaf hash (matches MerkleProof.verify).
 */
export function computeBonusMerkleRoot(leaves: MinerBonusLeaf[]): Uint8Array {
  const leafHashes = leaves.map(computeLeafHash);
  const levels = buildLevels(leafHashes);
  return levels[levels.length - 1]![0]!;
}

// ── Calldata builder ──────────────────────────────────────────────────────────

export interface FundEpochCalldata {
  readonly calldata: Uint8Array;
  readonly calldataHex: string;
  readonly merkleRoot: Uint8Array;
  readonly merkleRootHex: string;
  readonly totalBonus: bigint;
}

/**
 * Build calldata for CortexMergeBonus.fundEpoch(uint64 epoch, bytes32 root, uint256 totalBonus).
 */
export function buildFundEpochCalldata(
  epoch: bigint,
  leaves: MinerBonusLeaf[],
): FundEpochCalldata {
  const merkleRoot = computeBonusMerkleRoot(leaves);
  const totalBonus = leaves.reduce((sum, l) => sum + l.bonusBotcoin, 0n);

  const selectorFull = keccak256(new TextEncoder().encode('fundEpoch(uint64,bytes32,uint256)'));
  const selector = selectorFull.slice(0, 4);

  const calldata = concat(
    selector,
    encodeUint64(epoch),
    encodeBytes32(merkleRoot),
    encodeUint256(totalBonus),
  );

  return {
    calldata,
    calldataHex: bytesToHex(calldata),
    merkleRoot,
    merkleRootHex: bytesToHex(merkleRoot),
    totalBonus,
  };
}

// ── Per-miner claim proofs ────────────────────────────────────────────────────

/**
 * Production claim proof: a standard binary Merkle proof (array of sibling
 * hashes from leaf to root). Compatible with OZ MerkleProof.verify().
 */
export interface MinerClaimProof {
  readonly miner: string;
  readonly bonusBotcoin: bigint;
  readonly capBotcoin: bigint;
  /** Sibling hashes from leaf to root (each 0x-prefixed hex). */
  readonly proof: string[];
  /** The miner's leaf index in the original `leaves` array. */
  readonly leafIndex: number;
}

/**
 * Build a binary Merkle proof for the given miner. Returns null if the miner
 * is not in `leaves`.
 *
 * The proof array is in the order MerkleProof.verify expects: bottom (leaf
 * sibling) to top (root sibling).
 */
export function buildMinerClaimProof(
  leaves: MinerBonusLeaf[],
  miner: string,
): MinerClaimProof | null {
  const idx = leaves.findIndex((l) => l.miner.toLowerCase() === miner.toLowerCase());
  if (idx === -1) return null;
  const leaf = leaves[idx]!;

  const leafHashes = leaves.map(computeLeafHash);
  const levels = buildLevels(leafHashes);

  const proof: string[] = [];
  let pos = idx;
  for (let lvl = 0; lvl < levels.length - 1; lvl++) {
    const level = levels[lvl]!;
    if (pos === level.length - 1 && pos % 2 === 0) {
      // Unpaired tail at this level — no sibling, parent === self.
      pos = Math.floor(pos / 2);
      continue;
    }
    const sibling = pos % 2 === 0 ? level[pos + 1]! : level[pos - 1]!;
    proof.push(bytesToHex(sibling));
    pos = Math.floor(pos / 2);
  }

  return {
    miner: leaf.miner.toLowerCase(),
    bonusBotcoin: leaf.bonusBotcoin,
    capBotcoin: leaf.capBotcoin,
    proof,
    leafIndex: idx,
  };
}

/**
 * Verify a Merkle proof against a root. Mirrors OZ MerkleProof.verify
 * semantics so off-chain code can self-check before sending claims.
 */
export function verifyMinerClaimProof(
  leaf: MinerBonusLeaf,
  proof: string[],
  root: Uint8Array,
): boolean {
  let computed = computeLeafHash(leaf);
  for (const sib of proof) {
    const sibling = hexToBytes(sib);
    computed = hashPair(computed, sibling);
  }
  if (computed.length !== root.length) return false;
  for (let i = 0; i < computed.length; i++) {
    if (computed[i] !== root[i]) return false;
  }
  return true;
}
