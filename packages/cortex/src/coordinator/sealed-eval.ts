/**
 * Sealed-eval primitives — Phase S1 of
 * `docs/CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md`.
 *
 * Pure types + canonical hash functions for the commit / reveal flow.
 * No I/O, no model work, no persistence — the coordinator (or any
 * independent verifier) wires storage and on-chain anchoring on top.
 *
 * Wire shape:
 *
 *   patchCommit = H(
 *     "botcoin-coretex-patch-commit-v1",
 *     epochId,
 *     epochParentRoot,
 *     minerAddress,
 *     bundleHash,
 *     patchBytes,
 *     salt
 *   )
 *
 *   duplicateKey = H(
 *     "botcoin-coretex-patch-duplicate-key-v1",
 *     epochParentRoot,
 *     sortedTouchedWordIndices,
 *     normalizedPatchBytes,
 *     resultingStateRoot
 *   )
 *
 *   commitmentRoot = merkle(sorted commitment hashes)
 *
 * Replay determinism: every output here is a pure function of public
 * inputs, so any watcher can reproduce commitmentRoot byte-identically.
 *
 * The launch invariant is that the sealed-eval guard (Phase S0) keeps
 * `POST /coretex/evaluate` returning 403 to public callers; THIS module
 * supplies the data-shape miners use to commit / reveal patches via
 * the new endpoints below.
 */
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Domain-separation prefix for the patch-commitment hash. Hard-coded so
 * a different protocol cannot reuse the same hash for a different
 * commitment scheme by accident.
 */
export const PATCH_COMMIT_DOMAIN_PREFIX = 'botcoin-coretex-patch-commit-v1';

/** Domain-separation prefix for the duplicate-key hash. */
export const PATCH_DUPLICATE_KEY_DOMAIN_PREFIX = 'botcoin-coretex-patch-duplicate-key-v1';

/** Domain-separation prefix for the commitment Merkle leaf. */
export const COMMITMENT_LEAF_DOMAIN_PREFIX = 'botcoin-coretex-commitment-leaf-v1';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PatchCommitmentInput {
  /** Epoch ID this commitment targets (uint64). */
  readonly epochId: bigint | number;
  /**
   * Parent state root the patch was constructed against — bytes32 hex.
   * Locks the commitment to a specific substrate version.
   */
  readonly epochParentRoot: string;
  /**
   * Miner address — checksummed 0x-prefixed lowercase hex (20 bytes).
   * Used by the reveal verifier to refuse re-targeted commitments.
   */
  readonly minerAddress: string;
  /** Bundle hash this patch was scored against — bytes32 hex. */
  readonly bundleHash: string;
  /**
   * Raw compact-patch wire bytes. The commitment hashes the EXACT
   * bytes the miner will reveal later; any re-encoding fails the
   * commitment check.
   */
  readonly patchBytes: Uint8Array;
  /**
   * Per-commitment salt (32 random bytes hex). Prevents preimage
   * grinding of (epoch, parent, miner, bundle, patch) tuples that
   * are otherwise predictable.
   */
  readonly saltHex: string;
}

export interface PatchCommitment {
  readonly commitmentHash: string;     // 0x + 64 hex
  readonly epochId: bigint;
  readonly epochParentRoot: string;
  readonly minerAddress: string;
  readonly bundleHash: string;
  /** Length of patchBytes in bytes — keeps the commitment record self-describing. */
  readonly patchBytesLength: number;
  readonly saltHex: string;
}

export interface PatchRevealInput {
  /** Commitment to open. */
  readonly commitmentHash: string;
  /** Same bytes the commitment was computed over. */
  readonly patchBytes: Uint8Array;
  /** Same salt as the commitment. */
  readonly saltHex: string;
  /** Same context as the commitment (epochId, parentRoot, miner, bundleHash). */
  readonly epochId: bigint | number;
  readonly epochParentRoot: string;
  readonly minerAddress: string;
  readonly bundleHash: string;
}

export type RevealOutcome =
  | { readonly ok: true; readonly commitmentHash: string }
  | { readonly ok: false; readonly reason: RevealRejectReason };

export type RevealRejectReason =
  | 'commitment-hash-mismatch'
  | 'invalid-salt'
  | 'invalid-patch-bytes'
  | 'epoch-mismatch'
  | 'parent-root-mismatch'
  | 'miner-mismatch'
  | 'bundle-mismatch';

export interface DuplicateKeyInput {
  readonly epochParentRoot: string;       // bytes32 hex
  /** Word indices the patch touches, ascending unique. */
  readonly sortedTouchedWordIndices: readonly number[];
  /**
   * Re-encoded canonical patch bytes (after applyPatch normalization
   * if the contract semantics permit reordering of equivalent patches).
   */
  readonly normalizedPatchBytes: Uint8Array;
  /** State root the patch produces when applied to epochParentRoot. */
  readonly resultingStateRoot: string;
}

export type EpochSealStatus =
  | 'open'           // commit window accepting commitments
  | 'commit_closed'  // commitments locked, awaiting seed reveal
  | 'sealed'         // eval seed derived, gate/confirm packs known to coordinator
  | 'settled'        // batch settlement complete, winners on chain
  | 'retired';       // hidden pack revealed, retired forever

export type RevealAdmissionStatus =
  | 'committed'
  | 'revealed'
  | 'screened'
  | 'finalist'
  | 'accepted'
  | 'rejected';

// ─── Pure hashing primitives ──────────────────────────────────────────────────

const enc = new TextEncoder();

function concatU8(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function u64BE(v: bigint | number): Uint8Array {
  let n = typeof v === 'bigint' ? v : BigInt(v);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function u32BE(v: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error(`hexToBytes: odd length ${clean.length}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`hexToBytes: invalid hex at ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

function assertBytes32Hex(value: string, field: string): void {
  if (typeof value !== 'string') throw new Error(`${field}: not a string`);
  const clean = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (clean.length !== 64) throw new Error(`${field}: must be 32 bytes hex (got ${clean.length / 2})`);
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) throw new Error(`${field}: non-hex characters`);
}

function assertAddressHex(value: string, field: string): void {
  if (typeof value !== 'string') throw new Error(`${field}: not a string`);
  const clean = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (clean.length !== 40) throw new Error(`${field}: must be 20 bytes hex (got ${clean.length / 2})`);
  if (!/^[0-9a-fA-F]{40}$/.test(clean)) throw new Error(`${field}: non-hex characters`);
}

/**
 * Compute the canonical patch-commitment hash. Pure function of public
 * inputs. Any verifier with the same inputs produces the same hash.
 */
export function computePatchCommitmentHash(input: PatchCommitmentInput): string {
  assertBytes32Hex(input.epochParentRoot, 'epochParentRoot');
  assertAddressHex(input.minerAddress, 'minerAddress');
  assertBytes32Hex(input.bundleHash, 'bundleHash');
  assertBytes32Hex(input.saltHex, 'saltHex');
  if (!(input.patchBytes instanceof Uint8Array) || input.patchBytes.length === 0) {
    throw new Error('patchBytes: must be a non-empty Uint8Array');
  }
  const body = concatU8(
    enc.encode(PATCH_COMMIT_DOMAIN_PREFIX),
    u64BE(input.epochId),
    hexToBytes(input.epochParentRoot),
    hexToBytes(input.minerAddress.toLowerCase()),
    hexToBytes(input.bundleHash),
    u32BE(input.patchBytes.length),
    input.patchBytes,
    hexToBytes(input.saltHex),
  );
  return bytesToHex(keccak256(body));
}

/**
 * Build a fully-populated PatchCommitment record from the same inputs.
 */
export function buildPatchCommitment(input: PatchCommitmentInput): PatchCommitment {
  const commitmentHash = computePatchCommitmentHash(input);
  return {
    commitmentHash,
    epochId: typeof input.epochId === 'bigint' ? input.epochId : BigInt(input.epochId),
    epochParentRoot: '0x' + input.epochParentRoot.replace(/^0x/i, '').toLowerCase(),
    minerAddress: '0x' + input.minerAddress.replace(/^0x/i, '').toLowerCase(),
    bundleHash: '0x' + input.bundleHash.replace(/^0x/i, '').toLowerCase(),
    patchBytesLength: input.patchBytes.length,
    saltHex: '0x' + input.saltHex.replace(/^0x/i, '').toLowerCase(),
  };
}

/**
 * Verify a reveal matches its commitment. Pure check; the coordinator
 * applies side-effects (status transition, persistence) only on ok.
 */
export function verifyPatchReveal(input: PatchRevealInput): RevealOutcome {
  let recomputed: string;
  try {
    recomputed = computePatchCommitmentHash({
      epochId: input.epochId,
      epochParentRoot: input.epochParentRoot,
      minerAddress: input.minerAddress,
      bundleHash: input.bundleHash,
      patchBytes: input.patchBytes,
      saltHex: input.saltHex,
    });
  } catch (e) {
    // Shape-level rejection (bad hex, bad length). Map to the most
    // appropriate coarse reason rather than leaking the message.
    const msg = (e as Error).message;
    if (msg.includes('epochParentRoot')) return { ok: false, reason: 'parent-root-mismatch' };
    if (msg.includes('minerAddress')) return { ok: false, reason: 'miner-mismatch' };
    if (msg.includes('bundleHash')) return { ok: false, reason: 'bundle-mismatch' };
    if (msg.includes('saltHex')) return { ok: false, reason: 'invalid-salt' };
    if (msg.includes('patchBytes')) return { ok: false, reason: 'invalid-patch-bytes' };
    return { ok: false, reason: 'commitment-hash-mismatch' };
  }
  if (recomputed.toLowerCase() !== input.commitmentHash.toLowerCase()) {
    return { ok: false, reason: 'commitment-hash-mismatch' };
  }
  return { ok: true, commitmentHash: recomputed };
}

/**
 * Compute the duplicate-key hash for screener-credit collapse.
 * Two patches that produce the same state-root from the same parent
 * by touching the same word indices with the same bytes collapse to
 * one duplicate key and earn at most one screener admission credit.
 */
export function computeDuplicateKey(input: DuplicateKeyInput): string {
  assertBytes32Hex(input.epochParentRoot, 'epochParentRoot');
  assertBytes32Hex(input.resultingStateRoot, 'resultingStateRoot');
  if (!(input.normalizedPatchBytes instanceof Uint8Array)) {
    throw new Error('normalizedPatchBytes: must be Uint8Array');
  }
  const indices = [...input.sortedTouchedWordIndices];
  for (let i = 1; i < indices.length; i++) {
    if (indices[i]! <= indices[i - 1]!) {
      throw new Error('sortedTouchedWordIndices: must be strictly ascending');
    }
  }
  if (indices.some((idx) => !Number.isInteger(idx) || idx < 0 || idx > 1023)) {
    throw new Error('sortedTouchedWordIndices: each index must be an integer in [0, 1023]');
  }
  const idxBytes = new Uint8Array(indices.length * 2);
  for (let i = 0; i < indices.length; i++) {
    idxBytes[i * 2] = (indices[i]! >>> 8) & 0xff;
    idxBytes[i * 2 + 1] = indices[i]! & 0xff;
  }
  const body = concatU8(
    enc.encode(PATCH_DUPLICATE_KEY_DOMAIN_PREFIX),
    hexToBytes(input.epochParentRoot),
    u32BE(indices.length),
    idxBytes,
    u32BE(input.normalizedPatchBytes.length),
    input.normalizedPatchBytes,
    hexToBytes(input.resultingStateRoot),
  );
  return bytesToHex(keccak256(body));
}

/**
 * Merkleize a list of commitment hashes into a single root. The
 * coordinator anchors this root on chain before revealing the eval
 * seed. Any independent verifier with the same set of commitments
 * recomputes the same root.
 */
export function computeCommitmentRoot(commitmentHashes: readonly string[]): string {
  if (commitmentHashes.length === 0) return '0x' + '00'.repeat(32);
  // Sort + dedupe deterministically. Duplicate commitment hashes (same
  // miner, same patch, same salt) collapse to one leaf so re-sending
  // the same commit is a no-op against the root.
  const sortedUnique = [...new Set(commitmentHashes.map((h) => '0x' + h.replace(/^0x/i, '').toLowerCase()))].sort();
  let leaves = sortedUnique.map((h) => {
    return keccak256(concatU8(enc.encode(COMMITMENT_LEAF_DOMAIN_PREFIX), hexToBytes(h)));
  });
  const zero = new Uint8Array(32);
  while (leaves.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const left = leaves[i]!;
      const right = i + 1 < leaves.length ? leaves[i + 1]! : zero;
      next.push(keccak256(concatU8(left, right)));
    }
    leaves = next;
  }
  return bytesToHex(leaves[0]!);
}
