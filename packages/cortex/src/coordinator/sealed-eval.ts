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

/** Domain-separation prefix for the sealed eval seed. */
export const SEALED_EVAL_SEED_DOMAIN_PREFIX = 'botcoin-coretex-sealed-eval-v1';

/** Domain-separation tag for the gate-pack sub-seed. */
export const GATE_SEED_DOMAIN_TAG = 'gate';

/** Domain-separation tag for the confirm-pack sub-seed. */
export const CONFIRM_SEED_DOMAIN_TAG = 'confirm';

/** Domain-separation prefix for the gate-pack retirement ID (S6). */
export const GATE_PACK_ID_DOMAIN_PREFIX = 'botcoin-coretex-gate-pack-id-v1';

/** Domain-separation prefix for the confirm-pack retirement ID (S6). */
export const CONFIRM_PACK_ID_DOMAIN_PREFIX = 'botcoin-coretex-confirm-pack-id-v1';

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

// ─── Phase S2 — eval-seed randomness binding ──────────────────────────────────
//
// `coretexEvalSeed` is the per-epoch randomness that derives gate and
// confirm hidden packs. Binding rules from the hardening plan:
//
//   1. `epochSecret` is committed before the epoch starts
//   2. `futureBlockHash` is the hash of a Base block chosen BEFORE
//      commitments are known and produced AFTER the commit window closes
//   3. `commitmentRoot` is anchored before `epochSecret` is revealed
//   4. `optionalDrandRoundHash` adds coordinator/sequencer independence
//   5. NEVER use a coordinator-only seed as the sole eval seed
//
// `deriveCoretexEvalSeed` enforces rule 5 by REQUIRING `futureBlockHash`
// (the only external-to-coordinator binding the launch flow has). Drand
// is recommended but optional; if both external sources are missing it
// fails closed.
//
// The derivation hashes every binding (epochId, parentRoot, corpusRoot,
// bundleHash, commitmentRoot, epochSecret, futureBlockHash,
// optionalDrandRoundHash) so changing ANY of them produces a different
// seed — adversaries cannot grind preimages of just the epoch secret.

export interface CoretexEvalSeedInput {
  /** Epoch id (uint64). */
  readonly epochId: bigint | number;
  /** Substrate parent root the eval pack is sampled against (bytes32 hex). */
  readonly epochParentRoot: string;
  /** Corpus root the hidden pack is sampled from (bytes32 hex). */
  readonly corpusRoot: string;
  /** Bundle hash that pins the scorer + map (bytes32 hex). */
  readonly bundleHash: string;
  /**
   * Merkle root of accepted commitments, output of `computeCommitmentRoot`.
   * Must be anchored on chain before `epochSecret` is revealed.
   */
  readonly commitmentRoot: string;
  /**
   * Coordinator-committed epoch secret (bytes32 hex). Revealed after
   * commitmentRoot is anchored, never before.
   */
  readonly epochSecret: string;
  /**
   * Hash of a Base block chosen BEFORE commitments are known and
   * produced AFTER the commit window closes (bytes32 hex). The
   * external-to-coordinator binding that makes the seed unpredictable
   * to coordinator-affiliated actors. Required — fail closed if absent.
   */
  readonly futureBlockHash: string;
  /**
   * Drand round hash for additional coordinator/sequencer independence
   * (bytes32 hex). Optional; pass undefined to use the bonus-epoch
   * blockhash pattern alone. Recommended for production once a stable
   * drand round source is wired up.
   */
  readonly optionalDrandRoundHash?: string;
}

/**
 * Compute the canonical coretexEvalSeed. Pure function of public + just-
 * revealed inputs. Any verifier with the same bindings reproduces the
 * same seed; adversaries cannot precompute it because at least one
 * binding (`futureBlockHash`) is unknown until after commit close.
 *
 * Throws if `futureBlockHash` is missing or zero — that's a
 * coordinator-only-randomness scenario which the plan explicitly
 * forbids ("Never use a coordinator-only seed as the sole eval seed").
 */
export function deriveCoretexEvalSeed(input: CoretexEvalSeedInput): string {
  assertBytes32Hex(input.epochParentRoot, 'epochParentRoot');
  assertBytes32Hex(input.corpusRoot, 'corpusRoot');
  assertBytes32Hex(input.bundleHash, 'bundleHash');
  assertBytes32Hex(input.commitmentRoot, 'commitmentRoot');
  assertBytes32Hex(input.epochSecret, 'epochSecret');
  assertBytes32Hex(input.futureBlockHash, 'futureBlockHash');

  // Refuse a zero blockhash — it would let an adversary precompute the
  // seed using only coordinator-known material (the plan's rule 5).
  // The runtime expectation is that the coordinator pre-pins a Base
  // block height and reads the actual hash from chain after that block
  // is finalized; a zero hash means "not yet observed" and the seed
  // derivation must wait.
  if (/^0x0+$/i.test(input.futureBlockHash)) {
    throw new Error('futureBlockHash: cannot be zero (would collapse to coordinator-only randomness)');
  }
  // Same refusal on a zero epochSecret — a coordinator that "committed"
  // to zero is signalling no commitment at all.
  if (/^0x0+$/i.test(input.epochSecret)) {
    throw new Error('epochSecret: cannot be zero');
  }

  let drandPart: Uint8Array;
  if (input.optionalDrandRoundHash !== undefined) {
    assertBytes32Hex(input.optionalDrandRoundHash, 'optionalDrandRoundHash');
    drandPart = hexToBytes(input.optionalDrandRoundHash);
  } else {
    drandPart = new Uint8Array(32); // 32-byte zero sentinel when drand isn't mixed in
  }

  const body = concatU8(
    enc.encode(SEALED_EVAL_SEED_DOMAIN_PREFIX),
    u64BE(input.epochId),
    hexToBytes(input.epochParentRoot),
    hexToBytes(input.corpusRoot),
    hexToBytes(input.bundleHash),
    hexToBytes(input.commitmentRoot),
    hexToBytes(input.epochSecret),
    hexToBytes(input.futureBlockHash),
    drandPart,
  );
  return bytesToHex(keccak256(body));
}

/**
 * Derive the gate-pack sub-seed from the canonical eval seed.
 *
 *   gateSeed = keccak256(coretexEvalSeed || "gate")
 */
export function deriveGateSeed(coretexEvalSeed: string): string {
  assertBytes32Hex(coretexEvalSeed, 'coretexEvalSeed');
  return bytesToHex(keccak256(concatU8(
    hexToBytes(coretexEvalSeed),
    enc.encode(GATE_SEED_DOMAIN_TAG),
  )));
}

/**
 * Derive the confirm-pack sub-seed from the canonical eval seed.
 *
 *   confirmSeed = keccak256(coretexEvalSeed || "confirm")
 *
 * Distinct from gateSeed so the confirm pack is a fresh draw — only
 * finalists pay the expensive second pass and pack-luck advances are
 * filtered out.
 */
export function deriveConfirmSeed(coretexEvalSeed: string): string {
  assertBytes32Hex(coretexEvalSeed, 'coretexEvalSeed');
  return bytesToHex(keccak256(concatU8(
    hexToBytes(coretexEvalSeed),
    enc.encode(CONFIRM_SEED_DOMAIN_TAG),
  )));
}

// ─── Phase S5 — screener admission decision ──────────────────────────────────
//
// The hardening plan redefines screener credit semantics:
//   1. No credit for pre-commit structural validity
//   2. Screener-pass credit is post-commit admission credit
//   3. At most M screener-credit-eligible candidates per miner per epoch
//   4. Duplicate key collapse — two patches with the same duplicateKey
//      earn at most ONE candidate-admission credit
//   5. Existing stake/account requirements + flat rate limits stay the
//      Sybil boundary (this helper does not touch them)
//
// This module supplies a PURE decision function. The host maintains the
// epoch-scoped bookkeeping (which miners and which dup keys have
// already been credited this epoch) and passes those sets in. The
// function returns yes/no + a coarse reason code that the host logs in
// epoch metadata; the host does the actual credit accounting.

export interface ScreenerAdmissionInput {
  /** Miner address — checksum-insensitive, normalized to lowercase 0x. */
  readonly minerAddress: string;
  /** Commitment hash being admitted (must already be revealed + structurally valid). */
  readonly commitmentHash: string;
  /**
   * Duplicate key for the patch result. Computed via
   * `computeDuplicateKey` over (epochParentRoot, sorted touched word
   * indices, normalized patch bytes, resulting state root). Two patches
   * with the same duplicate key collapse to a single screener admission.
   */
  readonly duplicateKey: string;
  /**
   * Set of duplicate keys already credited THIS EPOCH (across all
   * miners). Host owns this state. New duplicateKey not in this set
   * → admissible; duplicateKey already in this set → collapsed.
   */
  readonly admittedDuplicateKeysThisEpoch: ReadonlySet<string>;
  /**
   * Count of screener-credit-eligible candidates this miner has
   * already had admitted THIS EPOCH. The cap is enforced here, not
   * by stake or rate limits.
   */
  readonly minerAdmissionsThisEpoch: number;
  /**
   * Per-miner per-epoch admission cap M. Pinned by the bundle profile
   * (calibrator output) or coordinator config; passed in explicitly
   * so this helper stays pure.
   */
  readonly perMinerCap: number;
  /**
   * Whether the reveal has already passed post-commit admission
   * (structural, visible-split non-regression, etc.). The host runs
   * the admission check separately; this helper assumes a true input
   * is already cleared. If false, admission is refused as
   * `pre-commit-structural-only`.
   */
  readonly postCommitAdmissionPassed: boolean;
}

export type ScreenerAdmissionDecision =
  | { readonly admit: true; readonly reason: 'OK' }
  | { readonly admit: false; readonly reason: ScreenerAdmissionRejectReason };

export type ScreenerAdmissionRejectReason =
  /** Reveal has not yet passed post-commit admission. */
  | 'pre-commit-structural-only'
  /** This miner has already hit the per-epoch cap. */
  | 'per-miner-cap-reached'
  /** Another commitment with the same duplicateKey was already admitted. */
  | 'duplicate-key-collapsed'
  /** Caller passed an obviously malformed input. */
  | 'malformed-input';

/**
 * Decide whether a revealed commitment qualifies for screener credit.
 * Pure; the host does the bookkeeping side-effects on `admit: true`.
 *
 * Reason codes are written to epoch metadata so independent verifiers
 * can audit the screener-credit ledger after retirement.
 */
export function screenerAdmissionDecision(input: ScreenerAdmissionInput): ScreenerAdmissionDecision {
  // Fail-closed shape checks — these would indicate a coordinator-side
  // bug, not a miner-attack vector; reject with a stable reason code so
  // the audit log can flag it.
  try {
    assertBytes32Hex(input.commitmentHash, 'commitmentHash');
    assertBytes32Hex(input.duplicateKey, 'duplicateKey');
    assertAddressHex(input.minerAddress, 'minerAddress');
  } catch {
    return { admit: false, reason: 'malformed-input' };
  }
  if (!Number.isInteger(input.minerAdmissionsThisEpoch) || input.minerAdmissionsThisEpoch < 0) {
    return { admit: false, reason: 'malformed-input' };
  }
  if (!Number.isInteger(input.perMinerCap) || input.perMinerCap <= 0) {
    return { admit: false, reason: 'malformed-input' };
  }
  if (typeof input.postCommitAdmissionPassed !== 'boolean') {
    return { admit: false, reason: 'malformed-input' };
  }

  // Rule 2: post-commit admission only. A revealed-but-structurally-invalid
  // patch earns no screener credit, no matter what.
  if (!input.postCommitAdmissionPassed) {
    return { admit: false, reason: 'pre-commit-structural-only' };
  }

  // Rule 4: duplicate-key collapse. If another commitment with the same
  // duplicateKey was already credited this epoch (could be a different
  // miner's identical patch, or the same miner re-submitting), refuse.
  const dupKeyLower = '0x' + input.duplicateKey.replace(/^0x/i, '').toLowerCase();
  if (input.admittedDuplicateKeysThisEpoch.has(dupKeyLower)) {
    return { admit: false, reason: 'duplicate-key-collapsed' };
  }

  // Rule 3: per-miner cap. Once a miner hits M admissions in this
  // epoch, further admissions don't earn credit (the reveal still
  // happens, the patch can still flow into gate/confirm eval, but no
  // additional screener credit is awarded).
  if (input.minerAdmissionsThisEpoch >= input.perMinerCap) {
    return { admit: false, reason: 'per-miner-cap-reached' };
  }

  return { admit: true, reason: 'OK' };
}

// ─── S6: Corpus retirement ────────────────────────────────────────────────────
//
// After settlement, the host marks the gate and confirm packs used in
// this epoch as "spent" so future hidden-pack derivation excludes them
// (plan §S6: "Mark gate/confirm packs spent after reveal"). These
// helpers are pure — the host owns the retired-set storage and
// canonical-form insertion.

/**
 * Derive a stable, domain-separated 32-byte identifier for the gate
 * pack of a sealed epoch. The host stores this ID forever once the
 * gate seed is revealed; future hidden-pack derivation refuses to
 * reuse a retired ID. Different domain prefix from the gate sub-seed
 * itself so callers can't accidentally substitute one for the other.
 */
export function computeGatePackId(gateSeedHex: string): string {
  assertBytes32Hex(gateSeedHex, 'gateSeedHex');
  const buf = concatU8(enc.encode(GATE_PACK_ID_DOMAIN_PREFIX), hexToBytes(gateSeedHex));
  return bytesToHex(keccak256(buf));
}

/**
 * Confirm-pack analog of computeGatePackId. Distinct domain prefix
 * guarantees gate-pack-ID and confirm-pack-ID never collide even if a
 * caller somehow reuses the same seed bytes for both packs.
 */
export function computeConfirmPackId(confirmSeedHex: string): string {
  assertBytes32Hex(confirmSeedHex, 'confirmSeedHex');
  const buf = concatU8(enc.encode(CONFIRM_PACK_ID_DOMAIN_PREFIX), hexToBytes(confirmSeedHex));
  return bytesToHex(keccak256(buf));
}

/**
 * Returns true iff `packId` (bytes32 hex) is already present in the
 * host's retired-set. Case-insensitive lookup — host canonicalizes
 * with `.toLowerCase()` on insertion (mirroring the duplicate-key
 * collapse rule).
 *
 * Pure predicate. The host owns the set storage and is responsible
 * for adding pack IDs after settlement completes.
 */
export function isPackRetired(packId: string, retired: ReadonlySet<string>): boolean {
  assertBytes32Hex(packId, 'packId');
  return retired.has('0x' + packId.replace(/^0x/i, '').toLowerCase());
}
