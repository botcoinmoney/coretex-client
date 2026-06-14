/**
 * Per-patch on-chain eval-seed derivation. Pure functions.
 *
 * Each patch derives TWO domain-separated seeds — `gate` and `confirm` —
 * from the same blockhash. A patch must clear threshold on both packs
 * to be accepted.
 *
 * Anti-pre-testing property: blockhash(receivedAtBlock + targetBlockOffset)
 * does not exist when the patch arrives at the coordinator. The
 * coordinator cannot compute any patch's eval seed at submission time.
 *
 * Miner identity is intentionally NOT part of the seed. Two miners
 * submitting the same `(parentRoot, patchBytes)` resolve to the same
 * dedup key and the same eval seed; first-submitter wins on the
 * shared cached verdict. Including minerAddress in the seed would
 * create ambiguity (different "true" seeds, single cached verdict)
 * without preventing sybil rerolls — the dedup cache already does
 * that.
 *
 * Replay verification: given the post-epoch `epochSecret` reveal + any
 * Base RPC, a third party recomputes every accepted patch's seeds
 * byte-identically.
 *
 * No I/O, no model work. Caller is responsible for fetching the
 * blockhash, holding the epochSecret, and feeding pinned bundle/corpus
 * roots.
 */
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';

// ─── Domain prefixes ──────────────────────────────────────────────────────────

/** Domain prefix for the gate-pack eval seed. */
export const EVAL_SEED_GATE_DOMAIN_PREFIX = 'coretex-eval-v1-gate';

/** Domain prefix for the confirm-pack eval seed. Distinct from gate so
 * gate and confirm packs are statistically independent draws. */
export const EVAL_SEED_CONFIRM_DOMAIN_PREFIX = 'coretex-eval-v1-confirm';

/** Domain prefix for the per-patch dedup key — the cache lookup for
 * "same patch already evaluated against this parent". */
export const DEDUP_KEY_DOMAIN_PREFIX = 'coretex-dedup-key-v1';

/** Domain prefix for the patchHash — the canonical identifier of the
 * normalized patch bytes. */
export const PATCH_HASH_DOMAIN_PREFIX = 'coretex-patch-hash-v1';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface EvalSeedInput {
  /** Epoch secret revealed at epoch close. bytes32 hex. */
  readonly epochSecret: string;
  /** blockhash(receivedAtBlock + targetBlockOffset). bytes32 hex. */
  readonly blockhash: string;
  /** Epoch ID this patch targets. */
  readonly epochId: bigint | number;
  /** keccak256 of normalized patch bytes, with domain prefix. bytes32 hex. */
  readonly patchHash: string;
  /** Parent state root the patch was constructed against. bytes32 hex. */
  readonly parentRoot: string;
  /** Corpus root pinned in the bundle. bytes32 hex. */
  readonly corpusRoot: string;
  /** Bundle hash. bytes32 hex. */
  readonly bundleHash: string;
}

// ─── Encoding helpers (private) ───────────────────────────────────────────────

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

// ─── Seed derivation ──────────────────────────────────────────────────────────

function deriveEvalSeedWithPrefix(prefix: string, input: EvalSeedInput): string {
  assertBytes32Hex(input.epochSecret, 'epochSecret');
  assertBytes32Hex(input.blockhash, 'blockhash');
  assertBytes32Hex(input.patchHash, 'patchHash');
  assertBytes32Hex(input.parentRoot, 'parentRoot');
  assertBytes32Hex(input.corpusRoot, 'corpusRoot');
  assertBytes32Hex(input.bundleHash, 'bundleHash');
  // Zero blockhash means "block not observed yet" — refuse rather than
  // silently degrade to coordinator-only randomness.
  if (/^0x?0{64}$/i.test(input.blockhash)) {
    throw new Error('deriveEvalSeed: blockhash is zero — wait for the target block before deriving');
  }
  const buf = concatU8(
    enc.encode(prefix),
    hexToBytes(input.epochSecret),
    hexToBytes(input.blockhash),
    u64BE(input.epochId),
    hexToBytes(input.patchHash),
    hexToBytes(input.parentRoot),
    hexToBytes(input.corpusRoot),
    hexToBytes(input.bundleHash),
  );
  return bytesToHex(keccak256(buf));
}

/** Derive the gate-pack eval seed. See module header for properties. */
export function deriveGateEvalSeed(input: EvalSeedInput): string {
  return deriveEvalSeedWithPrefix(EVAL_SEED_GATE_DOMAIN_PREFIX, input);
}

/** Derive the confirm-pack eval seed. Distinct from the gate seed even
 * for identical inputs because the domain prefix differs. */
export function deriveConfirmEvalSeed(input: EvalSeedInput): string {
  return deriveEvalSeedWithPrefix(EVAL_SEED_CONFIRM_DOMAIN_PREFIX, input);
}

/**
 * Canonical patchHash — domain-separated keccak256 of normalized patch
 * bytes. The "normalized" form is the compact-patch wire encoding
 * produced by the cortex encoder (no re-encoding artifacts, no
 * whitespace, no leading zeros on bigints, etc.). Caller is
 * responsible for normalization; this helper hashes the bytes it
 * receives.
 */
export function computePatchHash(normalizedPatchBytes: Uint8Array): string {
  if (!(normalizedPatchBytes instanceof Uint8Array)) {
    throw new TypeError('computePatchHash: normalizedPatchBytes must be Uint8Array');
  }
  const buf = concatU8(enc.encode(PATCH_HASH_DOMAIN_PREFIX), normalizedPatchBytes);
  return bytesToHex(keccak256(buf));
}

/**
 * Wire offset + width of the compact-patch `scoreDelta` field: it sits at
 * bytes [2, 10) of the fixed 42-byte header (patchType[1] · wordCount[1] ·
 * scoreDelta[8] · parentStateRoot[32]). Pinned against the contract by the
 * patch-type Solidity parity test.
 */
export const SCORE_DELTA_WIRE_OFFSET = 2;
export const SCORE_DELTA_WIRE_BYTES = 8;

/**
 * Semantic patch hash — `computePatchHash` over the wire bytes with the
 * `scoreDelta` field ZEROED. `scoreDelta` is miner-controlled and does NOT
 * affect the state transition (it is not a word write). Keying dedup, the
 * future-blockhash seed, and the eval artifact off the LITERAL bytes let a
 * miner vary those 8 bytes to redraw the hidden pack for the same semantic
 * patch (a grinding reroll) AND made state-advance post-reveal replay binding
 * impossible (the coordinator rewrites `scoreDelta` to `scoreAfter-scoreBefore`
 * before signing, so the on-chain bytes never matched the artifact's hash).
 * Hashing the scoreDelta-zeroed bytes makes one semantic patch one hash:
 * dedup/seed/artifact are reroll-proof, and the rewritten on-chain advance
 * binds to the same artifact (the client compares this hash, not the literal
 * on-chain patchHash). The contract still enforces the real scoreDelta in the
 * wire bytes via its independent `scoreDelta == scoreAfter-scoreBefore` check.
 */
export function semanticPatchHash(compactPatchBytes: Uint8Array): string {
  if (!(compactPatchBytes instanceof Uint8Array)) {
    throw new TypeError('semanticPatchHash: compactPatchBytes must be Uint8Array');
  }
  if (compactPatchBytes.length < SCORE_DELTA_WIRE_OFFSET + SCORE_DELTA_WIRE_BYTES) {
    throw new Error('semanticPatchHash: compact patch shorter than the fixed header');
  }
  const norm = compactPatchBytes.slice();
  norm.fill(0, SCORE_DELTA_WIRE_OFFSET, SCORE_DELTA_WIRE_OFFSET + SCORE_DELTA_WIRE_BYTES);
  return computePatchHash(norm);
}

/**
 * Canonical dedup key — used by the live-eval dedup cache. Patches
 * with the same (parentRoot, normalizedPatchBytes) share a dedup key
 * and get cached verdicts (anti-probing-via-resubmission).
 */
export function computeDedupKey(parentRoot: string, normalizedPatchBytes: Uint8Array): string {
  assertBytes32Hex(parentRoot, 'parentRoot');
  if (!(normalizedPatchBytes instanceof Uint8Array)) {
    throw new TypeError('computeDedupKey: normalizedPatchBytes must be Uint8Array');
  }
  const buf = concatU8(
    enc.encode(DEDUP_KEY_DOMAIN_PREFIX),
    hexToBytes(parentRoot),
    normalizedPatchBytes,
  );
  return bytesToHex(keccak256(buf));
}
