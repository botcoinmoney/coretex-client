/**
 * PatchReceivedNotice — coordinator's public commitment to "I received
 * this patch at this Base block".
 *
 * Per `docs/CORETEX_PRODUCTION_RUNBOOK.md §8.3` and `docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md
 * §Receipt Honesty`. `receivedAtBlock` is the only seed input the
 * coordinator picks unilaterally. A dishonest coordinator could delay
 * processing to wait for a favorable future blockhash. Mitigation: the
 * coordinator publishes a signed PatchReceivedNotice to a public
 * append-only log within the same Base block as `receivedAtBlock`.
 * Replay watchers cross-check every receipt's `receivedAtBlock` against
 * the public notice for that patchHash. Mismatch → invalid receipt.
 *
 * This module contains the pure-code primitives:
 *   - canonical notice envelope + canonical-bytes serialization
 *   - keccak256 commitment hash (domain-separated)
 *   - verification helper a watcher uses to validate a notice + receipt pair
 *
 * Storage / HTTP / signing are host concerns. The host writes a notice
 * to its public log at ingress time (before any eval scheduling) and
 * later binds receipts to the notice it wrote.
 *
 * Post-launch upgrade path: replace the off-chain log with a contract
 * event `PatchReceived(bytes32 patchHash, uint64 receivedAtBlock)`. The
 * canonical bytes of this notice align with the event's signed
 * envelope so the upgrade requires no replay rework.
 */
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Domain prefix for the notice commitment hash. */
export const PATCH_RECEIVED_NOTICE_DOMAIN_PREFIX = 'coretex-patch-received-notice-v1';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PatchReceivedNotice {
  /** bytes32 hex — same patchHash that ends up on the receipt. */
  readonly patchHash: string;
  /** Base block number at which the coordinator received the patch.
   *  Must equal `receivedAtBlock` on the eventual receipt. */
  readonly receivedAtBlock: number;
  /** Unix-seconds timestamp at the moment of receipt. Informational —
   *  the on-chain block number is the authoritative witness. */
  readonly receivedAtTimestamp: number;
  /** Coordinator's signing-key address (bytes20 hex, lowercased). */
  readonly coordinatorAddress: string;
}

// ─── Encoding helpers ─────────────────────────────────────────────────────────

const enc = new TextEncoder();

function concatU8(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function u64BE(v: number): Uint8Array {
  let n = BigInt(v);
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

function assertAddressHex(value: string, field: string): void {
  if (typeof value !== 'string') throw new Error(`${field}: not a string`);
  const clean = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
  if (clean.length !== 40) throw new Error(`${field}: must be 20 bytes hex (got ${clean.length / 2})`);
  if (!/^[0-9a-fA-F]{40}$/.test(clean)) throw new Error(`${field}: non-hex characters`);
}

// ─── Primitives ───────────────────────────────────────────────────────────────

/**
 * Canonical bytes the coordinator signs. Layout aligns with the
 * post-launch contract event `PatchReceived(bytes32 patchHash, uint64
 * receivedAtBlock)` so upgrading the publication channel doesn't
 * change replay semantics.
 */
export function canonicalNoticeBytes(notice: PatchReceivedNotice): Uint8Array {
  assertBytes32Hex(notice.patchHash, 'patchHash');
  assertAddressHex(notice.coordinatorAddress, 'coordinatorAddress');
  if (!Number.isInteger(notice.receivedAtBlock) || notice.receivedAtBlock < 0) {
    throw new Error('receivedAtBlock must be a non-negative integer');
  }
  if (!Number.isInteger(notice.receivedAtTimestamp) || notice.receivedAtTimestamp < 0) {
    throw new Error('receivedAtTimestamp must be a non-negative integer');
  }
  return concatU8(
    enc.encode(PATCH_RECEIVED_NOTICE_DOMAIN_PREFIX),
    hexToBytes(notice.patchHash),
    u64BE(notice.receivedAtBlock),
    u64BE(notice.receivedAtTimestamp),
    hexToBytes(notice.coordinatorAddress),
  );
}

/**
 * Domain-separated commitment hash of a notice. Used as the public
 * "I committed to this patch arrival" anchor on the notice log.
 */
export function computePatchReceivedNoticeHash(notice: PatchReceivedNotice): string {
  return bytesToHex(keccak256(canonicalNoticeBytes(notice)));
}

// ─── Verification ─────────────────────────────────────────────────────────────

export type NoticeVerificationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: NoticeVerificationFailureCode; readonly detail: string };

export type NoticeVerificationFailureCode =
  | 'NOTICE_MISSING'                    // host log has no entry for this patchHash
  | 'PATCH_HASH_MISMATCH'               // notice's patchHash != receipt's
  | 'RECEIVED_AT_BLOCK_MISMATCH'        // notice's block != receipt's receivedAtBlock
  | 'NOTICE_HASH_MISMATCH';             // recomputed notice hash != stored hash

export interface NoticeVerificationInput {
  /** The notice the watcher fetched from the host's public log. */
  readonly notice: PatchReceivedNotice | null;
  /** The pre-computed hash anchored on the public log alongside the
   *  notice. Verifier recomputes from `notice` and asserts equality. */
  readonly storedNoticeHash: string;
  /** Receipt fields the notice must agree with. */
  readonly receiptPatchHash: string;
  readonly receiptReceivedAtBlock: number;
}

/**
 * Cross-check a notice against a receipt. Watchers call this for every
 * accepted-transition receipt during replay; mismatch → reject the
 * receipt as untrusted.
 */
export function verifyPatchReceivedNotice(input: NoticeVerificationInput): NoticeVerificationResult {
  if (input.notice === null) {
    return {
      ok: false,
      code: 'NOTICE_MISSING',
      detail: `no PatchReceivedNotice published for patchHash ${input.receiptPatchHash}`,
    };
  }
  if (!hexEq(input.notice.patchHash, input.receiptPatchHash)) {
    return {
      ok: false,
      code: 'PATCH_HASH_MISMATCH',
      detail: `notice.patchHash=${input.notice.patchHash} receipt.patchHash=${input.receiptPatchHash}`,
    };
  }
  if (input.notice.receivedAtBlock !== input.receiptReceivedAtBlock) {
    return {
      ok: false,
      code: 'RECEIVED_AT_BLOCK_MISMATCH',
      detail: `notice.receivedAtBlock=${input.notice.receivedAtBlock} receipt.receivedAtBlock=${input.receiptReceivedAtBlock}`,
    };
  }
  const recomputed = computePatchReceivedNoticeHash(input.notice);
  if (!hexEq(recomputed, input.storedNoticeHash)) {
    return {
      ok: false,
      code: 'NOTICE_HASH_MISMATCH',
      detail: `recomputed=${recomputed} stored=${input.storedNoticeHash}`,
    };
  }
  return { ok: true };
}

function hexEq(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
