/**
 * How a CHAIN value is spelled before it enters a canonical document.
 *
 * The TypeScript mirror of `python/coretex_validator/canonical.py`. The two are
 * cross-checked by `test/unit/canonical-chain-values.test.mjs`, which compares
 * them field by field on the same inputs — including the one input that matters
 * most here, `2n ** 53n + 1n`.
 *
 * WIDE INTEGERS ARE THE REASON THIS FILE EXISTS.
 *
 * `uint256` and `uint128` values render as DECIMAL STRINGS. In Python that looks
 * like a stylistic choice; in TypeScript it is the difference between a correct
 * validator and a broken one. `Number(2n ** 53n)` and `Number(2n ** 53n + 1n)`
 * are THE SAME DOUBLE — 9007199254740992 — so a snapshot that rendered a
 * `uint256` as a JSON number would mean one thing to a Python reader and another
 * to this one, and "byte-for-byte reproduction" would be meaningless across the
 * two.
 *
 * The affected fields are real: `rigId`, `improvementCredits`, `workUnitsBps`,
 * `creditsEarned`, `difficultyCountSnapshot` (uint256) and `worldSeed`
 * (uint128). `wide()` is the only way one enters a payload, and `narrow()`
 * REFUSES an integer that would need to be wide — a refusal, never a rounding.
 *
 * TWO SPELLINGS, deliberately:
 *  - Solidity-boundary words (bytes32, address, hashes, ABI bytes) -> `0x`-prefixed
 *    lowercase, because that is what the chain, every explorer and `cast` produce;
 *  - content-addressed sha256 roots -> BARE lowercase 64-hex, per the frontier law.
 * A value that is both crosses only through `rootFromWord`.
 */

export class CanonicalizationError extends Error {}

export const MAX_SAFE_INTEGER_BIG = 2n ** 53n - 1n;
export const ZERO_WORD = '0x' + '0'.repeat(64);
export const ZERO_ADDRESS = '0x' + '0'.repeat(40);

const WORD_RE = /^0x[0-9a-f]{64}$/;
const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const HEXDATA_RE = /^0x([0-9a-f]{2})*$/;
const ROOT_RE = /^[0-9a-f]{64}$/;
const DECIMAL_RE = /^[0-9]+$/;

function refuse(message: string): never {
  throw new CanonicalizationError(message);
}

function hexOf(value: Uint8Array): string {
  return Array.from(value, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** A 32-byte chain word as `0x` + 64 lowercase hex. Short input is REFUSED, never padded. */
export function word(value: Uint8Array | string, field = 'bytes32'): string {
  if (value instanceof Uint8Array) {
    if (value.length !== 32) refuse(`${field}: ${value.length} bytes is not a 32-byte word`);
    return '0x' + hexOf(value);
  }
  if (typeof value !== 'string') refuse(`${field}: not a chain word`);
  let text = value.toLowerCase();
  if (!text.startsWith('0x')) text = '0x' + text;
  if (!WORD_RE.test(text)) refuse(`${field}: ${value} is not 32 bytes of hex`);
  return text;
}

/** A 20-byte address as `0x` + 40 lowercase hex. EIP-55 casing is accepted and lowercased. */
export function address(value: Uint8Array | string, field = 'address'): string {
  if (value instanceof Uint8Array) {
    let raw = value;
    if (raw.length === 32) {
      if (raw.subarray(0, 12).some((b) => b !== 0)) {
        refuse(`${field}: 32-byte value has a dirty address padding`);
      }
      raw = raw.subarray(12);
    }
    if (raw.length !== 20) refuse(`${field}: ${raw.length} bytes is not an address`);
    return '0x' + hexOf(raw);
  }
  if (typeof value !== 'string') refuse(`${field}: not an address`);
  let text = value.toLowerCase();
  if (!text.startsWith('0x')) text = '0x' + text;
  if (WORD_RE.test(text)) {
    if (text.slice(2, 26) !== '0'.repeat(24)) {
      refuse(`${field}: ${value} is a 32-byte word with a dirty address padding`);
    }
    text = '0x' + text.slice(26);
  }
  if (!ADDRESS_RE.test(text)) refuse(`${field}: ${value} is not 20 bytes of hex`);
  return text;
}

/** Variable-length ABI `bytes` as `0x` + even-length lowercase hex (`0x` when empty). */
export function hexdata(value: Uint8Array | string, field = 'bytes'): string {
  if (value instanceof Uint8Array) return '0x' + hexOf(value);
  if (typeof value !== 'string') refuse(`${field}: not byte data`);
  let text = value.toLowerCase();
  if (!text.startsWith('0x')) text = '0x' + text;
  if (!HEXDATA_RE.test(text)) refuse(`${field}: ${value} is not an even-length hex string`);
  return text;
}

/** A content-addressed root: BARE lowercase 64-hex. A `0x` prefix is refused, not stripped. */
export function bareRoot(value: string, field = 'root'): string {
  if (typeof value !== 'string' || !ROOT_RE.test(value)) {
    refuse(`${field}: ${value} is not a bare lowercase 64-hex root`);
  }
  return value;
}

/** The bare-root spelling of a chain word. The one sanctioned `0x` -> bare conversion. */
export function rootFromWord(value: Uint8Array | string, field = 'root'): string {
  return bareRoot(word(value, field).slice(2), field);
}

/** The chain-word spelling of a bare root. */
export function wordFromRoot(value: string, field = 'root'): string {
  return word(bareRoot(value, field), field);
}

/**
 * A wide unsigned integer as an EXACT decimal string.
 *
 * Takes `bigint` or a decimal string — NOT `number`. Accepting a `number` would
 * mean accepting a value that had already been narrowed before it got here, and
 * this function cannot un-narrow it.
 */
export function wide(value: bigint | string, field = 'uint256'): string {
  let big: bigint;
  if (typeof value === 'string') {
    if (!DECIMAL_RE.test(value)) refuse(`${field}: ${value} is not a decimal integer string`);
    big = BigInt(value);
  } else if (typeof value === 'bigint') {
    big = value;
  } else {
    refuse(
      `${field}: wide values must arrive as bigint or a decimal string. A number has already ` +
        'lost precision above 2**53-1 and this function cannot recover it',
    );
  }
  if (big < 0n) refuse(`${field}: ${big} is negative`);
  if (big >= 2n ** 256n) refuse(`${field}: ${big} does not fit a uint256`);
  return big.toString(10);
}

/**
 * A narrow unsigned integer as a JSON number — REFUSED if it could not survive a double.
 *
 * The caller's fix for a refusal is `wide()`. Silently returning a rounded
 * number would be the one outcome that produces a wrong answer quietly.
 */
export function narrow(value: bigint | number, field = 'uint64', bits = 64): number {
  const big = typeof value === 'bigint' ? value : BigInt(value);
  if (typeof value === 'number' && !Number.isInteger(value)) {
    refuse(`${field}: ${value} is not an integer`);
  }
  if (big < 0n) refuse(`${field}: ${big} is negative`);
  if (big >= 2n ** BigInt(bits)) refuse(`${field}: ${big} does not fit a uint${bits}`);
  if (big > MAX_SAFE_INTEGER_BIG) {
    refuse(
      `${field}: ${big} exceeds 2**53-1 and cannot be rendered as a JSON number without ` +
        'risking a narrowing in an IEEE-754 reader; render it with wide() instead',
    );
  }
  return Number(big);
}

/** What a snapshot states about its own serialisation. Mirrors the Python record exactly. */
export function canonicalRuleRecord(): Record<string, string> {
  return {
    rule_id: 'coretex_memory.release.canonical_manifest_bytes',
    json: 'UTF-8, keys sorted by code point, no insignificant whitespace',
    floats: 'refused',
    null: 'refused — a field is present with a well-typed value or absent',
    chain_words: '0x-prefixed lowercase hex (bytes32, address, tx/block hashes, ABI bytes)',
    content_roots: 'bare lowercase 64-hex sha256',
    wide_integers: 'uint256/uint128 as exact decimal STRINGS (IEEE-754 safety)',
    narrow_integers: 'uint64 and below as JSON numbers, refused above 2**53-1',
  };
}
