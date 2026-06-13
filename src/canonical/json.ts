/**
 * THE canonical-JSON serializer for every hash- and signature-feeding surface
 * (corpus deltas, rotation manifests, bundleHash, work-policy hash, eval-report
 * artifacts). One implementation — divergent copies were the repo's single
 * largest consensus-drift hazard (audit F14/Q1).
 *
 * Semantics (a strict superset of the retired per-file copies; byte-identical
 * output for every value any of them accepted without throwing, EXCEPT the two
 * deliberate bug-class removals below):
 *   - object keys are sorted by UTF-16 code units (default Array.sort — locale
 *     independent) and keys whose value is `undefined` are SKIPPED, matching
 *     `JSON.stringify`. (The retired copies emitted `"key":null`, so a
 *     spread-built manifest with an explicit-undefined key hashed differently
 *     from its own disk round-trip — a fail-closed verify footgun.)
 *   - non-finite numbers THROW. (`JSON.stringify(NaN)` silently corrupts a
 *     hash input to `null`.)
 *   - bigint -> decimal string (`"123"`), Uint8Array -> bare lowercase hex
 *     string, Map -> object via `String(key)` then the object rules.
 *   - array holes / `undefined` elements -> `null` (JSON semantics).
 *   - top-level `undefined`, symbols, and functions THROW.
 *
 * NOT used by `eval/index.ts`'s legacy phase-3 EvalReport hash, whose bigint
 * encoding (`"123n"`) is intentionally distinct and frozen.
 */

export interface CanonicalJsonOptions {
  /** 'finite' (default): any finite number. 'safe-integer': additionally
   *  reject non-integers — for hashes mirrored by integer-only consumers
   *  (e.g. the on-chain work-policy hash). */
  readonly numbers?: 'finite' | 'safe-integer';
}

/** Bare lowercase hex (no 0x prefix) — the embedding/byte-field encoding the
 *  corpus serializers already use. */
export function bytesToBareHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

export function canonicalJson(value: unknown, opts: CanonicalJsonOptions = {}): string {
  if (value === undefined) {
    throw new TypeError('canonicalJson: top-level undefined is not serializable');
  }
  return serialize(value, opts);
}

function serialize(value: unknown, opts: CanonicalJsonOptions): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`canonicalJson: non-finite number ${String(value)} would silently hash as null`);
    }
    if (opts.numbers === 'safe-integer' && !Number.isSafeInteger(value)) {
      throw new TypeError('canonicalJson: numbers must be safe integers under the safe-integer policy');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (value instanceof Uint8Array) return JSON.stringify(bytesToBareHex(value));
  if (value instanceof Map) {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of value) obj[String(k)] = v;
    return serialize(obj, opts);
  }
  if (Array.isArray(value)) {
    // JSON semantics: holes and undefined elements serialize as null.
    return `[${value.map((v) => (v === undefined ? 'null' : serialize(v, opts))).join(',')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(obj).sort()) {
      const v = obj[key];
      if (v === undefined) continue; // match JSON.stringify: absent, not null
      parts.push(`${JSON.stringify(key)}:${serialize(v, opts)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
}
