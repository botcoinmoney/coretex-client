/**
 * Structural validity helper.
 *
 * Wraps decoder output as a [0,1] decode-quality score for use in the
 * composite reward law as a sanity-only signal (w_structural_sanity ≤ 0.10).
 *
 * Spec: specs/retrieval_benchmark_v0.md §structuralValidity.
 */

import type { DecodedSubstrate } from './retrieval-decoder.js';

export function structuralValidity(decoded: DecodedSubstrate): number {
  if (decoded.decodeAttempts <= 0) return 1;
  const failures = decoded.decodeFailures;
  return Math.max(0, 1 - failures / decoded.decodeAttempts);
}
