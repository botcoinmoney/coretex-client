/**
 * Structural validity helper.
 *
 * Wraps decoder output as a [0,1] decode-quality score for use in the
 * composite reward law as a sanity-only signal (w_structural_sanity ≤ 0.10).
 *
 * Spec: specs/retrieval_benchmark.md §structuralValidity.
 */

import type { DecodedSubstrate } from './retrieval-decoder.js';

export function structuralValidity(decoded: DecodedSubstrate): number {
  // §6.4 lens-diversity floor: a collapse is a hard structural rejection,
  // not a graded decode-quality dip. This is the wire-level diagnostic
  // miners see (the diagnostic surface is the existing structuralValidity
  // number — `code: 'rejected'` from the opaque envelope when the floor
  // drives this to 0).
  if (decoded.lensDiversityCheck && !decoded.lensDiversityCheck.ok) return 0;
  if (decoded.decodeAttempts <= 0) return 1;
  const failures = decoded.decodeFailures;
  return Math.max(0, 1 - failures / decoded.decodeAttempts);
}
