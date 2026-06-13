/**
 * Cross-layer temporal-capacity invariant.
 *
 * For N temporal current/stale PAIRS built the way the eval patch-families build them
 * (each pair = a stale MemoryIndex slot + a current slot + one stride-1 temporal record),
 * the SAME N usable records must be visible through every layer:
 *   1. retrieval decoder      (substrate/retrieval-decoder.ts:decodeSubstrate)  ← what the scorer iterates
 *   2. reserved-bit validator (state/validate.ts:validateReservedBits)
 *
 * Tier-2 decoupling (TEMPORAL_DECOUPLING_DESIGN.md): the artificial retrievalSlot<36 cap is
 * removed (temporal slots set retrievalSlot=0 — the scorer's §temporal path resolves via
 * recordId, never retrievalSlot) and MemoryIndex is STRIDE-1 (352 slots). A pair now consumes
 * two 1-word slots with no <36 constraint; the honest end-to-end ceiling is the Temporal RANGE
 * (96 one-word records → 96 pairs, ≤192 slots, under 256 for 8-bit refs and under 352 slots).
 * N=12,18,24,48,96 all construct & round-trip identically across every layer. Beyond 96 needs a
 * Temporal-region expansion (separately gated).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  decodeSubstrate,
  encodeMemoryIndexSlot,
  encodeTemporalRecord,
} from '../../dist/substrate/retrieval-decoder.js';
import { validateReservedBits } from '../../dist/state/validate.js';
import { RANGES, MAGIC, SCHEMA_VERSION_CoreTex, WORD_COUNT_VALUE } from '../../dist/state/types.js';
import { setField } from '../../dist/state/codec.js';

const TEMPORAL_PAIR_CEILING = 96; // Tier-2: Temporal-region-bound (96 one-word records), retrievalSlot decoupled

function header(words) {
  let w0 = 0n;
  w0 = setField(w0, 255, 240, MAGIC);
  w0 = setField(w0, 239, 224, SCHEMA_VERSION_CoreTex);
  w0 = setField(w0, 223, 208, WORD_COUNT_VALUE);
  words[0] = w0;
}

// Build a state with N temporal current/stale pairs the way the patch-families now do
// (Tier-2): STRIDE-1 MemoryIndex slots (1 word each, write word 0 only), retrievalSlot=0
// (decoupled), one stride-1 temporal record per pair. Beyond the Temporal region (96 records)
// encodeTemporalRecord's recordIndex would exceed the range — that bounds the ceiling.
function buildTemporalState(N) {
  const words = new Array(1024).fill(0n);
  header(words);
  for (let i = 0; i < N; i++) {
    const staleSlot = i * 2, curSlot = i * 2 + 1;
    const sw = encodeMemoryIndexSlot({ slotIndex: staleSlot, recordId: BigInt(0x1000 + staleSlot), family: 'temporal', domainBits: 1n, valid: true, revoked: true, protected: false, retrievalSlot: 0, expiryEpoch: 0n });
    words[RANGES.MEMORY_INDEX_START + staleSlot] = sw[0]; // stride-1: one word per slot
    const cw = encodeMemoryIndexSlot({ slotIndex: curSlot, recordId: BigInt(0x1000 + curSlot), family: 'temporal', domainBits: 1n, valid: true, revoked: false, protected: false, retrievalSlot: 0, expiryEpoch: 0n });
    words[RANGES.MEMORY_INDEX_START + curSlot] = cw[0];
    const tw = encodeTemporalRecord({ recordIndex: i, memorySlot: staleSlot, supersededBy: curSlot, validFromEpoch: 1n, validUntilEpoch: (2n ** 40n - 1n), currentStaleFlag: true });
    words[RANGES.TEMPORAL_START + i] = tw[0]; // stride-1 temporal records
  }
  return { words };
}

describe('temporal capacity — cross-layer invariant', () => {
  for (const N of [12, 18, 24, 48, 96]) {
    test(`N=${N} temporal pairs visible identically across canonical layers (or construction-bounded at ${TEMPORAL_PAIR_CEILING})`, () => {
      let state;
      try {
        state = buildTemporalState(N);
      } catch (e) {
        // Expected for N beyond the honest pair ceiling (retrievalSlot >= 36).
        assert.ok(N > TEMPORAL_PAIR_CEILING, `N=${N} should construct (<= ${TEMPORAL_PAIR_CEILING}) but threw: ${e.message}`);
        assert.match(String(e.message), /retrievalSlot|out of range/i);
        return;
      }

      // 2. validator: state must be reserved-bit clean (canonical reserved region 151:0).
      assert.equal(validateReservedBits(state), null, `N=${N}: reserved-bit validation must pass`);

      // 1. retrieval decoder (scorer's view) sees N usable records (post cross-invariant).
      const sub = decodeSubstrate(state);
      assert.equal(sub.temporal.length, N, `N=${N}: retrieval/scorer must see ${N} usable temporal records, saw ${sub.temporal.length}`);
      // Each usable record points at a distinct, valid stale memory slot.
      const slots = new Set(sub.temporal.map((t) => t.memorySlot));
      assert.equal(slots.size, N, `N=${N}: each record governs a distinct memory slot`);
    });
  }
});
