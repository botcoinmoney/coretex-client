/**
 * Cross-layer temporal-capacity invariant.
 *
 * For N temporal current/stale PAIRS built the way the eval patch-families build them
 * (each pair = a stale MemoryIndex slot + a current slot + one stride-1 temporal record),
 * the SAME N usable records must be visible through every layer:
 *   1. raw state decoder      (decoder/index.ts:decodeCortexState)
 *   2. retrieval decoder      (substrate/retrieval-decoder.ts:decodeSubstrate)  ← what the scorer iterates
 *   3. reserved-bit validator (state/validate.ts:validateReservedBits)
 *
 * Honest ceiling: a pair consumes two MemoryIndex slots whose `retrievalSlot` must be < 36,
 * so the patch-family can place at most 18 pairs end-to-end even though the temporal RANGE
 * holds 96 one-word records. N=12,18 construct & round-trip; N=24,48,96 are expected to be
 * construction-bounded (retrievalSlot >= 36) until the MemoryIndex/retrieval-key coupling is
 * redesigned.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { decodeCortexState } from '../../dist/decoder/index.js';
import {
  decodeSubstrate,
  encodeMemoryIndexSlot,
  encodeTemporalRecord,
} from '../../dist/substrate/retrieval-decoder.js';
import { validateReservedBits } from '../../dist/state/validate.js';
import { RANGES, MAGIC, SCHEMA_VERSION_CoreTex, WORD_COUNT_VALUE } from '../../dist/state/types.js';
import { setField } from '../../dist/state/codec.js';

const TEMPORAL_PAIR_CEILING = 18; // retrievalSlot < 36, two slots per pair

function header(words) {
  let w0 = 0n;
  w0 = setField(w0, 255, 240, MAGIC);
  w0 = setField(w0, 239, 224, SCHEMA_VERSION_CoreTex);
  w0 = setField(w0, 223, 208, WORD_COUNT_VALUE);
  words[0] = w0;
}

// Build a state with N temporal current/stale pairs. Throws (from encodeMemoryIndexSlot)
// when a slot's retrievalSlot reaches 36 — that throw IS the honest end-to-end ceiling.
function buildTemporalState(N) {
  const words = new Array(1024).fill(0n);
  header(words);
  for (let i = 0; i < N; i++) {
    const staleSlot = i * 2, curSlot = i * 2 + 1;
    const sw = encodeMemoryIndexSlot({ slotIndex: staleSlot, recordId: BigInt(0x1000 + staleSlot), family: 'temporal', domainBits: 1n, valid: true, revoked: true, protected: false, retrievalSlot: staleSlot, expiryEpoch: 0n });
    for (let j = 0; j < sw.length; j++) words[RANGES.MEMORY_INDEX_START + staleSlot * 8 + j] = sw[j];
    const cw = encodeMemoryIndexSlot({ slotIndex: curSlot, recordId: BigInt(0x1000 + curSlot), family: 'temporal', domainBits: 1n, valid: true, revoked: false, protected: false, retrievalSlot: curSlot, expiryEpoch: 0n });
    for (let j = 0; j < cw.length; j++) words[RANGES.MEMORY_INDEX_START + curSlot * 8 + j] = cw[j];
    const tw = encodeTemporalRecord({ recordIndex: i, memorySlot: staleSlot, supersededBy: curSlot, validFromEpoch: 1n, validUntilEpoch: (2n ** 40n - 1n), currentStaleFlag: true });
    for (let j = 0; j < tw.length; j++) words[RANGES.TEMPORAL_START + i * tw.length + j] = tw[j];
  }
  return { words };
}

describe('temporal capacity — cross-layer invariant', () => {
  for (const N of [12, 18, 24, 48, 96]) {
    test(`N=${N} temporal pairs visible identically across all layers (or construction-bounded at ${TEMPORAL_PAIR_CEILING})`, () => {
      let state;
      try {
        state = buildTemporalState(N);
      } catch (e) {
        // Expected for N beyond the honest pair ceiling (retrievalSlot >= 36).
        assert.ok(N > TEMPORAL_PAIR_CEILING, `N=${N} should construct (<= ${TEMPORAL_PAIR_CEILING}) but threw: ${e.message}`);
        assert.match(String(e.message), /retrievalSlot|out of range/i);
        return;
      }

      // 3. validator: state must be reserved-bit clean (canonical reserved region 151:0).
      assert.equal(validateReservedBits(state), null, `N=${N}: reserved-bit validation must pass`);

      // 1. raw decoder sees N stale records.
      const raw = decodeCortexState(state);
      assert.equal(raw.ok, true, `N=${N}: raw decode ok`);
      const rawStale = raw.decoded.temporal.filter((t) => t.currentStaleFlag).length;
      assert.equal(rawStale, N, `N=${N}: raw decoder must see ${N} stale records, saw ${rawStale}`);

      // 2. retrieval decoder (scorer's view) sees N usable records (post cross-invariant).
      const sub = decodeSubstrate(state);
      assert.equal(sub.temporal.length, N, `N=${N}: retrieval/scorer must see ${N} usable temporal records, saw ${sub.temporal.length}`);
      // Each usable record points at a distinct, valid stale memory slot.
      const slots = new Set(sub.temporal.map((t) => t.memorySlot));
      assert.equal(slots.size, N, `N=${N}: each record governs a distinct memory slot`);
    });
  }
});
