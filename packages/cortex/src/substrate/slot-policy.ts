/**
 * Deterministic write-cursor for production patch builders.
 *
 * Decoupled from any reward law. Slot occupancy is a substrate state, not
 * a metric. This file provides region-aware ring-rotation so patch builders
 * can target a stable next-write slot without colliding with protected
 * memories.
 *
 * Used by miner-side patch construction tooling when proposing candidate
 * slots to fill.
 */

import { RANGES } from '../state/types.js';

export type SubstrateSlotRegion = 'memory_index' | 'retrieval_keys';

export interface SelectSubstrateSlotOptions {
  readonly region: SubstrateSlotRegion;
  /** Zero-based accepted state-advance counter for this region. */
  readonly advanceIndex: number;
  /** Slots that must not be evicted. */
  readonly protectedSlots?: ReadonlySet<number> | readonly number[] | undefined;
}

export interface SelectedSubstrateSlot {
  readonly region: SubstrateSlotRegion;
  readonly slotIndex: number;
  readonly wordIndex: number;
  readonly capacity: number;
  readonly wrapped: boolean;
}

export const SUBSTRATE_SLOT_CAPACITY = Object.freeze({
  memory_index: 44,
  retrieval_keys: 36,
} satisfies Record<SubstrateSlotRegion, number>);

export const SUBSTRATE_WORDS_PER_SLOT = 8;

export function selectSubstrateSlot(opts: SelectSubstrateSlotOptions): SelectedSubstrateSlot {
  const region = opts.region;
  const capacity = SUBSTRATE_SLOT_CAPACITY[region];
  if (!Number.isSafeInteger(opts.advanceIndex) || opts.advanceIndex < 0) {
    throw new Error(`advanceIndex must be a non-negative safe integer, got ${opts.advanceIndex}`);
  }
  const protectedSlots = normalizeProtectedSlots(opts.protectedSlots, capacity);
  let slotIndex = opts.advanceIndex % capacity;
  for (let tries = 0; tries < capacity; tries++) {
    if (!protectedSlots.has(slotIndex)) {
      return {
        region,
        slotIndex,
        wordIndex: wordIndexForSubstrateSlot(region, slotIndex),
        capacity,
        wrapped: opts.advanceIndex >= capacity,
      };
    }
    slotIndex = (slotIndex + 1) % capacity;
  }
  throw new Error(`no writable ${region} slots remain; ${capacity}/${capacity} slots are protected`);
}

export function wordIndexForSubstrateSlot(
  region: SubstrateSlotRegion,
  slotIndex: number,
  wordOffset = 0,
): number {
  const capacity = SUBSTRATE_SLOT_CAPACITY[region];
  if (!Number.isSafeInteger(slotIndex) || slotIndex < 0 || slotIndex >= capacity) {
    throw new Error(`${region} slotIndex out of range: ${slotIndex}`);
  }
  if (!Number.isSafeInteger(wordOffset) || wordOffset < 0 || wordOffset >= SUBSTRATE_WORDS_PER_SLOT) {
    throw new Error(`wordOffset out of range: ${wordOffset}`);
  }
  const start = region === 'memory_index' ? RANGES.MEMORY_INDEX_START : RANGES.RETRIEVAL_KEYS_START;
  return start + slotIndex * SUBSTRATE_WORDS_PER_SLOT + wordOffset;
}

function normalizeProtectedSlots(
  slots: ReadonlySet<number> | readonly number[] | undefined,
  capacity: number,
): Set<number> {
  const out = new Set<number>();
  if (!slots) return out;
  for (const slot of slots instanceof Set ? slots.values() : slots) {
    if (!Number.isSafeInteger(slot) || slot < 0 || slot >= capacity) {
      throw new Error(`protected slot out of range: ${slot}`);
    }
    out.add(slot);
  }
  return out;
}
