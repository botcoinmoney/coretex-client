# CoreTex State

## Overview

The active CortexState is **1024 state cells = 32 768 bytes**. A state cell is one EVM `uint256`: 32 bytes, 256 bits, and usually displayed as a 64-character hex value. Ethereum and Solidity call this same 32-byte unit a word. State cells are indexed 0–1023 (inclusive). All cells are big-endian 256-bit unsigned integers when serialised to / from bytes.

Each state cell is a packed bit field: sub-cell fields are extracted by masking and shifting, MSB-first. Reserved bits inside any cell MUST be zero; any state containing a non-zero reserved bit is rejected by both reference implementations with error code `RESERVED_BIT_SET`.

---

## State-cell range layout

| Range          | Cells (inclusive) | Count | Purpose                                               |
|----------------|-------------------|-------|-------------------------------------------------------|
| Header         | 0 – 31            | 32    | Protocol header, schema hash fragments, score counters, epoch metadata |
| MemoryIndex    | 32 – 383          | 352   | Memory-object index slots (Tier-2 stride-1: 352 single-cell slots; recordId, family, domain, validity, retrievalSlot, expiry) |
| RetrievalKeys  | 384 – 671         | 288   | **r4:** binary / multi-vector retrieval keys · **r5:** reclaimed → PolicyAtoms (evidence-bundle 384–511, conflict_lifecycle 512–639, abstention 640–671) |
| Relations      | 672 – 799         | 128   | Typed directed edges over MemoryIndex slots           |
| Temporal       | 800 – 895         | 96    | Temporal validity / revocation map                    |
| Codebook       | 896 – 991         | 96    | **r4:** codebook / operator table · **r5:** reclaimed → reserved r5 policy capacity (MUST be zero) |
| Reserved       | 992 – 1023        | 32    | Reserved / experimental / future compatibility        |

> **r5 protocol epoch (`coretex-retrieval-v2-policy-r5`).** The RetrievalKeys + Codebook state-cell ranges are
> reclaimed for typed **PolicyAtoms** (see Range C-r5 / Range F-r5 below). The *static* forms of those regions
> (dense lens, static EvidencePolicy) failed empirically — r5 reclaims their **cells**, not their semantics, for a
> typed/bounded/query-local policy grammar. Which interpretation is active is decided HARD by the bundle
> `pipelineVersion` / profile: an r4 (lens) profile reads the cells as RetrievalKeys/Codebook and ignores
> PolicyAtoms; an r5 (policy) profile reads them as PolicyAtoms and does NOT decode RetrievalKeys as a dense lens.
> No silent reinterpretation.

---

## Per-range packed bit-field definitions

### Range A: Header (cells 0–31)

Each cell in this range has dedicated semantics. Unused bit positions within each cell are reserved and MUST be zero.

| Cell | Field name            | Bits       | Type              | Description                                          |
|------|-----------------------|------------|-------------------|------------------------------------------------------|
| 0    | MAGIC                 | 255:240    | uint16            | Fixed value `0xC07E` — "coretex" sentinel             |
| 0    | SCHEMA_VERSION        | 239:224    | uint16            | Schema version; CoreTex = `0x0000`                        |
| 0    | WORD_COUNT            | 223:208    | uint16            | Must equal `1024`                                    |
| 0    | FLAGS                 | 207:192    | uint16            | Bit 0: genesis state. Bits 1–15: reserved            |
| 0    | reserved_0            | 191:0      | —                 | Reserved; MUST be zero                               |
| 1    | EPOCH                 | 255:192    | uint64            | Current epoch number                                 |
| 1    | EPOCH_START_TIMESTAMP | 191:128    | uint64            | Unix timestamp (seconds) at epoch start              |
| 1    | reserved_1            | 127:0      | —                 | Reserved; MUST be zero                               |
| 2    | STATE_ROOT_PREV       | 255:0      | bytes32           | State root of the parent state (all 256 bits)        |
| 3    | CORE_VERSION_HASH     | 255:0      | bytes32           | keccak256 of the Core decoder version string         |
| 4    | SCHEMA_HASH_LO        | 255:0      | bytes32           | Low 256 bits of schema hash (keccak256 of schema JSON)|
| 5    | EXPERIENCE_CORPUS_ROOT| 255:0      | bytes32           | Merkle root of the current experience corpus         |
| 6    | BENCHMARK_COMMITMENT  | 255:0      | bytes32           | keccak256 commitment to the benchmark parameters      |
| 7    | SCORE_ACCUMULATOR     | 255:192    | uint64            | Accumulated composite score × 1e6, saturating        |
| 7    | SCORE_EPOCH_BASELINE  | 191:128    | uint64            | Baseline score for this epoch × 1e6                  |
| 7    | PATCH_COUNT_EPOCH     | 127:64     | uint64            | Accepted patches this epoch                          |
| 7    | PATCH_COUNT_TOTAL     | 63:0       | uint64            | Accepted patches all-time                            |
| 8    | LAST_SNAPSHOT_EPOCH   | 255:192    | uint64            | Epoch of last full-state snapshot                    |
| 8    | SNAPSHOT_INTERVAL     | 191:128    | uint64            | Snapshot cadence (default 100)                       |
| 8    | REDUCER_NONCE         | 127:64     | uint64            | Monotonically increasing reducer invocation nonce    |
| 8    | reserved_8            | 63:0       | —                 | Reserved; MUST be zero                               |
| 9    | PATCH_SET_ROOT        | 255:0      | bytes32           | Merkle root of accepted patch set this epoch         |
| 10   | SCORE_ROOT            | 255:0      | bytes32           | Merkle root of per-miner score ledger                |
| 11–31| reserved_11_31        | 255:0      | —                 | Reserved; MUST be zero                               |

### Range B: MemoryIndex (cells 32–383)

**352 cells = 352 memory-object slots × 1 cell each (Tier-2 STRIDE-1; canonical).**

Tier-2 (`TEMPORAL_DECOUPLING_DESIGN.md`, protocol epoch `coretex-retrieval-v2-lens-r4`)
repacked MemoryIndex to **stride-1**: only cell 0 of the old 8-cell slot was ever used, so
the region now holds up to **352 slots instead of 44**. This is what the V2 launch scorer
(`substrate/retrieval-decoder.ts:decodeMemoryIndex`), the patch encoders
(`scripts/lib/v2-patch-families.mjs`), and the reserved-bit validator (`state/validate.ts`,
which applies the cell-0 reserved mask to every cell in the range) all agree on. Lifting the
slot count is what decoupled the temporal current/stale PAIR cap from the MemoryIndex (18→96).

**Canonical slot layout** (1 cell per slot, slot `k` at cell `32 + k`, for `k` ∈ [0, 351]):

| Bits    | Field         | Type    | Description                                                     |
|---------|---------------|---------|-----------------------------------------------------------------|
| 255:128 | RECORD_ID     | uint128 | 128-bit opaque record identifier (0 = empty slot)               |
| 127:124 | FAMILY        | uint4   | Family code (temporal / relation / …; see `FAMILY_BY_BITS`)     |
| 123:64  | DOMAIN_BITS   | uint60  | Domain classifier bits                                          |
| 63:48   | FLAGS         | uint16  | Bit 0: valid. Bit 1: revoked. Bit 2: protected. Bits 3–15: reserved |
| 47:40   | RETRIEVAL_SLOT| uint8   | Associated RetrievalKeys slot (must be < 36); 0 = unbound       |
| 39:0    | EXPIRY_EPOCH  | uint40  | Epoch after which the object is expired (0 = never)             |

A slot with a non-zero cell but RECORD_ID=0, an unknown FAMILY, RETRIEVAL_SLOT≥36, or any
non-zero high padding decodes as a failure (counted, slot dropped). 8-bit slot-reference
fields elsewhere (temporal `memorySlot`/`supersededBy`, relation `source`/`target`) cap
referencible slots at 0–255 — ample for the 96-pair temporal ceiling (≤192 slots).

> **Single decoder authority.** The debug CLI, eval stub, scorer, validators, and miner tooling
> all use the canonical stride-1 substrate
> interpretation above through `src/substrate/retrieval-decoder.ts`.

### Range C: RetrievalKeys (cells 384–671) — ⚠ RECLAIMED (r4): NOT a valid miner surface

> **RECLAIMED 2026-05-25.** The static dense-lens surface FAILED (`LENS_THIRDCLASS_VERDICT.md`) and the
> admission-headroom probe shows ~0 routing headroom for any static region. This region is **inactive** — no honest
> patch generator emits it; it is decoded only for back-compat. It is slated for **redefinition in substrate-r5 as part
> of a typed query-conditioned PolicyAtom region** (`SUBSTRATE_R5_POLICY_ATOMS.md`), NOT a static lens. Do not present
> RetrievalKeys as a miner surface.

288 cells = 36 key-slots × 8 cells each.

**Key-slot layout** (8 cells, slot `k` at cells `384 + 8k` through `384 + 8k + 7`, for `k` ∈ [0, 35]):

| Slot cell | Field       | Bits    | Type    | Description                                           |
|-----------|-------------|---------|---------|-------------------------------------------------------|
| 0         | KEY_ID      | 255:128 | uint128 | Key identifier (matches an EVENT_ID in MemoryIndex)   |
| 0         | KEY_TYPE    | 127:112 | uint16  | 0x0001 = binary key, 0x0002 = dense key, others reserved |
| 0         | KEY_DIM     | 111:96  | uint16  | Dimensionality (bits for binary; floats for dense)    |
| 0         | KEY_FLAGS   | 95:80   | uint16  | Bit 0: active. Bits 1–15: reserved MUST be zero       |
| 0         | reserved_rk0| 79:0    | —       | Reserved; MUST be zero                                |
| 1–7       | KEY_VECTOR  | 255:0   | bytes32 | Seven cells of key data (224 bytes); for binary keys MSB-first bit packed |

KEY_FLAGS reserved bits 1–15 MUST be zero.

### Range C-r5 / F-r5: PolicyAtoms (cells 384–671 + reserved 896–991) — r5 protocol epoch

Active under `pipelineVersion = coretex-retrieval-v2-policy-r5`. The same cells that r4 reads as
RetrievalKeys (384–671) and Codebook (896–991) are read as typed **PolicyAtoms**. A PolicyAtom is a typed,
bounded, **query-local** routing/scoring policy a miner emits from PUBLIC Memory-IR / corpus structure — never
from hidden qrels or direct answer identity. Atom families are implicit in the region:

| Family region          | Cells     | Slots | Allowed actions                  |
|------------------------|-----------|-------|----------------------------------|
| evidence-bundle / answer-density | 384–511 | 128 | include, boost, bundle, suppress(safe) |
| conflict_lifecycle               | 512–639 | 128 | boost (resolved), suppress (candidate, in-set) |
| abstention_missing               | 640–671 |  32 | abstain                          |
| reserved r5 policy capacity      | 896–991 |  96 | none — MUST be zero (invalid-for-reward) |

**Atom layout** (1 cell per atom; atom `k` of a region at `regionStart + k`):

| Bits    | Field           | Type   | Description                                                                   |
|---------|-----------------|--------|-------------------------------------------------------------------------------|
| 255:248 | SELECTOR        | uint8  | Query-predicate type (when the atom applies); enum, 0 = invalid               |
| 247:240 | EVIDENCE_FEATURE| uint8  | Which PUBLIC feature it reads (support-in-degree, bridge-hop, lifecycleState, contradicts, scope_differs, no-evidence-path); enum, 0 = invalid |
| 239:236 | ACTION          | uint4  | 1=include 2=boost 3=suppress 4=bundle 5=abstain (must be allowed for region)  |
| 235:232 | SCOPE           | uint4  | 1=entity 2=owner 3=relationPath 4=temporalChain 5=conflictSet 6=aspect        |
| 231:216 | TARGET_SLOT     | uint16 | Query-local anchor = MemoryIndex slot index (< 352); 0xFFFF = none (abstention)|
| 215:200 | BUDGET          | uint16 | Bounded effect magnitude (0..65535; capped per-family by profile)             |
| 199:192 | FLAGS           | uint8  | Per-family flags (e.g. abstention bit0 = require-no-evidence-path)            |
| 191:152 | VALID_FROM_EPOCH| uint40 | Atom active from this epoch (0 = genesis)                                      |
| 151:112 | EXPIRY_EPOCH    | uint40 | Atom expires at this epoch (0 = never); enables frontier-churn retirement      |
| 111:0   | reserved_pa     | —      | Reserved; MUST be zero                                                          |

Decode/validation rules (fail-closed per atom; an invalid atom is dropped + counted, never rewarded):
- SELECTOR / EVIDENCE_FEATURE / ACTION / SCOPE must be members of their enums; ACTION must be allowed for the region.
- TARGET_SLOT must be **0..255** (8-bit-addressable, matching temporal/relation slot references — avoids
  decoded-but-unaddressable anchors in 256..351), or 0xFFFF only when ACTION = abstain.
- reserved_pa (bits 111:0) MUST be zero.
- The atom carries **no** qrel/answer-id field — its effect set is reconstructed by the scorer from PUBLIC
  edges out of TARGET_SLOT (answer-density = public support/provenance structure, not answer identity).
- The reserved r5 policy region (896–991) MUST be entirely zero; any non-zero cell there is invalid-for-reward.
- **Hard gating:** under an r4 profile these cells are NOT decoded as PolicyAtoms (zero effect); under r5 the
  RetrievalKeys cells are NOT decoded as a dense lens. The abstention low-top1/margin threshold is an OPERATOR
  PROFILE knob (the miner atom only supplies the public no-evidence-path policy) — never a hardcoded constant.

### Range D: Relations (cells 672–799)

128 cells = 128 relation-weight entries × 1 cell each.

**Entry layout** (1 cell per entry, entry `k` at cell `672 + k`, for `k` ∈ [0, 127]):

| Bits     | Field            | Notes                                                |
|----------|------------------|------------------------------------------------------|
| 255:240  | weight           | uint16, 0 means empty entry                          |
| 239:224  | edgeType         | uint16 enum (see below)                              |
| 223:208  | reserved         | must be zero                                         |
| 207:192  | reserved         | must be zero                                         |
| 191:96   | sourceMemorySlot | 96-bit padded uint8, low 8 bits = MemoryIndex slot 0..43 |
| 95:0     | targetMemorySlot | 96-bit padded uint8, low 8 bits = MemoryIndex slot 0..43 |

edgeType enum:
  0x1 supports
  0x2 supersedes
  0x3 coreference_of
  0x4 causes
  0x5 derived_from
  0x6 co_occurs_with

> Note (decoder authority). The canonical decoder lives at `src/substrate/retrieval-decoder.ts:decodeRelations`. The bit layout above mirrors `specs/substrate_retrieval_semantics.md §Relations entries`, which is authoritative. The earlier RELATES_TO / SUPERSEDES (only) / ROUTES_TO and SRC_IDX-top framing was a planning sketch and is superseded — miners who follow it will produce patches the decoder drops.

### Range E: Temporal (cells 800–895)

96 cells = **96 temporal records × 1 cell each**. The canonical decoder
(`src/substrate/retrieval-decoder.ts:decodeTemporal`)
and `substrate_retrieval_semantics.md §Temporal records` are
authoritative for the per-record layout. The canonical decoder
and `state/validate.ts` both use the same one-cell layout with reserved
bits 151:0.

**Per-record layout** (1 cell per record, record `k` occupies cell
`800 + k`, for `k` ∈ [0, 95]).

Cell fields:

| Field                      | Bits      | Type    | Description                                            |
|----------------------------|-----------|---------|--------------------------------------------------------|
| memorySlot                 | 255:248   | uint8   | Target MemoryIndex slot (0–255; 8-bit ref into the 352-slot stride-1 MemoryIndex) |
| supersededBy_memorySlot    | 247:240   | uint8   | Slot that supersedes this one; `0xFF` = none           |
| validFromEpoch             | 239:200   | uint40  | First epoch for which this record is valid             |
| validUntilEpoch            | 199:160   | uint40  | Last epoch (inclusive); 0 = unbounded                  |
| flags                      | 159:152   | uint8   | Bit 0 `currentStaleFlag`; bits 1–7 reserved MUST zero  |
| reserved_tmp               | 151:0     | —       | Reserved; MUST be zero                                 |

Decoder failure modes (record dropped silently):
- `memorySlot` references a slot that does not decode to a valid stale MemoryIndex slot
- `validFromEpoch > validUntilEpoch`
- non-zero reserved bits (151:0) in the record cell
- `currentStaleFlag` set without the referenced MemoryIndex slot's
  `revoked` bit also set

> **Capacity note (Tier-2, `coretex-retrieval-v2-lens-r4`):** the temporal RANGE holds 96
> one-cell records, and the end-to-end current/stale temporal-PAIR capacity is now **96 pairs**.
> Tier-2 removed the artificial `retrievalSlot < 36` coupling (temporal slots pin
> `retrievalSlot=0`; the scorer resolves temporal via the record's `recordId`/`memorySlot`,
> never `retrievalSlot`) and repacked MemoryIndex to stride-1 (352 slots), so a pair consuming
> two single-cell MemoryIndex slots (≤192 slots for 96 pairs) is no longer MemoryIndex-bound. The
> cross-layer invariant test (`temporal-capacity-crosslayer.test.mjs`) constructs and round-trips
> N=12/18/24/48/96 identically across the canonical decoder and validator.
> (Historical: the prior **18-pair** end-to-end cap was the `retrievalSlot<36` artifact, since
> removed; beyond 96 needs a Temporal-region expansion, separately gated.)

### Range F: Codebook (cells 896–991) — ⚠ RECLAIMED (r4): NOT a valid miner surface

> **RECLAIMED 2026-05-25.** The static EvidencePolicy/high-density-policy surface FAILED
> (`EVIDENCE_POLICY_DESIGN.md` §VERDICT). This region is **inactive** — no honest patch generator emits it; decoded
> only for back-compat. Slated for **redefinition in substrate-r5 as part of the typed PolicyAtom region**
> (`SUBSTRATE_R5_POLICY_ATOMS.md`) — a real query-conditioned mechanism, NOT another static policy atom. Do not present
> Codebook as a miner surface.

96 cells = 48 codebook-entries × 2 cells each.

**Entry layout** (2 cells per entry, entry `k` at cells `896 + 2k` and `896 + 2k + 1`, for `k` ∈ [0, 47]):

| Cell | Field        | Bits    | Type    | Description                                         |
|------|--------------|---------|---------|-----------------------------------------------------|
| 0    | CODE         | 255:240 | uint16  | Codebook code (0 = unset)                           |
| 0    | CODE_TYPE    | 239:224 | uint16  | 0x0001 = operator, 0x0002 = token, others reserved  |
| 0    | CODE_FLAGS   | 223:208 | uint16  | Bit 0: active. Bits 1–15: reserved MUST zero        |
| 0    | reserved_cb0 | 207:0   | —       | Reserved; MUST be zero                              |
| 1    | CODE_DATA    | 255:0   | bytes32 | Arbitrary operator / token data                     |

### Range G: Reserved (cells 992–1023)

All 32 cells × 256 bits = entirely reserved. **Every bit in this range MUST be zero.**

---

## Reserved-bit rule

> Any cell where any reserved-bit position (as specified per range above) is non-zero MUST cause both reference implementations to reject the state with error `RESERVED_BIT_SET`.

This is a hard rejection rule. It is not a warning and not a conditional skip.

---

## Genesis state

The genesis state is seeded from the Phase 7 baseline E winner (revocation-aware encoding). It is **not all-zero**. The genesis `MAGIC`, `SCHEMA_VERSION`, `WORD_COUNT`, and `EPOCH` fields are set; all reserved bits are zero. The published genesis state root is the canonical starting point committed in `CortexRegistry`.

---

## Future ladder step: 1024 → 2048 (informational)

The launch substrate is fixed at 1024 state cells. A future widening to 2048
is reserved as a single ladder step, not a recurring schedule. The
mechanism is intentionally minimal:

- **Wire path already supports it.** `CortexState.initializeEpoch` takes
  `uint16 wordCount` as an argument. Switching to 2048 is a parameter
  change at epoch init plus a new pinned bundle, not a contract migration.
  Merkle tree depth grows from 10 → 11 levels; pack/unpack already
  parameterizes on `wordCount`.
- **Region layout doubles where it helps, dead-pads where it doesn't.**
  Indicative shape: MemoryIndex 352→704 slots (Tier-2 stride-1), RetrievalKeys
  36→72 slots, Relations 128→256 entries, Temporal 96→192 records, Codebook 48→96
  entries, plus a reserved region for further ladder steps. Concrete
  ranges land in the spec when the ladder triggers — not before.
- **Trigger is governance-on-data, not preemptive.** The launch design
  publishes a per-epoch dead-slot count (Definition A: slots whose bytes
  are structurally zero — cheap, observable, in the epoch rotation
  manifest, NEVER an input to miner reward). When dead-slot count trends
  toward zero over many epochs while retrieval headroom flattens,
  governance has visible data to authorize the ladder rotation. Until
  then, 1024 stays.
- **Replay stays clean.** Bundle hash changes on the rotation (different
  `wordCount` + region layout + spec hash), so the pre-rotation and
  post-rotation epochs anchor to distinct `coreVersionHash` values.
  Watchers verify each epoch against its own bundle.

The protocol explicitly does NOT reward "more substrate used", does NOT
gate the ladder on a vote, and does NOT preemptively allocate 2048.
Dead-slot count is published as a diagnostic; everything else flows
from miner competition under retrieval-native scoring. See
`docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md` §"Auditor Follow-Ups" for
the dead-slot-metric implementation, which lands as part of task #38
alongside the epoch rotation manifest changes.

**Trigger criteria (pinned pre-launch, ladder execution deferred until met):**

1. **Dead-slot count threshold**: when `bundle.deadSlotCount` (currently
   surfaced via the canary-overfitting watchdog at
   `scripts/canary-overfitting-watchdog.mjs`) drops below `4` for `5`
   consecutive epoch rotations on the MemoryIndex region, retrieval
   capacity in 1024 cells is provably saturated.
2. **Retrieval headroom flatness**: when the
   `minImprovementPpm` ratchet has been at `replayNoiseP90Ppm` (its
   floor) for `10` consecutive epochs AND `observedAdvances / target` >
   1.5 (miners advancing faster than the calibrator anticipates), the
   PID loop is exhausted as a difficulty lever.
3. **Typed-relations scorer lever exhausted**: by then we should
   already have activated the typed/weighted Relations traversal lever
   (`src/eval/retrieval-benchmark.ts:287-293,337` —
   currently performs untyped/unweighted BFS even though the substrate
   stores 6 edge types + per-edge weights). If activation has not
   moved the needle, the substrate width itself is the bottleneck.

**Governance** (deferred but pinned now): bundle-rotation step requires
co-signed approval from the same multisig that controls the seed-escrow
contract. No additional governance contract — reuse the existing
signer set.

**Drill** (deferred, documented now): a dry-run bundle rotation against
a 2048-cell test substrate is scheduled for post-launch epoch 4. The
drill must demonstrate (a) byte-identical reproducibility of the
2048-cell canonical state hash across the ≥3 calibrated hosts,
(b) all replay watchers verify both 1024-cell and 2048-cell epoch
manifests within the same binary, (c) miner-side substrate update
flow rotates cleanly without lost in-flight patches.

---

## See also

- `coretex_schema.json` — machine-readable field registry
- `packing_spec.md` — byte-level pack/unpack rules
- `merkleization_spec.md` — Merkle tree shape and leaf encoding
- `patch_format.md` — wire format for patches
