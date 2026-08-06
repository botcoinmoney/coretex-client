# CoreTex Transition Descriptor / Patch Wire Format

## Status

**Live model: `coretex.transition-descriptor/v2`.** Supersedes the 4-changed-word compact patch
in full (see "HISTORICAL: the retired word-diff format" below). Normative reference:
`botcoin-mining-rigs` @ `ba4d5acfa7aa3042f39eb6e8e4d8e4007400090c`,
`docs/CORETEX-TRANSITION-DESCRIPTOR-V2.md` (+ companion `-AUDIT.md`). Implemented in this repo by
`python/coretex_validator/rig_events.py` (`encode_transition_descriptor` /
`decode_transition_descriptor` / the canonical-patch-artifact functions) and
`python/coretex_validator/rig_receipt_binding.py` (the typehash/layout transcription).

## Purpose

Defines the on-chain commitment for one CoreTex state transition and the off-chain canonical
patch artifact it addresses. The chain **commits and orders** the transition; it never stores it
and never interprets it. The edit itself — what changed and why the resulting state root follows
from it — lives entirely off chain, content-addressed, fetched and replayed by anyone.

---

## Wire format (binary, field-by-field) — exactly 105 bytes

```
compactPatchBytes = [
  version            : 1 byte   — MUST equal 0x20
  patchArtifactHash  : 32 bytes — sha256 of the complete canonical patch artifact; MUST be non-zero
  parentStateRoot    : 32 bytes — MUST equal the receipt's signed parentStateRoot
  newStateRoot       : 32 bytes — MUST equal the receipt's signed newStateRoot
  scoreDeltaPpm      : 8 bytes  — uint64 big-endian; MUST equal scoreAfterPpm - scoreBeforePpm
]                                — TOTAL: 105 bytes, no padding, no length prefix, no optional field
```

**The length is the format.** There is no minimum/maximum window to check — a descriptor is
exactly 105 bytes or it is refused outright (`InvalidTransitionDescriptor` on chain,
`DESCRIPTOR_LENGTH_INVALID` in this repo's decoder). No LEB128, no variable-width field, no word
budget: a single descriptor may commit to a transition of unbounded breadth, because breadth lives
in the artifact the hash addresses, not in the commitment itself.

**Field order rationale.** `version` is first so every parser — including a legacy one — reaches
its accept/reject decision on byte 0. The three `bytes32` roots are contiguous at `[1, 97)`.
`scoreDeltaPpm` is last because it is the only sub-word scalar and because a fixed-length format's
cheapest evolution is to append.

---

## The hash rule and domain-separation table

```
patchHash = keccak256( abi.encodePacked("coretex-transition-descriptor-v2", compactPatchBytes) )
```

`patchHash` is a **signed** receipt member; `compactPatchBytes` is **unsigned**. The hash rule is
the entire binding between the two.

| label | bytes | status |
| --- | --- | --- |
| `coretex-transition-descriptor-v2` | 32 | **LIVE** — the only rule this decoder accepts |
| `coretex-patch-hash-v1` | 21 | **RETIRED.** This lane's own retired 4-word compact-patch label. Refused as `TransitionDescriptorHashMismatch` / `DESCRIPTOR_HASH_MISMATCH`, never silently accepted — a signer that was never migrated produces bytes that look right and hash wrong |
| `coretex-memory-transition-hash-v1` | 33 | **SUPERSEDED.** The V5 memory-frontier lane's own domain, never this lane's rule, already the cause of one production incident here |
| *(no label, plain `keccak256(bytes)`)* | 0 | **REFUSED** — a third value, and the one a naive reimplementation reaches for first |

The three live/dead labels are **prefix-free** (they diverge by byte 8) and have three distinct
lengths (32 / 21 / 33), which forecloses a `(label, payload)` re-split under `abi.encodePacked`.
The fixed 105-byte length removes the other half of that class: with one legal length there is no
re-split to find at all.

`patchArtifactHash`, by contrast, is **sha256**, not keccak — it is a component content address
(how the artifact is *fetched*), and every content-addressed object in this system uses sha256.
The two hash functions are deliberately not unified; see the normative doc §4.3.

---

## The version byte

| value | meaning |
| --- | --- |
| `0x00`–`0x07` | **PERMANENTLY BURNED** — `0x01`–`0x07` were the retired compact patch's `patchType` values; `0x00` was never legal anywhere |
| `0x08`–`0x1f` | **UNASSIGNED**, refused — left empty so the first real version is not adjacent to the burned range |
| `0x20` | **`coretex.transition-descriptor/v2` — this document** |
| `0x21`–`0xfe` | reserved for a successor (new version byte AND new domain label, together) |
| `0xff` | **PERMANENTLY BURNED** — `COMPACT_PATCH_TYPE_UNRESTRICTED`, the value every real epoch-180 advance actually used |

The version byte is an **opaque enumerated tag** compared for equality — never arithmetic, never a
range. One deployed verifier accepts exactly one version.

---

## The canonical patch artifact (off chain)

One document, content-addressed by `patchArtifactHash = sha256(canonical_bytes(artifact))`, under
this repo's one canonical-JSON law (`frontier.py::canonical_bytes` — UTF-8, keys sorted, no
floats, no `null`, no duplicate keys, bare lowercase 64-hex roots). It states, for one
`parentStateRoot`, everything required to reproduce exactly one `newStateRoot`. It is not chunked,
not truncated, and not bounded in size by this format — the descriptor stays 105 bytes whether the
artifact is 400 bytes or 40 MB.

This repo's validator (`rig_events.py`) implements the artifact envelope scoped to the
single-transition shape its own `frontier.py` already supports (one profile-release move per
transition — the T-1/T-2 shapes of the normative doc's §8, and the only shape any real mainnet
rehearsal has ever produced):

```jsonc
{
  "format": "coretex.transition-artifact/v2",
  "parent_state_root": "<64 lowercase hex>",  // MUST equal descriptor.parentStateRoot
  "new_state_root":    "<64 lowercase hex>",  // MUST equal descriptor.newStateRoot
  "score_delta_ppm":   5000,                  // MUST equal descriptor.scoreDeltaPpm
  "transition": { /* this repo's existing frontier.py transition document */ }
}
```

The full normative model (§8, T-3/T-4/T-5) additionally allows **zero or more** profile-release
moves plus an optional composition-only change in one artifact, because the chain no longer
bounds breadth at all. Expressing that here would require widening `frontier.py`'s
one-profile-per-transition law, which is **out of scope for this document's implementation** (it
is a frontier-law change, not a wire-format change) and is recorded as a known gap rather than
silently narrowed.

### Deterministic-replay authority statement

> The artifact plus the parent state is the authority. The chain is the clock.

Given `parentStateRoot` and the bytes addressed by `patchArtifactHash`, replay is a **pure
function** producing exactly one resulting state and therefore exactly one `newStateRoot`. Two
honest validators replaying the same `(parentStateRoot, artifact)` pair MUST agree, and
disagreeing with the descriptor's `newStateRoot` is a publicly provable refutation requiring
nothing but chain data and the addressed bytes. The chain does not perform this replay; it commits
the descriptor and orders the transition (the registry's compare-and-swap on `parentStateRoot`).

---

## On-chain vs off-chain refusal codes

### On chain (`RigCoreTexVerifier`, checked in this order)

| # | check | revert | this repo's decode-time code |
| --- | --- | --- | --- |
| 1 | `compactPatchBytes.length == 105` | `InvalidTransitionDescriptor` | `DESCRIPTOR_LENGTH_INVALID` |
| 2 | `keccak256(label ‖ descriptor) == patchHash` | `TransitionDescriptorHashMismatch` | `DESCRIPTOR_HASH_MISMATCH` |
| 3 | `descriptor[0] == 0x20` | `UnsupportedTransitionDescriptorVersion(uint8)` | `DESCRIPTOR_VERSION_UNSUPPORTED` |
| 4 | `patchArtifactHash != 0` | `InvalidTransitionDescriptor` | `DESCRIPTOR_ARTIFACT_HASH_ZERO` |
| 5 | `descriptor.parentStateRoot == r.parentStateRoot` | `TransitionDescriptorParentMismatch` | `DESCRIPTOR_PARENT_MISMATCH` |
| 6 | `descriptor.newStateRoot == r.newStateRoot` | `TransitionDescriptorNewRootMismatch` | `DESCRIPTOR_NEW_ROOT_MISMATCH` |
| 7 | `descriptor.scoreDeltaPpm == scoreAfterPpm - scoreBeforePpm` | `TransitionDescriptorScoreMismatch` | `DESCRIPTOR_SCORE_DELTA_MISMATCH` |
| 8 | `r.transitionFormatVersion == descriptor[0]` | `TransitionDescriptorVersionMismatch` | `DESCRIPTOR_FORMAT_VERSION_MISMATCH` |

**Length is checked before the hash**, inverted from the retired decoder's order: the old patch had
a *range* of legal lengths, so a length outside it was ambiguous between "malformed" and "a
different patch"; the fixed 105-byte length makes a mismatch unambiguously a format error.

A screener pass (outcome 1) advances no state and MUST carry an **empty** `compactPatchBytes` plus
zero scores and zero `transitionFormatVersion` — `UnexpectedTransitionDescriptor` /
`DESCRIPTOR_UNEXPECTED`. This is *stricter* than the retired verifier, which tolerated a
well-formed patch on a screener and let it pre-burn the advance's dedupe key.

### Off chain — the fail-closed availability rule (spec §6.3)

A coordinator MUST NOT return a broadcastable receipt until the complete canonical patch artifact
has been published and read back. A validator independently refuses, and never degrades:

| condition | refusal code |
| --- | --- |
| nothing is served at `patchArtifactHash` | `TRANSITION_ARTIFACT_UNAVAILABLE` |
| the served bytes re-hash to another address | `TRANSITION_ARTIFACT_ADDRESS_MISMATCH` |
| the served bytes decode but re-serialize differently | `TRANSITION_ARTIFACT_NOT_CANONICAL` |
| `artifact.parent_state_root != descriptor.parentStateRoot` | `TRANSITION_PARENT_MISMATCH` |
| replay from the parent state produces another root | `TRANSITION_REPLAY_ROOT_MISMATCH` |
| the evaluation artifact attests another delta | `TRANSITION_SCORE_DELTA_MISMATCH` |
| the descriptor's version byte is not one this validator implements | `TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED` |

**Refuse, do not degrade.** "The artifact did not mention it" MUST NOT become a way to avoid
publishing it, and "we could not fetch it" MUST NOT become a way to accept it.

---

## Encode/decode round-trip

`decode_transition_descriptor(encode_transition_descriptor(...))` must reproduce every field
exactly, and `encode_transition_descriptor` re-reads its own output through the decoder before
returning it — the encoder cannot emit a descriptor this repo's own decoder would refuse.

---

## HISTORICAL: the retired word-diff format (`coretex-patch-hash-v1`)

**Retired pre-production**, superseded in full by the model above. Kept as a dated record because
`python/coretex_validator/rig_events.py::decode_compact_patch` still decodes it — the epoch-180
mainnet-rehearsal advances (two 75-byte patches, `patchType 0xff`, `wordCount 1`) are legacy-era
history and remain valid **only** against the deployed legacy verifier, under these rules. They
MUST NOT be re-read under v2: their first byte, `0xff`, is a permanently-burned version.

This section corrects two drifts the pre-migration document carried, so that even as history it is
accurate:

* **The score delta was ONE `uint64` big-endian field (offset 2, 8 bytes), not two `uint32`
  halves.** The prior "`SCORE_DELTA_HI` / `SCORE_DELTA_LO`" framing described a split that did not
  exist in the deployed contract (`RigCoreTexVerifier`'s `_readUint64BE` reads eight contiguous
  bytes as one integer). The two readings are numerically equivalent for values that fit both, but
  the split framing invited an implementation to get byte order or field boundaries wrong.
* **`patchType` was CHECKED, not "advisory/descriptive".** `_wordMatchesPatchType` windowed each
  target word index against the declared `patchType`'s legal range and reverted
  `PATCH_INDEX_OUT_OF_WINDOW` on a violation. It degenerated in practice — every real advance used
  `0xff` (unrestricted) because a hard-coded `patchType → word-range` table is a second copy of a
  schema the chain cannot see — but "degenerated to a no-op in practice" is not "advisory by
  design", and the retired decoder enforced it.

### Wire format (binary, field-by-field)

```
Compact patch = [
  patchType         : 1 byte   — see patch type table below
  wordCount         : 1 byte   — number of words changed (1-4)
  scoreDeltaPpm     : 8 bytes  — uint64 big-endian
  parentStateRoot   : 32 bytes — keccak256 Merkle root of the parent state
  [for each word in 0..wordCount-1]:
    index           : 1-2 bytes — LEB128-encoded word index (0-1023, non-minimal 2-byte forms
                                   in [128, 1024) refused as PATCH_INDEX_REDUNDANT)
    value            : 32 bytes  — new value for the word at index
]
```

Total for a 4-word patch: 42 (header) + 4×(1 or 2 + 32) = **174-178 bytes**. Header alone: 42
bytes (`COMPACT_PATCH_HEADER_BYTES`). Legal length window: **42-178 bytes**
(`COMPACT_PATCH_MIN/MAX_BYTES`).

### Patch types

| Code | Name | Word range checked |
|------|------|---------------------|
| `0x01` | KEY_UPDATE | 384-671 |
| `0x02` | SLOT_REPLACE | 32-383 |
| `0x03` | TEMPORAL_UPDATE | 800-895 |
| `0x04` | RELATION_UPDATE | 672-799 |
| `0x05` | CODEBOOK_UPDATE | 896-991 |
| `0x06` | HEADER_UPDATE | 0-31 |
| `0xFF` | MIXED / unrestricted | any index below 992 |

Word indices at or above `RESERVED_WORD_START = 992` were refused (`PATCH_INDEX_RESERVED`)
regardless of `patchType`.

### Rejection taxonomy (as implemented by `rig_events.py::decode_compact_patch`)

| Code | Trigger |
|------|---------|
| `PATCH_LENGTH_INVALID` | length outside `[42, 178]` |
| `PATCH_HASH_MISMATCH` | `keccak256("coretex-patch-hash-v1" ‖ raw) != expected` |
| `PATCH_TYPE_UNKNOWN` | `patchType` not in the table above |
| `PATCH_WORD_COUNT_INVALID` | `wordCount` outside `1..4` |
| `PATCH_SCORE_DELTA_OVERFLOW` | `scoreDeltaPpm` exceeds `int64` |
| `PATCH_SCORE_DELTA_MISMATCH` | disagrees with the signed receipt |
| `PATCH_PARENT_MISMATCH` | disagrees with the signed receipt |
| `PATCH_INDEX_TRUNCATED` / `PATCH_INDEX_OVERLONG` / `PATCH_INDEX_REDUNDANT` | malformed LEB128 |
| `PATCH_INDEX_RESERVED` | index `>= 992` |
| `PATCH_INDEX_OUT_OF_WINDOW` | index outside the declared `patchType`'s window |
| `PATCH_INDEX_DUPLICATE` | one index moved twice inside one patch |
| `PATCH_WORD_TRUNCATED` | value runs past the end of the patch |
| `PATCH_TRAILING_BYTES` | bytes remain after the declared words |

Why the ceiling and the window were retired (not merely "superseded"): the 4-word budget forced
truncation or artificial multi-transaction splitting of any genuinely broad improvement, and the
`patchType` window was a second, unmaintained copy of a schema the chain could not see — both
findings are recorded in full in `docs/CORETEX-TRANSITION-DESCRIPTOR-V2.md` §1.

### Patch hash domains (historical)

| Hash name | Definition | Domain prefix |
|-----------|-----------|----------------|
| `patchBytesHash` | `keccak256(wireBytes)` | (none, raw) |
| `evalPatchHash` | `keccak256("coretex-patch-hash-v1" \|\| wireBytes)` | `coretex-patch-hash-v1` |

Both are superseded by the single `patchHash = keccak256("coretex-transition-descriptor-v2" ‖
compactPatchBytes)` rule above; neither retired domain is ever accepted for a v2 descriptor.

---

## See also

- `coretex_state.md` — the CoreTex core substrate's own word-count/field definitions (a different,
  lower layer than this document's transition commitment — unaffected by this migration)
- `merkleization_spec.md` — computing `parentStateRoot` / `newStateRoot`
- `packing_spec.md` — word serialization for the retired substrate patch
- `hidden_query_pack.md` — per-patch eval-seed derivation and dual-pack confirmation
- `docs/CORETEX-TRANSITION-DESCRIPTOR-V2.md` (botcoin-mining-rigs) — the normative spec this
  document mirrors
- `docs/V5-RIG-VALIDATOR.md` — this repo's operator-facing migration note
