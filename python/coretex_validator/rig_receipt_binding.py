"""
# GENERATED FROM bundle.json sha256=307df364b165023b20ec1ea9ac699b8b39a5f340040be9a418b1a7d1d50b2c5a — DO NOT EDIT.
#
# Regenerate with:
#   node scripts/generate-rig-receipt-bindings.mjs --bundle <path-to-bundle.json>
#
# MIGRATION NOTE (transition-descriptor v2). The generation tool and the real ABI bundle it reads
# are not vendored in this repo (they live on the coordinator side), so the values below were
# TRANSCRIBED by hand from the migrated coordinator's mirrored binding
# (botcoin-coordinator-v5 @ 167444f, v5/resolver/receipt.py) and cross-checked independently: the
# typehash was RE-DERIVED from CORETEX_RECEIPT_TYPEHASH_STRING with this repo's own keccak256
# implementation (python/coretex_validator/keccak256.py) and found to equal the literal below
# before it was committed. Regenerate this file for real once a v2 bundle.json is available; until
# then this transcription is the authority, not an inference.
#
# Source of authority: the rig lane's integration bundle
#   schema        botcoin.rig-coordinator-integration.bundle/2
#   mining ABI    sha256=cd1c9f7404053e944a612dcbd74365b6248e80adb3c05c6ec989f8a1d9ba2881
#   vendored .sol contracts/rig/mining/BotcoinMiningRigsV1.sol (sha256=95b8a6f6efd677f85bd71e571c1c816511ad89facc7daf624a7b32afdab71962)
#   rig source    github.com/botcoinmoney/botcoin-mining-rigs @ ba4d5acfa7aa3042f39eb6e8e4d8e4007400090c
#
# EVERYTHING BELOW IS SOURCE-DERIVED. The bundle's ABIs come from a real compile of the
# rig team's own source, vendored verbatim (contracts/rig/VENDOR.md). They are no longer
# reconstructed from probed bytecode, and nothing here is an inference.
#
# THE TUPLE LAYOUT IS DERIVED, NOT TRANSCRIBED. BotcoinMiningRigsV1.sol reaches the
# CoreTexReceipt struct only BY NAME, so a hand-written layout would be an inference
# dressed as a transcription. Everything is projected mechanically from the ABI and
# cross-checked three ways: the projected typehash equals the bundle's recorded
# RigCoreTexReceipt typehash, it equals the independently pinned
# 0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf,
# and the fragment's selector equals the pinned 0xcc45427e (unchanged: renaming member 20
# does not change the tuple's ABI TYPES, and selectors are built from types, not names).
#
# MEMBER 20 IS NOW `uint16 transitionFormatVersion`, NOT `uint16 stateWordCount`
# (coretex.transition-descriptor/v2 §9.1). Same position, same width, DIFFERENT MEANING, and
# therefore a DIFFERENT TYPEHASH — EIP-712 hashes the member NAMES. Every receipt signed under the
# retired typehash (1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b) is
# unverifiable here and vice versa; there is no dual-accept window.
#
# MEMBER 25 IS `bytes compactPatchBytes` — CONFIRMED, no longer inferred.
# It is the 105-byte transition descriptor whose hash is the SIGNED `patchHash`. It is OUTSIDE the
# typehash, so it is UNSIGNED: a miner can alter it without invalidating the
# coordinator's signature, which is exactly why the COORDINATOR must hash-bind it before
# signing. The mining contract never reads it; the verifier does, and forwards it as
# submitStateAdvance's dynamic tail.
#
# THE HASH RULE IS keccak256(utf8("coretex-transition-descriptor-v2") ++ compactPatchBytes).
# This lane previously used "coretex-patch-hash-v1" (the retired 4-word compact patch's own
# label) and, before that, "coretex-memory-transition-hash-v1" — the V5 MEMORY lane's
# transition-hash domain. Receipts signed under either dead label revert
# TransitionDescriptorHashMismatch on chain.
#
# THE PATCH IS A FIXED 105-BYTE COMMITMENT, not a parsed word-diff structure: version (1 byte,
# == 0x20) ++ patchArtifactHash (32 bytes, sha256 of the complete canonical patch artifact) ++
# parentStateRoot (32 bytes) ++ newStateRoot (32 bytes) ++ scoreDeltaPpm (8 bytes, big-endian
# uint64). THE LENGTH IS THE FORMAT — no padding, no optional field, no length prefix, no word
# ceiling. The retired 42..178-byte / patchType / LEB128-word-index layout is history; see
# `rig_events.py`'s "HISTORY" section for the decoder that still reads it.
#
# THE REGISTRY MUTATOR'S TAIL IS DYNAMIC. submitStateAdvance has
# 11 static parameters followed by `bytes compactPatchBytes`; the twelfth
# head word is that tail's OFFSET, not a twelfth value. And transitionCount returns
# uint64, not uint256.
"""

from __future__ import annotations

from typing import Any, Dict, List

BUNDLE_SHA256 = "307df364b165023b20ec1ea9ac699b8b39a5f340040be9a418b1a7d1d50b2c5a"

BINDING_SOURCE: Dict[str, Any] = {
    "bundle_schema": "botcoin.rig-coordinator-integration.bundle/2",
    "bundle_generated_at": "unknown",
    "mining_abi_sha256": "cd1c9f7404053e944a612dcbd74365b6248e80adb3c05c6ec989f8a1d9ba2881",
    "vendored_mining_source_path": "contracts/rig/mining/BotcoinMiningRigsV1.sol",
    "vendored_mining_source_sha256": "95b8a6f6efd677f85bd71e571c1c816511ad89facc7daf624a7b32afdab71962",
    "release_classification": "DISPOSABLE_REHEARSAL_AVAILABLE",
    "production_allowed": False,
}

# All 27 ABI components of IRigCoreTexVerifier.CoreTexReceipt, in declared order.
CORETEX_RECEIPT_TUPLE_COMPONENTS: List[Dict[str, str]] = [
    {"name": "rigId", "type": "uint256"},
    {"name": "operator", "type": "address"},
    {"name": "epochId", "type": "uint64"},
    {"name": "solveIndex", "type": "uint64"},
    {"name": "prevReceiptHash", "type": "bytes32"},
    {"name": "outcome", "type": "uint8"},
    {"name": "challengeId", "type": "bytes32"},
    {"name": "parentStateRoot", "type": "bytes32"},
    {"name": "newStateRoot", "type": "bytes32"},
    {"name": "corpusRoot", "type": "bytes32"},
    {"name": "activeFrontierRoot", "type": "bytes32"},
    {"name": "coreVersionHash", "type": "bytes32"},
    {"name": "evalReportHash", "type": "bytes32"},
    {"name": "patchHash", "type": "bytes32"},
    {"name": "artifactHash", "type": "bytes32"},
    {"name": "worldSeed", "type": "uint128"},
    {"name": "rulesVersion", "type": "uint32"},
    {"name": "workPolicyHash", "type": "bytes32"},
    {"name": "workUnitsBps", "type": "uint256"},
    {"name": "difficultyCountSnapshot", "type": "uint256"},
    {"name": "transitionFormatVersion", "type": "uint16"},
    {"name": "scoreBeforePpm", "type": "uint32"},
    {"name": "scoreAfterPpm", "type": "uint32"},
    {"name": "issuedAt", "type": "uint64"},
    {"name": "expiresAt", "type": "uint64"},
    {"name": "compactPatchBytes", "type": "bytes"},
    {"name": "signature", "type": "bytes"},
]

CORETEX_RECEIPT_TUPLE_TYPES: List[str] = [c["type"] for c in CORETEX_RECEIPT_TUPLE_COMPONENTS]

SUBMIT_CORETEX_RECEIPT_FRAGMENT = "function submitCoreTexReceipt((uint256,address,uint64,uint64,bytes32,uint8,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint128,uint32,bytes32,uint256,uint256,uint16,uint32,uint32,uint64,uint64,bytes,bytes) r) external"
SUBMIT_CORETEX_RECEIPT_SELECTOR = "0xcc45427e"

EIP712_DOMAIN_NAME = "BotcoinMiningRigs"
EIP712_DOMAIN_VERSION = "2"

CORETEX_RECEIPT_PRIMARY_TYPE = "RigCoreTexReceipt"

# The typed data: the tuple MINUS its two unsigned trailing bytes members.
CORETEX_RECEIPT_TYPES: Dict[str, List[Dict[str, str]]] = {
    CORETEX_RECEIPT_PRIMARY_TYPE: [
        {"name": "rigId", "type": "uint256"},
        {"name": "operator", "type": "address"},
        {"name": "epochId", "type": "uint64"},
        {"name": "solveIndex", "type": "uint64"},
        {"name": "prevReceiptHash", "type": "bytes32"},
        {"name": "outcome", "type": "uint8"},
        {"name": "challengeId", "type": "bytes32"},
        {"name": "parentStateRoot", "type": "bytes32"},
        {"name": "newStateRoot", "type": "bytes32"},
        {"name": "corpusRoot", "type": "bytes32"},
        {"name": "activeFrontierRoot", "type": "bytes32"},
        {"name": "coreVersionHash", "type": "bytes32"},
        {"name": "evalReportHash", "type": "bytes32"},
        {"name": "patchHash", "type": "bytes32"},
        {"name": "artifactHash", "type": "bytes32"},
        {"name": "worldSeed", "type": "uint128"},
        {"name": "rulesVersion", "type": "uint32"},
        {"name": "workPolicyHash", "type": "bytes32"},
        {"name": "workUnitsBps", "type": "uint256"},
        {"name": "difficultyCountSnapshot", "type": "uint256"},
        {"name": "transitionFormatVersion", "type": "uint16"},
        {"name": "scoreBeforePpm", "type": "uint32"},
        {"name": "scoreAfterPpm", "type": "uint32"},
        {"name": "issuedAt", "type": "uint64"},
        {"name": "expiresAt", "type": "uint64"},
    ],
}

CORETEX_RECEIPT_TYPEHASH_STRING = "RigCoreTexReceipt(uint256 rigId,address operator,uint64 epochId,uint64 solveIndex,bytes32 prevReceiptHash,uint8 outcome,bytes32 challengeId,bytes32 parentStateRoot,bytes32 newStateRoot,bytes32 corpusRoot,bytes32 activeFrontierRoot,bytes32 coreVersionHash,bytes32 evalReportHash,bytes32 patchHash,bytes32 artifactHash,uint128 worldSeed,uint32 rulesVersion,bytes32 workPolicyHash,uint256 workUnitsBps,uint256 difficultyCountSnapshot,uint16 transitionFormatVersion,uint32 scoreBeforePpm,uint32 scoreAfterPpm,uint64 issuedAt,uint64 expiresAt)"
CORETEX_RECEIPT_TYPEHASH = "0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf"
#: The retired member-20 typehash (``uint16 stateWordCount``). Kept so it can be named in a
#: mismatch report rather than appearing as an opaque wrong hash; NEVER accepted.
RETIRED_CORETEX_RECEIPT_TYPEHASH = "0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b"

# Member 25 — SOURCE-CONFIRMED. The 105-byte transition descriptor whose hash is the SIGNED
# patchHash. UNSIGNED (outside the typehash), so the COORDINATOR must hash-bind it before signing.
CORETEX_RECEIPT_AUX_MEMBER: Dict[str, Any] = {
    "tuple_index": 25,
    "name": "compactPatchBytes",
    "type": "bytes",
    "signed": False,
    "derivation": "SOURCE_DERIVED",
}

# ── The transition descriptor (coretex.transition-descriptor/v2) ─────────────────────────
#
# The hash rule RigCoreTexVerifier._validateDescriptorHash applies. Both dead labels are recorded
# deliberately: COMPACT_PATCH_SUPERSEDED_LABEL is the V5 MEMORY lane's transition-hash domain (this
# lane signed under it once, historically); TRANSITION_DESCRIPTOR_RETIRED_LABEL is THIS lane's own
# retired 4-word compact-patch rule. A receipt signed under either reverts
# TransitionDescriptorHashMismatch (not CompactPatchHashMismatch — that revert belonged to the
# retired verifier and no longer exists).
TRANSITION_DESCRIPTOR_HASH_DOMAIN_LABEL = "coretex-transition-descriptor-v2"
TRANSITION_DESCRIPTOR_HASH_RULE = (
    "keccak256(abi.encodePacked(\"coretex-transition-descriptor-v2\", compactPatchBytes))")
TRANSITION_DESCRIPTOR_RETIRED_LABEL = "coretex-patch-hash-v1"
COMPACT_PATCH_SUPERSEDED_LABEL = "coretex-memory-transition-hash-v1"

# The descriptor is a FIXED 105-byte commitment — no padding, no optional field, no length
# prefix, no word ceiling. THE LENGTH IS THE FORMAT.
TRANSITION_DESCRIPTOR_LAYOUT: Dict[str, Any] = {
    "total_bytes": 105,
    "version": "0x20",
    "burned_versions": ["0x00-0x07", "0xff"],
    "unassigned_versions": ["0x08-0x1f"],
    "fields": [
        {"offset": 0, "size": 1, "field": "version", "encoding": "uint8, == 0x20"},
        {"offset": 1, "size": 32, "field": "patchArtifactHash",
         "encoding": "bytes32, != 0, sha256 of the complete canonical patch artifact"},
        {"offset": 33, "size": 32, "field": "parentStateRoot", "encoding": "bytes32"},
        {"offset": 65, "size": 32, "field": "newStateRoot", "encoding": "bytes32"},
        {"offset": 97, "size": 8, "field": "scoreDeltaPpm", "encoding": "uint64 big-endian"},
    ],
    "empty_patch":
        "MANDATORY for a SCREENER pass (outcome 1); a STATE ADVANCE MUST carry exactly 105 bytes",
}

# ── HISTORY — the retired 4-changed-word compact patch (coretex-patch-hash-v1 era) ───────────
#
# Kept, not deleted: epoch-180 mainnet-rehearsal advances used this exact layout and remain valid
# LEGACY-ERA history against the deployed legacy verifier (spec §9.5). MUST NOT be re-read under
# v2 — 0xff, every real epoch-180 advance's patchType byte, is a permanently-burned version.
COMPACT_PATCH_HASH_DOMAIN_LABEL = "coretex-patch-hash-v1"
COMPACT_PATCH_HASH_RULE = "keccak256(abi.encodePacked(\"coretex-patch-hash-v1\", compactPatchBytes))"

# The RETIRED patch was PARSED and cross-checked against the receipt's signed fields.
RETIRED_COMPACT_PATCH_LAYOUT: Dict[str, Any] = {
    "header_bytes": 42,
    "max_bytes": 178,
    "max_words": 4,
    "reserved_word_start": 992,
    "patch_type_word_ranges": {"0x01":[384,671],"0x02":[32,383],"0x03":[800,895],"0x04":[672,799],"0x05":[896,991],"0x06":[0,31],"0x07":[384,671],"0xff":"any index below 992"},
    "header": [
        {"offset": 0, "size": 1, "field": "patchType"},
        {"offset": 1, "size": 1, "field": "wordCount"},
        {"offset": 2, "size": 8, "field": "scoreDeltaPpm", "encoding": "uint64 big-endian"},
        {"offset": 10, "size": 32, "field": "parentStateRoot"},
    ],
    "words_begin_at": 42,
    "word_encoding":
        "LEB128 index (1-2 bytes, two-byte forms decode into [128, 1024)) then bytes32 value",
    "empty_patch":
        "legal for a SCREENER pass (outcome 1); fatal for a STATE ADVANCE (length < header_bytes)",
}

# ── The receipt window ────────────────────────────────────────────────────
#
# RigCoreTexVerifier._validateReceiptWindow. The TTL is CONSENSUS-BEARING, not advisory.
RECEIPT_WINDOW: Dict[str, Any] = {
    "enforced": True,
    "max_ttl_seconds": 3600,
    "derivation": "SOURCE_DERIVED",
    "rules": [
        "issuedAt <= block.timestamp",
        "expiresAt > issuedAt",
        "expiresAt - issuedAt <= max_ttl_seconds",
        "block.timestamp <= expiresAt",
    ],
}

# ── The registry mutator ──────────────────────────────────────────────────
#
# ICoreTexRegistry.submitStateAdvance. Its LAST parameter is a DYNAMIC bytes, so the calldata head
# is 11 static words plus ONE OFFSET word. Modelling it as
# 12 static words yields malformed calldata.
#
# THE 11TH PARAMETER IS RENAMED, THE SELECTOR IS NOT (transition-descriptor v2 §6.4): `uint16
# wordCount` becomes `uint16 transitionFormatVersion` at the same position. Solidity selectors and
# event topic0s are built from TYPES, not names, so `0xa2d87e1d` is unchanged; a name-keyed reader
# (as opposed to a positional one) is the one thing this rename is meant to break loudly rather
# than let drift silently.
SUBMIT_STATE_ADVANCE_FRAGMENT = "function submitStateAdvance(uint64 epoch, address miner, bytes32 parentStateRoot, bytes32 newStateRoot, bytes32 patchHash, bytes32 evalReportHash, bytes32 coreVersionHash, bytes32 corpusRoot, bytes32 activeFrontierRoot, uint256 improvementCredits, uint16 transitionFormatVersion, bytes compactPatchBytes) external"
SUBMIT_STATE_ADVANCE_SIGNATURE = "submitStateAdvance(uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint16,bytes)"
SUBMIT_STATE_ADVANCE_SELECTOR = "0xa2d87e1d"
SUBMIT_STATE_ADVANCE_PARAMETERS: List[Dict[str, str]] = [
    {"name": "epoch", "type": "uint64"},
    {"name": "miner", "type": "address"},
    {"name": "parentStateRoot", "type": "bytes32"},
    {"name": "newStateRoot", "type": "bytes32"},
    {"name": "patchHash", "type": "bytes32"},
    {"name": "evalReportHash", "type": "bytes32"},
    {"name": "coreVersionHash", "type": "bytes32"},
    {"name": "corpusRoot", "type": "bytes32"},
    {"name": "activeFrontierRoot", "type": "bytes32"},
    {"name": "improvementCredits", "type": "uint256"},
    {"name": "transitionFormatVersion", "type": "uint16"},
    {"name": "compactPatchBytes", "type": "bytes"},
]
SUBMIT_STATE_ADVANCE_STATIC_PARAMS = 11
SUBMIT_STATE_ADVANCE_DYNAMIC_TAIL: Dict[str, Any] = {
    "name": "compactPatchBytes",
    "type": "bytes",
    "head_word_index": 11,
}

# The ICoreTexRegistry READ surface the verifier consumes.
CORETEX_REGISTRY_READS: List[Dict[str, Any]] = [
    {"signature": "epochActiveFrontierRoot(uint64)", "selector": "0x00879d98", "returns": ["bytes32"]},
    {"signature": "epochCoreVersionHash(uint64)", "selector": "0xf392d765", "returns": ["bytes32"]},
    {"signature": "epochCorpusRoot(uint64)", "selector": "0xad64f0c3", "returns": ["bytes32"]},
    {"signature": "epochFinalized(uint64)", "selector": "0xbc68a310", "returns": ["bool"]},
    {"signature": "liveStateRoot(uint64)", "selector": "0x696466ed", "returns": ["bytes32"]},
    {"signature": "transitionCount(uint64)", "selector": "0x9f6b961d", "returns": ["uint64"]},
]

# uint64, NOT uint256.
TRANSITION_COUNT_RETURN_TYPE = "uint64"

# Rehearsal-observed. NEVER a default; the real values come from the signed release artifact.
EIP712_REHEARSAL_OBSERVED: Dict[str, Any] = {
    "chain_id": 8453,
    "verifying_contract": "0x7302bCaBa9a2f17447AEA5CEB3dC1593681758F6",
    "domain_separator": "0xa97f26f993229e776369e7d009083557b1d5b469c057bd18311a36ef4baab6bb",
    "note": "rehearsal-observed only; never a default, never production",
}

WORK_UNITS_VALID_OUTCOMES: List[int] = [1,2]
WORK_UNITS_INVALID_OUTCOMES_PROBED: List[int] = [0,3]
WORK_UNITS_OUTCOME_1_BPS = 20000
WORK_UNITS_OUTCOME_2_STEPS: List[Dict[str, int]] = [
    {"max_difficulty_count": 1, "bps": 100000},
    {"max_difficulty_count": 4, "bps": 150000},
    {"max_difficulty_count": 9, "bps": 200000},
]
WORK_UNITS_OUTCOME_2_TOP: Dict[str, int] = {
    "from_difficulty_count": 10,
    "bps": 300000,
}


def expected_work_units_bps(outcome: int, difficulty_count: int) -> int | None:
    """The staged pricing model, mirroring the TypeScript lane's expectedCoreTexWorkUnitsBps."""
    if outcome == 1:
        return WORK_UNITS_OUTCOME_1_BPS
    if outcome != 2:
        return None
    for step in WORK_UNITS_OUTCOME_2_STEPS:
        if difficulty_count <= step["max_difficulty_count"]:
            return step["bps"]
    return WORK_UNITS_OUTCOME_2_TOP["bps"]
