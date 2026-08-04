"""
# GENERATED FROM bundle.json sha256=c47d93fce5d1130283fbbd8592db00da86a3b656aa374a816d841c0925487199 — DO NOT EDIT.
#
# Regenerate with:
#   node scripts/generate-rig-receipt-bindings.mjs --bundle <path-to-bundle.json>
#
# Source of authority: the rig lane's integration bundle
#   schema        botcoin.rig-coordinator-integration.bundle/2
#   mining ABI    sha256=cd1c9f7404053e944a612dcbd74365b6248e80adb3c05c6ec989f8a1d9ba2881
#   vendored .sol contracts/rig/mining/BotcoinMiningRigsV1.sol (sha256=95b8a6f6efd677f85bd71e571c1c816511ad89facc7daf624a7b32afdab71962)
#   rig source    undefined @ undefined
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
# 0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b,
# and the fragment's selector equals the pinned 0xcc45427e.
#
# MEMBER 25 IS `bytes compactPatchBytes` — CONFIRMED, no longer inferred.
# It is the compact state patch whose hash is the SIGNED `patchHash`. It is OUTSIDE the
# typehash, so it is UNSIGNED: a miner can alter it without invalidating the
# coordinator's signature, which is exactly why the COORDINATOR must hash-bind it before
# signing. The mining contract never reads it; the verifier does, and forwards it as
# submitStateAdvance's dynamic tail.
#
# THE HASH RULE IS keccak256(utf8("coretex-patch-hash-v1") ++ compactPatchBytes).
# This lane previously used "coretex-memory-transition-hash-v1" — the V5 MEMORY lane's
# transition-hash domain. Receipts signed under that label revert
# CompactPatchHashMismatch on chain.
#
# THE PATCH IS A PARSED STRUCTURE, not opaque bytes: a 42-byte header carrying
# patchType, wordCount, a big-endian score delta and the parent state root — each
# cross-checked against the receipt's own SIGNED fields — then LEB128-indexed 32-byte
# words, bounded at 178 bytes and 4 words.
#
# THE REGISTRY MUTATOR'S TAIL IS DYNAMIC. submitStateAdvance has
# 11 static parameters followed by `bytes compactPatchBytes`; the twelfth
# head word is that tail's OFFSET, not a twelfth value. And transitionCount returns
# uint64, not uint256.
"""

from __future__ import annotations

from typing import Any, Dict, List

BUNDLE_SHA256 = "c47d93fce5d1130283fbbd8592db00da86a3b656aa374a816d841c0925487199"

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
    {"name": "stateWordCount", "type": "uint16"},
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
        {"name": "stateWordCount", "type": "uint16"},
        {"name": "scoreBeforePpm", "type": "uint32"},
        {"name": "scoreAfterPpm", "type": "uint32"},
        {"name": "issuedAt", "type": "uint64"},
        {"name": "expiresAt", "type": "uint64"},
    ],
}

CORETEX_RECEIPT_TYPEHASH_STRING = "RigCoreTexReceipt(uint256 rigId,address operator,uint64 epochId,uint64 solveIndex,bytes32 prevReceiptHash,uint8 outcome,bytes32 challengeId,bytes32 parentStateRoot,bytes32 newStateRoot,bytes32 corpusRoot,bytes32 activeFrontierRoot,bytes32 coreVersionHash,bytes32 evalReportHash,bytes32 patchHash,bytes32 artifactHash,uint128 worldSeed,uint32 rulesVersion,bytes32 workPolicyHash,uint256 workUnitsBps,uint256 difficultyCountSnapshot,uint16 stateWordCount,uint32 scoreBeforePpm,uint32 scoreAfterPpm,uint64 issuedAt,uint64 expiresAt)"
CORETEX_RECEIPT_TYPEHASH = "0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b"

# Member 25 — SOURCE-CONFIRMED. The compact state patch whose hash is the SIGNED patchHash.
# UNSIGNED (outside the typehash), so the COORDINATOR must hash-bind it before signing.
CORETEX_RECEIPT_AUX_MEMBER: Dict[str, Any] = {
    "tuple_index": 25,
    "name": "compactPatchBytes",
    "type": "bytes",
    "signed": False,
    "derivation": "SOURCE_DERIVED",
}

# ── The compact patch ─────────────────────────────────────────────────────
#
# The hash rule RigCoreTexVerifier._validatePatchHash applies. The superseded label is recorded
# deliberately: it is the V5 MEMORY lane's transition-hash domain, this lane signed under it, and
# every state-advance receipt built that way reverts CompactPatchHashMismatch (0x41c32e40).
COMPACT_PATCH_HASH_DOMAIN_LABEL = "coretex-patch-hash-v1"
COMPACT_PATCH_HASH_RULE = "keccak256(abi.encodePacked(\"coretex-patch-hash-v1\", compactPatchBytes))"
COMPACT_PATCH_SUPERSEDED_LABEL = "coretex-memory-transition-hash-v1"

# The patch is PARSED and cross-checked against the receipt's signed fields, not opaque bytes.
COMPACT_PATCH_LAYOUT: Dict[str, Any] = {
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
SUBMIT_STATE_ADVANCE_FRAGMENT = "function submitStateAdvance(uint64 epoch, address miner, bytes32 parentStateRoot, bytes32 newStateRoot, bytes32 patchHash, bytes32 evalReportHash, bytes32 coreVersionHash, bytes32 corpusRoot, bytes32 activeFrontierRoot, uint256 improvementCredits, uint16 wordCount, bytes compactPatchBytes) external"
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
    {"name": "wordCount", "type": "uint16"},
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
