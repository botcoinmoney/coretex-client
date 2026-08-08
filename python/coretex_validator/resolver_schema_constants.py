# SPDX-License-Identifier: Apache-2.0
"""Versioned resolver-snapshot schema constants — spec text, not chain data.

Every value here is IDENTICAL in every snapshot of this schema. Reproducing them proves that this
package transcribed the schema correctly and says NOTHING WHATEVER about any chain, which is why
:data:`resolver_snapshot.SCHEMA_CONSTANT_KEYS` names them and the comparison report keeps them
in their own bucket. A reproduction that matched only these would have proved nothing.

They live in their own module, generated once from the published schema and committed as source,
for two reasons. First, so that a diff of this package shows plainly which bytes are transcribed
and which are derived. Second, so that nobody is tempted to "compute" them: they are prose about
what the schema means, and a lane that generated its own wording would produce a payload that
cannot reproduce however correct its chain reads were. That failure mode is not hypothetical —
this package hit it with the checks vocabulary, where eight descriptive names of its own
invention said exactly the right things and reproduced nothing.

prior is here in its GENESIS form only: the record for "no prior snapshot was supplied". A
resolution that chains onto a previous snapshot carries a different, derived prior.

Transcribed from the published mainnet-rehearsal snapshot for epoch 180
(payload_sha256 7087b32d3199c352336c3d7faa2126b3a1ce139a0f16b2ecc62d292fc9c672c7).

MIGRATION NOTE. ``DERIVATION_V1`` reconstructs epoch-180's published bytes under the historical
``coretex-patch-hash-v1`` / ``stateWordCount`` rules. ``DERIVATION_V2`` preserves the later
105-byte descriptor schema. ``DERIVATION_V3`` projects the canonical 97-byte three-pin receipt and
event facts from :mod:`rig_receipt_binding`. The declared snapshot schema selects one of them;
there is no payload-shape sniffing and no live dual-accept path.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from . import rig_receipt_binding as binding

CANONICALIZATION: Dict[str, Any] = {'chain_word_rendering': '0x-prefixed lowercase hex',
 'content_root_rendering': 'bare lowercase 64-hex',
 'digest': 'sha256',
 'python_authority': 'v5/frontier.py::canonical_bytes',
 'rule_id': 'coretex_memory.release.canonical_manifest_bytes',
 'serialization': "json.dumps(body, sort_keys=True, separators=(',',':'), "
                  "ensure_ascii=True).encode('utf-8')",
 'typescript_mirror': 'packages/coordinator/src/coretex-memory-v5-canonical.ts::canonicalFrontierJsonBytes',
 'wide_integer_rendering': 'decimal string (uint128/uint256 never render as JSON numbers)'}

DERIVATION: Dict[str, Any] = {'join_recipe': {'fields': {'activeFrontierRoot': {'how': 'registry log; also an epoch-context '
                                                          'read (step 6)',
                                                   'source': 'A, C'},
                            'artifactHash': {'how': 'CALLDATA ONLY. No event and no registry '
                                                    'parameter carries it; bound because it is '
                                                    'signed member 15 of the EIP-712 digest that '
                                                    'the step-4 preimage hashes',
                                             'source': 'C|digest'},
                            'challengeId': {'how': 'mining log data word 2; in the step-4 '
                                                   'preimage',
                                            'source': 'B, C'},
                            'compactPatchBytes': {'how': 'registry log tail, VERBATIM; required '
                                                         'byte-equal to the calldata tail (step '
                                                         '6). Unsigned, hence step 8',
                                                  'source': 'A, C'},
                            'coordinatorSigner': {'how': 'mining.coordinatorSigner() at the '
                                                         'observation block',
                                                  'source': 'state'},
                            'coreVersionHash': {'how': 'registry log; also an epoch-context read '
                                                       '(step 6)',
                                                'source': 'A, C'},
                            'corpusRoot': {'how': 'registry log; also an epoch-context read '
                                                  '(step 6)',
                                           'source': 'A, C'},
                            'difficultyCountSnapshot': {'how': 'calldata; directly in the step-4 '
                                                               'preimage',
                                                        'source': 'C|B'},
                            'domainSeparator': {'how': 'mining.DOMAIN_SEPARATOR(), cross-checked '
                                                       'against the derivation from (name, '
                                                       'version, chainId, mining)',
                                                'source': 'state'},
                            'epochActiveFrontierRoot': {'how': 'registry.epochActiveFrontierRoot(epoch) '
                                                               '-> context',
                                                        'source': 'state'},
                            'epochBaselineManifestHash': {'how': 'registry.epochBaselineManifestHash(epoch) '
                                                                 '-> context',
                                                          'source': 'state'},
                            'epochCoreVersionHash': {'how': 'registry.epochCoreVersionHash(epoch) '
                                                            '-> context',
                                                     'source': 'state'},
                            'epochCorpusRoot': {'how': 'registry.epochCorpusRoot(epoch) -> '
                                                       'verifier context',
                                                'source': 'state'},
                            'epochFinalized': {'how': 'registry.epochFinalized(epoch)',
                                               'source': 'state'},
                            'epochHiddenSeedCommit': {'how': 'registry.epochHiddenSeedCommit(epoch) '
                                                             '-> mining.epochCommit',
                                                      'source': 'state'},
                            'epochId': {'how': 'registry log topic 1 == mining log topic 1 == '
                                               'calldata',
                                        'source': 'A, B, C'},
                            'epochParentStateRoot': {'how': 'registry.epochParentStateRoot(epoch) '
                                                            '-> verifier context',
                                                     'source': 'state'},
                            'evalReportHash': {'how': 'registry log data word 3; in the step-4 '
                                                      'preimage',
                                               'source': 'A, C'},
                            'expiresAt': {'how': 'calldata; signed member 25, bound via the '
                                                 'digest',
                                          'source': 'C|digest'},
                            'getHeader': {'how': 'registry.getHeader(epoch) — ZERO-FILLED when '
                                                 'unsealed, never a revert; epochFinalized is '
                                                 'the discriminator',
                                          'source': 'state'},
                            'issuedAt': {'how': 'calldata; signed member 24, bound via the '
                                                'digest',
                                         'source': 'C|digest'},
                            'liveStateRoot': {'how': 'registry.liveStateRoot(epoch)',
                                              'source': 'state'},
                            'newStateRoot': {'how': 'registry log data word 1; in the step-4 '
                                                    'preimage',
                                             'source': 'A, C'},
                            'operator': {'how': 'registry log `miner` == mining log topic 3 == '
                                                'calldata',
                                         'source': 'A, B, C'},
                            'outcome': {'how': 'calldata; in the step-4 preimage. Always 2 here '
                                               '— a screener pass never reaches the registry '
                                               '(verifier :258)',
                                        'source': 'C|B'},
                            'parentStateRoot': {'how': 'registry log data word 0; in the step-4 '
                                                       'preimage',
                                                'source': 'A, C'},
                            'patchHash': {'how': 'registry log data word 2; in the step-4 '
                                                 'preimage; ALSO re-derived from '
                                                 'compactPatchBytes (step 8)',
                                          'source': 'A, C'},
                            'prevReceiptHash': {'how': 'calldata; proven by the step-4 '
                                                       'receiptHash preimage',
                                                'source': 'C|B'},
                            'rigId': {'how': 'mining log topic 2; equal to calldata (step 4 '
                                             'preimage)',
                                      'source': 'B, C'},
                            'rulesVersion': {'how': 'calldata; signed member 17, bound via the '
                                                    'digest',
                                             'source': 'C|digest'},
                            'scoreAfterPpm': {'how': 'calldata; signed member 23, bound via the '
                                                     'digest. Same §3.4 caveat',
                                              'source': 'C|digest'},
                            'scoreBeforePpm': {'how': 'calldata; signed member 22, bound via the '
                                                      'digest. NOTHING ON CHAIN CHECKS THAT THE '
                                                      'SCORE IS TRUE — design §3.4',
                                               'source': 'C|digest'},
                            'signature': {'how': 'CALLDATA ONLY, and unsigned by construction. '
                                                 'Verified by recovering the coordinator signer '
                                                 '(step 7)',
                                          'source': 'C'},
                            'solveIndex': {'how': 'mining log data word 0; in the step-4 '
                                                  'preimage',
                                           'source': 'B, C'},
                            'transitionFormatVersion': {'how': 'registry log '
                                                      '`transitionFormatVersion` (uint16, '
                                                      'renamed from `wordCount` by '
                                                      'transition-descriptor/v2 §9.1; same slot, '
                                                      'same topic0) == calldata',
                                               'source': 'A, C'},
                            'transitionCount': {'how': 'registry.transitionCount(epoch)',
                                                'source': 'state'},
                            'workPolicyHash': {'how': 'CALLDATA ONLY among the transports, but '
                                                      'it sits DIRECTLY in the step-4 '
                                                      'receiptHash preimage, so step 4 alone '
                                                      'proves it',
                                               'source': 'C|B'},
                            'workUnitsBps': {'how': 'mining log data word 3; also signed member '
                                                    '19',
                                             'source': 'B, C'},
                            'worldSeed': {'how': 'calldata; signed member 16, bound via the '
                                                 'digest',
                                          'source': 'C|digest'}},
                 'not_checked_anywhere_on_chain': ['scoreBeforePpm / scoreAfterPpm truthfulness '
                                                   '— coordinator-attested only (design §3.4)',
                                                   'epoch-to-epoch continuity — asserted by the '
                                                   'context operator, not derived on chain '
                                                   '(design §11 gap 1); the resolver checks it '
                                                   'OFF chain and reports the result'],
                 'primary_key': ['epoch', 'parentStateRoot', 'patchHash'],
                 'primary_key_note': '(epoch, parentStateRoot) is NOT unique — the head may '
                                     'legally cycle P->A->P->C within one epoch, so P occurs as '
                                     'a parent twice. Uniqueness comes ENTIRELY from the '
                                     "verifier's coreTexPatchCredited[epoch][parent][patchHash] "
                                     'guard',
                 'sources': {'A': 'registry log CoreTexStateAdvanced',
                             'B': 'mining log RigCoreTexCreditAccepted (same transaction, higher '
                                  'log index)',
                             'C': 'transaction calldata submitCoreTexReceipt(CoreTexReceipt)',
                             'state': 'eth_call against the pinned observation block'},
                 'specification': 'RIG-CORETEX-REGISTRY-DESIGN.md §7 (normative)',
                 'steps': ['1. find A: registry CoreTexStateAdvanced, filtered BY ADDRESS '
                           "(topic0 collides with the retired V4 lane's advance)",
                           '2. find B: the next RigCoreTexCreditAccepted in the same '
                           'transaction; cross-check epoch, operator and credits',
                           "3. fetch C: the transaction's calldata, ABI-decoded as the 27-member "
                           'receipt',
                           '4. bind C to B: recompute receiptHash over 13 members + the EIP-712 '
                           'digest and require equality with B — this alone proves '
                           'workPolicyHash',
                           '5. bind artifactHash: it is signed member 15 of the digest hashed in '
                           'step 4',
                           '6. bind C to A: 16 field equalities including compactPatchBytes '
                           'byte-for-byte',
                           '7. verify the signature: ecrecover(digest, signature) == '
                           'mining.coordinatorSigner()',
                           "8. verify the descriptor: keccak256("
                           "'coretex-transition-descriptor-v2' || compactPatchBytes) == "
                           'patchHash'],
                 'unrecoverable_without_calldata': ['artifactHash',
                                                    'workPolicyHash',
                                                    'signature',
                                                    'worldSeed',
                                                    'rulesVersion',
                                                    'scoreBeforePpm',
                                                    'scoreAfterPpm',
                                                    'issuedAt',
                                                    'expiresAt',
                                                    'prevReceiptHash',
                                                    'difficultyCountSnapshot']},
 'receipt_layout': {'artifact_hash_member_ordinal': 15,
                    'transition_descriptor_hash_rule':
                        "keccak256(utf8('coretex-transition-descriptor-v2') || "
                        'compactPatchBytes)',
                    'transition_descriptor_bytes': 105,
                    'transition_descriptor_version': '0x20',
                    'retired_compact_patch_hash_rule':
                        "keccak256(utf8('coretex-patch-hash-v1') || compactPatchBytes) "
                        '(LEGACY-ERA history only; refused on v2 as '
                        'TransitionDescriptorHashMismatch)',
                    'eip712_domain': {'name': 'BotcoinMiningRigs', 'version': '2'},
                    'receipt_hash_preimage_members': ['rigId',
                                                      'operator',
                                                      'epochId',
                                                      'solveIndex',
                                                      'prevReceiptHash',
                                                      'outcome',
                                                      'challengeId',
                                                      'parentStateRoot',
                                                      'newStateRoot',
                                                      'patchHash',
                                                      'evalReportHash',
                                                      'workPolicyHash',
                                                      'difficultyCountSnapshot',
                                                      'eip712Digest'],
                    'signed_members': 25,
                    'source_commit': 'ba4d5acfa7aa3042f39eb6e8e4d8e4007400090c',
                    'source_repo': 'github.com/botcoinmoney/botcoin-mining-rigs',
                    'submit_selector': '0xcc45427e',
                    'submit_signature': 'submitCoreTexReceipt((uint256,address,uint64,uint64,bytes32,uint8,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint128,uint32,bytes32,uint256,uint256,uint16,uint32,uint32,uint64,uint64,bytes,bytes))',
                    'tuple_members': 27,
                    'typehash': '0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf',
                    'typehash_string': 'RigCoreTexReceipt(uint256 rigId,address operator,uint64 '
                                       'epochId,uint64 solveIndex,bytes32 prevReceiptHash,uint8 '
                                       'outcome,bytes32 challengeId,bytes32 '
                                       'parentStateRoot,bytes32 newStateRoot,bytes32 '
                                       'corpusRoot,bytes32 activeFrontierRoot,bytes32 '
                                       'coreVersionHash,bytes32 evalReportHash,bytes32 '
                                       'patchHash,bytes32 artifactHash,uint128 worldSeed,uint32 '
                                       'rulesVersion,bytes32 workPolicyHash,uint256 '
                                       'workUnitsBps,uint256 difficultyCountSnapshot,uint16 '
                                       'transitionFormatVersion,uint32 scoreBeforePpm,uint32 '
                                       'scoreAfterPpm,uint64 issuedAt,uint64 expiresAt)',
                    'retired_typehash':
                        '0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b'},
 'reproduction': 'Re-run the resolver against the same chain_id at the same observation block '
                 "with the same content store. The payload's sha256 must match. No resolver key, "
                 'no signature and no private input is required',
 'scope': 'per-epoch',
 'scope_rationale': 'the consumer is an isolated runtime agent performing portable CoreTex '
                    'activation: it needs the STATE at an epoch (live root, per-profile release '
                    'roots, composed manifest, locks), not the story of one advance. A '
                    'per-transition document describes an edge; activation needs a node. Lineage '
                    'is carried inside the snapshot as the EVIDENCE for that state, never as the '
                    'subject',
 'sources': ['finalized contract state',
             'registry events',
             'mining events',
             'transaction calldata',
             'content-addressed artifacts']}

DERIVATION_V2: Dict[str, Any] = DERIVATION


def _legacy_v1_derivation() -> Dict[str, Any]:
    """Restore the exact immutable signed-snapshot/v1 derivation block."""
    result = deepcopy(DERIVATION_V2)
    fields = result["join_recipe"]["fields"]
    fields["stateWordCount"] = {
        "how": "registry log `wordCount` (uint16) == calldata",
        "source": "A, C",
    }
    fields.pop("transitionFormatVersion", None)
    result["join_recipe"]["steps"][-1] = (
        "8. verify the patch: keccak256('coretex-patch-hash-v1' || compactPatchBytes) == "
        "patchHash")
    layout = result["receipt_layout"]
    for name in ("transition_descriptor_hash_rule", "transition_descriptor_bytes",
                 "transition_descriptor_version", "retired_compact_patch_hash_rule",
                 "retired_typehash"):
        layout.pop(name, None)
    layout.update({
        "compact_patch_hash_rule": (
            "keccak256(utf8('coretex-patch-hash-v1') || compactPatchBytes)"),
        "source_commit": "cdb91d211e4620c6ecfd90b68d827d607033e1f1",
        "typehash": "0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b",
        "typehash_string": layout["typehash_string"].replace(
            "uint16 transitionFormatVersion", "uint16 stateWordCount"),
    })
    return result


DERIVATION_V1: Dict[str, Any] = _legacy_v1_derivation()


def _descriptor_v3_derivation() -> Dict[str, Any]:
    """Project the v3 schema constants from the canonical generated receipt binding.

    ``DERIVATION`` remains the immutable v1/v2-era transcription above. V3 changes the inner
    receipt/event/state law while retaining the unsigned v2 top-level envelope, so it has its own
    constant block instead of silently rewriting historical reproduction bytes.
    """
    result = deepcopy(DERIVATION_V2)
    recipe = result["join_recipe"]
    fields = recipe["fields"]
    for retired in ("activeFrontierRoot", "corpusRoot", "epochActiveFrontierRoot",
                    "epochBaselineManifestHash", "epochCorpusRoot"):
        fields.pop(retired, None)
    fields["epochContextRoot"] = {
        "how": "registry.epochContextRoot(epoch) -> content-addressed epoch-context manifest",
        "source": "state",
    }
    fields["getHeader"] = {
        "how": "registry.getHeader(epoch) -> patchSetRoot/scoreRoot; ZERO-FILLED when unsealed",
        "source": "state",
    }
    fields["transitionFormatVersion"] = {
        "how": ("registry log's twelfth parameter (uint16) == calldata. The registry RENAMED "
                "this slot from `wordCount`; the types are unchanged, so the selector and topic0 "
                "are too. THAT EQUALITY IS NOT THE BINDING — both sides are the same value from "
                "the same transaction. The binding is step 8's `transitionFormatVersion == "
                "descriptorBytes[0]`, against the BYTES, which is the point of the field"),
        "source": "A, C",
    }
    fields["compactPatchBytes"]["how"] = (
        "registry log tail, VERBATIM — the 97-byte transition descriptor; required byte-equal "
        "to the calldata tail (step 6). Unsigned, hence step 8. It is a COMMITMENT: the edit is "
        "the canonical patch artifact it addresses, which no log carries")
    fields["artifactHash"]["how"] = (
        "CALLDATA ONLY. No event and no registry parameter carries it; bound because it is "
        "signed member 14 of the EIP-712 digest that the step-4 preimage hashes")
    fields["outcome"]["how"] = (
        "calldata; in the step-4 preimage. Always 2 here — a screener pass never reaches the "
        "registry (verifier :258) — and step 8 now READS it rather than assuming it: a screener "
        "joined to a registry advance is refused, after its own outcome-1 rule has been evaluated")
    fields["patchHash"]["how"] = (
        "registry log data word 2; in the step-4 preimage; ALSO re-derived from "
        "compactPatchBytes (step 8). Under coretex.transition-descriptor/v3 it is a content "
        "address of the whole EDGE, so this key now DETERMINES newStateRoot — which it did not "
        "before")
    fields["worldSeed"]["how"] = "calldata; signed member 15, bound via the digest"
    fields["scoreBeforePpm"]["how"] = (
        "calldata; signed member 21, bound via the digest. NOTHING ON CHAIN CHECKS THAT THE "
        "SCORE IS TRUE — design §3.4")
    fields["scoreAfterPpm"]["how"] = (
        "calldata; signed member 22, bound via the digest. Same §3.4 caveat")
    fields["issuedAt"]["how"] = "calldata; signed member 23, bound via the digest"
    fields["expiresAt"]["how"] = "calldata; signed member 24, bound via the digest"
    fields["rulesVersion"]["how"] = "calldata; signed member 16, bound via the digest"
    fields["workUnitsBps"]["how"] = "mining log data word 3; also signed member 18"
    recipe["steps"] = [
        "1. find A: live descriptor-v3 registry CoreTexStateAdvanced, filtered BY ADDRESS; the "
        "retired 13-field rig topic is diagnosed but never decoded as live",
        "2. find B: the next RigCoreTexCreditAccepted in the same transaction; cross-check "
        "epoch, operator and credits",
        "3. fetch C: the transaction's calldata, ABI-decoded as the 26-member receipt",
        "4. bind C to B: recompute receiptHash over 13 members + the EIP-712 digest and require "
        "equality with B — this alone proves workPolicyHash",
        "5. bind artifactHash: it is signed member 14 of the digest hashed in step 4",
        "6. bind C to A/B: 14 field equalities including epochContextRoot and compactPatchBytes "
        "byte-for-byte",
        "7. verify the signature: ecrecover(digest, signature) == mining.coordinatorSigner()",
        "8. verify the descriptor — ALL descriptor-v3 bindings, not just the hash: (a) "
        "keccak256('coretex-transition-descriptor-v3' || compactPatchBytes) == patchHash [the "
        "resolver's own implementation, with all three dead labels named on a mismatch]; then "
        "DECODE the bytes (validator.dispatch, imported) and require (b) non-empty and "
        "descriptorBytes[0] == 0x21, with retired 0x20/105 diagnosed before generic semantic "
        "checks, (c) length == 97 exactly, (d) patchArtifactHash != 0, (e) "
        "descriptor.parentStateRoot == the advance's parentStateRoot, (f) "
        "descriptor.newStateRoot == the advance's newStateRoot, and (g) the SIGNED "
        "transitionFormatVersion == descriptorBytes[0]. The descriptor carries no score delta. "
        "(g) is the point of the field and is NOT what step 6 checks: step 6 compares the "
        "calldata's transitionFormatVersion to the registry log's twelfth parameter, which is "
        "one value arriving twice from one transaction. Only (g) binds it to the BYTES. The "
        "outcome is read here too: outcome 1 (a screener) is refused against a registry advance, "
        "and the outcome-1 rule — EMPTY descriptor, zero scores, zero transitionFormatVersion "
        "and patchHash == bytes32(0) — is evaluated before the contradiction is reported",
    ]
    layout = result["receipt_layout"]
    layout.update({
        "artifact_hash_member_ordinal": 14,
        "transition_descriptor_hash_rule": (
            "keccak256(utf8('coretex-transition-descriptor-v3') || compactPatchBytes)"),
        "transition_descriptor_bytes": binding.TRANSITION_DESCRIPTOR_BYTES,
        "transition_descriptor_version": binding.TRANSITION_DESCRIPTOR_VERSION,
        "transition_descriptor_check_order": (
            "non-empty -> version byte (0x20 gets the dedicated retired-v2 diagnosis) -> exact "
            "length -> hash -> fields"),
        "transition_descriptor_dead_labels": [
            "coretex-transition-descriptor-v2",
            "coretex-patch-hash-v1",
            "coretex-memory-transition-hash-v1",
        ],
        "transition_descriptor_retired_bytes": 105,
        "transition_descriptor_retired_version": 32,
        "signed_members": len(binding.CORETEX_RECEIPT_TYPES[
            binding.CORETEX_RECEIPT_PRIMARY_TYPE]),
        "source_commit": "a473f3fd1038a81f8ef456cd4c7ce1f7b9fbef6e",
        "submit_selector": binding.SUBMIT_CORETEX_RECEIPT_SELECTOR,
        "submit_signature": ("submitCoreTexReceipt(("
                             + ",".join(binding.CORETEX_RECEIPT_TUPLE_TYPES) + "))"),
        "tuple_members": len(binding.CORETEX_RECEIPT_TUPLE_COMPONENTS),
        "typehash": binding.CORETEX_RECEIPT_TYPEHASH,
        "typehash_string": binding.CORETEX_RECEIPT_TYPEHASH_STRING,
    })
    for retired in ("retired_compact_patch_hash_rule", "retired_typehash"):
        layout.pop(retired, None)
    result["reproduction"] = (
        "Re-run against the same chain_id at the same observation block with the same content "
        "store and runtime-integration record. The payload's sha256 must match. There is no key, "
        "no signature and no private input anywhere in this path")
    return result


DERIVATION_V3: Dict[str, Any] = _descriptor_v3_derivation()


DISCLOSURE = ('MAINNET_REHEARSAL. This snapshot is derived from chain truth alone and is signed by a '
 'QUALIFIED REHEARSAL/TEST authority for transport only. It is NOT MAINNET_CANONICAL, it carries '
 'no production authority, and its signature is not a substitute for chain replay: the unsigned '
 "payload below reproduces byte-for-byte from the same chain state without the resolver's key")

DISCLOSURE_V3 = (
    "MAINNET_REHEARSAL. Derived from chain truth alone. It is NOT MAINNET_CANONICAL and carries "
    "no production authority. It is UNSIGNED, and that is deliberate: a downloaded copy of this "
    "document is a CACHE, not an authority. It is authoritative only insofar as you — or any "
    "independent implementation — reconstruct these exact bytes from the same pinned chain "
    "state. See the `authority` block")

PRIOR: Dict[str, Any] = {'genesis': True,
 'note': 'no prior snapshot was supplied; this is the first resolution of this lane. A zero hash '
         'is NOT used as a stand-in for a link that does not exist'}
