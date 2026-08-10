# SPDX-License-Identifier: Apache-2.0
"""Step 1-2: discover a rig release, and verify the deployed bytecode against it.

THE TWO AUTHORITIES, WHICH ARE NOT THE SAME THING AND MUST NEVER BE COLLAPSED.

* The **release artifact** is the DEPLOYMENT authority. It records the addresses that were
  deployed and the ``keccak256`` of the runtime bytecode each of them actually carries. If the
  chain disagrees with it, the chain is right and the release is stale or wrong — but either way
  something is broken and the run must stop.
* The **pinned source commit** is the SOURCE / INTERFACE authority. It is where the event
  signatures, the receipt tuple layout, the typehash and the join recipe come from.

The rehearsal deployment was built from an EARLIER tree than the pinned source HEAD. So the two
authorities *legitimately* disagree about bytecode, and a validator that compiled HEAD and
compared the result to the chain would report a false alarm on every single deployment. It is
modelled explicitly instead: :class:`Release` carries both, :func:`verify_deployment` checks the
chain against the RELEASE, and :meth:`Release.source_divergence` states in the report that the
interface authority is a different tree. What is NOT tolerated is a release that fails to say
which source it was built from — that turns "we know they differ" into "we have no idea".

WHAT IS DELIBERATELY NOT DONE HERE. This module does not compile anything. Reproducing a build
from source needs a pinned solc, pinned settings and a pinned dependency tree, and getting any of
them wrong produces a mismatch that looks exactly like tampering. Bytecode reproduction is a
separate, opt-in claim; conflating it with deployment verification would make the everyday check
fail for boring reasons and train operators to ignore it.
"""
from __future__ import annotations

import json
import hashlib
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from . import rehearsal_deployment as rd
from . import rig_events as rig
from .keccak256 import keccak256_hex

RELEASE_FORMAT = "coretex.rig-rehearsal-release/v1"
PRODUCTION_RELEASE_FORMAT = "botcoin-rig-release/v1"
BUILTIN_PRODUCTION_RELEASE_FORMAT = "coretex.canonical-production-release/v1"
DEFAULT_PRODUCTION_RELEASE_URL = "builtin:base-mainnet"
PRODUCTION_COORDINATOR = "0x6463f89F102e9f53168ABe557173f53c0bBbF635"
PRODUCTION_CONTRACTS = {
    "registry": "0xa4d8a7Bb3Ba2D023af29Bf77601A61673ED89ad3",
    "mining": "0xB61BC7487424172CB9fa9dD381a9eC06C7067dCd",
    "verifier": "0x82384E4DA334a4e3E1d8d2623359dC8c4d931Ed4",
}
PRODUCTION_GENESIS_STATE_ROOT = (
    "8f2455e5cbf49cd4bb5e1b148c1828a9c79aa7fd27d3db7035fe7fb5e0287788")
PRODUCTION_CUTOVER_EPOCH = 171
PRODUCTION_SOURCE_COMMIT = "1f8ba5c11b6fc4bc97e4e23000e9fefea5ba6252"
PRODUCTION_DEPLOY_BLOCK = 49773104
PRODUCTION_RELEASE_PAYLOAD_HASH = (
    "959ab7028bc90fd71995fcfc6f7498e8912c18d66de5a454f98fd0660b9632ba")
PRODUCTION_RELEASE_SIGNATURE = (
    "0xbae09cdb7b623f1cfd8574eded6bd507888f6808fb2ad183f78f48d63ec1e2e0"
    "36e2a014f2d8f1595215eff5446d7e4e1fc9b2fadf224e733c87c5560f32201a1b")
PRODUCTION_CODE_HASHES = {
    "registry": "c38537574e711e069118f9ade2e92a04df768ed0ad3d59f813ce144fbed04c25",
    "mining": "61b768d6678405bf286757dcfd931bde1586e089871d6cbc906454d263d3039d",
    "verifier": "a27ea294e4acf6062f7cc1cf57fb02bb372c628b7ccd40255fad0a21cb213d7b",
}

#: The ONLY classification this package will produce a snapshot under. Stated here as well as in
#: :mod:`.export` because it is a property of the release, not only of the output.
CLASSIFICATION_REHEARSAL = "MAINNET_REHEARSAL"
#: Named so it can be REFUSED by name. A release that claims it is rejected: this package has
#: never been through the process that would justify the claim.
CLASSIFICATION_CANONICAL = "MAINNET_CANONICAL"
CLASSIFICATION_PRODUCTION = "CANONICAL_PRODUCTION"

#: The three contracts a rig lane is. Every one of them must be pinned by the release, because
#: verifying two of three leaves the unverified one free to be anything.
CONTRACT_ROLES = ("registry", "mining", "verifier")


class ReleaseError(Exception):
    """A release that cannot be trusted to be about a real deployment."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SourcePin:
    """Where the INTERFACE authority lives. Repo + commit, never a branch."""

    repo: str
    commit: str
    #: Free-form, e.g. ``"contracts/rig/mining"``. Recorded so a reader can find the files.
    paths: Tuple[str, ...] = ()
    #: ``True`` when the repo is fetchable by an anonymous clean machine. See
    #: ``docs/V5-RIG-VALIDATOR.md``: at the time of writing it is NOT, which is a finding about
    #: whether the public validator can exist, not a detail of this dataclass.
    public: bool = False


@dataclass(frozen=True)
class Release:
    """A rehearsal release artifact, parsed and range-checked.

    Nothing here is derived from the chain. That is the point: the release is the CLAIM, and
    :func:`verify_deployment` is where the claim meets the state.
    """

    format: str
    classification: str
    chain_id: int
    network: str
    addresses: Dict[str, str]
    #: ``role -> keccak256(runtime bytecode)`` as bare lowercase 64-hex.
    runtime_code_hashes: Dict[str, str]
    deploy_block: int
    #: The block the release wants read as the deployment's settled observation point. A run may
    #: choose a later one; it may not choose an earlier one.
    observation_block: Optional[int]
    source: SourcePin
    #: Where content-addressed artifacts (eval artifact, candidate manifest) can be fetched.
    artifact_base_url: Optional[str]
    #: The frozen runtime packet this deployment's admission law is pinned to.
    runtime_packet_sha256: Optional[str]
    #: The resolver's signing address. TRANSPORT authentication only — see :mod:`.snapshot`.
    resolver_signer: Optional[str]
    raw: Mapping[str, Any]
    production_authority: bool = False

    @property
    def deployment(self) -> rig.RigDeployment:
        return rig.RigDeployment(chain_id=self.chain_id, registry=self.addresses["registry"],
                                 mining=self.addresses["mining"],
                                 verifier=self.addresses["verifier"])

    def source_divergence(self) -> Dict[str, Any]:
        """The statement every report must carry: which authority is which.

        Not a warning and not an error. It exists so no reader can come away thinking the
        bytecode on chain was proved to be a build of the pinned source — it was not, and the
        release is the only thing that says what was deployed.
        """
        if self.production_authority:
            signature = self.raw.get("operatorSignature", {})
            return {
                "deployment_authority": "operator_signed_canonical_release",
                "production_authority": True,
                "release_payload_sha256": signature.get("payloadHash"),
                "release_signer": signature.get("signer"),
                "source_interface_authority": {
                    "repo": self.source.repo, "commit": self.source.commit,
                    "publicly_fetchable": self.source.public},
                "note": ("the canonical deployment artifact is authenticated by its production "
                         "coordinator signature; runtime bytecode and immutable wiring are still "
                         "read independently from the pinned chain block"),
            }
        return {
            "deployment_authority": "release_artifact",
            "source_interface_authority": {"repo": self.source.repo, "commit": self.source.commit,
                                           "publicly_fetchable": self.source.public},
            "note": ("the deployed rehearsal was built from an EARLIER tree than the pinned "
                     "source commit. Bytecode is verified against the RELEASE's recorded runtime "
                     "hashes; the pinned commit is the authority for ABI/event/typehash "
                     "interfaces ONLY. These are not the same claim and this run does not "
                     "compile anything"),
        }


def _require(document: Mapping[str, Any], field: str) -> Any:
    if field not in document:
        raise ReleaseError("RELEASE_INCOMPLETE", f"the release carries no {field!r}")
    return document[field]


def parse_release(document: Mapping[str, Any]) -> Release:
    """Parse and range-check. Refuses anything it cannot fully understand."""
    if not isinstance(document, Mapping):
        raise ReleaseError("RELEASE_MALFORMED", "a release is a JSON object")
    fmt = _require(document, "format")
    if fmt == BUILTIN_PRODUCTION_RELEASE_FORMAT:
        return _parse_builtin_production_release(document)
    if fmt == PRODUCTION_RELEASE_FORMAT:
        return _parse_production_release(document)
    if fmt != RELEASE_FORMAT:
        raise ReleaseError("RELEASE_FORMAT_UNKNOWN",
                           f"format {fmt!r} is not {RELEASE_FORMAT!r}; refusing to guess")
    classification = _require(document, "classification")
    if classification == CLASSIFICATION_CANONICAL:
        raise ReleaseError(
            "CLASSIFICATION_REFUSED",
            "this release claims MAINNET_CANONICAL. This package validates REHEARSAL deployments "
            "and has never been through the process that would justify a canonical claim; a "
            "canonical snapshot must not be mintable by pointing this tool at a file")
    if classification != CLASSIFICATION_REHEARSAL:
        raise ReleaseError("CLASSIFICATION_UNKNOWN",
                           f"unsupported classification {classification!r}")

    addresses_raw = _require(document, "addresses")
    if not isinstance(addresses_raw, Mapping):
        raise ReleaseError("RELEASE_MALFORMED", "addresses must be an object")
    addresses: Dict[str, str] = {}
    for role in CONTRACT_ROLES:
        value = addresses_raw.get(role)
        if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
            raise ReleaseError("RELEASE_INCOMPLETE",
                               f"addresses.{role} must be a 0x-prefixed address, got {value!r}")
        addresses[role] = value

    hashes_raw = _require(document, "runtime_code_hashes")
    if not isinstance(hashes_raw, Mapping):
        raise ReleaseError("RELEASE_MALFORMED", "runtime_code_hashes must be an object")
    code_hashes: Dict[str, str] = {}
    for role in CONTRACT_ROLES:
        value = hashes_raw.get(role)
        try:
            code_hashes[role] = fr.check_root(value, f"runtime_code_hashes.{role}")
        except fr.FrontierError as exc:
            raise ReleaseError("RELEASE_INCOMPLETE", str(exc)) from exc

    source_raw = _require(document, "source")
    if not isinstance(source_raw, Mapping):
        raise ReleaseError("RELEASE_MALFORMED", "source must be an object")
    commit = source_raw.get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise ReleaseError(
            "SOURCE_PIN_MISSING",
            "source.commit must be a full 40-hex git commit. A release that does not say which "
            "tree its interfaces come from turns a known divergence into an unknown one")
    source = SourcePin(repo=str(source_raw.get("repo", "")), commit=commit,
                       paths=tuple(source_raw.get("paths", ())),
                       public=bool(source_raw.get("publicly_fetchable", False)))

    chain_id = _require(document, "chain_id")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise ReleaseError("RELEASE_MALFORMED", "chain_id must be a positive integer")
    deploy_block = _require(document, "deploy_block")
    if not isinstance(deploy_block, int) or isinstance(deploy_block, bool) or deploy_block < 0:
        raise ReleaseError("RELEASE_MALFORMED", "deploy_block must be a non-negative integer")

    return Release(
        format=fmt, classification=classification, chain_id=chain_id,
        network=str(document.get("network", "")), addresses=addresses,
        runtime_code_hashes=code_hashes, deploy_block=deploy_block,
        observation_block=document.get("observation_block"), source=source,
        artifact_base_url=document.get("artifact_base_url"),
        runtime_packet_sha256=document.get("runtime_packet_sha256"),
        resolver_signer=document.get("resolver_signer"), raw=dict(document))


def _require_address(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        raise ReleaseError("RELEASE_INCOMPLETE",
                           f"{field} must be a 0x-prefixed address, got {value!r}")
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise ReleaseError("RELEASE_MALFORMED", f"{field} is not hex") from exc
    return value


def _production_payload_bytes(document: Mapping[str, Any]) -> bytes:
    """Exact mirror of sign-canonical-deployment.mjs payloadDocument + JSON.stringify.

    JSON object insertion order is retained by Python's parser.  ``ensure_ascii=False`` matches
    JavaScript's UTF-8 JSON.stringify output; compact separators remove Python-only whitespace.
    """
    payload = {key: value for key, value in document.items()
               if key not in ("signature", "operatorSignature")}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _verify_production_signature(document: Mapping[str, Any]) -> str:
    block = _require(document, "operatorSignature")
    if not isinstance(block, Mapping):
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID", "operatorSignature must be an object")
    if (block.get("status") != "SIGNED" or
            block.get("algorithm") != "secp256k1-eip191-personal_sign"):
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID",
                           "the canonical release has no supported signed operator signature")
    payload_hash = hashlib.sha256(_production_payload_bytes(document)).digest()
    if str(block.get("payloadHash", "")).removeprefix("0x").lower() != payload_hash.hex():
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID",
                           "operatorSignature.payloadHash does not match the release contents")
    signature_hex = str(block.get("signature", ""))
    try:
        signature = bytes.fromhex(signature_hex.removeprefix("0x"))
    except ValueError as exc:
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID", "operator signature is not hex") from exc
    # ethers.signMessage(getBytes(payloadHash)): EIP-191 over an exact 32-byte message.
    from .keccak256 import keccak256
    from .secp256k1 import ecrecover, addresses_equal, SignatureError
    digest = keccak256(b"\x19Ethereum Signed Message:\n32" + payload_hash)
    try:
        recovered = ecrecover(digest, signature)
    except SignatureError as exc:
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID", str(exc)) from exc
    coordinator = _require_address(document.get("coordinatorSigner"), "coordinatorSigner")
    signer = _require_address(block.get("signer"), "operatorSignature.signer")
    if not addresses_equal(recovered, coordinator) or not addresses_equal(recovered, signer):
        raise ReleaseError(
            "PRODUCTION_SIGNATURE_INVALID",
            f"operator signature recovers {recovered}, not coordinator {coordinator}")
    if not addresses_equal(recovered, PRODUCTION_COORDINATOR):
        raise ReleaseError("PRODUCTION_AUTHORITY_INVALID",
                           f"release signer {recovered} is not the canonical production signer")
    return recovered


def _recover_production_signature(payload_hash_hex: str, signature_hex: str) -> str:
    from .keccak256 import keccak256
    from .secp256k1 import ecrecover, addresses_equal, SignatureError
    try:
        payload_hash = bytes.fromhex(payload_hash_hex.removeprefix("0x"))
        signature = bytes.fromhex(signature_hex.removeprefix("0x"))
    except ValueError as exc:
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID", "production signature pin is not hex") from exc
    if len(payload_hash) != 32:
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID", "production payload hash is not bytes32")
    digest = keccak256(b"\x19Ethereum Signed Message:\n32" + payload_hash)
    try:
        recovered = ecrecover(digest, signature)
    except SignatureError as exc:
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID", str(exc)) from exc
    if not addresses_equal(recovered, PRODUCTION_COORDINATOR):
        raise ReleaseError("PRODUCTION_SIGNATURE_INVALID",
                           f"pinned release signature recovers {recovered}")
    return recovered


def _builtin_production_document() -> Dict[str, Any]:
    return {
        "format": BUILTIN_PRODUCTION_RELEASE_FORMAT,
        "classification": CLASSIFICATION_PRODUCTION,
        "productionAllowed": True,
        "chain_id": 8453,
        "network": "base-mainnet",
        "addresses": dict(PRODUCTION_CONTRACTS),
        "runtime_code_hashes": dict(PRODUCTION_CODE_HASHES),
        "deploy_block": PRODUCTION_DEPLOY_BLOCK,
        "genesis_state_root": PRODUCTION_GENESIS_STATE_ROOT,
        "cutover_epoch": PRODUCTION_CUTOVER_EPOCH,
        "source": {"repo": "https://github.com/botcoinmoney/botcoin-mining-rigs",
                   "commit": PRODUCTION_SOURCE_COMMIT, "publicly_fetchable": False},
        "operatorSignature": {
            "status": "SIGNED", "algorithm": "secp256k1-eip191-personal_sign",
            "payloadHash": PRODUCTION_RELEASE_PAYLOAD_HASH,
            "signer": PRODUCTION_COORDINATOR, "signature": PRODUCTION_RELEASE_SIGNATURE},
        "authority_note": ("minimal public identity extracted from the signed canonical release; "
                           "all identity fields are pinned in validator code and re-read on chain"),
    }


def _parse_builtin_production_release(document: Mapping[str, Any]) -> Release:
    expected = _builtin_production_document()
    if dict(document) != expected:
        raise ReleaseError("PRODUCTION_IDENTITY_MISMATCH",
                           "builtin production identity was modified")
    recovered = _recover_production_signature(PRODUCTION_RELEASE_PAYLOAD_HASH,
                                              PRODUCTION_RELEASE_SIGNATURE)
    source = SourcePin(repo=expected["source"]["repo"], commit=PRODUCTION_SOURCE_COMMIT,
                       paths=("contracts/rig/mining",), public=False)
    return Release(
        format=BUILTIN_PRODUCTION_RELEASE_FORMAT, classification=CLASSIFICATION_PRODUCTION,
        chain_id=8453, network="base-mainnet", addresses=dict(PRODUCTION_CONTRACTS),
        runtime_code_hashes=dict(PRODUCTION_CODE_HASHES), deploy_block=PRODUCTION_DEPLOY_BLOCK,
        observation_block=None, source=source, artifact_base_url=None,
        runtime_packet_sha256=None, resolver_signer=None, raw=dict(expected),
        production_authority=True)


def _parse_production_release(document: Mapping[str, Any]) -> Release:
    classification = _require(document, "classification")
    if not isinstance(classification, Mapping):
        raise ReleaseError("CLASSIFICATION_UNKNOWN", "production classification must be an object")
    if (classification.get("productionAllowed") is not True or
            classification.get("status") != CLASSIFICATION_PRODUCTION or
            classification.get("lane") != "rig-coretex-descriptor-v3"):
        raise ReleaseError("CLASSIFICATION_REFUSED",
                           "the rig release is not canonical descriptor-v3 production")
    _verify_production_signature(document)

    chain_id = _require(document, "chainId")
    if chain_id != 8453:
        raise ReleaseError("RELEASE_MALFORMED",
                           f"canonical production is Base chain 8453, not {chain_id!r}")
    contracts = _require(document, "contracts")
    hashes = _require(document, "codeHashes")
    if not isinstance(contracts, Mapping) or not isinstance(hashes, Mapping):
        raise ReleaseError("RELEASE_MALFORMED", "contracts/codeHashes must be objects")
    aliases = {"registry": "coreTexRegistry", "mining": "mining",
               "verifier": "coreTexVerifier"}
    addresses = {role: _require_address(contracts.get(alias), f"contracts.{alias}")
                 for role, alias in aliases.items()}
    for role, expected in PRODUCTION_CONTRACTS.items():
        if addresses[role].lower() != expected.lower():
            raise ReleaseError("PRODUCTION_IDENTITY_MISMATCH",
                               f"{role} {addresses[role]} is not canonical {expected}")
    code_hashes: Dict[str, str] = {}
    for role, alias in aliases.items():
        try:
            value = hashes.get(alias)
            if isinstance(value, str):
                value = value.removeprefix("0x")
            code_hashes[role] = fr.check_root(value, f"codeHashes.{alias}")
        except fr.FrontierError as exc:
            raise ReleaseError("RELEASE_INCOMPLETE", str(exc)) from exc

    git = _require(document, "git")
    if not isinstance(git, Mapping) or git.get("workingTreeDirty") is not False:
        raise ReleaseError("SOURCE_PIN_MISSING", "canonical release source tree is absent or dirty")
    commit = str(git.get("commit", ""))
    if len(commit) != 40:
        raise ReleaseError("SOURCE_PIN_MISSING", "git.commit must be a full commit")
    source = SourcePin(repo="https://github.com/botcoinmoney/botcoin-mining-rigs",
                       commit=commit, paths=("contracts/rig/mining",), public=True)

    deployment = _require(document, "deployment")
    deploy_block = deployment.get("firstBlock") if isinstance(deployment, Mapping) else None
    if not isinstance(deploy_block, int) or isinstance(deploy_block, bool) or deploy_block < 0:
        raise ReleaseError("RELEASE_MALFORMED", "deployment.firstBlock is invalid")
    genesis_value = _require(document, "genesisStateRoot")
    if isinstance(genesis_value, str):
        genesis_value = genesis_value.removeprefix("0x")
    genesis = fr.check_root(genesis_value, "genesisStateRoot")
    cutover = _require(document, "cutoverEpoch")
    if not isinstance(cutover, int) or isinstance(cutover, bool) or cutover < 0:
        raise ReleaseError("RELEASE_MALFORMED", "cutoverEpoch is invalid")
    if genesis != PRODUCTION_GENESIS_STATE_ROOT or cutover != PRODUCTION_CUTOVER_EPOCH:
        raise ReleaseError("PRODUCTION_IDENTITY_MISMATCH",
                           "canonical production genesis/cutover identity does not match")

    from .rig_receipt_binding import CORETEX_RECEIPT_TYPEHASH
    if str(document.get("receiptTypehashes", {}).get("coreTex", "")).lower() != \
            CORETEX_RECEIPT_TYPEHASH.lower():
        raise ReleaseError("INTERFACE_PIN_MISMATCH",
                           "canonical release CoreTex receipt typehash differs from this client")
    domain = document.get("eip712Domain", {})
    if (domain.get("chainId") != chain_id or
            str(domain.get("verifyingContract", "")).lower() != addresses["mining"].lower()):
        raise ReleaseError("INTERFACE_PIN_MISMATCH", "canonical EIP-712 domain is not the mining contract")

    return Release(
        format=PRODUCTION_RELEASE_FORMAT, classification=CLASSIFICATION_PRODUCTION,
        chain_id=chain_id, network="base-mainnet", addresses=addresses,
        runtime_code_hashes=code_hashes, deploy_block=deploy_block,
        observation_block=None, source=source, artifact_base_url=None,
        runtime_packet_sha256=None, resolver_signer=None, raw=dict(document),
        production_authority=True)


def discover(location: str, *, timeout: float = 30.0) -> Release:
    """Load a release from a path or an ``http(s)`` url.

    Both are "discovery" in the sense that matters: the validator is TOLD where the release is and
    then verifies everything the release says against the chain. There is no registry lookup that
    would make the location itself trusted, and pretending otherwise would just move the trust.
    """
    if location == DEFAULT_PRODUCTION_RELEASE_URL:
        return parse_release(_builtin_production_document())
    if location.startswith("http://") or location.startswith("https://"):
        with urllib.request.urlopen(location, timeout=timeout) as response:  # noqa: S310
            raw = response.read().decode("utf-8")
    else:
        with open(os.path.expanduser(location), "r", encoding="utf-8") as fh:
            raw = fh.read()
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ReleaseError("RELEASE_MALFORMED", f"{location} is not JSON: {exc}") from exc
    return parse_release(document)


@dataclass
class DeploymentVerification:
    ok: bool
    block: int
    #: ``role -> {"expected", "observed", "bytes", "match"}``
    contracts: Dict[str, Dict[str, Any]]
    #: Registry <-> verifier <-> mining, read back from the chain rather than assumed.
    wiring: Dict[str, Any]
    failures: List[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "block": self.block, "contracts": self.contracts,
                "wiring": self.wiring, "failures": list(self.failures)}


def verify_deployment(release: Release, rpc, *, block: int) -> DeploymentVerification:
    """Step 2. Every contract's runtime bytecode, and the wiring between them.

    THE WIRING CHECK IS NOT DECORATION. Three correct bytecodes at three addresses prove nothing
    if the registry's verifier is a fourth contract: the registry only accepts advances from the
    verifier it names, so a validator reading pins from a verifier the registry does not bind is
    reading a stranger's numbers. It is read back from the chain, in both directions, and a
    disagreement is a failure rather than a note.
    """
    from .rpc import RigViews

    deployment = release.deployment
    contracts: Dict[str, Dict[str, Any]] = {}
    failures: List[str] = []
    # Name a known-dead set BEFORE reading bytecode. Pointed at a superseded deployment, the
    # bytecode check reports "no code at address", which reads like an RPC or block-height
    # problem; saying "this is the 2026-08-03 set, superseded on 2026-08-04" sends the operator
    # to the right place.
    dead = rd.superseded_match(release.addresses)
    if dead is not None:
        date, hits = dead
        failures.append(
            f"this release names the SUPERSEDED {date} rehearsal deployment ({hits}). That "
            "deployment is dead; its EIP-712 domain separator moved with it, so every receipt "
            "digest computed against it would be wrong")
    for role in CONTRACT_ROLES:
        address = release.addresses[role]
        code = rpc.code(address, block=block)
        observed = keccak256_hex(code)
        expected = release.runtime_code_hashes[role]
        match = observed == expected
        contracts[role] = {"address": address, "expected": expected, "observed": observed,
                           "bytes": len(code), "match": match}
        if not code:
            failures.append(f"{role} {address} carries NO code at block {block}")
        elif not match:
            failures.append(
                f"{role} {address}: runtime code hash {observed} != the release's {expected}. "
                "The release is the deployment authority, so this is either a stale release or a "
                "different contract; it is never something to continue past")

    views = RigViews(rpc, deployment, block=block)
    wiring: Dict[str, Any] = {}
    try:
        wiring["registry.coreTexVerifier"] = views.core_tex_verifier()
        wiring["verifier.coreTexRegistry"] = views.verifier_registry()
        wiring["verifier.mining"] = views.verifier_mining()
        wiring["mining.coordinatorSigner"] = views.coordinator_signer()
        # THREE FIELDS IDENTIFY A REGISTRY, NOT TWO. Address and code hash are not sufficient: a
        # SUCCESSOR registry deployed from the same source has an IDENTICAL code hash, and on
        # arrival it inherits every epoch's context and answers the pin getters identically. So
        # neither the code nor the state separates a live registry from a retired one — only the
        # verifier BINDING does, and it is the third field for exactly that reason.
        wiring["registry_identity"] = {
            "address": deployment.registry.lower(),
            "code_hash": contracts["registry"]["observed"],
            "verifier_bound_registry": str(wiring["verifier.coreTexRegistry"]).lower(),
            "note": ("a successor deployed from the same source shares this code_hash and, once "
                     "it has inherited the epoch contexts, answers the pin getters identically. "
                     "`verifier_bound_registry` is the only field that distinguishes the live "
                     "registry from a retired one"),
        }
    except Exception as exc:                                  # noqa: BLE001 - reported, not raised
        failures.append(f"wiring could not be read: {exc}")
        wiring["error"] = str(exc)
    else:
        pairs = (("registry.coreTexVerifier", deployment.verifier),
                 ("verifier.coreTexRegistry", deployment.registry),
                 ("verifier.mining", deployment.mining))
        for name, expected_address in pairs:
            if str(wiring[name]).lower() != expected_address.lower():
                extra = ""
                if name == "verifier.coreTexRegistry":
                    extra = (" This is the RETIREMENT case specifically: the named registry may "
                             "carry the right code and answer every getter correctly and still "
                             "not be the one the verifier writes through. Nothing else in this "
                             "check can catch that")
                failures.append(
                    f"{name} = {wiring[name]}, the release names {expected_address}. The three "
                    f"contracts do not form one lane.{extra}")
        if release.production_authority:
            expected_signer = str(release.raw.get("coordinatorSigner") or
                                  release.raw.get("operatorSignature", {}).get("signer", ""))
            if str(wiring["mining.coordinatorSigner"]).lower() != expected_signer.lower():
                failures.append(
                    f"mining.coordinatorSigner = {wiring['mining.coordinatorSigner']}, signed "
                    f"canonical release names {expected_signer}")
        wiring["consistent"] = not failures

    return DeploymentVerification(ok=not failures, block=block, contracts=contracts,
                                  wiring=wiring, failures=failures)
