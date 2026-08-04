# SPDX-License-Identifier: Apache-2.0
"""Step 1-2: discover a rehearsal release, and verify the deployed bytecode against it.

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
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from . import rig_events as rig
from .keccak256 import keccak256_hex

RELEASE_FORMAT = "coretex.rig-rehearsal-release/v1"

#: The ONLY classification this package will produce a snapshot under. Stated here as well as in
#: :mod:`.export` because it is a property of the release, not only of the output.
CLASSIFICATION_REHEARSAL = "MAINNET_REHEARSAL"
#: Named so it can be REFUSED by name. A release that claims it is rejected: this package has
#: never been through the process that would justify the claim.
CLASSIFICATION_CANONICAL = "MAINNET_CANONICAL"

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


def discover(location: str, *, timeout: float = 30.0) -> Release:
    """Load a release from a path or an ``http(s)`` url.

    Both are "discovery" in the sense that matters: the validator is TOLD where the release is and
    then verifies everything the release says against the chain. There is no registry lookup that
    would make the location itself trusted, and pretending otherwise would just move the trust.
    """
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
    except Exception as exc:                                  # noqa: BLE001 - reported, not raised
        failures.append(f"wiring could not be read: {exc}")
        wiring["error"] = str(exc)
    else:
        pairs = (("registry.coreTexVerifier", deployment.verifier),
                 ("verifier.coreTexRegistry", deployment.registry),
                 ("verifier.mining", deployment.mining))
        for name, expected_address in pairs:
            if str(wiring[name]).lower() != expected_address.lower():
                failures.append(
                    f"{name} = {wiring[name]}, the release names {expected_address}. The three "
                    "contracts do not form one lane")
        wiring["consistent"] = not failures

    return DeploymentVerification(ok=not failures, block=block, contracts=contracts,
                                  wiring=wiring, failures=failures)
