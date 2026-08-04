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

import dataclasses
import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from . import rehearsal_deployment as rd
from . import rig_events as rig
from . import rotation as rot
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
    #: STEP F — the release's declaration that its ``registry`` arrived by ROTATION from an earlier
    #: one, or ``None`` when it claims no rotation. ``None`` means the continuity check has nothing
    #: to check; it is NEVER a pass, and :func:`verify_deployment` says so in the report.
    registry_rotation: Optional["rot.RotationDeclaration"] = None
    #: Where this release was loaded from, when it was loaded by :func:`discover`. Quoted in the
    #: rotation refusal so an operator is told WHICH file states the pin that did not match, rather
    #: than being left to guess which of several artifacts is in play.
    location: str = ""

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
        resolver_signer=document.get("resolver_signer"), raw=dict(document),
        # STEP F. A malformed declaration RAISES rather than degrading to "no rotation declared" —
        # an operator who wrote the block believes it is doing something.
        registry_rotation=rot.parse_rotation_declaration(
            document, registry_address=addresses["registry"]))


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
    return dataclasses.replace(parse_release(document), location=location)


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

    STEP F — AND THE FOURTH QUESTION, WHICH THE THREE-FIELD IDENTITY BELOW CANNOT ASK. Address,
    code hash and verifier binding together tell you WHICH registry is live. They do not tell you
    whether the live one has any legitimate relationship to the one whose history this validator
    already replayed: a successor deployed from the same source has an identical code hash and, on
    arrival, answers every pin getter identically. When the release DECLARES a rotation,
    :mod:`.rotation` evaluates the six continuity conditions and a failure is a hard failure here.

    That check is a CONVENTION, NOT A CHAIN GUARANTEE — ``MINING_POLICY_ADMIN`` can repoint the
    FROZEN verifier at any registry it likes. See :data:`.rotation.ROTATION_CONVENTION_LIMITATION`,
    which travels in the report on both the accept and the refuse path.
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
            # STEP F. The three fields answer WHICH registry is live. They cannot answer whether
            # the live one is a legitimate successor of the one whose history was replayed —
            # exactly because a same-source successor is indistinguishable by code and state. That
            # is `wiring["rotation"]`, below, and it is a CONVENTION rather than a chain rule.
            "continuity": ("identity is not lineage: see wiring['rotation'] for the six "
                           "registry-rotation continuity conditions, which are enforced OFF CHAIN "
                           "by refusal. " + rot.ROTATION_LIMITATION_LINE),
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
        wiring["consistent"] = not failures

    # STEP F — registry-ROTATION continuity, when the release declares one.
    #
    # THREE SHAPES, ALL STATED PLAINLY. No declaration -> ``checked: False``, which is reported as
    # NOT CHECKED and never rendered as a pass. Declared and unreadable -> a failure, because "we
    # could not check" and "we checked and it is fine" must not be the same outcome. Declared and
    # evaluated -> the verdict, carrying the limitation on BOTH branches.
    wiring["rotation"] = _verify_rotation(release, rpc, block=block, failures=failures)

    return DeploymentVerification(ok=not failures, block=block, contracts=contracts,
                                  wiring=wiring, failures=failures)


def _verify_rotation(release: Release, rpc, *, block: int,
                     failures: List[str]) -> Dict[str, Any]:
    declaration = release.registry_rotation
    if declaration is None:
        return {
            "checked": False,
            "reason": ("the release declares no registry_rotation, so there was nothing to check. "
                       "THIS IS NOT A PASS — no continuity condition was evaluated"),
            "limitation": dict(rot.ROTATION_CONVENTION_LIMITATION),
        }
    try:
        observation = rot.read_rotation_observation(
            rpc,
            incumbent_registry=declaration.predecessor_registry,
            successor_registry=release.addresses["registry"],
            mining=release.addresses["mining"],
            verifier=release.addresses["verifier"],
            rotation_block=declaration.rotation_block,
            observation_block=block,
            approved_registry_code_hash=release.runtime_code_hashes.get("registry"),
            approved_release_path=release.location or "the release artifact")
    except Exception as exc:                                  # noqa: BLE001 - reported, not raised
        failures.append(
            f"the release DECLARES that registry {release.addresses['registry']} arrived by "
            f"rotation from {declaration.predecessor_registry} at block "
            f"{declaration.rotation_block}, and that rotation could not be read from the chain: "
            f"{exc}. An unverifiable rotation is refused rather than assumed continuous. "
            f"{rot.ROTATION_LIMITATION_LINE}")
        return {"checked": False, "error": str(exc),
                "limitation": dict(rot.ROTATION_CONVENTION_LIMITATION)}

    verdict = rot.evaluate_rotation_continuity(observation)
    if not verdict.accepted:
        for refusal in verdict.refusals:
            failures.append(
                f"registry rotation {declaration.predecessor_registry} -> "
                f"{release.addresses['registry']}: {refusal.code}: {refusal.checked} — expected "
                f"{refusal.expected}, observed {refusal.observed}. {refusal.reason}")
    report = verdict.as_dict()
    report["checked"] = True
    report["predecessor_registry"] = declaration.predecessor_registry
    report["rotation_block"] = declaration.rotation_block
    report["summary"] = rot.format_rotation_verdict(observation, verdict)
    return report
