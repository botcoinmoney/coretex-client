# SPDX-License-Identifier: Apache-2.0
"""Step 8: export the verified snapshot for portable CoreTex activation.

WHAT AN EXPORT IS. A single self-contained document that another machine can activate CoreTex
from without repeating the chain scan: the reproduced snapshot, the artifact roots it depends on,
the law that applied, and — crucially — the RECORD OF WHAT WAS ACTUALLY CHECKED, including what
was not.

THE CLASSIFICATION IS ENFORCED HERE, NOT CONVENTIONAL. Every export this package produces is
``MAINNET_REHEARSAL``. :func:`build_export` refuses to emit ``MAINNET_CANONICAL`` — not by leaving
it unimplemented, but by raising on it — because the difference between the two is a governance
process, and a governance process must not be satisfiable by passing a string to a function.

AN EXPORT IS NEVER "CLEAN" BY OMISSION. :attr:`Export.unverified` carries every check that did not
complete: a BACKLOGged deterministic admission because the private benchmark trees are not on this
host, an unavailable policy schedule, an unsealed epoch in the lineage walk. A consumer decides
what it can live with; a consumer that is handed a document with the gaps deleted cannot.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import frontier as fr
from . import snapshot as snap

EXPORT_FORMAT = "coretex.rig-activation-export/v1"
CLASSIFICATION_REHEARSAL = "MAINNET_REHEARSAL"
CLASSIFICATION_CANONICAL = "MAINNET_CANONICAL"
CLASSIFICATION_PRODUCTION = "CANONICAL_PRODUCTION"


def drop_nulls(value: Any) -> Any:
    """Recursively remove ``None`` values. A BOUNDARY GUARD, not a licence to be sloppy.

    WHY THIS EXISTS, STATED PLAINLY BECAUSE IT IS A CONCESSION. The canonical grammar refuses
    ``null`` by design — absence is expressed by absence, so that "I do not have this" and "this
    field does not exist" cannot become the same bytes. Every report dict in this package is
    supposed to be built with that in mind.

    Three times now one was not, and each time the failure landed at SERIALISATION: after the
    chain reads, after a twenty-minute deterministic admission, after everything expensive had
    already succeeded. A dict assembled across a dozen call sites will eventually carry a ``None``
    somebody defaulted, and discovering that at the end of the most costly operation in the
    package is the worst possible trade.

    So the report is swept HERE, at the one boundary where a report becomes canonical bytes. This
    does not make the rule optional upstream — a value that should have been present and is
    ``None`` is still a bug, and dropping it hides that. It makes the failure mode proportionate:
    a missing optional field is omitted, rather than costing a run.
    """
    if isinstance(value, Mapping):
        return {k: drop_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [drop_nulls(v) for v in value if v is not None]
    return value


class ExportError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass
class Export:
    document: Dict[str, Any]

    @property
    def unverified(self) -> List[Dict[str, Any]]:
        return list(self.document.get("unverified", ()))

    def canonical_bytes(self) -> bytes:
        return fr.canonical_bytes(self.document)

    def root(self) -> str:
        """The export's own content address. What a consumer pins."""
        return fr.sha256_hex(self.canonical_bytes())

    def write(self, path: str) -> str:
        with open(path, "wb") as fh:
            fh.write(self.canonical_bytes())
            fh.write(b"\n")
        return self.root()


def build_export(*, snapshot_payload: Mapping[str, Any],
                 reproduction: snap.ReproductionResult,
                 release_document: Mapping[str, Any],
                 source_divergence: Mapping[str, Any],
                 deployment_verification: Mapping[str, Any],
                 receipt_chains: Mapping[int, Mapping[str, Any]],
                 admission: Mapping[str, Any],
                 unverified: Sequence[Mapping[str, Any]],
                 classification: str = CLASSIFICATION_REHEARSAL) -> Export:
    """Assemble an export from a reproduced snapshot.

    Production cannot be selected by a string: the supplied release document must itself pass
    the canonical release signature and classification checks.
    """
    if classification == CLASSIFICATION_CANONICAL:
        raise ExportError(
            "CLASSIFICATION_REFUSED",
            "MAINNET_CANONICAL is not something this tool can mint. A canonical snapshot is the "
            "output of a governance process, not of a command-line flag; exporting one here "
            "would launder a rehearsal into a canonical claim")
    if classification == CLASSIFICATION_PRODUCTION:
        from . import release as rel
        try:
            parsed = rel.parse_release(release_document)
        except rel.ReleaseError as exc:
            raise ExportError("PRODUCTION_AUTHORITY_INVALID", exc.message) from exc
        if not parsed.production_authority:
            raise ExportError("PRODUCTION_AUTHORITY_INVALID",
                              "production export requires an authenticated canonical release")
    elif classification != CLASSIFICATION_REHEARSAL:
        raise ExportError("CLASSIFICATION_UNKNOWN", f"unsupported classification {classification!r}")
    if not reproduction.reproduced:
        raise ExportError(
            "SNAPSHOT_NOT_REPRODUCED",
            "the snapshot was not reproduced byte-for-byte from chain state, so there is nothing "
            "verified to export. A valid signature does not substitute — see snapshot.reproduce")

    document: Dict[str, Any] = {
        "format": EXPORT_FORMAT,
        "classification": classification,
        "snapshot": dict(snapshot_payload),
        "snapshot_sha256": reproduction.reconstructed_hash,
        "verification": {
            # NO SIGNATURE FIELD, and its absence is the design rather than an omission.
            #
            # A downloaded snapshot is a CACHE. What makes it true is that this package
            # independently reconstructs identical canonical bytes from the pinned chain,
            # contracts, finalized block, events, calldata and content-addressed artifacts — not
            # that somebody signed it. Carrying a `transport_signature` verdict beside the
            # reproduction invited exactly the wrong reading: that a valid signature was a second,
            # alternative reason to believe the payload. It was never that, and now it is not
            # there to be misread.
            #
            # The ONE signature this package still verifies is the coordinator's EIP-712 mining
            # receipt, checked against `mining.coordinatorSigner()` in the §7.2 join. That one is
            # enforced by a deployed contract, so it is a fact about the chain rather than about
            # a publisher.
            "reproduction": reproduction.as_dict(),
            "authority": (
                "reconstruction equality from chain truth. This export attests that the canonical "
                "bytes were rebuilt independently and matched; it makes no claim about who "
                "transmitted them and requires no key to check"),
            "deployment": dict(deployment_verification),
            "receipt_chains": {str(k): dict(v) for k, v in sorted(receipt_chains.items())},
            "deterministic_admission": dict(admission),
        },
        "authorities": dict(source_divergence),
        # OMITTED, NEVER NULL. The canonical value grammar refuses `null` on purpose: a field
        # is either present with a well-typed value or absent, and encoding "I do not have this"
        # as a present null makes the two indistinguishable to anyone re-deriving the bytes.
        "release": {key: release_document[key]
                    for key in ("format", "classification", "chain_id", "addresses",
                                "runtime_code_hashes", "source", "runtime_packet_sha256")
                    if release_document.get(key) is not None},
        "unverified": [dict(item) for item in unverified],
    }
    # Sweep, THEN canonicalise. The sweep is the boundary guard above; the canonicalisation is
    # still a hard check, so anything the grammar refuses for a reason OTHER than nullity — a
    # float, a non-string key — fails here exactly as before.
    document = drop_nulls(document)
    fr.canonical_bytes(document)
    return Export(document)
