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
                 signature: Optional[snap.SignatureResult],
                 release_document: Mapping[str, Any],
                 source_divergence: Mapping[str, Any],
                 deployment_verification: Mapping[str, Any],
                 receipt_chains: Mapping[int, Mapping[str, Any]],
                 admission: Mapping[str, Any],
                 unverified: Sequence[Mapping[str, Any]],
                 classification: str = CLASSIFICATION_REHEARSAL) -> Export:
    """Assemble the export. Refuses a canonical classification and an unreproduced snapshot."""
    if classification == CLASSIFICATION_CANONICAL:
        raise ExportError(
            "CLASSIFICATION_REFUSED",
            "MAINNET_CANONICAL is not something this tool can mint. A canonical snapshot is the "
            "output of a governance process, not of a command-line flag; exporting one here "
            "would launder a rehearsal into a canonical claim")
    if classification != CLASSIFICATION_REHEARSAL:
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
            "reproduction": reproduction.as_dict(),
            "transport_signature": (signature.as_dict() if signature is not None else
                                    {"meaning": "transport authentication only",
                                     "valid": False,
                                     "reason": "no resolver signature was checked in this run"}),
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
    fr.canonical_bytes(document)                     # fail fast on anything uncanonicalisable
    return Export(document)
