# SPDX-License-Identifier: Apache-2.0
"""Verify the preserved mined source in an explicitly composed successor baseline.

A composition has its own executable identity. The original manifest and exact source remain
part of the bridge; no miner attribution or reward is reassigned to the migration. This check
binds the unchanged local implementation and the sole M6 registration replacement. Quality and
off-mode equivalence are established by the release's recorded measurements, not by this parser.
"""
import hashlib

FORMAT = "coretex.release-baseline-bridge/v3"
KIND = "jev-m6-wrapper.v1"
ANCHOR = "    dispatch.set_override(abi2.M6, m6_pack)\n"
WRAPPER = '''    def jev_m6_pack(question, merged):

        # ---- composed judge-aware stage (jev.m6.composed.v1) ----------------
        # The local baseline's own M6 proposal, then the judge stage.  With the
        # capability unavailable this returns the proposal verbatim.
        return jev_compose(context, question, merged, m6_pack(question, merged))

    dispatch.set_override(abi2.M6, jev_m6_pack)
'''


def validate_origin(profile, original, successor, module_bytes, composition):
    if not isinstance(composition, dict) or set(composition) != {"kind", "original_module_utf8"}:
        raise ValueError("composed origin has another shape")
    if composition["kind"] != KIND or not isinstance(composition["original_module_utf8"], str):
        raise ValueError("composed origin has another recipe")
    original_source = composition["original_module_utf8"]
    original_hash = hashlib.sha256(original_source.encode("utf-8")).hexdigest()
    if original_hash != original.get("module_sha256"):
        raise ValueError("preserved mined payload does not match its original manifest")
    provenance = successor.get("source_provenance") or {}
    if provenance.get("composed_from") != {profile: original_hash}:
        raise ValueError("composed module does not name its exact mined parent")
    if "cap.judge.v1" not in successor.get("capabilities", []):
        raise ValueError("composed module does not declare its judgment capability")
    if original_source.count(ANCHOR) != 1:
        raise ValueError("mined parent has no unique M6 registration")
    transformed = original_source.replace(ANCHOR, WRAPPER)
    transformed = "\n".join(line for line in transformed.split("\n") if line not in (
        "from coretex_memory import abi2", "from coretex_memory.hooks import HookDispatch"))
    if not module_bytes.decode("utf-8").endswith(transformed):
        raise ValueError("composed module changes the preserved local implementation")
    if hashlib.sha256(module_bytes).hexdigest() != successor.get("module_sha256"):
        raise ValueError("composed executable differs from its own manifest")
