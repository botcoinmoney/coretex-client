from __future__ import annotations

import pytest

from coretex_validator import rig_events as rig


ARTIFACT = "1" * 64
PARENT = "2" * 64
CHILD = "3" * 64


def descriptor() -> bytes:
    return rig.encode_transition_descriptor(
        patch_artifact_hash=ARTIFACT, parent_state_root=PARENT, new_state_root=CHILD)


def test_descriptor_v3_exact_layout_and_domain_hash():
    raw = descriptor()
    assert len(raw) == 97 and raw[0] == 0x21
    decoded = rig.decode_transition_descriptor(
        raw,
        expected_patch_hash=rig.transition_descriptor_hash(raw),
        parent_state_root=PARENT,
        new_state_root=CHILD,
        transition_format_version=0x21,
    )
    assert decoded.patch_artifact_hash == ARTIFACT
    assert decoded.parent_state_root == PARENT
    assert decoded.new_state_root == CHILD


@pytest.mark.parametrize("mutation,code", [
    (lambda raw: bytes([0x22]) + raw[1:], rig.DESCRIPTOR_VERSION_UNSUPPORTED),
    (lambda raw: raw[:1] + bytes(32) + raw[33:], rig.DESCRIPTOR_ARTIFACT_HASH_ZERO),
    (lambda raw: raw[:-1], rig.DESCRIPTOR_LENGTH_INVALID),
    (lambda raw: raw + b"\0", rig.DESCRIPTOR_LENGTH_INVALID),
])
def test_descriptor_current_shape_negative_controls(mutation, code):
    with pytest.raises(rig.TransitionDescriptorError) as caught:
        rig.decode_transition_descriptor(mutation(descriptor()))
    assert caught.value.code == code


def test_descriptor_refuses_wrong_addressed_edge():
    raw = descriptor()
    cases = (
        ({"expected_patch_hash": "4" * 64}, rig.DESCRIPTOR_HASH_MISMATCH),
        ({"parent_state_root": "4" * 64}, rig.DESCRIPTOR_PARENT_MISMATCH),
        ({"new_state_root": "4" * 64}, rig.DESCRIPTOR_NEW_ROOT_MISMATCH),
    )
    for kwargs, code in cases:
        with pytest.raises(rig.TransitionDescriptorError) as caught:
            rig.decode_transition_descriptor(raw, **kwargs)
        assert caught.value.code == code

