from __future__ import annotations

import json

import pytest

from coretex_validator.activation import ActivationError, PublicActivation
from coretex_validator import activation as activation_module


def test_activation_is_exact_canonical_pair():
    activation = PublicActivation(188, 34_567_890)
    assert PublicActivation.from_bytes(activation.canonical_bytes()) == activation
    assert json.loads(activation.canonical_bytes()) == {
        "activation": {"confirmed_block": 34_567_890, "epoch": 188},
        "format": "coretex.public-activation/v1",
    }


@pytest.mark.parametrize("epoch,block", [(0, 1), (-1, 1), (1, 0), (True, 1), (1, True)])
def test_activation_coordinates_are_positive_integers(epoch, block):
    with pytest.raises(ActivationError):
        PublicActivation(epoch, block)


def test_activation_refuses_open_or_noncanonical_records():
    good = PublicActivation(3, 9).as_document()
    for changed in (
        {**good, "release_root": "1" * 64},
        {**good, "format": "coretex.public-activation/v2"},
        {"format": good["format"], "activation": {**good["activation"], "note": "x"}},
    ):
        with pytest.raises(ActivationError):
            PublicActivation.from_document(changed)
    with pytest.raises(ActivationError):
        PublicActivation.from_bytes(json.dumps(good).encode())


def test_both_scan_floors_are_enforced():
    activation = PublicActivation(10, 20)
    assert activation.require_epoch(10) == 10
    assert activation.require_block("0x14") == 20
    with pytest.raises(ActivationError, match="BELOW_PUBLIC_ACTIVATION_EPOCH"):
        activation.require_epoch(9)
    with pytest.raises(ActivationError, match="BELOW_PUBLIC_ACTIVATION_BLOCK"):
        activation.require_log({"blockNumber": "0x13"})


def test_activation_public_url_uses_the_same_canonical_parser(monkeypatch):
    expected = PublicActivation(188, 34_567_890)

    class Response:
        headers = {"Content-Length": str(len(expected.canonical_bytes()))}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, limit):
            assert limit == activation_module.MAX_ACTIVATION_BYTES + 1
            return expected.canonical_bytes()

    monkeypatch.setattr(activation_module.urllib.request, "urlopen", lambda *a, **k: Response())
    assert PublicActivation.load(
        "https://coordinator.example/coretex/v5/activation") == expected
