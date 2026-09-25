"""Run the installed release reader against the actual composed release, when supplied."""
import json
import os
from pathlib import Path

import pytest

from coretex_validator import baseline_composition, release


def test_reader_loads_actual_composed_genesis():
    name = os.environ.get('CORETEX_TEST_COMPOSED_RELEASE')
    if not name:
        pytest.skip('provide the built release for this installed-artifact check')
    root = Path(name)
    loaded = release.load(str(root))
    document = json.loads((root / 'RELEASE.json').read_text())
    bridge = json.loads((root / 'objects/baseline-bridge.json').read_text())
    assert loaded.release_root == document['release_root']
    assert bridge['format'] == baseline_composition.FORMAT
    assert bridge['credits'] == 0
    for profile, row in bridge['modules'].items():
        directory = (root / document['genesis']['profile_releases'][profile]['path']).parent
        manifest = json.loads((directory / 'manifest.json').read_text())
        baseline_composition.validate_origin(profile, row['original_manifest'], manifest,
                                              (directory / 'module.py').read_bytes(),
                                              row['composition'])
        assert 'cap.judge.v1' in manifest['capabilities']
