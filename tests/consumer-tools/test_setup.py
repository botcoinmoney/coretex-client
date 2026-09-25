import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('setup_helper', ROOT / 'tools/coretex-setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def test_downloaded_tools_bind_exact_public_files():
    raw_inventory = (ROOT / 'tools/release-inventory.json').read_bytes()
    assert len(raw_inventory) == setup.INVENTORY['size']
    assert hashlib.sha256(raw_inventory).hexdigest() == setup.INVENTORY['sha256']
    for name, entry in json.loads(raw_inventory)['tools'].items():
        raw = (ROOT / entry['path']).read_bytes()
        assert len(raw) == entry['size']
        assert hashlib.sha256(raw).hexdigest() == entry['sha256'], name


def test_corrupt_cached_download_is_refused(tmp_path):
    target = tmp_path / 'tool'
    target.write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='hash/size'):
        setup.download('https://example.invalid/tool', target, 4, hashlib.sha256(b'good').hexdigest())
    assert target.read_bytes() == b'corrupt'


def test_existing_files_and_profile_changes_are_preserved(tmp_path):
    inventory = {'release_root': 'a' * 64}
    unrelated = tmp_path / 'unrelated'
    unrelated.mkdir()
    (unrelated / 'memory.db').write_bytes(b'keep me')
    (unrelated / 'unrelated.txt').write_text('not an installation')
    with pytest.raises(ValueError, match='unrelated'):
        setup.prepare_directory(unrelated, 'event.schema.v1', inventory, False)
    assert (unrelated / 'memory.db').read_bytes() == b'keep me'
    owned = tmp_path / 'owned'
    owned.mkdir()
    setup.prepare_directory(owned, 'conv.pref.v1', inventory, False)
    before = (owned / 'INSTALL-STATE.json').read_bytes()
    with pytest.raises(ValueError, match='existing installation serves profile'):
        setup.prepare_directory(owned, 'event.schema.v1', inventory, False)
    assert (owned / 'INSTALL-STATE.json').read_bytes() == before


def test_failed_setup_never_publishes_completion_or_wrapper(tmp_path, monkeypatch):
    def unavailable(*args):
        raise OSError('download unavailable')
    monkeypatch.setattr(setup, 'fetch', unavailable)
    assert setup.main(['--dir', str(tmp_path / 'install')]) == 1
    assert not (tmp_path / 'install/INSTALL-COMPLETE.json').exists()
    assert not (tmp_path / 'install/bin/coretex').exists()


def test_completed_setup_refreshes_without_reinstall_or_memory_loss(tmp_path, monkeypatch):
    inventory = {'release_root': 'a' * 64, 'version': '1.1.2',
                 'profiles': ['event.schema.v1']}
    setup.prepare_directory(tmp_path, 'event.schema.v1', inventory, False)
    gen = tmp_path / 'gen' / inventory['release_root']
    setup.write_generation_pointer(tmp_path, gen, inventory, 'chain', 'event.schema.v1')
    (tmp_path / 'memory.db').write_bytes(b'preserved')
    calls = []
    def run(args, env, **kwargs):
        calls.append(args)
        return json.dumps({'ok': True, 'frontier_root': 'a' * 64})
    monkeypatch.setattr(setup, 'run', run)
    monkeypatch.setattr(setup, 'load_inventory', lambda *args: inventory)
    monkeypatch.setattr(setup, 'download', lambda *args: pytest.fail('should only sync'))
    monkeypatch.setattr(setup, 'build_generation', lambda *args: pytest.fail('should only sync'))
    args = SimpleNamespace(dir=str(tmp_path), profile=None, rollback=False, source_dir=None,
        inventory=None, upgrade=False, force=False, install_addon=None, jev=None, jev_key=None)
    assert setup.setup(args)['ok']
    assert calls == [[tmp_path / 'bin/coretex', 'sync']]
    assert (tmp_path / 'memory.db').read_bytes() == b'preserved'


def test_wrapper_handles_spaces_and_does_not_allow_config_replacement(tmp_path):
    root = tmp_path / 'install with spaces'
    (root / 'bin').mkdir(parents=True)
    wrapper = root / 'bin/coretex'
    wrapper.write_bytes(setup.wrapper())
    (root / 'CURRENT.json').write_text(json.dumps({
        'python': sys.executable, 'tools': str(root / 'gen/tools')}))
    help_result = subprocess.run([sys.executable, str(wrapper), '--help'], capture_output=True, text=True)
    assert help_result.returncode == 0 and 'serve' in help_result.stdout
    refused = subprocess.run([sys.executable, str(wrapper), 'sync', '--config=elsewhere'], capture_output=True, text=True)
    assert refused.returncode != 0 and 'own consumer.json' in refused.stderr


def test_setup_refuses_other_platform_before_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(setup.platform, 'machine', lambda: 'aarch64')
    assert setup.main(['--dir', str(tmp_path / 'install')]) == 1
    assert not (tmp_path / 'install').exists()
