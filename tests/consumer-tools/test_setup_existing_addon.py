import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('setup_existing_addon', ROOT / 'tools/coretex-setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

@pytest.mark.parametrize('upgrading', [False, True])
def test_existing_generation_installs_addon_before_enable_without_rewriting_store(tmp_path, monkeypatch, upgrading):
    gen = tmp_path / 'gen' / ('a' * 64)
    gen.mkdir(parents=True)
    (tmp_path/'memory.db').write_bytes(b'existing canonical memories')
    pointer = dict(release_root='a'*64, dir=str(gen), version='1.1.2', authority_mode='genesis')
    inventory = dict(release_root='a'*64,version='1.1.2',profiles=['doc.tool.v1'])
    calls = []
    monkeypatch.setattr(setup,'current',lambda _:pointer)
    monkeypatch.setattr(setup,'load_inventory',lambda *a:inventory)
    monkeypatch.setattr(setup,'prepare_directory',lambda *a:None)
    monkeypatch.setattr(setup,'install_addon',lambda *a:calls.append(('install',a[0],a[2])) or {'installed':'addon.whl'})
    monkeypatch.setattr(setup,'jev_control',lambda *a:calls.append(('enable',a[1])) or {'enabled':True})
    monkeypatch.setattr(setup,'build_generation',lambda *a:pytest.fail('existing generation must stay intact'))
    args=SimpleNamespace(dir=str(tmp_path),profile='doc.tool.v1',rollback=False,source_dir=None,inventory=None,
        upgrade=upgrading,force=False,install_addon='addon.whl')
    result=setup.setup(args)
    assert result['addon']=={'installed':'addon.whl'}
    assert result['jev']=={'enabled':True}
    assert calls==[('install',gen,'addon.whl'),('enable',gen)]
    assert (tmp_path/'memory.db').read_bytes()==b'existing canonical memories'


@pytest.mark.parametrize('profile', ['doc.tool.v1', 'conv.pref.v1'])
@pytest.mark.parametrize('upgrading', [False, True])
def test_omitted_profile_keeps_existing_store_profile(tmp_path, monkeypatch, profile, upgrading):
    gen = tmp_path / 'gen' / ('a' * 64)
    gen.mkdir(parents=True)
    pointer = dict(release_root='a'*64, dir=str(gen), version='1.1.2',
                   authority_mode='genesis', profile=profile)
    (tmp_path/'CURRENT.json').write_text(json.dumps(pointer))
    (tmp_path/'INSTALL-STATE.json').write_text(json.dumps(dict(
        format=setup.INSTALL_FORMAT, profile=profile)))
    (tmp_path/'memory.db').write_bytes(b'existing memories')
    inventory = dict(release_root='a'*64, version='1.1.2',
                     profiles=['doc.tool.v1', 'conv.pref.v1', 'event.schema.v1'])
    monkeypatch.setattr(setup, 'load_inventory', lambda *a: inventory)
    monkeypatch.setattr(setup, 'install_addon', lambda *a: {'installed':'addon.whl'})
    monkeypatch.setattr(setup, 'jev_control', lambda *a: None)
    args = SimpleNamespace(dir=str(tmp_path), profile=None, rollback=False,
        source_dir=None, inventory=None, upgrade=upgrading, force=False,
        install_addon='addon.whl')
    assert setup.setup(args)['addon']['installed'] == 'addon.whl'
    assert args.profile == profile
    assert (tmp_path/'memory.db').read_bytes() == b'existing memories'
    assert setup.current(tmp_path) == pointer
    args.profile = 'event.schema.v1'
    with pytest.raises(ValueError, match='existing installation serves profile'):
        setup.setup(args)


def test_new_install_still_defaults_to_event_profile(tmp_path, monkeypatch):
    inventory = dict(release_root='a'*64, version='1.1.2', profiles=['event.schema.v1'])
    monkeypatch.setattr(setup, 'load_inventory', lambda *a: inventory)
    monkeypatch.setattr(setup, 'fresh_install', lambda prefix, inventory, args, env:
                        {'profile':args.profile})
    args = SimpleNamespace(dir=str(tmp_path), profile=None, rollback=False,
        source_dir=None, inventory=None, upgrade=False)
    assert setup.setup(args)['profile'] == 'event.schema.v1'
