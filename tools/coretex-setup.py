#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install and sync CoreTex using public downloads. Linux amd64, Python 3.8+ to start."""
import argparse
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

RELEASE_ROOT = 'fb1a0c66ce641b9df4ca1a9c630357a0057d7ea4159c910c4a09776ed0749bec'
SOURCE = 'https://raw.githubusercontent.com/botcoinmoney/coretex-client/bcb6b81b40fe16102faaab56af57e3f7b05fee69/'
FILES = {
    'coretex-bootstrap.py': ('tools/coretex-bootstrap.py', 12980, 'a8d9e136de77f6b49d640410f1589e84cd53b4d06db25e9a997fa94a22b3c12d'),
    'coretex-sidecar.py': ('tools/coretex-sidecar.py', 2036, 'e65f6dca3472d461910a1c971d0c4058a7428988bbe6601615801f4cefe5f718'),
    'coretex_consumer-0.1.0-py3-none-any.whl': ('consumer-artifacts/coretex_consumer-0.1.0-py3-none-any.whl', 19476, '37dfad0ac9c1a2837124759751d72e5e26ce9397ba7d0ffaeb4ce5b53ae48275'),
}
UV_URL = 'https://files.pythonhosted.org/packages/13/fc/e0da45ee179367dcc1e1040ad00ed8a99b78355d43024b0b5fc2edf5c389/uv-0.8.15-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
UV_SHA = '07765f99fd5fd3b257d7e210e8d0844c0a8fd111612e31fcca66a85656cc728e'
PROFILES = ('event.schema.v1', 'conv.pref.v1', 'doc.tool.v1')


def atomic(path, data, mode=0o600, replace=True):
    fd, name = tempfile.mkstemp(prefix='.setup-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        if replace:
            os.replace(name, path)
        else:
            os.link(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('setup download redirect refused')


def download(url, path, size, digest):
    if path.is_symlink():
        raise ValueError('linked download refused')
    data = path.read_bytes() if path.exists() else None
    if data is None:
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=120) as response:
            data = response.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('setup download hash/size mismatch: ' + path.name)
    if not path.exists():
        atomic(path, data)
    return data


def run(args, env, *, capture=False):
    result = subprocess.run([str(a) for a in args], env=env, check=True, text=True,
                            stdout=subprocess.PIPE if capture else sys.stderr, timeout=1200)
    return result.stdout


def wrapper(prefix):
    # No shell interpolation, PATH edits or replacement of an existing global command.
    return ('''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
PYTHON = str(ROOT / '.venv/bin/python')
args = sys.argv[1:]
if not args or args[0] in ('-h', '--help'):
    print('CoreTex: sync | status | ingest TEXT | context QUERY | prewarm | serve [--port 18761]')
    raise SystemExit(0)
command, rest = args[0], args[1:]
if any(a == '--config' or a.startswith('--config=') for a in rest):
    raise SystemExit('This installation uses its own consumer.json; use a separate installation for another store.')
config = ['--config', str(ROOT / 'consumer.json')]
if command == 'serve':
    argv = [PYTHON, '-I', str(ROOT / 'tools/coretex-sidecar.py'), *config, *rest]
else:
    argv = [PYTHON, '-I', '-m', 'coretex_consumer.cli', command, *config, *rest]
os.execv(PYTHON, argv)
''').encode()


def prepare_directory(prefix, profile):
    identity = {'format': 'coretex.consumer-install/v1', 'release_root': RELEASE_ROOT, 'profile': profile}
    if prefix.is_symlink():
        raise ValueError('installation directory must not be a symlink')
    if prefix.exists() and any(prefix.iterdir()) and not (prefix / 'INSTALL-STATE.json').is_file():
        raise ValueError('directory already contains unrelated files; choose a new --dir')
    prefix.mkdir(parents=True, exist_ok=True)
    marker = prefix / 'INSTALL-STATE.json'
    if marker.exists():
        if marker.is_symlink() or json.loads(marker.read_bytes()) != identity:
            raise ValueError('existing installation has another profile/release; choose a new --dir')
    else:
        try:
            atomic(marker, (json.dumps(identity, sort_keys=True) + '\n').encode(), replace=False)
        except FileExistsError:
            if json.loads(marker.read_bytes()) != identity:
                raise ValueError('another setup selected a different profile/release')
    return identity


def setup(prefix, profile):
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise ValueError('this setup helper supports Linux amd64; use the manual guide for other platforms')
    prefix = Path(prefix).expanduser().absolute()
    identity = prepare_directory(prefix, profile)
    descriptor = os.open(prefix / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        tools = prefix / 'tools'
        tools.mkdir(exist_ok=True)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UV_', 'PIP_', 'PYTHON')) and key != 'VIRTUAL_ENV'}
        env.update(UV_PYTHON_INSTALL_DIR=str(prefix / '.python'), UV_CACHE_DIR=str(prefix / '.cache'),
                   UV_NO_CONFIG='1', UV_NO_PROGRESS='1')
        if (prefix / 'INSTALL-COMPLETE.json').exists():
            print('Refresh current confirmed modules; retain existing memories', file=sys.stderr, flush=True)
            result = json.loads(run([prefix / 'bin/coretex', 'sync'], env, capture=True))
            return dict(result, command=str(prefix / 'bin/coretex'))
        print('1/4 Download verified setup tools', file=sys.stderr, flush=True)
        for name, (source, size, digest) in FILES.items():
            download(SOURCE + source, tools / name, size, digest)
        uv_wheel = download(UV_URL, tools / 'uv.whl', 21009338, UV_SHA)
        with zipfile.ZipFile(io.BytesIO(uv_wheel)) as archive:
            atomic(tools / 'uv', archive.read('uv-0.8.15.data/scripts/uv'), 0o700)
        print('2/4 Prepare private Python 3.10 and verify public release', file=sys.stderr, flush=True)
        if not (prefix / '.venv/bin/python').exists():
            run([tools / 'uv', 'venv', '--python', '3.10', prefix / '.venv'], env)
        python = prefix / '.venv/bin/python'
        release_dir = prefix / 'release'
        if not release_dir.exists():
            run([python, '-I', tools / 'coretex-bootstrap.py', '--out', release_dir,
                 '--expected-release-root', RELEASE_ROOT], env)
        spec = importlib.util.spec_from_file_location('coretex_setup_bootstrap', tools / 'coretex-bootstrap.py')
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        release = bootstrap.parse((release_dir / 'RELEASE.json').read_bytes())
        if release['release_root'] != RELEASE_ROOT:
            raise ValueError('cached release differs from setup release')
        bootstrap.verify_sealed(release_dir, release)
        # Re-hash the extracted dependency files as well as the sealed tar on a resumed install.
        inventory = bootstrap.parse((release_dir / 'wheelhouse/CPU-RUNTIME.json').read_bytes())
        with tempfile.TemporaryDirectory(prefix='.inventory-', dir=prefix) as check:
            # Use the same bounded extractor on the verified archive to authenticate the inventory.
            scratch = Path(check)
            (scratch / 'artifacts').mkdir()
            binding = release['artifacts']['numeric_runtime_amd64']
            os.symlink(release_dir / binding['path'], scratch / binding['path'])
            bootstrap.numeric_wheels(scratch, release)
            if inventory != bootstrap.parse((scratch / 'wheelhouse/CPU-RUNTIME.json').read_bytes()):
                raise ValueError('extracted numeric inventory differs')
            for name, entry in inventory['wheels'].items():
                if not bootstrap.exact((release_dir / 'wheelhouse' / bootstrap.relative(name)).read_bytes(),
                                       entry['bytes'], entry['sha256']):
                    raise ValueError('extracted numeric wheel differs: ' + name)
        print('3/4 Install exact runtime, adapter and current-state client', file=sys.stderr, flush=True)
        wheels = [release_dir / release['artifacts'][key]['path'] for key in
                  ('runtime_wheel', 'adapter_wheel', 'wasmtime_amd64_wheel')]
        wheels += [release_dir / 'wheelhouse' / name for name in sorted(inventory['wheels'])]
        wheels += [tools / 'coretex_consumer-0.1.0-py3-none-any.whl']
        run([tools / 'uv', 'pip', 'install', '--python', python, '--no-index', '--no-deps', '--reinstall', *wheels], env)
        run([tools / 'uv', 'pip', 'check', '--python', python], env)
        print('4/4 Sync public current state and prepare memory store', file=sys.stderr, flush=True)
        command = [python, '-I', '-m', 'coretex_consumer.cli', 'sync', '--config', prefix / 'consumer.json']
        if not (prefix / 'consumer.json').exists():
            command += ['--release-dir', release_dir, '--expected-release-root', RELEASE_ROOT,
                        '--out', prefix / 'current', '--store', prefix / 'memory.db', '--profile', profile]
        synced = json.loads(run(command, env, capture=True))
        check = '''import json,sys
from coretex_consumer.current_state import CurrentState, authority_from_current
state = CurrentState.load(sys.argv[2])
authority = authority_from_current(sys.argv[1], state)
with authority.open_memory(sys.argv[3], sys.argv[4]) as memory:
    memory.memory.prewarm(progress=lambda done,total: print(f'vector index {done}/{total}', file=sys.stderr))
    health = memory.health()
    assert health['ok'] and health['serving_module'].get('module_root'), health
    print(json.dumps(health))
'''
        health = json.loads(run([python, '-I', '-c', check, release_dir, synced['snapshot'],
                                 profile, prefix / 'memory.db'], env, capture=True))
        (prefix / 'bin').mkdir(exist_ok=True)
        atomic(prefix / 'bin/coretex', wrapper(prefix), 0o700)
        complete = dict(identity, frontier_root=synced['frontier_root'], epoch=synced['epoch'],
                        module_root=health['serving_module']['module_root'])
        atomic(prefix / 'INSTALL-COMPLETE.json', (json.dumps(complete, sort_keys=True) + '\n').encode())
        return dict(ok=True, command=str(prefix / 'bin/coretex'), config=str(prefix / 'consumer.json'),
                    profile=profile, epoch=synced['epoch'], frontier_root=synced['frontier_root'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', default='./coretex', help='private installation directory (default: ./coretex)')
    parser.add_argument('--profile', choices=PROFILES, default='event.schema.v1')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(setup(args.dir, args.profile), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'detail': str(exc),
                          'retry': 'Fix the reported issue and rerun the same command; local data is retained.'}),
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
