#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install, upgrade, roll back and enable CoreTex. Linux amd64, Python 3.8+ to start.

This installer carries exactly ONE literal about the product: the pin of the generated release
inventory below. The version, the release root, the client source commit, every wheel name and
every digest are read from that inventory and re-checked against the downloaded bytes, so a new
release is published by regenerating the inventory (``tools/make-release-inventory.py``) rather
than by editing this file, and a digest that does not match is refused.

An installation is GENERATIONAL. The tools, the private environment and the verified release of
one release root live under ``gen/<release_root>/``; the memory store, its configuration and the
optional-addon state live at the top and are never rewritten by an upgrade. ``--upgrade``
therefore updates the tools and keeps the memories, with no re-ingestion, and ``--rollback``
re-points the launcher at the previous generation against the same store.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

INVENTORY = {'name': 'release-inventory.json',
             'url': 'https://agentmoney.net/coretex-release-inventory.json',
             'size': 4258,
             'sha256': '6dbe6ffdfbca1d2b81e8f599db174a534d9a7209e7f7aad64bc6220806b1755a'}
INVENTORY_FORMAT = 'coretex.consumer-release-inventory/v1'
PINNED_FORMAT = 'coretex.consumer-pinned/v1'
INSTALL_FORMAT = 'coretex.consumer-install/v2'
MAX_INVENTORY = 1024 * 1024


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


def fetch(url, size, timeout=120):
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as response:
        return response.read(size + 1)


def digest_of(data):
    return hashlib.sha256(data).hexdigest()


def check(data, size, sha256, what):
    if len(data) != size or digest_of(data) != sha256:
        raise ValueError('hash/size mismatch: ' + what)
    return data


def download(url, path, size, sha256, *, source=None):
    """Verified materialization: a local source copy, an existing file, or the network."""
    if path.is_symlink():
        raise ValueError('linked download refused')
    data = None
    if path.exists():
        data = path.read_bytes()
    elif source is not None and Path(source).is_file():
        data = Path(source).read_bytes()
    if data is None:
        data = fetch(url, size)
    check(data, size, sha256, path.name)
    if not path.exists():
        atomic(path, data)
    return data


def run(args, env, *, capture=False, timeout=1800):
    result = subprocess.run([str(a) for a in args], env=env, check=True, text=True,
                            stdout=subprocess.PIPE if capture else sys.stderr, timeout=timeout)
    return result.stdout


def parse(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


# --------------------------------------------------------------------------- #
# the generated inventory: the only thing this installer is pinned to
# --------------------------------------------------------------------------- #
def load_inventory(cache_path, source_dir=None, override=None):
    """Resolve the inventory this installer is pinned to.

    A CACHED inventory is only usable while it still matches the pin: an upgrade runs a newer
    installer with a newer pin, so the previous release's cached copy must not shadow it. The
    cache is always refreshed to whatever was resolved, so the generation built from it and the
    file left behind can never disagree.
    """
    if override is not None:
        # An explicitly supplied inventory is the caller's own trust decision (air-gapped
        # installs, pre-release verification); the artifact digests inside it are still enforced.
        raw = Path(override).read_bytes()
        if len(raw) > MAX_INVENTORY:
            raise ValueError('release inventory is too large')
    else:
        raw = None
        for candidate in (cache_path,
                          None if source_dir is None else Path(source_dir) / INVENTORY['name']):
            if candidate is None or not Path(candidate).is_file():
                continue
            data = Path(candidate).read_bytes()
            if len(data) == INVENTORY['size'] and digest_of(data) == INVENTORY['sha256']:
                raw = data
                break
        if raw is None:
            raw = check(fetch(INVENTORY['url'], INVENTORY['size']), INVENTORY['size'],
                        INVENTORY['sha256'], INVENTORY['name'])
    atomic(cache_path, raw)
    inventory = parse(raw)
    if inventory.get('format') != INVENTORY_FORMAT:
        raise ValueError('unsupported release inventory format')
    for field in ('version', 'release_root', 'source', 'tools', 'install', 'verify',
                  'support', 'uv', 'profiles'):
        if field not in inventory:
            raise ValueError('release inventory is missing ' + field)
    return inventory


def declared(inventory, key):
    """Every artifact the inventory declares, by artifact name."""
    merged = {}
    for section in ('install', 'verify', 'support'):
        merged.update(inventory[section])
    return merged[key]


# --------------------------------------------------------------------------- #
# installation layout
# --------------------------------------------------------------------------- #
def generation_dir(prefix, release_root):
    return prefix / 'gen' / release_root


def read_json(path):
    try:
        return parse(Path(path).read_bytes())
    except (OSError, ValueError):
        return None


def current(prefix):
    return read_json(prefix / 'CURRENT.json')


def legacy_generation(prefix):
    """A pre-generational install (1.1.0/1.1.1 layout): tools, .venv and release at the top."""
    marker = read_json(prefix / 'INSTALL-STATE.json')
    if marker is None or not (prefix / '.venv/bin/python').exists():
        return None
    if (prefix / 'CURRENT.json').exists():
        return None
    return {'generation': 'legacy', 'release_root': marker.get('release_root'),
            'version': marker.get('version'), 'dir': str(prefix),
            'python': str(prefix / '.venv/bin/python'), 'tools': str(prefix / 'tools'),
            'release': str(prefix / 'release'), 'authority_mode': 'chain'}


def history(prefix):
    value = read_json(prefix / 'UPGRADE-HISTORY.json')
    if not isinstance(value, dict) or not isinstance(value.get('entries'), list):
        return {'format': 'coretex.consumer-upgrade-history/v1', 'entries': []}
    return value


def record_history(prefix, entry):
    value = history(prefix)
    value['entries'].append(entry)
    atomic(prefix / 'UPGRADE-HISTORY.json',
           (json.dumps(value, sort_keys=True, indent=1) + '\n').encode(), 0o600)


# --------------------------------------------------------------------------- #
# the launcher
# --------------------------------------------------------------------------- #
def wrapper():
    # No shell interpolation, PATH edits or replacement of an existing global command.
    # Every verb runs on the generation CURRENT.json names, under the one Jev decision this
    # installation holds, so a serving process can never disagree with `coretex jev status`.
    return ('''#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
HELP = """CoreTex: sync | status | ingest TEXT | context QUERY | prewarm | serve [--port N]
            setup --jev-key - | jev enable|disable|status | jev cache stats|purge
            upgrade [--offline --source-dir DIR] | rollback | which"""
try:
    CURRENT = json.loads((ROOT / 'CURRENT.json').read_bytes())
except OSError:
    raise SystemExit('this installation has no CURRENT.json; rerun coretex-setup.py')
PYTHON = CURRENT['python']
TOOLS = Path(CURRENT['tools'])
CONFIG = str(ROOT / 'consumer.json')
MODE = CURRENT.get('authority_mode', 'chain')

args = sys.argv[1:]
if not args or args[0] in ('-h', '--help'):
    print(HELP)
    raise SystemExit(0)
command, rest = args[0], args[1:]
if any(a == '--config' or a.startswith('--config=') for a in rest):
    raise SystemExit('This installation uses its own consumer.json; use a separate installation for another store.')

spec = importlib.util.spec_from_file_location('coretex_jevctl', TOOLS / 'coretex-jevctl.py')
jevctl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jevctl)
env = dict(os.environ)
env.update(jevctl.serving_env(ROOT))

if command == 'which':
    print(json.dumps(dict(CURRENT, install=str(ROOT), config=CONFIG,
                          jev=jevctl.effective(ROOT)), sort_keys=True, indent=1))
    raise SystemExit(0)
if command == 'serve':
    argv = [PYTHON, '-I', str(TOOLS / 'coretex-sidecar.py'), '--config', CONFIG,
            '--prefix', str(ROOT), *rest]
elif command == 'setup':
    key = [a for a in rest if a not in ('--jev-key',)]
    argv = [PYTHON, '-I', str(TOOLS / 'coretex-jevctl.py'), '--prefix', str(ROOT),
            '--config', CONFIG, 'enable'] + (['--key', key[0]] if key else ['--key', '-'])
elif command == 'jev' and rest[:1] in (['enable'], ['disable'], ['status']):
    argv = [PYTHON, '-I', str(TOOLS / 'coretex-jevctl.py'), '--prefix', str(ROOT),
            '--config', CONFIG, *rest]
elif command == 'jev':
    argv = [PYTHON, '-I', '-m', 'coretex_memory.cli', 'jev', *rest]
elif command in ('upgrade', 'rollback'):
    argv = [PYTHON, '-I', str(TOOLS / 'coretex-setup.py'), '--dir', str(ROOT),
            '--' + command, *rest]
elif MODE == 'chain':
    argv = [PYTHON, '-I', '-m', 'coretex_consumer.cli', command, '--config', CONFIG, *rest]
else:
    if command == 'sync':
        raise SystemExit('this installation is pinned (%s authority); it does not read the chain'
                         % MODE)
    argv = [PYTHON, '-I', str(TOOLS / 'coretex-run.py'), command, *rest, '--config', CONFIG]
os.execve(PYTHON, argv, env)
''').encode()


# --------------------------------------------------------------------------- #
# verified release materialization
# --------------------------------------------------------------------------- #
def load_bootstrap(tools):
    spec = importlib.util.spec_from_file_location('coretex_setup_bootstrap',
                                                  tools / 'coretex-bootstrap.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def place_release(release_dir, inventory, tools, python, env, source_dir):
    """Materialize the release, offline from a verified local copy or online via bootstrap."""
    if release_dir.exists():
        return
    if source_dir is not None:
        source = Path(source_dir) / 'release'
        if not (source / 'RELEASE.json').is_file():
            raise ValueError('offline source has no release/RELEASE.json')
        shutil.copytree(source, release_dir, symlinks=False)
        return
    run([python, '-I', tools / 'coretex-bootstrap.py', '--out', release_dir,
         '--expected-release-root', inventory['release_root']], env)


def verify_release(release_dir, inventory, prefix, bootstrap):
    """Release identity, the sealed verifier, the numeric inventory, and — new — every artifact
    digest against the generated inventory this installer was pinned to."""
    release = bootstrap.parse((release_dir / 'RELEASE.json').read_bytes())
    if release['release_root'] != inventory['release_root']:
        raise ValueError('release differs from the pinned inventory release root')
    if release.get('version') != inventory['version']:
        raise ValueError('release version differs from the pinned inventory version')
    for section in ('install', 'verify', 'support'):
        for name, entry in inventory[section].items():
            binding = release['artifacts'].get(name)
            if binding is None:
                raise ValueError('release is missing inventory artifact ' + name)
            if binding['sha256'] != entry['sha256'] or binding['size'] != entry['size'] \
                    or binding['path'] != entry['path']:
                raise ValueError('inventory/release artifact mismatch: ' + name)
            raw = (release_dir / bootstrap.relative(entry['path'])).read_bytes()
            check(raw, entry['size'], entry['sha256'], name)
    bootstrap.verify_sealed(release_dir, release)
    if not (release_dir / 'wheelhouse').exists():
        bootstrap.numeric_wheels(release_dir, release)
    numeric = bootstrap.parse((release_dir / 'wheelhouse/CPU-RUNTIME.json').read_bytes())
    with tempfile.TemporaryDirectory(prefix='.inventory-', dir=prefix) as work:
        # Re-extract with the same bounded extractor to authenticate the cached inventory.
        scratch = Path(work)
        (scratch / 'artifacts').mkdir()
        binding = release['artifacts']['numeric_runtime_amd64']
        os.symlink(release_dir / binding['path'], scratch / binding['path'])
        bootstrap.numeric_wheels(scratch, release)
        if numeric != bootstrap.parse((scratch / 'wheelhouse/CPU-RUNTIME.json').read_bytes()):
            raise ValueError('extracted numeric inventory differs')
    for name, entry in numeric['wheels'].items():
        if not bootstrap.exact((release_dir / 'wheelhouse' / bootstrap.relative(name)).read_bytes(),
                               entry['bytes'], entry['sha256']):
            raise ValueError('extracted numeric wheel differs: ' + name)
    return release, numeric


def install_wheels(gen, inventory, numeric, tools, python, env):
    release_dir = gen / 'release'
    wheels = [release_dir / inventory['install'][key]['path']
              for key in ('runtime_wheel', 'adapter_wheel', 'wasmtime_amd64_wheel')]
    wheels += [release_dir / 'wheelhouse' / name for name in sorted(numeric['wheels'])]
    wheels += [tools / inventory['tools_consumer_wheel']]
    run([tools / 'uv', 'pip', 'install', '--python', python, '--no-index', '--no-deps',
         '--reinstall', *wheels], env)
    run([tools / 'uv', 'pip', 'check', '--python', python], env)


def install_extra_wheels(gen, paths, env):
    """Wheels installed AFTER the release's own, for verifying a candidate fix before it is cut
    into a release. A normal installation passes none, and each one is recorded by digest in
    CURRENT.json so `coretex which` always shows that this is not a pure release installation."""
    recorded = []
    for path in paths or ():
        source = Path(path).resolve()
        raw = source.read_bytes()
        staged = gen / 'tools' / source.name
        if not staged.exists():
            atomic(staged, raw)
        run([gen / 'tools/uv', 'pip', 'install', '--python', gen / '.venv/bin/python',
             '--no-index', '--no-deps', '--reinstall', staged], env)
        recorded.append({'filename': source.name, 'size': len(raw),
                         'sha256': digest_of(raw)})
    return recorded


def install_addon(gen, inventory, wheel_path, env):
    """The OPTIONAL addon. Never required: absent, the store serves the complete local path."""
    entry = (inventory.get('optional') or {}).get('jev_addon')
    if entry is None:
        raise ValueError('this release inventory declares no optional addon')
    raw = Path(wheel_path).read_bytes()
    check(raw, entry['size'], entry['sha256'], entry['filename'])
    staged = gen / 'tools' / entry['filename']
    if not staged.exists():
        atomic(staged, raw)
    run([gen / 'tools/uv', 'pip', 'install', '--python', gen / '.venv/bin/python',
         '--no-index', '--no-deps', '--reinstall', staged], env)
    return {'installed': entry['filename'], 'sha256': entry['sha256'],
            'version': entry.get('version')}


# --------------------------------------------------------------------------- #
# configuration: chain-refreshing (default) or pinned/genesis
# --------------------------------------------------------------------------- #
def write_pinned_config(prefix, gen, inventory, profile, snapshot=None):
    body = {'format': PINNED_FORMAT, 'store': str(prefix / 'memory.db'), 'profile': profile,
            'release_dir': str(gen / 'release'),
            'expected_release_root': inventory['release_root'],
            'snapshot': None if snapshot is None else str(snapshot)}
    atomic(prefix / 'consumer.json', (json.dumps(body, sort_keys=True, indent=1) + '\n').encode())
    return body


def retarget_config(prefix, gen, inventory):
    """Point an EXISTING configuration at the new generation. The store is not touched."""
    config = read_json(prefix / 'consumer.json')
    if config is None:
        raise ValueError('installation has no consumer.json to retarget')
    before = json.loads(json.dumps(config))
    config['release_dir'] = str(gen / 'release')
    if config.get('format') == PINNED_FORMAT:
        config['expected_release_root'] = inventory['release_root']
        if config.get('snapshot'):
            # A snapshot is bound to the release it was confirmed against.
            config['snapshot'] = None
    else:
        config['sync']['expected_release_root'] = inventory['release_root']
        config['sync']['output_dir'] = str(prefix / 'current')
    atomic(prefix / 'consumer.json',
           (json.dumps(config, sort_keys=True, indent=1) + '\n').encode())
    return before, config


def chain_sync(prefix, gen, inventory, profile, python, env, initial):
    command = [python, '-I', '-m', 'coretex_consumer.cli', 'sync', '--config',
               prefix / 'consumer.json']
    if initial:
        command += ['--release-dir', gen / 'release',
                    '--expected-release-root', inventory['release_root'],
                    '--out', prefix / 'current', '--store', prefix / 'memory.db',
                    '--profile', profile]
    return json.loads(run(command, env, capture=True))


HEALTH_PROBE = '''import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('runner', sys.argv[1])
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
config = runner.read_config(sys.argv[2])
memory, mode = runner.open_memory(config)
with memory as bound:
    bound.memory.prewarm(progress=lambda done, total:
                         print('vector index %d/%d' % (done, total), file=sys.stderr))
    health = bound.health()
    assert health['ok'] and health['serving_module'].get('module_root'), health
    print(json.dumps(dict(health, authority_mode=mode, judge=runner.judge_status_of(bound)),
                     default=str))
'''


def health_check(prefix, tools, python, env):
    return json.loads(run([python, '-I', '-c', HEALTH_PROBE, tools / 'coretex-run.py',
                           prefix / 'consumer.json'], env, capture=True))


# --------------------------------------------------------------------------- #
# generations
# --------------------------------------------------------------------------- #
def build_generation(prefix, inventory, args, env):
    gen = generation_dir(prefix, inventory['release_root'])
    tools = gen / 'tools'
    tools.mkdir(parents=True, exist_ok=True)
    print('1/4 Download verified setup tools', file=sys.stderr, flush=True)
    consumer_wheel = None
    for name, entry in sorted(inventory['tools'].items()):
        download(inventory['source'] + entry['path'], tools / name, entry['size'],
                 entry['sha256'],
                 source=None if args.source_dir is None else Path(args.source_dir) / name)
        if name.endswith('.whl'):
            consumer_wheel = name
    if consumer_wheel is None:
        raise ValueError('release inventory declares no current-state client wheel')
    inventory['tools_consumer_wheel'] = consumer_wheel
    shutil.copyfile(Path(__file__).resolve(), tools / 'coretex-setup.py')
    os.chmod(tools / 'coretex-setup.py', 0o700)
    shutil.copyfile(prefix / 'tools' / INVENTORY['name'], tools / INVENTORY['name'])

    uv_pin = inventory['uv']
    uv_wheel = download(uv_pin['url'], tools / 'uv.whl', uv_pin['size'], uv_pin['sha256'],
                        source=None if args.source_dir is None
                        else Path(args.source_dir) / Path(uv_pin['url']).name)
    if not (tools / 'uv').exists():
        with zipfile.ZipFile(io.BytesIO(uv_wheel)) as archive:
            atomic(tools / 'uv', archive.read(uv_pin['script']), 0o700)

    print('2/4 Prepare private Python 3.10 and verify the public release', file=sys.stderr,
          flush=True)
    python = gen / '.venv/bin/python'
    if not python.exists():
        venv = [tools / 'uv', 'venv', gen / '.venv', '--python',
                args.python or '3.10']
        if args.python:
            venv += ['--python-preference', 'only-system']
        run(venv, env)
    place_release(gen / 'release', inventory, tools, python, env, args.source_dir)
    bootstrap = load_bootstrap(tools)
    release, numeric = verify_release(gen / 'release', inventory, prefix, bootstrap)

    print('3/4 Install exact runtime, adapter and current-state client', file=sys.stderr,
          flush=True)
    install_wheels(gen, inventory, numeric, tools, python, env)
    extras = install_extra_wheels(gen, args.extra_wheel, env)
    return gen, tools, python, release, extras


def write_generation_pointer(prefix, gen, inventory, mode, profile, extras=()):
    pointer = {'format': INSTALL_FORMAT, 'generation': inventory['release_root'],
               'release_root': inventory['release_root'], 'version': inventory['version'],
               'dir': str(gen), 'python': str(gen / '.venv/bin/python'),
               'tools': str(gen / 'tools'), 'release': str(gen / 'release'),
               'authority_mode': mode, 'profile': profile,
               'extra_wheels': list(extras), 'pure_release': not extras}
    atomic(prefix / 'CURRENT.json',
           (json.dumps(pointer, sort_keys=True, indent=1) + '\n').encode())
    (prefix / 'bin').mkdir(exist_ok=True)
    atomic(prefix / 'bin/coretex', wrapper(), 0o700)
    return pointer


#: Everything this installer itself creates in the installation directory.
OWNED = frozenset((
    'tools', 'bin', 'gen', 'release', '.venv', '.python', '.cache', '.jev', 'current',
    'memory.db', 'memory.db-wal', 'memory.db-shm', 'consumer.json', 'jev-state.json',
    'CURRENT.json', 'INSTALL-STATE.json', 'INSTALL-COMPLETE.json', 'UPGRADE-HISTORY.json',
    'SERVING-STATE.json', '.install.lock'))


def prepare_directory(prefix, profile, inventory, upgrading):
    identity = {'format': INSTALL_FORMAT, 'profile': profile}
    if prefix.is_symlink():
        raise ValueError('installation directory must not be a symlink')
    marker = prefix / 'INSTALL-STATE.json'
    foreign = sorted(entry.name for entry in prefix.iterdir()
                     if entry.name not in OWNED and not entry.name.startswith('.setup-'))
    if foreign and not marker.is_file():
        raise ValueError('directory already contains unrelated files (%s); choose a new --dir'
                         % ', '.join(foreign[:5]))
    prefix.mkdir(parents=True, exist_ok=True)
    if marker.exists():
        if marker.is_symlink():
            raise ValueError('installation marker must not be a symlink')
        existing = parse(marker.read_bytes())
        if existing.get('profile') != profile:
            raise ValueError('existing installation serves profile %r; a store is bound to its '
                             'profile, so use a new --dir' % existing.get('profile'))
        if existing.get('format') != INSTALL_FORMAT:
            # A pre-generational install: adopt it, keeping its store.
            atomic(marker, (json.dumps(identity, sort_keys=True) + '\n').encode())
        pointer = current(prefix)
        if pointer is not None and pointer['release_root'] != inventory['release_root'] \
                and not upgrading:
            raise ValueError(
                'this installation is on release %s (%s) and the inventory is %s (%s); run '
                '`%s/bin/coretex upgrade` to update the tools and KEEP the memories'
                % (pointer['version'], pointer['release_root'][:12], inventory['version'],
                   inventory['release_root'][:12], prefix))
    else:
        try:
            atomic(marker, (json.dumps(identity, sort_keys=True) + '\n').encode(), replace=False)
        except FileExistsError:
            if parse(marker.read_bytes()).get('profile') != profile:
                raise ValueError('another setup selected a different profile')
    return identity


# --------------------------------------------------------------------------- #
# the three operations
# --------------------------------------------------------------------------- #
def jev_control(prefix, gen, args, env):
    """Apply --jev on|off / --jev-key through the SAME control the launcher exposes."""
    if args.jev is None and args.jev_key is None:
        return None
    argv = [gen / '.venv/bin/python', '-I', gen / 'tools/coretex-jevctl.py',
            '--prefix', prefix, '--config', prefix / 'consumer.json']
    if args.jev == 'off':
        argv += ['disable']
    else:
        argv += ['enable']
        if args.jev_key is not None:
            argv += ['--key', args.jev_key]
    return json.loads(run(argv, env, capture=True))


def fresh_install(prefix, inventory, args, env):
    profile = args.profile
    gen, tools, python, release, extras = build_generation(prefix, inventory, args, env)
    print('4/4 Bind the memory store and prepare the vector index', file=sys.stderr, flush=True)
    mode = args.authority
    if mode == 'chain':
        if not (prefix / 'consumer.json').exists():
            synced = chain_sync(prefix, gen, inventory, profile, python, env, initial=True)
        else:
            retarget_config(prefix, gen, inventory)
            synced = chain_sync(prefix, gen, inventory, profile, python, env, initial=False)
    else:
        write_pinned_config(prefix, gen, inventory, profile)
        synced = {'epoch': None, 'frontier_root': release['genesis']['frontier_root']}
    pointer = write_generation_pointer(prefix, gen, inventory, mode, profile, extras)
    health = health_check(prefix, tools, python, env)
    atomic(gen / 'INSTALL-COMPLETE.json', (json.dumps(
        dict(pointer, frontier_root=synced.get('frontier_root'), epoch=synced.get('epoch'),
             module_root=health['serving_module']['module_root']), sort_keys=True) + '\n').encode())
    result = {'ok': True, 'operation': 'install', 'extra_wheels': extras, 'command': str(prefix / 'bin/coretex'),
              'config': str(prefix / 'consumer.json'), 'profile': profile,
              'version': inventory['version'], 'release_root': inventory['release_root'],
              'authority_mode': mode, 'epoch': synced.get('epoch'),
              'frontier_root': synced.get('frontier_root'),
              'module_root': health['serving_module']['module_root'],
              'store': str(prefix / 'memory.db'), 'store_retained': False}
    if args.install_addon:
        result['addon'] = install_addon(gen, inventory, args.install_addon, env)
    jev = jev_control(prefix, gen, args, env)
    if jev is not None:
        result['jev'] = jev
    return result


def upgrade(prefix, inventory, args, env):
    """Replace the tools generation; KEEP the store, its canonical ids and its history."""
    pointer = current(prefix) or legacy_generation(prefix)
    if pointer is None:
        raise ValueError('no existing installation to upgrade in ' + str(prefix))
    if pointer['release_root'] == inventory['release_root'] and not args.force:
        return {'ok': True, 'operation': 'upgrade', 'changed': False,
                'version': inventory['version'], 'release_root': inventory['release_root'],
                'detail': 'already on this release'}
    before_config = read_json(prefix / 'consumer.json')
    store = Path(before_config['store'])
    if not store.exists():
        raise ValueError('the configured store does not exist: ' + str(store))
    store_before = {'path': str(store), 'size': store.stat().st_size}
    profile = before_config['profile']
    addon_before = (prefix / '.jev').exists() or args.install_addon
    gen, tools, python, release, extras = build_generation(prefix, inventory, args, env)
    print('4/4 Retarget the existing store at the new generation', file=sys.stderr, flush=True)
    kept, after_config = retarget_config(prefix, gen, inventory)
    mode = after_config.get('format') == PINNED_FORMAT and (
        'pinned' if after_config.get('snapshot') else 'genesis') or 'chain'
    if mode == 'chain':
        synced = chain_sync(prefix, gen, inventory, profile, python, env, initial=False)
    else:
        synced = {'epoch': None, 'frontier_root': release['genesis']['frontier_root']}
    new_pointer = write_generation_pointer(prefix, gen, inventory, mode, profile, extras)
    health = health_check(prefix, tools, python, env)
    atomic(gen / 'INSTALL-COMPLETE.json', (json.dumps(
        dict(new_pointer, frontier_root=synced.get('frontier_root'), epoch=synced.get('epoch'),
             module_root=health['serving_module']['module_root']), sort_keys=True) + '\n').encode())
    record_history(prefix, {'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                            'from': pointer, 'to': new_pointer, 'config_before': kept,
                            'store': store_before})
    result = {'ok': True, 'operation': 'upgrade', 'changed': True, 'extra_wheels': extras,
              'command': str(prefix / 'bin/coretex'),
              'from_version': pointer.get('version'), 'from_release': pointer.get('release_root'),
              'version': inventory['version'], 'release_root': inventory['release_root'],
              'authority_mode': mode, 'profile': profile,
              'store': str(store), 'store_retained': True, 're_ingestion': False,
              'store_size_before': store_before['size'], 'store_size_after': store.stat().st_size,
              'event_counts': health.get('event_counts'),
              'module_root': health['serving_module']['module_root'],
              'previous_generation_kept': pointer.get('dir'),
              'rollback': str(prefix / 'bin/coretex') + ' rollback'}
    if args.install_addon:
        result['addon'] = install_addon(gen, inventory, args.install_addon, env)
    elif addon_before and args.addon_wheel_from_previous:
        previous = Path(pointer['tools'])
        staged = sorted(previous.glob('coretex_jev_addon-*.whl'))
        if staged:
            result['addon'] = install_addon(gen, inventory, staged[-1], env)
    jev = jev_control(prefix, gen, args, env)
    if jev is not None:
        result['jev'] = jev
    return result


def rollback(prefix, args, env):
    entries = history(prefix)['entries']
    if not entries:
        raise ValueError('no upgrade to roll back')
    entry = entries[-1]
    target = entry['from']
    if not Path(target['python']).exists():
        raise ValueError('the previous generation is no longer installed: ' + target['dir'])
    atomic(prefix / 'consumer.json',
           (json.dumps(entry['config_before'], sort_keys=True, indent=1) + '\n').encode())
    atomic(prefix / 'CURRENT.json', (json.dumps(target, sort_keys=True, indent=1) + '\n').encode())
    (prefix / 'bin').mkdir(exist_ok=True)
    atomic(prefix / 'bin/coretex', wrapper(), 0o700)
    health = health_check(prefix, Path(target['tools']), Path(target['python']), env)
    record_history(prefix, {'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                            'from': entry['to'], 'to': target, 'config_before': entry['config_before'],
                            'operation': 'rollback'})
    return {'ok': True, 'operation': 'rollback', 'command': str(prefix / 'bin/coretex'),
            'version': target.get('version'), 'release_root': target.get('release_root'),
            'store': str(read_json(prefix / 'consumer.json')['store']), 'store_retained': True,
            'event_counts': health.get('event_counts'),
            'module_root': health['serving_module']['module_root']}


def setup(args):
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise ValueError('this setup helper supports Linux amd64; use the manual guide for '
                         'other platforms')
    prefix = Path(args.dir).expanduser().absolute()
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / 'tools').mkdir(exist_ok=True)
    descriptor = os.open(prefix / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UV_', 'PIP_', 'PYTHON')) and key != 'VIRTUAL_ENV'}
        env.update(UV_PYTHON_INSTALL_DIR=str(prefix / '.python'),
                   UV_CACHE_DIR=str(prefix / '.cache'), UV_NO_CONFIG='1', UV_NO_PROGRESS='1')
        if args.rollback:
            # Rollback re-points the launcher at a generation that is ALREADY installed and
            # verified; it resolves no inventory and reaches no network.
            return rollback(prefix, args, env)
        inventory = load_inventory(prefix / 'tools' / INVENTORY['name'], args.source_dir,
                                   args.inventory)
        if args.profile not in inventory['profiles']:
            raise ValueError('profile %r is not in this release' % args.profile)
        prepare_directory(prefix, args.profile, inventory, args.upgrade)
        if args.upgrade:
            return upgrade(prefix, inventory, args, env)
        pointer = current(prefix)
        if pointer is not None and pointer['release_root'] == inventory['release_root'] \
                and not args.force:
            print('Refresh current confirmed modules; retain existing memories', file=sys.stderr,
                  flush=True)
            result = {'ok': True, 'operation': 'refresh', 'store_retained': True,
                      'command': str(prefix / 'bin/coretex'),
                      'version': pointer['version'], 'release_root': pointer['release_root']}
            if pointer.get('authority_mode', 'chain') == 'chain':
                result.update(json.loads(run([prefix / 'bin/coretex', 'sync'], env, capture=True)))
            jev = jev_control(prefix, Path(pointer['dir']), args, env)
            if jev is not None:
                result['jev'] = jev
            return result
        return fresh_install(prefix, inventory, args, env)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', default='./coretex', help='private installation directory')
    parser.add_argument('--profile', default='event.schema.v1')
    parser.add_argument('--upgrade', action='store_true',
                        help='update the tools of an existing installation, KEEPING its memories')
    parser.add_argument('--rollback', action='store_true',
                        help='return the launcher to the previous generation, same store')
    parser.add_argument('--force', action='store_true', help='rebuild the current generation')
    parser.add_argument('--authority', choices=('chain', 'genesis'), default='chain',
                        help="'chain' refreshes the confirmed pointer on every open; 'genesis' "
                             'pins the verified release with no chain read at all')
    parser.add_argument('--offline', action='store_true',
                        help='install from --source-dir only; never reach the network')
    parser.add_argument('--source-dir', default=None,
                        help='directory holding the inventory, tools, uv wheel and release/')
    parser.add_argument('--inventory', default=None,
                        help='use this generated inventory file instead of the pinned download')
    parser.add_argument('--python', default=None, help='existing interpreter for the private env')
    parser.add_argument('--extra-wheel', action='append', default=[],
                        help='install this wheel after the release wheels (candidate-fix '
                             'verification; recorded by digest in CURRENT.json)')
    parser.add_argument('--install-addon', default=None,
                        help='path to the OPTIONAL coretex_jev_addon wheel (default: not installed)')
    parser.add_argument('--addon-wheel-from-previous', action='store_true', default=True,
                        help='on upgrade, reinstall the addon the previous generation carried')
    parser.add_argument('--jev', choices=('on', 'off'), default=None,
                        help='the ONE enable control; default off')
    parser.add_argument('--jev-key', default=None,
                        help="'-' reads one line from stdin and never echoes it")
    args = parser.parse_args(argv)
    if args.offline and args.source_dir is None:
        parser.error('--offline requires --source-dir')
    if args.jev_key is not None and args.jev is None:
        args.jev = 'on'
    try:
        print(json.dumps(setup(args), sort_keys=True, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'detail': str(exc),
                          'retry': 'Fix the reported issue and rerun the same command; local '
                                   'data is retained.'}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
