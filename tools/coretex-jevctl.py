#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE control for the optional Jev addon, and an honest answer about what is bound.

The review found the enablement split across two layers that never met:

* ``coretex-memory setup --jev-key -`` wrote ``{"enabled": true}`` into the addon's ``jev.json``,
  and the addon also honours ``CORETEX_JEV_ENABLED``; but
* ``AgentMemory.open`` binds a provider to the serving store only when it is passed ``judge=``
  or when ``CORETEX_JUDGE_ENABLED`` is true.

So a consumer could follow the documented flow, see "enabled", and serve with NO provider bound
at all. Rather than change the release-bound runtime to connect a launcher, this installation
owns one control and sets BOTH facts for every serving process it starts:

    coretex jev enable [--key -]        # or: coretex setup --jev-key -
    coretex jev disable
    coretex jev status

``enable`` is two-condition, exactly as the addon's own contract says: the addon is effective
only when the consumer explicitly turned it ON **and** a key is resolvable. Either one missing
leaves the complete local M1-M6 path running, with no addon import, credential probe or socket.
``disable`` is explicit OFF and takes precedence over anything inherited from the environment.

What ``enable`` actually sets, for every serve/ingest/context this launcher starts:

    CORETEX_JUDGE_ENABLED=1     the HOST binding read by AgentMemory.open (the missing half)
    CORETEX_JEV_ENABLED=1       the addon factory's own opt-in
    CORETEX_JEV_CONFIG=<prefix>/.jev/jev.json   this installation's key-free addon config

``disable`` sets the first two to ``0``. The key itself is never an argument, never an exported
variable of the wrapper and never printed: it lives in ``<prefix>/.jev/jev.key`` at mode 0600
and is named from the config file the addon reads.

``status`` does not read that config back to you. It opens the store the way the serving
process opens it (or reports the running sidecar's own captured binding) and prints what
``AgentMemory.judge_status()`` says is bound.
"""
from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

STATE_FORMAT = 'coretex.consumer-jev-state/v1'
HOST_ENABLE_VAR = 'CORETEX_JUDGE_ENABLED'
ADDON_ENABLE_VAR = 'CORETEX_JEV_ENABLED'
ADDON_CONFIG_VAR = 'CORETEX_JEV_CONFIG'
ADDON_KEY_VAR = 'JEV_API_KEY'


# --------------------------------------------------------------------------- #
# installation-local state
# --------------------------------------------------------------------------- #
def jev_home(prefix: Path) -> Path:
    return Path(prefix) / '.jev'


def state_path(prefix: Path) -> Path:
    return Path(prefix) / 'jev-state.json'


def config_path(prefix: Path) -> Path:
    return jev_home(prefix) / 'jev.json'


def key_path(prefix: Path) -> Path:
    return jev_home(prefix) / 'jev.key'


def cache_dir(prefix: Path) -> Path:
    return jev_home(prefix) / 'jev-cache'


def atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix='.jev-', dir=str(path.parent))
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_state(prefix: Path) -> dict:
    try:
        value = json.loads(state_path(prefix).read_bytes())
    except (OSError, ValueError):
        return {'format': STATE_FORMAT, 'enabled': False}
    if not isinstance(value, dict) or value.get('format') != STATE_FORMAT:
        return {'format': STATE_FORMAT, 'enabled': False}
    return {'format': STATE_FORMAT, 'enabled': bool(value.get('enabled'))}


def write_state(prefix: Path, enabled: bool) -> dict:
    state = {'format': STATE_FORMAT, 'enabled': bool(enabled)}
    atomic(state_path(prefix), (json.dumps(state, sort_keys=True) + '\n').encode(), 0o600)
    return state


def key_available(prefix: Path, env=None) -> dict:
    """Is a key resolvable for THIS installation? The value is never returned."""
    env = os.environ if env is None else env
    if env.get(ADDON_KEY_VAR):
        return {'available': True, 'source': 'environ',
                'length': len(env[ADDON_KEY_VAR])}
    path = key_path(prefix)
    try:
        value = path.read_text(encoding='utf-8').strip()
    except OSError:
        return {'available': False, 'source': 'missing_file', 'length': 0}
    if not value:
        return {'available': False, 'source': 'empty_file', 'length': 0}
    return {'available': True, 'source': 'key_file', 'length': len(value)}


def write_key(prefix: Path, value: str) -> dict:
    if not isinstance(value, str) or not value.strip():
        raise ValueError('an API key is required')
    target = key_path(prefix)
    target.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(handle, value.strip().encode('utf-8'))
    finally:
        os.close(handle)
    os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    return {'key_path': str(target), 'key_mode': '0600', 'key_length': len(value.strip())}


def write_addon_config(prefix: Path, enabled: bool) -> Path:
    """The key-FREE config the addon reads. Never carries the key; names the 0600 file."""
    body = {'enabled': bool(enabled), 'key_file': str(key_path(prefix)),
            'cache_dir': str(cache_dir(prefix))}
    atomic(config_path(prefix), (json.dumps(body, indent=1, sort_keys=True) + '\n').encode(),
           0o600)
    return config_path(prefix)


# --------------------------------------------------------------------------- #
# the one thing the serving process reads
# --------------------------------------------------------------------------- #
def effective(prefix: Path, env=None) -> dict:
    """Two-condition: explicitly ON **and** a usable key. Anything else is OFF."""
    env = os.environ if env is None else env
    state = read_state(prefix)
    key = key_available(prefix, env)
    on = bool(state['enabled']) and bool(key['available'])
    reason = ('enabled with a usable key' if on else
              'explicitly disabled' if not state['enabled'] else
              'enabled, but no key is resolvable: run `coretex jev enable --key -`')
    return {'requested': bool(state['enabled']), 'key_available': bool(key['available']),
            'key_source': key['source'], 'effective': on, 'reason': reason}


def serving_env(prefix: Path, env=None) -> dict:
    """The environment overlay every serving invocation of this installation gets."""
    prefix = Path(prefix)
    decision = effective(prefix, env)
    overlay = {HOST_ENABLE_VAR: '1' if decision['effective'] else '0',
               ADDON_ENABLE_VAR: '1' if decision['effective'] else '0',
               ADDON_CONFIG_VAR: str(config_path(prefix))}
    return overlay


def serving_env_fingerprint(prefix: Path, env=None) -> dict:
    overlay = serving_env(prefix, env)
    return {key: overlay[key] for key in (HOST_ENABLE_VAR, ADDON_ENABLE_VAR)}


# --------------------------------------------------------------------------- #
# status: what is ACTUALLY bound
# --------------------------------------------------------------------------- #
def _load_runner(prefix: Path):
    # The runner lives beside THIS file, in the generation's tools directory -- not at the
    # installation root, which holds only the store and the cross-generation state.
    runner = Path(__file__).resolve().parent / 'coretex-run.py'
    spec = importlib.util.spec_from_file_location('coretex_install_runner', runner)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _running_sidecar(prefix: Path):
    path = Path(prefix) / 'SERVING-STATE.json'
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    pid = value.get('pid')
    if not isinstance(pid, int):
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return value


def status(prefix: Path, config: str, *, probe_store: bool = True) -> dict:
    prefix = Path(prefix)
    decision = effective(prefix)
    payload = {
        'install': str(prefix),
        'control': 'coretex jev enable|disable',
        'configured': decision,
        'sets': serving_env(prefix),
        'addon_installed': importlib.util.find_spec('coretex_jev_addon') is not None,
        'config_path': str(config_path(prefix)),
        'key_path': str(key_path(prefix)),
    }
    running = _running_sidecar(prefix)
    if running is not None:
        payload['probe'] = 'running-sidecar'
        payload['sidecar'] = {key: running.get(key) for key in ('pid', 'url', 'started_at')}
        payload['bound'] = running.get('judge_status')
        payload['restart_required'] = (running.get('judge_env') !=
                                       serving_env_fingerprint(prefix))
        if payload['restart_required']:
            payload['note'] = ('a running serving process captured its binding at construction; '
                               'restart `coretex serve` for this change to take effect')
    elif probe_store:
        payload['probe'] = 'opened-store'
        try:
            runner = _load_runner(prefix)
            payload['bound'] = runner.judge_status(runner.read_config(config))
        except Exception as exc:                               # noqa: BLE001 - reported
            payload['probe_error'] = f'{type(exc).__name__}: {exc}'
            payload['bound'] = None
    else:
        payload['probe'] = 'none'
        payload['bound'] = None
    bound = payload.get('bound') or {}
    payload['provider_attached'] = bool(bound.get('available'))
    payload['summary'] = (
        'a judgment provider IS attached to this store' if payload['provider_attached'] else
        'no judgment provider is attached; this store serves the complete local path')
    return payload


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def _read_key(raw, stdin=None) -> str:
    if raw is None or raw == '-':
        stream = sys.stdin if stdin is None else stdin
        if stream is not None and not getattr(stream, 'isatty', lambda: False)():
            return stream.readline().strip()
        return getpass.getpass('Jev API key (not echoed): ').strip()
    return raw.strip()


def cmd_enable(prefix: Path, args) -> dict:
    summary = {}
    if args.key is not None or args.prompt:
        summary.update(write_key(prefix, _read_key(args.key)))
    write_state(prefix, True)
    write_addon_config(prefix, True)
    decision = effective(prefix)
    summary.update({'ok': True, 'enabled': True, 'effective': decision['effective'],
                    'reason': decision['reason'], 'sets': serving_env(prefix),
                    'restart': 'restart `coretex serve` if a sidecar is running'})
    if not decision['key_available']:
        summary['next'] = 'supply a key: coretex jev enable --key -'
    if importlib.util.find_spec('coretex_jev_addon') is None:
        summary['addon'] = ('the addon wheel is not installed; install it with '
                            '`coretex setup --install-addon <wheel>` or leave it out — '
                            'the local path is complete without it')
    return summary


def cmd_disable(prefix: Path, args) -> dict:
    write_state(prefix, False)
    if config_path(prefix).exists():
        write_addon_config(prefix, False)
    return {'ok': True, 'enabled': False, 'effective': False,
            'reason': 'explicitly disabled; explicit off overrides the environment',
            'sets': serving_env(prefix),
            'key_retained': key_path(prefix).exists(),
            'restart': 'restart `coretex serve` if a sidecar is running'}


def cmd_status(prefix: Path, args) -> dict:
    return status(prefix, args.config, probe_store=not args.no_probe)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='coretex jev', description=__doc__)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--json', action='store_true')
    sub = parser.add_subparsers(dest='command', required=True)

    enable = sub.add_parser('enable', help='turn the addon ON for this installation')
    enable.add_argument('--key', nargs='?', const='-', default=None,
                        help="Jev API key; '-' (default) reads one line from stdin, never echoed")
    enable.add_argument('--prompt', action='store_true', help='prompt for the key')
    enable.set_defaults(func=cmd_enable)

    disable = sub.add_parser('disable', help='turn it OFF (explicit off wins)')
    disable.set_defaults(func=cmd_disable)

    report = sub.add_parser('status', help='what is ACTUALLY bound to this store')
    report.add_argument('--no-probe', action='store_true',
                        help='do not open the store; report configuration only')
    report.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    prefix = Path(args.prefix).resolve()
    try:
        result = args.func(prefix, args)
    except Exception as exc:                                   # noqa: BLE001 - reported as JSON
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'detail': str(exc)}),
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=None if args.json else 1, default=str))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
