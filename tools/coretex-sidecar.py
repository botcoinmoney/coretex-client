#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve a confirmed current profile, a pinned local authority, or an audit snapshot.

Two additions over the original serve-only helper:

* it accepts this installation's pinned/genesis authority as well as the chain-refreshing
  consumer config, so an offline or air-gapped store still serves; and
* it records what it ACTUALLY bound for ``cap.judge.v1`` into ``SERVING-STATE.json`` beside the
  store. A provider is resolved once, at construction, so a later configuration change does not
  reach a running process — ``coretex jev status`` reads this file, sees the live pid, and can
  therefore say "attached" or "restart required" about the real serving process instead of
  reading a config file back to the user.
"""
import argparse
import json
import os
import signal
import tempfile
import threading
import time
from pathlib import Path
import sys

SERVING_STATE_FORMAT = 'coretex.consumer-serving-state/v1'


def _atomic(path, data):
    handle, name = tempfile.mkstemp(prefix='.serving-', dir=str(Path(path).parent))
    try:
        with os.fdopen(handle, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _judge_env_fingerprint():
    return {name: os.environ.get(name, '')
            for name in ('CORETEX_JUDGE_ENABLED', 'CORETEX_JEV_ENABLED')}


def _load_authority(config_path):
    """The chain-refreshing consumer config, this installation's pinned config, or a snapshot."""
    kind = json.loads(Path(config_path).read_text()).get('format')
    if kind == 'coretex-consumer/config/v1':
        from coretex_consumer.config import load_authority, load_config
        config = load_config(config_path)
        authority = load_authority(config, progress=lambda message:
                                   print(message, file=sys.stderr, flush=True))
        return config, authority, 'chain'
    if kind == 'coretex.consumer-pinned/v1':
        runner = Path(__file__).resolve().parent / 'coretex-run.py'
        import importlib.util
        spec = importlib.util.spec_from_file_location('coretex_install_runner', runner)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        config = module.read_config(config_path)
        authority, mode = module.load_authority(config)
        return config, authority, mode
    from coretex_memory_agent.config import load_authority, load_config
    config = load_config(config_path, required=True)
    return config, load_authority(config), 'snapshot'


def main():
    from coretex_memory_agent.sidecar import SidecarServer
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--port', type=int, default=18761)
    parser.add_argument('--prefix', default=None,
                        help='installation directory to record SERVING-STATE.json in')
    args = parser.parse_args()
    config, authority, mode = _load_authority(args.config)
    if authority is None:
        parser.error('config must name a verified release_dir and resolver_snapshot')
    prefix = Path(args.prefix).resolve() if args.prefix else Path(args.config).resolve().parent
    state_path = prefix / 'SERVING-STATE.json'
    with authority.open_memory(config['profile'], config['store']) as memory:
        server = SidecarServer(memory, host='127.0.0.1', port=args.port).start()
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        try:
            health = memory.health()
            if not health['ok'] or not health['serving_module'].get('module_root'):
                raise RuntimeError('sidecar has no healthy bound module')
            judge = memory.judge_status()
            ready = {'ready': True, 'url': server.url, 'profile': config['profile'],
                     'authority_mode': mode,
                     'module_root': health['serving_module']['module_root'],
                     'judge': {'bound': judge['bound'], 'available': judge['available'],
                               'reason': judge['reason']}}
            try:
                _atomic(state_path, (json.dumps(
                    {'format': SERVING_STATE_FORMAT, 'pid': os.getpid(), 'url': server.url,
                     'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                     'profile': config['profile'], 'store': config['store'],
                     'authority_mode': mode, 'judge_status': judge,
                     'judge_env': _judge_env_fingerprint()}, sort_keys=True) + '\n').encode())
            except OSError as exc:                             # never fail a serve on a record
                print(json.dumps({'warning': 'serving state not recorded',
                                  'detail': str(exc)}), file=sys.stderr, flush=True)
            print(json.dumps(ready, sort_keys=True), flush=True)
            stop.wait()
        finally:
            server.stop()
            memory.flush_session()
            try:
                os.unlink(state_path)
            except OSError:
                pass


if __name__ == '__main__':
    main()
