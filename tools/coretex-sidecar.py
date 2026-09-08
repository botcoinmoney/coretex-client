#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve a confirmed current profile, or an explicitly selected audit snapshot."""
import argparse
import json
import signal
import threading
from pathlib import Path
import sys


def main():
    from coretex_memory_agent.config import load_authority, load_config
    from coretex_memory_agent.sidecar import SidecarServer
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--port', type=int, default=18761)
    args = parser.parse_args()
    kind = json.loads(Path(args.config).read_text()).get('format')
    if kind == 'coretex-consumer/config/v1':
        from coretex_consumer.config import load_config, load_authority
        config = load_config(args.config)
        authority = load_authority(config, progress=lambda message:
                                   print(message, file=sys.stderr, flush=True))
    else:
        config = load_config(args.config, required=True)
        authority = load_authority(config)
    if authority is None:
        parser.error('config must name a verified release_dir and resolver_snapshot')
    with authority.open_memory(config['profile'], config['store']) as memory:
        server = SidecarServer(memory, host='127.0.0.1', port=args.port).start()
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        try:
            health = memory.health()
            if not health['ok'] or not health['serving_module'].get('module_root'):
                raise RuntimeError('sidecar has no healthy bound module')
            print(json.dumps({'ready': True, 'url': server.url, 'profile': config['profile'],
                              'module_root': health['serving_module']['module_root']}), flush=True)
            stop.wait()
        finally:
            server.stop()
            memory.flush_session()


if __name__ == '__main__':
    main()
