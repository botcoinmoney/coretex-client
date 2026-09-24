#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one memory verb against THIS installation's store, on a pinned or chain authority.

The default installation is unchanged: `coretex_consumer.cli` refreshes the chain pointer on
every open, and the launcher sends the ordinary verbs straight there. This helper exists for the
two authorities that client cannot express:

``pinned``    the last confirmed current state on disk, opened WITHOUT re-reading the chain
              (an offline or air-gapped session, and the mode the installation check runs in).
``genesis``   the verified release directory alone — no chain pointer was ever read.

It is also where ``jev status`` gets its answer: :func:`judge_status` opens the store exactly
the way the serving process opens it and reports the provider that is ACTUALLY bound, rather
than reading a configuration file back to the user.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PINNED_FORMAT = 'coretex.consumer-pinned/v1'
CONSUMER_FORMAT = 'coretex-consumer/config/v1'
AGENT_FORMAT = 'coretex-memory-agent/config/v1'
PINNED_FIELDS = {'format', 'store', 'profile', 'release_dir', 'expected_release_root', 'snapshot'}


def read_config(path):
    value = json.loads(Path(path).read_bytes())
    if not isinstance(value, dict) or not isinstance(value.get('format'), str):
        raise ValueError('unsupported configuration: ' + str(path))
    return value


def load_authority(config, *, progress=None):
    """The authority for one config, and the mode name that produced it."""
    kind = config['format']
    if kind == CONSUMER_FORMAT:
        from coretex_consumer.config import load_authority as consumer_authority
        return consumer_authority(config, progress=progress), 'chain'
    if kind == AGENT_FORMAT:
        from coretex_memory_agent.config import load_authority as agent_authority
        return agent_authority(config), 'snapshot'
    if kind != PINNED_FORMAT:
        raise ValueError('unsupported configuration format: ' + kind)
    if set(config) != PINNED_FIELDS:
        raise ValueError('pinned configuration fields must be exactly %s' % sorted(PINNED_FIELDS))
    from coretex_memory_agent.authority import CurrentReleaseAuthority
    if config['snapshot']:
        from coretex_consumer.current_state import CurrentState, authority_from_current
        snapshot = CurrentState.load(config['snapshot'])
        if snapshot.release_root != config['expected_release_root']:
            raise ValueError('pinned snapshot is from another release')
        return authority_from_current(config['release_dir'], snapshot), 'pinned'
    return CurrentReleaseAuthority.load(
        config['release_dir'], expected_release_root=config['expected_release_root']), 'genesis'


def open_memory(config, *, progress=None):
    authority, mode = load_authority(config, progress=progress)
    return authority.open_memory(config['profile'], config['store']), mode


def judge_status(config) -> dict:
    """What the serving process would bind RIGHT NOW, read off a real open of this store."""
    memory, mode = open_memory(config)
    with memory as bound:
        status = bound.judge_status()
        status['authority_mode'] = mode
        status['profile'] = config['profile']
        status['store'] = config['store']
        return status


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='coretex-run', description=__doc__)
    parser.add_argument('command', choices=('status', 'ingest', 'context', 'prewarm',
                                            'judge-status'))
    parser.add_argument('--config', required=True)
    parser.add_argument('text', nargs='?')
    parser.add_argument('--id')
    parser.add_argument('--budget', type=int, default=800)
    parser.add_argument('--as-of', type=int, dest='as_of')
    args = parser.parse_args(argv)

    def progress(message):
        print(message, file=sys.stderr, flush=True)

    try:
        config = read_config(args.config)
        if args.command == 'judge-status':
            print(json.dumps(judge_status(config), sort_keys=True, default=str))
            return 0
        memory, _mode = open_memory(config, progress=progress)
        with memory as bound:
            if args.command == 'status':
                result = bound.health()
            elif args.command == 'prewarm':
                result = bound.memory.prewarm(
                    progress=lambda done, total: progress(f'vector index {done}/{total}'))
            elif args.command == 'ingest':
                if not args.text:
                    raise ValueError('ingest needs TEXT')
                result = bound.sync_turn(
                    messages=[{'role': 'user', 'content': args.text, 'id': args.id}])
            else:
                if not args.text:
                    raise ValueError('context needs QUERY')
                pack = bound.prefetch(args.text, budget=args.budget, as_of=args.as_of)
                result = {'context': pack.render(), 'receipt': pack.receipt,
                          'items': pack.compact()}
        print(json.dumps(result, sort_keys=True, default=str))
        return 0
    except Exception as exc:                                   # noqa: BLE001 - reported as JSON
        print(json.dumps({'ok': False, 'error': str(exc), 'type': type(exc).__name__}),
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
