#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Visible public snapshot creation using the unchanged installed sealed validator.

Run with the sealed CoreTex Python environment. This companion does not change
the snapshot scope, verifier payload, replay, signatures, or receipt-window checks.
"""
import argparse
import json
import sys
import threading
import time


class Progress:
    def __init__(self, interval=30):
        self.started = time.monotonic()
        self.phase = 'verifying release'
        self.activity = ''
        self.interval = interval
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)

    def emit(self, phase=None, activity=None):
        if phase is not None:
            self.phase = phase
        if activity is not None:
            self.activity = activity
        print(json.dumps({'phase': self.phase, 'activity': self.activity,
                          'elapsed_seconds': round(time.monotonic() - self.started)}),
              file=sys.stderr, flush=True)

    def _heartbeat(self):
        while not self.stop.wait(self.interval):
            self.emit()


def progress_rpc_class(base_class, progress):
    class ProgressRpc(base_class):
        receipt_rigs = None

        def call(self, method, params):
            if method == 'eth_getLogs':
                row = params[0]
                progress.emit(activity=f"log window {int(row['fromBlock'], 16)}.."
                              f"{int(row['toBlock'], 16)}; RPC calls {self.calls}")
            try:
                result = super().call(method, params)
            except Exception as exc:
                if getattr(exc, 'status', None) == 403:
                    # Do not echo the transport message: RPC URLs can contain API keys.
                    raise RuntimeError(
                        'RPC HTTP 403: this endpoint refused the request. eth_getLogs must be '
                        'available, not only eth_chainId. https://mainnet.base.org worked in '
                        'the consumer qualification; public access is rate limited. Try another '
                        'RPC explicitly. --log-window 10000 is optional only when its provider '
                        'supports that range; the default remains 2000.') from None
                raise RuntimeError(f'RPC {method} failed ({type(exc).__name__}); '
                                   'check endpoint access, range limits and rate limits') from None
            if method != 'eth_getLogs':
                progress.activity = f'RPC {method}; calls {self.calls}; rate limits {self.rate_limited}'
            if method == 'eth_call' and self.receipt_rigs is not None:
                from coretex_validator.keccak256 import keccak256
                selectors = {'0x' + keccak256(s.encode())[:4].hex() for s in
                             ('rigNextIndex(uint256)', 'rigLastReceiptHash(uint256)')}
                data = params[0].get('data', '')
                if data[:10] in selectors and len(data) == 74:
                    rig = int(data[10:], 16)
                    self.receipt_reads.setdefault(rig, set()).add((data[:10], params[1]))
                    completed = sum(len(reads) == 4 for reads in self.receipt_reads.values())
                    progress.emit(activity=f'rig receipt windows read {completed}/{len(self.receipt_rigs)}; '
                                  'awaiting sealed continuity checks')
            return result
    return ProgressRpc


def main(argv=None):
    from coretex_validator import cli, discovery, release, snapshot
    from coretex_validator.rpc import JsonRpc

    parser = cli.build_parser()
    # Keep the existing public arguments, add only transport/progress options.
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    command = sub.choices['snapshot']
    command.add_argument('--log-window', type=int, default=2000)
    command.add_argument('--preflight-only', action='store_true',
                         help='verify release and RPC access only; does not create a snapshot')
    args = parser.parse_args(['snapshot'] + (sys.argv[1:] if argv is None else argv))
    if not 1 <= args.log_window <= 10000:
        parser.error('--log-window must be 1..10000 (provider dependent)')
    if args.confirmations < 12:
        parser.error('consumer snapshots require at least 12 confirmations')
    progress = Progress()
    progress.thread.start()
    try:
        progress.emit()
        installed = release.load(args.release)  # exact installed wheel payload check stays intact
        activation = installed.activation(args.activation)
        rpc = progress_rpc_class(JsonRpc, progress)(cli._read_rpc_url(args),
                                                    chunk_blocks=args.log_window)
        deployment = discovery.deployment_from_authority(installed.authority)
        progress.emit('RPC access preflight')
        rpc.assert_chain(deployment.chain_id)
        # Refuse an eth_getLogs-blocked endpoint before the long scan; no automatic fallback.
        retries, rpc.retries = rpc.retries, 1
        try:
            rpc.get_logs(addresses=(deployment.mining,), topics=(),
                         from_block=activation.confirmed_block,
                         to_block=activation.confirmed_block)
        finally:
            rpc.retries = retries
        if args.preflight_only:
            progress.emit('preflight complete', 'no snapshot or adoption claim')
            print(json.dumps({'ok': True, 'scope': 'preflight-only',
                              'release_root': installed.release_root}))
            return 0
        progress.emit('confirmed chain discovery')
        scan = discovery.scan_public_feed(rpc, activation=activation, release=installed,
            to_block=args.to_block, confirmation_depth=args.confirmations)
        rigs = {x.rig_id for x in list(scan.decoded.coretex_credits) + list(scan.decoded.standard_credits)}
        rpc.receipt_rigs, rpc.receipt_reads = rigs, {}
        progress.emit('full replay and receipt verification',
                      f'{len(scan.decoded.advances)} transitions; {len(rigs)} rig receipt windows; '
                      'cold replay may take tens of minutes')
        reader = snapshot.PublicObjectReader(args.objects)

        def fetch(address, rule):
            progress.emit(activity=f'fetching CAS object {address[:12]} ({rule})')
            value = reader(address, rule)
            progress.activity = ('deterministic replay / receipt checks; waiting for sealed '
                                 'verifier (no checks skipped)')
            return value

        document = snapshot.materialize(release=installed, activation=activation, scan=scan,
            rpc=rpc, object_fetch=fetch, output_dir=args.out, confirmation_depth=args.confirmations)
        progress.emit('complete', 'all sealed snapshot checks passed')
        print(json.dumps({'epoch': document['epoch']['id'],
            'frontier_root': document['frontier']['root'], 'output': args.out,
            'release_root': document['release_root'], 'scope': 'full',
            'rpc_calls': rpc.calls, 'rate_limits': rpc.rate_limited}, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'detail': str(exc)}),
              file=sys.stderr)
        return 1
    finally:
        progress.stop.set()
        progress.thread.join(timeout=1)


if __name__ == '__main__':
    raise SystemExit(main())
