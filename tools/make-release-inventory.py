#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the single consumer release inventory that `coretex-setup.py` installs from.

`coretex-setup.py` used to carry the release root, the source commit and a wheel list as
LITERALS, so every release needed the installer edited by hand and a wheel that was added to a
release (the optional addon, a second wasmtime) was invisible to it. It now carries exactly ONE
literal — the pin of THIS file — and reads the version, the release root, every artifact name
and every digest from here. A digest that does not match what was downloaded is refused.

Usage:

    tools/make-release-inventory.py --release-dir <dir with RELEASE.json> \\
        --source-commit <client commit> [--addon <coretex_jev_addon-*.whl>] \\
        [--out tools/release-inventory.json] [--pin tools/coretex-setup.py]

`--pin` rewrites the installer's INVENTORY literal to the generated file's own size/digest, so
the two can never drift apart silently.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

FORMAT = 'coretex.consumer-release-inventory/v1'
RAW = 'https://raw.githubusercontent.com/botcoinmoney/coretex-client/'
INVENTORY_URL = 'https://agentmoney.net/coretex-release-inventory.json'

# The client-side files the installer downloads before it has a release: the bootstrap
# verifier, the launcher's serve/run/jev helpers and the current-state client wheel.
TOOLS = (
    ('coretex-bootstrap.py', 'tools/coretex-bootstrap.py'),
    ('coretex-sidecar.py', 'tools/coretex-sidecar.py'),
    ('coretex-run.py', 'tools/coretex-run.py'),
    ('coretex-jevctl.py', 'tools/coretex-jevctl.py'),
    ('coretex_consumer-0.1.1-py3-none-any.whl',
     'consumer-artifacts/coretex_consumer-0.1.1-py3-none-any.whl'),
)

# Installed into the private environment, in this order.
INSTALL_ARTIFACTS = ('runtime_wheel', 'adapter_wheel', 'wasmtime_amd64_wheel')
# Verified but not installed (the sealed verifier runs it from a disposable directory).
VERIFY_ARTIFACTS = ('validator_wheel',)
# Needed to unpack the CPU numeric inventory.
SUPPORT_ARTIFACTS = ('numeric_runtime_amd64',)

UV = {
    'version': '0.8.15',
    'url': ('https://files.pythonhosted.org/packages/13/fc/'
            'e0da45ee179367dcc1e1040ad00ed8a99b78355d43024b0b5fc2edf5c389/'
            'uv-0.8.15-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'),
    'size': 21009338,
    'sha256': '07765f99fd5fd3b257d7e210e8d0844c0a8fd111612e31fcca66a85656cc728e',
    'script': 'uv-0.8.15.data/scripts/uv',
}


def digest(path: Path) -> dict:
    raw = path.read_bytes()
    return {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def build(release_dir: Path, source_commit: str, addon: Path | None, client_root: Path) -> dict:
    release = json.loads((release_dir / 'RELEASE.json').read_bytes())
    artifacts = release['artifacts']
    wanted = INSTALL_ARTIFACTS + VERIFY_ARTIFACTS + SUPPORT_ARTIFACTS
    missing = [name for name in wanted if name not in artifacts]
    if missing:
        raise SystemExit('release is missing required artifacts: %s' % missing)

    def entry(name):
        binding = artifacts[name]
        value = {'path': binding['path'], 'filename': binding['filename'],
                 'size': binding['size'], 'sha256': binding['sha256']}
        for key in ('distribution', 'version'):
            if key in binding:
                value[key] = binding[key]
        return value

    inventory = {
        'format': FORMAT,
        'version': release['version'],
        'release_root': release['release_root'],
        'predecessor_release_root': release.get('predecessor'),
        'source': RAW + source_commit + '/',
        'source_commit': source_commit,
        'profiles': ['event.schema.v1', 'conv.pref.v1', 'doc.tool.v1'],
        'uv': dict(UV),
        'tools': {name: dict(digest(client_root / path), path=path) for name, path in TOOLS},
        'install': {name: entry(name) for name in INSTALL_ARTIFACTS},
        'verify': {name: entry(name) for name in VERIFY_ARTIFACTS},
        'support': {name: entry(name) for name in SUPPORT_ARTIFACTS},
        'optional': {},
    }
    if 'judge' in release:
        inventory['judge'] = {
            'capability': release['judge']['capability'],
            'model_id': release['judge']['descriptor']['model_id'],
            'tariff_id': release['judge']['tariff_id'],
            'descriptor_mapping': dict(release['judge']['descriptor_mapping']),
            # The sealed table is a SEPARATE verified download and is deliberately not part of
            # the consumer kit: a consumer never needs it, a miner/validator does.
            'sealed_table': dict(release['judge']['table']),
        }
    if addon is not None:
        name = addon.name
        matched = re.fullmatch(r'coretex_jev_addon-([0-9][^-]*)-py3-none-any\.whl', name)
        if matched is None:
            raise SystemExit('addon wheel name is not a coretex_jev_addon wheel: ' + name)
        inventory['optional']['jev_addon'] = dict(
            digest(addon), filename=name, distribution='coretex-jev-addon',
            version=matched.group(1),
            note='optional; default OFF; never required by the local M1-M6 path')
    return inventory


def render(inventory: dict) -> bytes:
    return (json.dumps(inventory, sort_keys=True, indent=1) + '\n').encode()


def repin(setup_path: Path, out_path: Path, raw: bytes) -> None:
    text = setup_path.read_text()
    pin = ("INVENTORY = {'name': %r,\n"
           "             'url': %r,\n"
           "             'size': %d,\n"
           "             'sha256': %r}" % (out_path.name, INVENTORY_URL, len(raw),
                                           hashlib.sha256(raw).hexdigest()))
    pattern = re.compile(r"^INVENTORY = \{.*?\}\s*$", re.DOTALL | re.MULTILINE)
    if pattern.search(text) is None:
        raise SystemExit('no INVENTORY literal found in ' + str(setup_path))
    setup_path.write_text(pattern.sub(lambda _: pin, text, count=1))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--addon', default=None)
    parser.add_argument('--client-root', default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument('--out', default=None)
    parser.add_argument('--pin', default=None, help='rewrite this installer\'s INVENTORY literal')
    args = parser.parse_args(argv)
    client_root = Path(args.client_root).resolve()
    out = Path(args.out) if args.out else client_root / 'tools/release-inventory.json'
    inventory = build(Path(args.release_dir), args.source_commit,
                      Path(args.addon) if args.addon else None, client_root)
    raw = render(inventory)
    out.write_bytes(raw)
    if args.pin:
        repin(Path(args.pin), out, raw)
    print(json.dumps({'ok': True, 'out': str(out), 'size': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest(),
                      'version': inventory['version'],
                      'release_root': inventory['release_root'],
                      'addon': bool(inventory['optional'])}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
