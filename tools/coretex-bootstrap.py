#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Download a complete public release, then run its unchanged sealed verifier.

Python standard library only. HTTPS is the discovery trust anchor unless
--expected-release-root is supplied independently. Nothing is installed globally.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

MAX_FILE = 128 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


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


def relative(name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('invalid relative path')
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('unsafe relative path: ' + name)
    return Path(*path.parts)


def root(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('invalid SHA-256/root')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('redirect refused; use the canonical HTTPS coordinator URL')


class Public:
    def __init__(self, base):
        url = urllib.parse.urlsplit(base)
        if url.scheme != 'https' or not url.hostname or url.username or url.password \
                or url.path not in ('', '/') or url.query or url.fragment:
            raise ValueError('--coordinator must be an HTTPS origin, without credentials or path')
        self.base = base.rstrip('/')
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
        self.last_request = 0.0

    def get(self, path, limit=MAX_JSON, raw=False):
        if not path.startswith('/coretex/v5/') or '#' in path:
            raise ValueError('unexpected public API path')
        request = urllib.request.Request(self.base + path, headers={
            'User-Agent': 'coretex-bootstrap/1',
            'Accept': 'application/octet-stream' if raw else 'application/json'})
        for attempt in range(5):
            time.sleep(max(0, 1.0 - (time.monotonic() - self.last_request)))
            self.last_request = time.monotonic()
            try:
                with self.opener.open(request, timeout=180) as response:
                    data = response.read(limit + 1)
                break
            except urllib.error.HTTPError as exc:
                if exc.code not in (429, 502, 503, 504) or attempt == 4:
                    raise
                retry = exc.headers.get('Retry-After', '')
                delay = min(60, max(2 ** attempt, int(retry) if retry.isdigit() else 5))
                print(f'HTTP {exc.code}; retrying in {delay}s', file=sys.stderr, flush=True)
                time.sleep(delay)
        if len(data) > limit:
            raise ValueError('public response exceeds size bound')
        return data

    def object(self, entry):
        address = root(entry['address'])
        rule = entry['hashRule']
        document = parse(self.get('/coretex/v5/object/' + address + '?hashRule=' +
                                 urllib.parse.quote(rule, safe=''), 2 * MAX_FILE))
        if document.get('verified') is not True or document.get('root') != address \
                or document.get('hashRule') != rule:
            raise ValueError('object envelope identity mismatch')
        data = base64.b64decode(document['data'], validate=True)
        if len(data) > MAX_FILE or len(data) != document['size']:
            raise ValueError('object size mismatch')
        if rule == 'sha256-bytes' and sha(data) != address:
            raise ValueError('object SHA-256 mismatch')
        # Structured roots are independently verified by the sealed verifier below.
        return data


def exact(raw, size, digest):
    root(digest)
    if type(size) is not int or not 0 < size <= MAX_FILE:
        raise ValueError('invalid declared size')
    return len(raw) == size and sha(raw) == digest


def restore(raw, declaration):
    if exact(raw, declaration['size'], declaration['raw_sha256']):
        return raw
    value = parse(raw)
    for sort in (True, False):
        for ascii_ in (True, False):
            candidate = (json.dumps(value, sort_keys=sort, indent=2,
                                    ensure_ascii=ascii_) + '\n').encode()
            if exact(candidate, declaration['size'], declaration['raw_sha256']):
                return candidate
    raise ValueError('no byte-exact materialization for ' + declaration['path'])


def numeric_wheels(release_dir, release):
    """Extract only the release-bound amd64 numeric inventory, never tar paths/links."""
    binding = release['artifacts']['numeric_runtime_amd64']
    archive_path = release_dir / relative(binding['path'])
    if not exact(archive_path.read_bytes(), binding['size'], binding['sha256']):
        raise ValueError('numeric archive differs from release')
    destination = release_dir / 'wheelhouse'
    destination.mkdir()
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        if len(members) > 100 or sum(m.size for m in members) > 256 * 1024 * 1024:
            raise ValueError('numeric inventory exceeds extraction bound')
        seen = set()
        for member in members:
            path = relative(member.name)
            if len(path.parts) != 1 or not member.isfile() or member.name in seen:
                raise ValueError('unsafe or duplicate numeric archive member')
            seen.add(member.name)
            (destination / path).write_bytes(archive.extractfile(member).read())
    inventory = parse((destination / 'CPU-RUNTIME.json').read_bytes())
    if set(inventory['wheels']) | {'CPU-RUNTIME.json'} != seen:
        raise ValueError('numeric inventory has undeclared/missing files')
    for name, binding in inventory['wheels'].items():
        if not exact((destination / relative(name)).read_bytes(),
                     binding['bytes'], binding['sha256']):
            raise ValueError('numeric wheel hash mismatch: ' + name)


def verify_sealed(release_dir, release):
    """Run the exact wheel payload in a disposable import directory, with no pip/network."""
    binding = release['artifacts']['validator_wheel']
    wheel = release_dir / relative(binding['path'])
    if not exact(wheel.read_bytes(), binding['size'], binding['sha256']):
        raise ValueError('validator wheel differs from release')
    with tempfile.TemporaryDirectory(prefix='coretex-sealed-verifier-') as work:
        with zipfile.ZipFile(wheel) as archive:
            seen = set()
            for member in archive.infolist():
                if not member.filename.startswith('coretex_validator/') or member.is_dir():
                    continue
                path = relative(member.filename)
                if len(path.parts) != 2 or member.filename in seen or member.file_size > MAX_JSON:
                    raise ValueError('unsafe validator wheel member')
                seen.add(member.filename)
                target = Path(work) / path
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(archive.read(member))
        print('Running sealed coretex-validator verify-release', file=sys.stderr, flush=True)
        # -I excludes ambient site/PYTHONPATH; explicitly insert only the verified package directory.
        code = ('import sys; sys.path.insert(0, sys.argv.pop(1)); '
                'from coretex_validator.cli import main; raise SystemExit(main())')
        result = subprocess.run([sys.executable, '-I', '-S', '-c', code, work,
                                 'verify-release', '--release', str(release_dir)],
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise ValueError('sealed verify-release refused: ' + result.stdout[-2000:])
        verified = parse(result.stdout)
        if verified.get('release_root') != release['release_root']:
            raise ValueError('sealed verifier returned another release')
        return verified


def bootstrap(public, output, expected=None):
    status = parse(public.get('/coretex/v5/status'))
    selected = root(status['release']['releaseRoot'])
    if expected and selected != root(expected):
        raise ValueError('coordinator release differs from --expected-release-root')
    entries = status['artifacts']['contentReadBack']['releaseObjects']['roots']
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise ValueError('invalid release index size')
    releases = [e for e in entries if e['path'].endswith('/RELEASE.json')]
    if len(releases) != 1 or releases[0]['address'] != selected:
        raise ValueError('release index is ambiguous')
    prefix = releases[0]['path'][:-len('RELEASE.json')]
    relative(prefix.rstrip('/'))
    raw = public.object(releases[0])
    release = parse(raw)
    body = {k: v for k, v in release.items() if k != 'release_root'}
    if release.get('release_root') != selected or sha(json.dumps(
            body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()) != selected:
        raise ValueError('release body does not reproduce the selected root')
    output = Path(output).expanduser().absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('--out already exists; choose a new directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=output.name + '.partial-', dir=output.parent))
    try:
        seen = set()
        for i, entry in enumerate(entries, 1):
            if not entry['path'].startswith(prefix):
                raise ValueError('release index path outside selected release')
            path = relative(entry['path'][len(prefix):])
            if path in seen:
                raise ValueError('duplicate release path')
            seen.add(path)
            print(f'[{i}/{len(entries)}] download {path}', file=sys.stderr, flush=True)
            if str(path) == 'RELEASE.json':
                data = raw
            elif entry['hashRule'] == 'sha256-bytes':
                address = root(entry['address'])
                data = public.get('/coretex/v5/kit/file/' + address, MAX_FILE, raw=True)
                if sha(data) != address:
                    raise ValueError('downloaded file SHA-256 mismatch: ' + str(path))
            else:
                data = public.object(entry)
            target = staging / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for declaration in release['objects'].values():
            target = staging / relative(declaration['path'])
            target.write_bytes(restore(target.read_bytes(), declaration))
        frontier_path = staging / 'GENESIS-FRONTIER.json'
        frontier = parse(frontier_path.read_bytes())
        if frontier.get('format') == 'coretex.memory-frontier.v1':
            frontier_path.write_text(json.dumps({'format': 'coretex.genesis-frontier/v1',
                'frontier_root': release['genesis']['frontier_root'], 'manifest': frontier},
                sort_keys=True, indent=2) + '\n')
        verified = verify_sealed(staging, release)
        numeric_wheels(staging, release)
        (staging / 'BOOTSTRAP-VERIFIED.json').write_text(json.dumps(verified, indent=2) + '\n')
        os.rename(staging, output)
        return {'ok': True, 'release_root': selected, 'output': str(output),
                'paths': len(entries), 'verification': 'unchanged sealed validator wheel'}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    parser.add_argument('--coordinator', default='https://coordinator.agentmoney.net')
    parser.add_argument('--expected-release-root')
    args = parser.parse_args()
    try:
        result = bootstrap(Public(args.coordinator), args.out, args.expected_release_root)
        print(json.dumps(result, indent=2))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': type(exc).__name__, 'detail': str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
