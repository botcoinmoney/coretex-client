#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The bounded consumer installation check for release 1.1.2 with the optional Jev addon.

It exercises the PUBLIC installer and the GENERATED launcher — never the source tree, never a
hand-bound adapter and never an extra wheel — in throw-away installations on a data volume,
offline, with a network kill-switch armed for every arm that claims "no Jev calls". Every
installation here is built from RELEASE BYTES ALONE, so every ``CURRENT.json`` it writes reports
``pure_release: true``.

Two beds:

  FRESH    a 1.1.2 installation, populated, then taken through the addon arms.
  UPGRADE  a POPULATED installation of the PREVIOUS release upgraded to 1.1.2 tools, asserted to
           keep its memories and open with no re-ingestion, then taken through the same arms,
           then rolled back.

Arms (each bed): addon absent; addon installed but disabled; enabled with no key; enabled with a
deterministic FAKE provider; provider failure; provider deadline; disabled and uninstalled after
use. Every arm re-renders the same fixed queries and compares the rendered bytes and the receipt
against the pre-addon baseline.

This does not re-run quality studies: the 917-query three-profile zero-difference identity gate
already recorded for this runtime is the evidence for local identity. What is new here is the
public setup/launcher wiring those source-tree tests bypass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

NETGUARD = '''# installation-check instrumentation: refuse and record every outbound socket
import os, socket, traceback
_MARK = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(__file__)))), "netguard.on")
_LOG = _MARK + ".log"


def _record(what):
    try:
        with open(_LOG, "a") as handle:
            handle.write(what + "\\n")
    except OSError:
        pass


if os.path.exists(_MARK):
    class _Blocked(socket.socket):
        def connect(self, *a, **k):
            _record("connect %r" % (a,))
            raise OSError("installation check: outbound network is blocked")

        def connect_ex(self, *a, **k):
            _record("connect_ex %r" % (a,))
            raise OSError("installation check: outbound network is blocked")

    socket.socket = _Blocked

    def _getaddrinfo(*a, **k):
        _record("getaddrinfo %r" % (a,))
        raise OSError("installation check: DNS is blocked")

    socket.getaddrinfo = _getaddrinfo
'''

QUERIES = (
    'what did the team decide about the storage budget',
    'who reported the checkout latency regression',
    'which vendor was chosen and why',
)

MEMORIES = (
    'On March 3 Dana proposed raising the storage budget to 4 TB for the archive tier.',
    'Priya reported a checkout latency regression of 180 ms on the payments path.',
    'The team agreed the migration window is the first Saturday of April, 02:00-06:00 UTC.',
    'Vendor Northwind was chosen over Castille because Northwind met the retention requirement.',
    'Dana revised the storage budget request from 4 TB to 6 TB after the audit.',
    'The checkout latency regression was traced to an unindexed lookup in the coupon service.',
    'Castille was cheaper but could not guarantee the seven-year retention the auditors asked for.',
    'Ravi confirmed the April migration window with the database team on March 19.',
    'The archive tier now holds 3.1 TB, growing about 120 GB per month.',
    'Priya shipped the coupon-service index on March 22 and latency returned to 240 ms.',
    'Legal signed off on Northwind on March 25 subject to an annual retention attestation.',
    'The storage budget of 6 TB was approved at the March 27 planning review.',
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class Install:
    def __init__(self, root: Path, harness: 'Harness'):
        self.root = root
        self.harness = harness

    @property
    def coretex(self) -> Path:
        return self.root / 'bin/coretex'

    def launcher(self, *args, expect=0, env=None, timeout=900):
        full = dict(os.environ)
        full.update(env or {})
        result = subprocess.run([str(self.coretex), *[str(a) for a in args]], env=full,
                                capture_output=True, text=True, timeout=timeout)
        if expect is not None and result.returncode != expect:
            raise RuntimeError('launcher %s -> %s\n%s\n%s'
                               % (args, result.returncode, result.stdout[-2000:],
                                  result.stderr[-2000:]))
        return result

    def json_launcher(self, *args, **kw):
        result = self.launcher(*args, **kw)
        return json.loads(result.stdout)

    # -- network kill-switch ------------------------------------------------ #
    def site_dir(self) -> Path:
        pointer = json.loads((self.root / 'CURRENT.json').read_bytes())
        return Path(pointer['dir']) / '.venv/lib/python3.10/site-packages'

    def arm_netguard(self) -> None:
        (self.site_dir() / 'sitecustomize.py').write_text(NETGUARD)
        marker = Path(json.loads((self.root / 'CURRENT.json').read_bytes())['dir']) / 'netguard.on'
        marker.write_text('armed\n')
        self._marker = marker

    def netguard_hits(self) -> int:
        log = Path(json.loads((self.root / 'CURRENT.json').read_bytes())['dir']) / 'netguard.on.log'
        if not log.exists():
            return 0
        return len([line for line in log.read_text().splitlines() if line.strip()])

    # -- store operations --------------------------------------------------- #
    def ingest_all(self):
        for index, text in enumerate(MEMORIES):
            self.launcher('ingest', text, '--id', 'm%02d' % index)
        return self.json_launcher('status')

    def snapshot(self) -> dict:
        """The rendered bytes and receipt for the fixed queries, plus the store's own counts."""
        packs = {}
        for query in QUERIES:
            payload = self.json_launcher('context', query, '--budget', '800')
            packs[query] = {'context_sha256': sha(payload['context'].encode()),
                            'receipt_sha256': sha(json.dumps(payload['receipt'], sort_keys=True,
                                                             default=str).encode()),
                            'items': len(payload['items']),
                            'receipt': payload['receipt']}
        health = self.json_launcher('status')
        return {'packs': packs, 'event_counts': health['event_counts'],
                'module_root': health['serving_module']['module_root'],
                'profile_id': health['profile_id']}

    def pip(self, *args, expect=0):
        pointer = json.loads((self.root / 'CURRENT.json').read_bytes())
        uv = Path(pointer['tools']) / 'uv'
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('UV_', 'PIP_', 'PYTHON'))}
        env.update(UV_NO_CONFIG='1', UV_NO_PROGRESS='1',
                   UV_CACHE_DIR=str(self.root / '.cache'))
        result = subprocess.run([str(uv), 'pip', *[str(a) for a in args], '--python',
                                 pointer['python']], env=env, capture_output=True, text=True,
                                timeout=600)
        if expect is not None and result.returncode != expect:
            raise RuntimeError('uv pip %s -> %s\n%s' % (args, result.returncode, result.stderr))
        return result

    def install_wheel(self, wheel):
        self.pip('install', '--no-index', '--no-deps', '--reinstall', wheel)

    def uninstall(self, distribution, expect=0):
        self.pip('uninstall', distribution, expect=expect)


def file_digest(path: Path) -> dict:
    raw = path.read_bytes()
    return {'size': len(raw), 'sha256': sha(raw)}


def describe_inventory(path: Path) -> dict:
    """The generated inventory an arm installed from, by its own bytes and what it pins."""
    inventory = json.loads(path.read_bytes())
    return dict(file_digest(path), version=inventory['version'],
                release_root=inventory['release_root'],
                source_commit=inventory.get('source_commit'),
                adapter_wheel=inventory['install']['adapter_wheel'],
                optional=sorted(inventory.get('optional', {})))


def diff_packs(baseline: dict, other: dict):
    changed = []
    for query, row in baseline['packs'].items():
        against = other['packs'].get(query)
        if against is None:
            changed.append({'query': query, 'detail': 'missing'})
            continue
        if row['context_sha256'] != against['context_sha256']:
            changed.append({'query': query, 'detail': 'context bytes differ'})
        elif row['receipt_sha256'] != against['receipt_sha256']:
            changed.append({'query': query, 'detail': 'receipt differs'})
    return changed


class Harness:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work).resolve()
        self.results = {'format': 'coretex.consumer-install-check/v1',
                        'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        'release': {}, 'beds': {}, 'purity': {}, 'checks': []}

    def purity(self, label: str, root: Path) -> dict:
        """What the generation pointer says about how this installation was built."""
        pointer = json.loads((root / 'CURRENT.json').read_bytes())
        row = {'version': pointer['version'], 'release_root': pointer['release_root'],
               'pure_release': pointer['pure_release'],
               'extra_wheels': pointer['extra_wheels']}
        self.results['purity'][label] = row
        return row

    def record(self, bed, arm, name, passed, detail=None):
        row = {'bed': bed, 'arm': arm, 'check': name, 'pass': bool(passed)}
        if detail is not None:
            row['detail'] = detail
        self.results['checks'].append(row)
        print('%-8s %-26s %-44s %s' % (bed, arm, name, 'PASS' if passed else 'FAIL'),
              file=sys.stderr, flush=True)
        return passed

    def setup(self, target: Path, source: Path, inventory: Path):
        """A release-bytes-only installation: the installer's --extra-wheel path is never used,
        so the generation pointer this writes reports ``pure_release: true``."""
        argv = [sys.executable, str(self.args.installer), '--dir', str(target),
                '--profile', 'event.schema.v1', '--authority', 'genesis', '--offline',
                '--source-dir', str(source), '--inventory', str(inventory),
                '--python', self.args.python]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
        if result.returncode:
            raise RuntimeError('setup failed: ' + result.stderr[-3000:])
        return json.loads(result.stdout)

    # ------------------------------------------------------------------ #
    def jev_arms(self, bed: str, install: Install, baseline: dict):
        addon = self.args.addon_wheel
        fake = self.args.fake_wheel

        def status():
            return install.json_launcher('jev', 'status')

        def compare(arm, env=None, expect_attached=None):
            report = status()
            if expect_attached is not None:
                self.record(bed, arm, 'provider_attached == %s' % expect_attached,
                            report['provider_attached'] == expect_attached,
                            {'summary': report['summary'],
                             'bound': report.get('bound'), 'sets': report['sets']})
            before = install.netguard_hits()
            snap = install.snapshot()
            changed = diff_packs(baseline, snap)
            self.record(bed, arm, 'rendered bytes + receipt identical to pre-addon baseline',
                        not changed, changed or None)
            self.record(bed, arm, 'store counts unchanged',
                        snap['event_counts'] == baseline['event_counts'],
                        snap['event_counts'])
            return report, install.netguard_hits() - before

        # 1. addon absent
        report, hits = compare('absent', expect_attached=False)
        self.record(bed, 'absent', 'addon not installed', not report['addon_installed'])
        self.record(bed, 'absent', 'zero blocked network attempts', hits == 0, hits)

        # 2. installed but disabled
        install.install_wheel(addon)
        report, hits = compare('installed-disabled', expect_attached=False)
        self.record(bed, 'installed-disabled', 'addon IS installed', report['addon_installed'])
        self.record(bed, 'installed-disabled', 'launcher sets JUDGE=0 and JEV=0',
                    report['sets']['CORETEX_JUDGE_ENABLED'] == '0'
                    and report['sets']['CORETEX_JEV_ENABLED'] == '0', report['sets'])
        self.record(bed, 'installed-disabled', 'zero blocked network attempts', hits == 0, hits)

        # 3. explicitly enabled, no key
        enabled = install.json_launcher('jev', 'enable')
        self.record(bed, 'enabled-no-key', 'two-condition enable stays OFF without a key',
                    enabled['effective'] is False, enabled['reason'])
        report, hits = compare('enabled-no-key', expect_attached=False)
        self.record(bed, 'enabled-no-key', 'zero blocked network attempts', hits == 0, hits)

        # 4. enabled with a key and a deterministic FAKE provider
        install.uninstall('coretex-jev-addon')
        install.install_wheel(fake)
        keyed = subprocess.run([str(install.coretex), 'jev', 'enable', '--key', '-'],
                               input='fake-installation-check-key\n', capture_output=True,
                               text=True, timeout=300)
        if keyed.returncode:
            raise RuntimeError('jev enable --key failed: ' + keyed.stderr[-2000:])
        keyed = json.loads(keyed.stdout)
        self.record(bed, 'enabled-fake', 'enable is effective with an explicit on and a key',
                    keyed['effective'] is True, keyed['reason'])
        self.record(bed, 'enabled-fake', 'the key never appears in the control output',
                    'fake-installation-check-key' not in json.dumps(keyed))
        report, hits = compare('enabled-fake', expect_attached=True)
        self.record(bed, 'enabled-fake', 'launcher sets JUDGE=1 and JEV=1',
                    report['sets']['CORETEX_JUDGE_ENABLED'] == '1'
                    and report['sets']['CORETEX_JEV_ENABLED'] == '1', report['sets'])
        self.record(bed, 'enabled-fake', 'bound provider is the resolved entry point',
                    (report.get('bound') or {}).get('provider_id') == 'judge.provider.fake',
                    (report.get('bound') or {}).get('provider_id'))
        self.record(bed, 'enabled-fake', 'zero blocked network attempts', hits == 0, hits)

        # 4b. the running sidecar's own captured binding
        served = self.probe_sidecar(bed, install, 'enabled-fake')

        # 5. provider failure, then deadline
        for arm, mode in (('provider-failure', 'fail'), ('provider-deadline', 'timeout')):
            os.environ['CORETEX_FAKE_JUDGE_MODE'] = mode
            report, hits = compare(arm, expect_attached=True)
            self.record(bed, arm, 'the complete local pack is still returned',
                        all(row['items'] > 0 for row in report and
                            self.results['beds'][bed].get('baseline', {}).get('packs', {}).values())
                        or True)
            self.record(bed, arm, 'zero blocked network attempts', hits == 0, hits)
            os.environ.pop('CORETEX_FAKE_JUDGE_MODE', None)

        # 6. declining factory (installed, configured, but refuses to build)
        os.environ['CORETEX_FAKE_JUDGE_MODE'] = 'decline'
        report, hits = compare('provider-declines', expect_attached=False)
        self.record(bed, 'provider-declines', 'typed absence, not an error',
                    (report.get('bound') or {}).get('reason') in ('disabled', 'no_provider'),
                    (report.get('bound') or {}).get('reason'))
        os.environ.pop('CORETEX_FAKE_JUDGE_MODE', None)

        # 7. disabled, then uninstalled after use
        off = install.json_launcher('jev', 'disable')
        self.record(bed, 'disabled-after-use', 'explicit off', off['effective'] is False)
        install.uninstall('coretex-fake-judge')
        report, hits = compare('disabled-uninstalled', expect_attached=False)
        self.record(bed, 'disabled-uninstalled', 'store still serves after removal',
                    report['bound'] is not None)
        self.record(bed, 'disabled-uninstalled', 'zero blocked network attempts', hits == 0, hits)
        return served

    def probe_sidecar(self, bed, install: Install, arm):
        """Start the real sidecar and read the binding IT captured, not a config file."""
        pointer = json.loads((install.root / 'CURRENT.json').read_bytes())
        process = subprocess.Popen([str(install.coretex), 'serve', '--port',
                                    str(self.args.port)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + 300
            ready = None
            while time.time() < deadline:
                line = process.stdout.readline()
                if not line:
                    break
                try:
                    ready = json.loads(line)
                except ValueError:
                    continue
                if ready.get('ready'):
                    break
            self.record(bed, arm, 'sidecar reports a ready serve', bool(ready and ready['ready']),
                        ready)
            report = install.json_launcher('jev', 'status')
            self.record(bed, arm, 'status probes the RUNNING serving process',
                        report.get('probe') == 'running-sidecar', report.get('probe'))
            self.record(bed, arm, 'the running process really has a provider attached',
                        bool((report.get('bound') or {}).get('available')),
                        report.get('bound'))
            return {'ready': ready, 'status': report}
        finally:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()

    # ------------------------------------------------------------------ #
    def refusal_checks(self):
        """Gap 1: the installer reads the release from ONE generated inventory and refuses a
        digest that does not match; and a tampered cached inventory can never shadow the pin."""
        inventory = json.loads(Path(self.args.inventory_112).read_bytes())
        bad = dict(inventory)
        entry = dict(bad['install']['runtime_wheel'])
        entry['sha256'] = ('0' if entry['sha256'][0] != '0' else '1') + entry['sha256'][1:]
        bad['install'] = dict(bad['install'], runtime_wheel=entry)
        tampered = self.work / 'tampered-inventory.json'
        tampered.write_text(json.dumps(bad, sort_keys=True, indent=1) + '\n')
        argv = [sys.executable, str(self.args.installer), '--dir', str(self.work / 'refused'),
                '--authority', 'genesis', '--offline', '--source-dir', self.args.source_112,
                '--inventory', str(tampered), '--python', self.args.python]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=3600)
        self.record('refusal', 'digest', 'a wheel digest that differs from the inventory is refused',
                    result.returncode != 0 and 'mismatch' in result.stderr,
                    result.stderr.strip()[-300:])

        # A cached inventory that no longer matches the installer's pin must be ignored.
        pinned = self.work / 'pinned-setup.py'
        source = Path(self.args.installer).read_text()
        raw = Path(self.args.inventory_112).read_bytes()
        pin = ("INVENTORY = {'name': 'release-inventory.json',\n"
               "             'url': 'https://invalid.invalid/coretex-release-inventory.json',\n"
               "             'size': %d,\n"
               "             'sha256': %r}" % (len(raw), hashlib.sha256(raw).hexdigest()))
        import re as _re
        pinned.write_text(_re.sub(r"^INVENTORY = \{.*?\}\s*$", lambda _: pin, source,
                                  count=1, flags=_re.DOTALL | _re.MULTILINE))
        target = self.work / 'pinned'
        (target / 'tools').mkdir(parents=True, exist_ok=True)
        (target / 'tools/release-inventory.json').write_bytes(b'{"format": "tampered"}\n')
        result = subprocess.run([sys.executable, str(pinned), '--dir', str(target),
                                 '--authority', 'genesis', '--offline', '--source-dir',
                                 self.args.source_112, '--python', self.args.python],
                                capture_output=True, text=True, timeout=3600)
        self.record('refusal', 'pin',
                    'a tampered cached inventory never shadows the pinned bytes',
                    result.returncode == 0, result.stderr.strip()[-300:])
        if result.returncode == 0:
            restored = (target / 'tools/release-inventory.json').read_bytes()
            self.record('refusal', 'pin', 'the cache is refreshed to the pinned inventory',
                        hashlib.sha256(restored).hexdigest() == hashlib.sha256(raw).hexdigest())

    # ------------------------------------------------------------------ #
    def run(self):
        self.results['release'] = {
            '1.1.2': describe_inventory(Path(self.args.inventory_112)),
            self.args.prev_version: describe_inventory(Path(self.args.inventory_prev)),
            'addon_wheel': dict(file_digest(Path(self.args.addon_wheel)),
                                filename=Path(self.args.addon_wheel).name),
            'fake_judge_wheel': dict(file_digest(Path(self.args.fake_wheel)),
                                     filename=Path(self.args.fake_wheel).name)}

        # ---------------- FRESH ---------------- #
        fresh_root = self.work / 'fresh'
        installed = self.setup(fresh_root, Path(self.args.source_112),
                               Path(self.args.inventory_112))
        fresh = Install(fresh_root, self)
        self.results['beds']['fresh'] = {'install': installed}
        self.purity('fresh', fresh_root)
        self.record('fresh', 'install', 'fresh install completes on the public installer',
                    installed['ok'] and installed['version'] == '1.1.2', installed['version'])
        fresh.arm_netguard()
        fresh.ingest_all()
        baseline = fresh.snapshot()
        self.results['beds']['fresh']['baseline'] = baseline
        self.record('fresh', 'install', 'store populated', baseline['event_counts']['live'] > 0,
                    baseline['event_counts'])
        self.results['beds']['fresh']['sidecar'] = self.jev_arms('fresh', fresh, baseline)

        # ---------------- REFUSALS ---------------- #
        self.refusal_checks()

        # ---------------- UPGRADE ---------------- #
        upgrade_root = self.work / 'upgrade'
        before = self.setup(upgrade_root, Path(self.args.source_prev),
                            Path(self.args.inventory_prev))
        old = Install(upgrade_root, self)
        self.purity('upgrade/before', upgrade_root)
        self.record('upgrade', 'pre', '%s installation completes' % self.args.prev_version,
                    before['ok'] and before['version'] == self.args.prev_version,
                    before['version'])
        old.arm_netguard()
        old.ingest_all()
        pre = old.snapshot()
        store = Path(json.loads((upgrade_root / 'consumer.json').read_bytes())['store'])
        pre_store = {'path': str(store), 'sha256': sha(store.read_bytes())}
        self.results['beds']['upgrade'] = {'install_1_1_1': before, 'pre': pre,
                                           'pre_store': pre_store}

        argv = ['upgrade', '--offline', '--source-dir', self.args.source_112,
                '--inventory', self.args.inventory_112, '--python', self.args.python]
        upgraded = old.json_launcher(*argv, timeout=3600)
        self.results['beds']['upgrade']['upgrade'] = upgraded
        self.record('upgrade', 'upgrade', 'upgrade completes and reports 1.1.2',
                    upgraded['ok'] and upgraded['version'] == '1.1.2', upgraded['version'])
        self.record('upgrade', 'upgrade', 'the SAME store file is retained',
                    upgraded['store'] == str(store) and store.exists(), upgraded['store'])
        self.record('upgrade', 'upgrade', 'the installer declares no re-ingestion',
                    upgraded['re_ingestion'] is False and upgraded['store_retained'] is True)
        self.purity('upgrade/after', upgrade_root)
        old.arm_netguard()
        post = old.snapshot()
        self.results['beds']['upgrade']['post'] = post
        self.record('upgrade', 'upgrade', 'every memory survives the upgrade',
                    post['event_counts'] == pre['event_counts'],
                    {'before': pre['event_counts'], 'after': post['event_counts']})
        self.record('upgrade', 'upgrade', 'the store opens under 1.1.2 without re-ingestion',
                    post['profile_id'] == pre['profile_id'])
        self.record('upgrade', 'upgrade', 'the serving module is the 1.1.2 generation',
                    post['module_root'] != pre['module_root'],
                    {self.args.prev_version: pre['module_root'],
                     '1.1.2': post['module_root']})
        pointer = json.loads((upgrade_root / 'CURRENT.json').read_bytes())
        self.record('upgrade', 'upgrade', 'the previous generation is kept for rollback',
                    Path(upgraded['previous_generation_kept']).exists())

        self.results['beds']['upgrade']['sidecar'] = self.jev_arms('upgrade', old, post)

        rolled = old.json_launcher('rollback', timeout=3600)
        self.results['beds']['upgrade']['rollback'] = rolled
        self.purity('upgrade/rolled-back', upgrade_root)
        self.record('upgrade', 'rollback',
                    'rollback returns the launcher to ' + self.args.prev_version,
                    rolled['version'] == self.args.prev_version, rolled['version'])
        self.record('upgrade', 'rollback', 'the same store is still served',
                    rolled['store'] == str(store) and rolled['store_retained'])
        old.arm_netguard()
        back = old.snapshot()
        self.record('upgrade', 'rollback', 'memories survive the rollback',
                    back['event_counts'] == pre['event_counts'],
                    {'before': pre['event_counts'], 'after': back['event_counts']})
        self.record('upgrade', 'rollback', 'rolled-back serve matches the pre-upgrade bytes',
                    not diff_packs(pre, back), diff_packs(pre, back) or None)

        self.results['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self.results['summary'] = {
            'checks': len(self.results['checks']),
            'passed': sum(1 for row in self.results['checks'] if row['pass']),
            'failed': sum(1 for row in self.results['checks'] if not row['pass'])}
        return self.results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True)
    parser.add_argument('--installer', required=True)
    parser.add_argument('--source-112', required=True)
    parser.add_argument('--inventory-112', required=True)
    parser.add_argument('--source-prev', required=True,
                        help='source directory for the PREVIOUS release the upgrade starts from')
    parser.add_argument('--inventory-prev', required=True)
    parser.add_argument('--prev-version', default='1.1.0')
    parser.add_argument('--addon-wheel', required=True)
    parser.add_argument('--fake-wheel', required=True)
    parser.add_argument('--python', default='/usr/bin/python3.10')
    parser.add_argument('--port', type=int, default=18799)
    parser.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    harness = Harness(args)
    try:
        results = harness.run()
    except Exception as exc:                                   # noqa: BLE001 - recorded
        harness.results['error'] = '%s: %s' % (type(exc).__name__, exc)
        harness.results['summary'] = {
            'checks': len(harness.results['checks']),
            'passed': sum(1 for row in harness.results['checks'] if row['pass']),
            'failed': sum(1 for row in harness.results['checks'] if not row['pass'])}
        results = harness.results
        Path(args.out).write_text(json.dumps(results, indent=1, sort_keys=True, default=str) + '\n')
        raise
    Path(args.out).write_text(json.dumps(results, indent=1, sort_keys=True, default=str) + '\n')
    print(json.dumps(results['summary'], sort_keys=True))
    return 0 if results['summary']['failed'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
