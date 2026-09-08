import importlib.util
import io
from pathlib import Path
import unittest
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'python'))
spec = importlib.util.spec_from_file_location('progress', ROOT / 'tools/coretex-snapshot.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SnapshotProgressTests(unittest.TestCase):
    def test_transport_propagates_data_without_changing_parameters(self):
        calls = []
        class Rpc:
            calls = 0
            rate_limited = 0
            def call(self, method, params):
                calls.append((method, params))
                return ['original-result']
        rpc = module.progress_rpc_class(Rpc, module.Progress())()
        params = [{'fromBlock': '0x12', 'toBlock': '0x34'}]
        stream = io.StringIO()
        with redirect_stderr(stream):
            self.assertEqual(rpc.call('eth_getLogs', params), ['original-result'])
        self.assertEqual(calls, [('eth_getLogs', params)])
        self.assertIn('18..52', stream.getvalue())

    def test_http403_is_actionable_and_does_not_print_rpc_secret(self):
        class Refusal(Exception):
            status = 403
        class Rpc:
            calls = 0
            def call(self, method, params):
                raise Refusal('https://secret-provider/key/DO-NOT-PRINT')
        rpc = module.progress_rpc_class(Rpc, module.Progress())()
        with self.assertRaises(RuntimeError) as caught:
            rpc.call('eth_chainId', [])
        self.assertIn('eth_getLogs', str(caught.exception))
        self.assertIn('mainnet.base.org', str(caught.exception))
        self.assertNotIn('DO-NOT-PRINT', str(caught.exception))

    def test_heartbeat_makes_long_silent_work_visible(self):
        progress = module.Progress(interval=.01)
        stream = io.StringIO()
        with redirect_stderr(stream):
            progress.thread.start()
            progress.stop.wait(.03)
            progress.stop.set()
            progress.thread.join()
        self.assertIn('elapsed_seconds', stream.getvalue())

    def test_full_command_passes_unfiltered_scan_to_unchanged_materializer(self):
        from coretex_validator import release, snapshot, discovery
        from coretex_validator.rpc import JsonRpc
        activation = SimpleNamespace(confirmed_block=100)
        installed = SimpleNamespace(authority={}, activation=lambda _: activation)
        scan = SimpleNamespace(decoded=SimpleNamespace(advances=[object()],
            coretex_credits=[SimpleNamespace(rig_id=73)],
            standard_credits=[SimpleNamespace(rig_id=42)]))
        document = {'epoch': {'id': 199}, 'frontier': {'root': 'a' * 64}, 'release_root': 'b' * 64}
        output = io.StringIO()
        with patch.object(release, 'load', return_value=installed), \
             patch.object(discovery, 'deployment_from_authority', return_value=SimpleNamespace(chain_id=8453, mining='0xabc')), \
             patch.object(JsonRpc, 'assert_chain'), patch.object(JsonRpc, 'get_logs', return_value=[]), \
             patch.object(discovery, 'scan_public_feed', return_value=scan), \
             patch.object(snapshot, 'materialize', return_value=document) as materialize, \
             redirect_stderr(io.StringIO()), redirect_stdout(output):
            code = module.main(['--release', '/release', '--activation', '/activation',
                '--rpc', 'https://rpc.example', '--objects', 'https://objects.example',
                '--out', '/snapshot', '--confirmations', '12'])
        self.assertEqual(code, 0)
        self.assertIs(materialize.call_args.kwargs['scan'], scan)
        self.assertEqual(len(scan.decoded.standard_credits), 1)
        self.assertEqual(materialize.call_args.kwargs['confirmation_depth'], 12)
        self.assertIn('"scope": "full"', output.getvalue())
