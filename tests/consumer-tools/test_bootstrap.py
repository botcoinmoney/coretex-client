import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bootstrap', ROOT / 'tools/coretex-bootstrap.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def test_paths_refuse_escape_and_ambiguous_spelling(self):
        for value in ('../x', '/x', 'a/../../x', 'a//b', 'a/./b', 'x\\y', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bootstrap.relative(value)

    def test_json_materialization_requires_exact_declared_bytes(self):
        raw = b'{"b":2,"a":1}'
        expected = b'{\n  "a": 1,\n  "b": 2\n}\n'
        binding = {'path': 'test.json', 'size': len(expected), 'raw_sha256': bootstrap.sha(expected)}
        self.assertEqual(bootstrap.restore(raw, binding), expected)
        with self.assertRaises(ValueError):
            bootstrap.restore(b'{"a":3,"b":2}', binding)

    def test_duplicate_keys_and_nonfinite_refused(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError):
                bootstrap.parse(raw)

    def test_coordinator_origin_refuses_credentials_and_non_https(self):
        for value in ('http://host', 'https://user:secret@host', 'https://host/path',
                      'https://host?key=secret'):
            with self.assertRaises(ValueError):
                bootstrap.Public(value)

    def test_numeric_archive_refuses_links(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            path = out / 'numeric.tar'
            with tarfile.open(path, 'w') as archive:
                item = tarfile.TarInfo('CPU-RUNTIME.json')
                item.type = tarfile.SYMTYPE
                item.linkname = '/tmp/escape'
                archive.addfile(item)
            raw = path.read_bytes()
            release = {'artifacts': {'numeric_runtime_amd64': {
                'path': 'numeric.tar', 'size': len(raw), 'sha256': bootstrap.sha(raw)}}}
            with self.assertRaises(ValueError):
                bootstrap.numeric_wheels(out, release)

    def test_expected_release_refused_before_download_or_output_creation(self):
        class Public:
            def get(self, path):
                return json.dumps({'release': {'releaseRoot': 'a' * 64}}).encode()
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'release'
            with self.assertRaises(ValueError):
                bootstrap.bootstrap(Public(), out, 'b' * 64)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
