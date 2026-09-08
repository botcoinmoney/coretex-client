"""The downloadable consumer wheel must contain precisely the reviewed public source."""
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def test_consumer_wheel_matches_source_and_declares_no_validator():
    wheel = ROOT / 'consumer-artifacts/coretex_consumer-0.1.0-py3-none-any.whl'
    expected, name = (ROOT / 'consumer-artifacts/SHA256SUMS').read_text().split()
    assert name == str(wheel.relative_to(ROOT))
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == expected
    source = ROOT / 'integrations/consumer/coretex_consumer'
    expected_members = {'coretex_consumer/' + path.name: path.read_bytes() for path in source.glob('*.py')}
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names))
        observed = {name: archive.read(name) for name in names if name.startswith('coretex_consumer/')}
        assert observed == expected_members
        assert not any(name.startswith(('coretex_memory/', 'coretex_memory_agent/', 'coretex_validator/'))
                       for name in names)
        metadata = archive.read('coretex_consumer-0.1.0.dist-info/METADATA').decode()
        assert 'Requires-Dist: coretex-memory-agent==1.1.0' in metadata
        assert 'Requires-Dist: coretex-validator' not in metadata
        entry = archive.read('coretex_consumer-0.1.0.dist-info/entry_points.txt').decode()
        assert 'coretex-consumer = coretex_consumer.cli:main' in entry
        assert '\ncoretex =' not in entry  # never overwrite the sealed adapter's command
