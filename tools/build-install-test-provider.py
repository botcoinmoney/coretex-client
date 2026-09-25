#!/usr/bin/env python3
"""Build the deterministic offline provider used by the real installer acceptance test."""
import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile


def build(output):
    dist = "coretex_fake_judge-0.1.0.dist-info"
    files = {
        "coretex_fake_judge/__init__.py": (Path(__file__).parent / "fixtures/install_judge_provider.py").read_bytes(),
        dist + "/METADATA": b"Metadata-Version: 2.1\nName: coretex-fake-judge\nVersion: 0.1.0\n",
        dist + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: coretex-install-check\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        dist + "/entry_points.txt": b"[coretex_memory.judge_providers]\nlive = coretex_fake_judge:factory\n",
        dist + "/top_level.txt": b"coretex_fake_judge\n",
    }
    record = io.StringIO(); writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([name, "sha256=" + digest, len(data)])
    writer.writerow([dist + "/RECORD", "", ""])
    files[dist + "/RECORD"] = record.getvalue().encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    print(build(Path(parser.parse_args().out)))
