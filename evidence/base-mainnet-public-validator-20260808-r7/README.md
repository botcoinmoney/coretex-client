# Independent public validator proof — Base epoch 8 transition 0

Date: 2026-08-08 UTC

This directory records an independent replay performed on `root@185.189.46.79`
(`precise-reindeer`). The proof used a new environment under
`/opt/coretex-public-validator-20260808-r7-g8uhxF`, outside every source tree.
No private RPC, source-checkout import, editable install, or production mutation was
used. Chain reads used only `https://mainnet.base.org`; artifacts and replay trees were
retrieved from their public object-storage URLs.

## Inputs

- validator wheel: `coretex_validator-0.1.0-py3-none-any.whl`, 296,994 bytes,
  SHA-256 `3c5b9662e0c774d18d9ede485fcb86103b15d463fa8c49469b3431991b6880da`
- runtime wheel: `coretex_memory-0.1.2-py3-none-any.whl`, 215,557 bytes,
  SHA-256 `7c304fca98809fe756d6d1143a00de9689237af88f5df7d23b92aca904c299a6`
- replay trees: 8,202,240-byte public tar, SHA-256
  `154f1338dadc86d514588d195e301b854f34e39c01c1e3bf0fd48f38ba4a764a`;
  514 safe entries under only `benchmark-v2/` and `coretex-memory/`
- release: 1,268 bytes, SHA-256
  `625ae2f237e1f20ace474f25fea0bb9a47c56fc7745e895ff4fdc777dc263e0c`
- published snapshot: 28,471 bytes, SHA-256
  `49dac6c1237c49430b07b89aa7ef13e8af0487157c24cd781450cfeb21e60e3f`
- 27 public accepted-transition objects: every byte length, content root, raw SHA-256,
  public URL, and remote CAS path is in `public-downloads.json`

The public-input download inventory is itself 16,732 bytes with SHA-256
`3d72b15e95f86ec11d5bddf72a7e5c40cf30d2f7eb8ba6f6c3683bc0c83bc4aa`.

## Snapshot identity

The clean public host independently ran:

```sh
env -u PYTHONPATH \
  /opt/coretex-public-validator-20260808-r7-g8uhxF/venv/bin/coretex-validator \
  --compact reproduce-snapshot \
  --snapshot /opt/coretex-public-validator-20260808-r7-g8uhxF/downloads/snapshot.json \
  --rpc https://mainnet.base.org \
  --artifacts /opt/coretex-public-validator-20260808-r7-g8uhxF/cas \
  --out /opt/coretex-public-validator-20260808-r7-g8uhxF/reports/reproduced-snapshot.json \
  --min-interval 0.7
```

The independently reconstructed output was byte-identical: 28,471 bytes and SHA-256
`49dac6c1237c49430b07b89aa7ef13e8af0487157c24cd781450cfeb21e60e3f`.
The locally returned exact bytes are at
`/tmp/coretex-public-replay-evidence-r7-Lq0bHU/reports/reproduced-snapshot.json` and
are byte-identical to `/tmp/coretex-resolver-snapshot-epoch8-20260808.json`.

## Complete replay command

The successful complete replay used the receipt's pinned host law: Python 3.10.20
from the exact image below and an explicit four-CPU limit.

```sh
docker run --rm \
  --cpuset-cpus=0-3 --cpus=4 --pids-limit=256 \
  --security-opt=no-new-privileges \
  -v /opt/coretex-public-validator-20260808-r7-g8uhxF:/proof \
  -w /tmp \
  python:3.10-slim@sha256:c1e4e6c01eb489c422288b2de34b0761ca316f7a2d98e2c33f47659a73ed108a \
  sh -lc 'env -u PYTHONPATH \
    CORETEX_ADMISSION_REPO_ROOT=/proof/trees \
    CORETEX_BENCHMARK_V2_DIR=/proof/trees/benchmark-v2 \
    CORETEX_MEMORY_RUNTIME_DIR=/proof/trees/coretex-memory \
    /proof/venv-py310/bin/coretex-validator --compact reproduce \
    --require-complete \
    --release /proof/downloads/validator-release.json \
    --rpc https://mainnet.base.org \
    --epoch 8 --transition-index 0 \
    --artifact-dir /proof/cas \
    --snapshot /proof/downloads/snapshot.json \
    --from-block 49708835 --to-block 49709494 \
    --confirmation-depth 64 \
    --export /proof/reports/unsigned-activation-proof-py310.json'
```

The venv was created inside the public-input work directory. It installed the exact
validator and runtime wheels without editable mode, plus public PyPI
`wasmtime==46.0.1`. Only the two extracted public replay-tree roots and the venv's
stdlib/site-packages were on the candidate child's allow-listed import path. The
candidate child installed and proved its networkless seccomp filter before execution.

## Results

The pinned Python 3.10 run exited zero. All eight stages passed:
`discover_release`, `verify_deployment`, `receipt_continuity`, `join_transition`,
`deterministic_admission`, `historical_law`, `resolver_snapshot`, and `export`.
`unverified` is empty. The export root is
`b3d7c340f28615d0001e11a0cfbcc0e928e47c03a590b5257d57dee81442b436`.

- `validator-run-py310.json`: 42,660 bytes, SHA-256
  `07668749f9e37c6cf80dc3dbe1bfb1c2bcf6e37188127de444047dd5d344985f`
- `unsigned-activation-proof.json`: 33,811 bytes, SHA-256
  `d2547c81e612f2ce5473738b8abf5eb6b4cea5d1e0b11cdf243554104f59936e`
- `sandbox-detail-py310-4cpu.json`: 47,772 bytes, SHA-256
  `4e857abed5b3ea0ab7966b1e989295092eb0f5c9348830de9a6c792841e8cf34`;
  rebuilt report root exactly
  `6f2cf67d10122263d0733cf5e262819ccd7544abe14624be9257db168b08d565`

## Fail-closed compatibility control

The unchanged public inputs were also run with four CPUs under the host's Python
3.12.3. Chain/deployment/receipt/join checks passed, but deterministic admission
correctly failed closed: rebuilt root
`19656b1d214afd84d39366cb4a4d42618487767cadbefa0eb2fc7f9981e2b85b`
did not equal the bound root `6f2cf67d...`; differing blocks were `outputs_hash`,
`scores`, and `verdicts`. No export was produced by that run.

- `validator-run-py312-fail-closed.json`: 12,199 bytes, SHA-256
  `9b537314820533c2c4921b68f6faa2154ea545086737321ab7e441978e747f59`
- `sandbox-detail-py312-4cpu.json`: 49,538 bytes, SHA-256
  `3b97fc72c818e825c892bef7262cca51ecbe3b15cd7d844440c30a56a0642f67`

The 3.10 and 3.12 detail reports preserve the bound and rebuilt score, output-hash,
and verdict blocks; code roots; selected cases and seeds; networkless proof; import
origins; Python/platform/distribution versions; and exact replay-tree paths.
