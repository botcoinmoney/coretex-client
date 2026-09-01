# CoreTex validator client 1.0.0

The first-public standalone client in this repository is the `coretex-validator` Python package
under `python/`. The root TypeScript workspace is a private contract-codec test harness; it has no
package exports or publication script and is not a CoreTex release artifact.

Admission uses one deterministic canonical suite,
`benchmark-v2-law/dominance-fixed-suite.v2`. A candidate must stay inside the fixed product cap
on every resource axis, hold every declared quality objective within the bounded trade of the
exact accepted parent (no objective may fall more than 2.5 points in one step or sit more than
2.5 points below the genesis floor, and every point lost must be paid by two points gained on
other objectives), keep the quality composite at or above the genesis composite, and must satisfy
the declared improvement threshold. Candidate IDs, retries, epoch entropy, authors, rigs, and
submission order do not select another exam.

## Authority and activation

The canonical release directory is the product authority. `RELEASE.json` binds every law,
configuration, ABI, support document, contract-authority object, and distributable artifact. The
validator wheel carries the closed validation inputs needed to verify that supplied directory; it
does not embed its own final release hash, because the release binds the wheel bytes.

The public chain scan floor is a separate canonical file:

```json
{
  "activation": {
    "confirmed_block": 55000000,
    "epoch": 200
  },
  "format": "coretex.public-activation/v1"
}
```

Both coordinates are mandatory. The epoch is the first public CoreTex epoch, and
`confirmed_block` is the exact confirmed `CoreTexEpochContextSet` event block for that epoch.

## Install and verify

```sh
python -m pip install ./python
coretex-validator selftest
coretex-validator verify-release \
  --release /path/to/v5/release \
  --activation /path/to/PUBLIC-ACTIVATION.json
```

To inspect the one current event vocabulary:

```sh
coretex-validator topics
```

`verify-descriptor` checks a confirmed 97-byte descriptor, its addressed transition artifact,
the release-derived epoch context, and the resulting frontier root. Run
`coretex-validator verify-descriptor --help` for its explicit inputs.

## Development

```sh
cd python
python -m pip install -e '.[dev]'
python -m pytest -q

cd ..
npm run typecheck
npm test
```

The npm commands exercise the private contract-codec harness only; they do not build or publish the
standalone client.

The Python validator has zero runtime dependencies. Keccak-256, secp256k1 recovery, ABI encoding,
canonical JSON, and JSON-RPC are implemented with the standard library and covered by focused
tests.
