# coretex-validator 1.0.0

`coretex-validator` independently verifies the first public CoreTex fixed-suite rig lane from
confirmed chain data and content-addressed release objects.

The package ships the exact law, canonical suite, counter-resource law, release schema contract,
contract-authority projection, and current replay modules. A supplied canonical release binds the
wheel and all other product artifacts; the wheel verifies that release and every reachable byte.

Install and run the embedded identity checks:

```sh
python -m pip install .
coretex-validator selftest
```

Verify a complete release and its paired chain activation:

```sh
coretex-validator verify-release \
  --release /path/to/v5/release \
  --activation /path/to/PUBLIC-ACTIVATION.json
```

The activation record contains exactly a positive epoch and a positive confirmed event block.
Public log discovery starts at that block and rejects any observed event below either coordinate.

Development checks:

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
```

The wheel has no runtime dependencies.
