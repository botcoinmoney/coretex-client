# coretex-validator 1.1.2

`coretex-validator` independently verifies the prospective CoreTex fixed-suite rig lane from
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
  --release /path/to/v5/release-1.1.2 \
  --activation /path/to/PUBLIC-ACTIVATION.json
```

The activation record contains exactly a positive epoch and a positive confirmed event block.
Public log discovery starts at that block and rejects any observed event below either coordinate.

Development checks:

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
```

## Building the wheel as a release sub-build

`build_release.py` is the only package builder, and it is meant to be invoked by the coordinator's
release cut rather than run by hand. The build target is derived from `pyproject.toml`, never
restated, so a caller discovers it instead of assuming it:

```sh
python3 build_release.py --print-target
# {"distribution": "coretex_validator", "out_dir": "...", "sdist_name": "...",
#  "version": "1.1.2", "wheel_name": "..."}
```

`--version X.Y.Z` asserts the version a caller expects: it can only agree with `pyproject.toml`,
never override it.

Five package data members — `CANONICAL-SUITE.v1.json`, `COUNTER_RESOURCE_LAW.v1.json`, `LAW.md`,
`RIG-CONTRACT-AUTHORITY.base-mainnet.json` and `RIG-WIRE-BINDING.v1.json` — are verbatim copies of
the coordinator tree's own law sources, and `RELEASE-CONTRACT.v1.json` names that tree's product
and law identity. Before cutting, prove the copies are still current:

```sh
python3 build_release.py --coordinator-repo /path/to/coordinator --verify-law-inputs
```

That writes nothing and exits non-zero naming every member that drifted. The source paths come out
of the coordinator's `v5/RELEASE-MANIFEST.<version>.json`, so relocating the law text there does
not need a matching edit here. Refreshing the copies is a separate, explicit step — law inputs are
never synced implicitly:

```sh
python3 build_release.py --coordinator-repo /path/to/coordinator \
  --sync-law-inputs --sync-release-contract
```

The wheel itself has no runtime dependencies. Full canonical hybrid replay materializes the
release's closed CPU dependency and model inventory and requires Linux amd64 CPython 3.10.
ARM adapter serving is separately qualified. Initial working module bindings are distinct from
the builtin reference floors; accepted children are replayed against their actual parent module.
