# CoreTex consumer sync

`coretex-consumer` lets the memory adapter follow the confirmed chain frontier
without installing the validator or replaying admission history. It uses the
unchanged `coretex-memory-agent==1.1.0` and its runtime, module, ABI and retrieval
provider checks. The sealed product release and its build inputs stay unchanged.

For a new installation on Linux amd64 with curl and Python 3.8+:

```sh
curl -fsSLo coretex-setup.py https://agentmoney.net/coretex-setup.py
python3 coretex-setup.py --dir ./coretex --profile conv.pref.v1
```

Setup manages Python 3.10, the exact release/dependency downloads, current-state
sync and store readiness. No RPC configuration, sudo or validator replay is needed.
Use `./coretex/bin/coretex sync` for later updates and
`./coretex/bin/coretex serve` for the private sidecar. The
[full setup guide](https://github.com/botcoinmoney/coretex-client/blob/main/CONSUMER-SETUP.md)
includes ingestion, recall, existing stores and the separate Hermes installation.

The lower-level API below is for an already installed consumer package and
verified release directory.

```sh
coretex-consumer sync --config ./consumer.json --release-dir ./release \
  --expected-release-root fb1a0c66ce641b9df4ca1a9c630357a0057d7ea4159c910c4a09776ed0749bec \
  --out ./current --store ./memory.db --profile conv.pref.v1
coretex-consumer prewarm --config ./consumer.json
coretex-consumer context --config ./consumer.json --budget 800 'What do we remember?'
```

No RPC account, API key, or endpoint configuration is needed. Sync automatically
uses the public Base endpoint and public CoreTex object service. Initial
release/model download is still required. Sync makes current-state RPC
reads at a single confirmed block and downloads only the current executable
closure. It verifies chain id, deployed contract code and bindings, epoch context,
compatibility lock, frontier, composition, per-profile module roots, source bytes,
static capabilities, ABI and retrieval provider. It rechecks the observation for
reorgs and intervening frontier changes before publishing an immutable directory.
Requests and retries are bounded; previous state survives a failed sync.

The local format is `coretex.current-state/v1`, with
`provenance = {"mode":"chain-pointer","admission_replayed":false}`. It is deliberately
different from a validator replay snapshot. The configured RPC is trusted for
chain observations; CAS supplies untrusted bytes checked against those roots.
This proves which modules the chain selected, not that each admission was lawful.
Full validator replay remains the independent audit path.

Consumer configuration refreshes on each open, including sidecar restart. An open
sidecar keeps one stable module until restart; writes are never interrupted by a
background module swap. A failed refresh refuses the new open; it does not erase
the store or stop a sidecar already running. An offline application can explicitly
load a retained `CurrentState` and call `authority_from_current` without claiming
freshness. A new product compatibility lock requires bootstrapping that release.

Optional advanced overrides are `--rpc URL`, `--rpc-env NAME` and `--rpc-file PATH`. The
default is 12 confirmations; “latest” means the current confirmed frontier.
Public endpoint rate limits can affect refresh latency. Cache and immutable
generation files belong to the local user and must not be writable by untrusted
processes. Automatic module use still needs trust or external process confinement;
the adapter's serving worker is not the evaluator's kernel sandbox.

See the public client's `CONSUMER-SETUP.md` for the complete two-environment
Hermes setup. Its sidecar launcher accepts this consumer config as well as the
existing explicit audit-snapshot config.
