# CoreTex memory adapter and Hermes

The supported consumer path is two environments on one Linux amd64 host:
CoreTex's release-bound Python 3.10 numeric bundle runs the memory sidecar;
Hermes uses Python 3.11 and the small `coretex-hermes-sidecar` connector. The
connector has no numeric dependencies. Only `conv.pref.v1` uses the hybrid
BM25/BGE-small RRF60 provider; event and document remain lexical. All three
profiles adopt their confirmed M5 modules. The adapter defaults to event, so
select conversation explicitly when you want hybrid retrieval.

These companion tools do not change the release, law, evaluator or validator.
The validator and adapter verify the exact installed 1.1.0 validator payload.
A locally modified validator or an arbitrary 1.1.1 wheel cannot replace it.

## Download and verify the complete release

Start with Python 3.10 and its `venv` support installed. The bootstrap itself
uses only the standard library and makes no global package changes.

```sh
git clone https://github.com/botcoinmoney/coretex-client.git
cd coretex-client
python3.10 tools/coretex-bootstrap.py --out ./release \
  --coordinator https://coordinator.agentmoney.net \
  --expected-release-root fb1a0c66ce641b9df4ca1a9c630357a0057d7ea4159c910c4a09776ed0749bec
```

This fetches every status-index release path, restores canonical JSON to the
release-declared raw hash and size, materializes the genesis wrapper, and runs
the unchanged sealed `coretex-validator verify-release`. It extracts the
amd64 numeric wheel inventory to `release/wheelhouse`. Only a fully verified
directory is moved to `--out`; a failure never leaves a successful-looking
release directory. Existing output is refused. Downloads are paced and bounded
HTTP rate-limit retries are visible on stderr.

The supplied root is the qualified 1.1.0 release, independent of future mined
frontier advances. Without `--expected-release-root`, HTTPS coordinator discovery
is your release trust anchor. The optional kit `consumer_tools` component is a
coordinator-hashed transport catalog, not an additional sealed release object.

```sh
python3.10 -m venv coretex-env
coretex-env/bin/python -m pip install --no-index \
  --find-links release/artifacts --find-links release/wheelhouse \
  'coretex-memory[hybrid]==1.1.0' coretex-memory-agent==1.1.0 coretex-validator==1.1.0
coretex-env/bin/python -m pip check
coretex-env/bin/coretex-validator verify-release --release ./release
```

## Verify current mined modules

An adapter adopts a locally verified chain snapshot, not an operator's unexplained
module file. Creating a cold snapshot replays the confirmed improvements. The
first consumer proof took 54 minutes, about 38 of which were deterministic replay;
this is an observation, not an ETA. More accepted transitions can increase cost.

```sh
coretex-env/bin/python tools/coretex-snapshot.py --release ./release \
  --activation https://coordinator.agentmoney.net/coretex/v5/activation \
  --rpc https://mainnet.base.org \
  --objects https://coordinator.agentmoney.net/coretex/v5/object/ \
  --out ./resolver --confirmations 12
coretex-env/bin/coretex verify-authority ./release ./resolver/resolver-snapshot.json
```

The companion prints discovery block windows, periodic elapsed-time updates,
CAS fetch activity and receipt-window read progress to stderr. Its output format
and checks are those of the unchanged sealed validator. `--preflight-only`
tests release verification and RPC log access without building a snapshot.
For a secret-bearing RPC URL, use the existing `--rpc-env NAME` or `--rpc-file PATH`
options. An RPC that answers `eth_chainId` may still refuse `eth_getLogs` with
403. The official Base endpoint worked in qualification; public endpoints are
rate limited and availability can change. No endpoint is switched automatically.
The default log window is 2,000 blocks. `--log-window 10000` is an optional
transport optimization only for endpoints that support it, not a universal rule.

There is no `--scope frontier` shortcut here: full transition replay, signer
verification, interleaved standard/CoreTex receipt continuity and reorg checks
remain enforced. Future acceleration must preserve these checks. The adapter's
snapshot parser is not evidence that a reduced scan proved equivalent trust.

## Start one private sidecar

```sh
coretex-env/bin/coretex init --config ./adapter.json --store ./memory.db \
  --profile conv.pref.v1 --release-dir ./release \
  --resolver-snapshot ./resolver/resolver-snapshot.json
coretex-env/bin/coretex prewarm --config ./adapter.json
coretex-env/bin/python tools/coretex-sidecar.py --config ./adapter.json --port 18761
```

Keep that process running. Wait for `ready: true`. Large existing lexical stores
should be prewarmed before traffic. The sidecar binds only 127.0.0.1 and opens
the module selected by the verified snapshot. One store is one user's private
scope/profile; this connector is not a multi-user gateway. The loopback API has
no authentication: isolate it from untrusted local processes. Future mined
Python modules require operator trust or external process/container confinement;
the pip serving worker is not the evaluator's kernel sandbox.

## Install Hermes and the connector

The qualified Hermes source is
`NousResearch/hermes-agent@e624e9fde561e1add9388384012b295fde669ade` (0.20.4).
Install Hermes using its documented installer, or in a separate Python 3.11 venv:

```sh
git clone https://github.com/NousResearch/hermes-agent.git hermes-source
git -C hermes-source checkout e624e9fde561e1add9388384012b295fde669ade
python3.11 -m venv hermes-env
hermes-env/bin/python -m pip install -e ./hermes-source ./integrations/hermes
mkdir -p ./hermes-home
```

Add this to `hermes-home/config.yaml` (use the same profile as the sidecar):

```yaml
memory:
  provider: coretex_sidecar
  memory_enabled: false
  user_profile_enabled: false
  coretex_sidecar:
    url: http://127.0.0.1:18761
    profile: conv.pref.v1
    budget: 800
    ready_timeout_seconds: 15
    timeout_seconds: 30
```

The pip entry point registers the provider; do not copy an older user plugin of
the same name into `HERMES_HOME/plugins` because Hermes gives that directory
precedence. Optional `expected_module_root` pins a specific adopted module and
refuses a different one; update it consciously when adopting a newer snapshot.

## Run a checked agent turn

Set your model API key in an environment variable. Put a synthetic fact into
`note.txt`, then run:

```sh
hermes-env/bin/coretex-hermes-chat --home ./hermes-home --prompt-file ./note.txt \
  --model gpt-4.1-mini --base-url https://api.openai.com/v1 --api-key-env OPENAI_API_KEY
```

The provided entrypoint runs one fresh, nonstreaming Hermes session with tools
disabled. It checks the bound store before generation, prepares recall, waits
for Hermes' asynchronous write, checks receipts and flushes before emitting an
answer with `memory_write_confirmed: true`. Missing providers, failed writes,
or timeouts return a nonzero exit without releasing an answer. A failed POST
can have an unknown commit outcome; no automatic write retry occurs. Inspect
the store/receipts and restart deliberately after reconciling an ambiguous write.

Ask for the fact using a new prompt file and a new invocation. Stop/restart the
sidecar and ask again to test durable reopen. A verbal “saved” is not proof;
check the machine completion flag and independent recall.

**Ordinary Hermes CLI/gateway mode is best effort.** Hermes catches provider
initialization and write exceptions. Installing this plugin alone does not
make every Hermes interface fail closed. Applications can use
`GuardedConversation` with buffered model output, or add an equivalent checked
completion boundary. Streaming answers/tools can act before durability is known
and are outside this connector's guarded qualification.

Recalled text remains the exact CoreTex render, JSON-quoted under a fixed
historical-data header. Old conversational instructions are records, not commands
for the current turn. This framing does not change the sealed renderer or its
meter; the wrapper adds a small amount of model context outside that meter.
Retrieval and downstream answer accuracy remain distinct. Run
`integrations/hermes/qualify_models.py --help` for the bounded three-turn-per-model
fixture; use only a dedicated synthetic test store. Qualification results are
small-sample evidence, not general guarantees or a substitute for your application's tests.
