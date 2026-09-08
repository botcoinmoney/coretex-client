# CoreTex memory adapter and Hermes

## Install and sync in two commands

On **Linux amd64** with `curl` and Python 3.8 or newer:

```sh
curl -fsSLo coretex-setup.py https://agentmoney.net/coretex-setup.py
python3 coretex-setup.py --dir ./coretex --profile conv.pref.v1
```

The second command installs everything into `./coretex`, verifies the public
release and exact dependency files, syncs the current confirmed modules, opens
the store and prepares its indexes. It provisions Python 3.10 privately if needed.
No sudo, global pip changes, Git checkout, RPC account, API key, wallet or chain
replay is needed. The first download includes the model/runtime bundle, so allow
a few minutes; subsequent current-state sync measured about 35–41 seconds in the
qualified runs, subject to public endpoint limits. Progress is printed throughout.
Success ends with JSON containing `"ok": true` and the installed command path.

`conv.pref.v1` selects hybrid BM25/BGE-small conversation retrieval. Omitting
`--profile` selects lexical `event.schema.v1`; `doc.tool.v1` is also lexical.
All three profiles adopt current confirmed mined modules. Use one installation
and store per profile. A conflicting existing directory/profile is refused.

The helper is also available from the [public client source](https://github.com/botcoinmoney/coretex-client/blob/main/tools/coretex-setup.py).
It downloads hash-pinned tools and wheels. Its private environment uses the
[Astral uv Python installer](https://docs.astral.sh/uv/guides/install-python/)
when Python 3.10 is missing. The current automated installer targets Linux amd64;
other platforms require separate qualification and manual package setup.

## Use it and keep it current

```sh
./coretex/bin/coretex ingest "The Cedarbrook deployment window is Friday."
./coretex/bin/coretex context "When is the Cedarbrook deployment window?" --budget 800
./coretex/bin/coretex sync
```

`sync` refreshes current modules from public endpoints. Re-running the original
setup command after success also syncs, retaining the existing store. A failed
install may be resumed with the same command; it never clears memories or creates
a success marker before the store passes its readiness check.

For an agent harness, start the private loopback sidecar:

```sh
./coretex/bin/coretex serve
```

Wait for `"ready": true`. The default address is `http://127.0.0.1:18761`.
`status`, `prewarm`, `ingest`, `context` and `serve` refresh before opening the store.
An open sidecar keeps one stable module until restart; it does not make a network
request per turn or replace executable code during a turn. To adopt a later
module, stop and restart that sidecar. An outage refuses a new open and preserves
the store and previous observations.

The installer writes `./coretex/consumer.json`, `./coretex/memory.db`,
`./coretex/release/` and immutable module generations under `./coretex/current/`.
Run the generated command from its actual path; no shell activation or PATH edit
is needed. With a custom `--dir`, use the path printed by setup.

For an **existing store**, stop its writer, back it up, and set `store` in
`consumer.json` to its absolute database path while retaining the same profile.
Run `./coretex/bin/coretex prewarm` before restarting traffic. This rebuilds derived
indexes and preserves records; it does not resurrect retracted history. The
shortened-history repair remains a separate explicit operation.

## Authority and scope

The public RPC supplies confirmed chain state; content hashes bind downloaded
module bytes to that state. The consumer verifies deployed contracts, epoch
context, compatibility lock, frontier, composition, ABI and provider bindings.
It rechecks block hashes and a moving frontier before publication, refuses an
RPC behind its previous successful observation, and uses 12 confirmations by
default. A new product compatibility lock needs the matching release bootstrap;
ordinary mined-module advances use the one-command sync above.

This is `coretex.current-state/v1` with `admission_replayed: false`. It identifies
what the chain selected. Independent admission auditing belongs to the separate
validator and remains available through [the validator guide](https://github.com/botcoinmoney/coretex-client/tree/main/python)
and [the full snapshot companion](https://github.com/botcoinmoney/coretex-client/blob/main/tools/coretex-snapshot.py).
The unchanged sealed verifier checks release bytes once during setup; the
validator is not installed in the serving environment and no admission history
is replayed. The prior 54-minute audit is no longer a consumer setup requirement.

Advanced users can use `coretex-consumer` directly with explicit release/config
paths and optional RPC overrides; see [the lower-level guide](integrations/consumer/README.md).
Normal setup needs no endpoint configuration. An explicit offline `CurrentState`
open checks local bindings without claiming freshness.

The loopback API is private to the host and has no authentication. One store is
one user's scope/profile. Mined Python modules require trust or external process
confinement; the pip serving worker is not the evaluator's kernel sandbox.

## Python integration

Use the installation's `./coretex/.venv/bin/python`:

```python
from coretex_consumer.config import load_config, load_authority

config = load_config("./coretex/consumer.json")
authority = load_authority(config)
with authority.open_memory(config["profile"], config["store"]) as memory:
    memory.sync_turn(messages=[{"role": "user", "content": "The launch is Friday."}])
    print(memory.prefetch("When is the launch?", budget=800).render())
```

Hermes uses a separate Python 3.11 environment and the sidecar connector below.
The memory adapter install above is already complete; these additional commands
install and configure the agent harness itself.

## Install Hermes and the connector

The qualified Hermes source is
`NousResearch/hermes-agent@e624e9fde561e1add9388384012b295fde669ade` (0.20.4).
Install Hermes using its documented installer, or in a separate Python 3.11 venv:

```sh
git clone https://github.com/botcoinmoney/coretex-client.git coretex-client
git clone https://github.com/NousResearch/hermes-agent.git hermes-source
git -C hermes-source checkout e624e9fde561e1add9388384012b295fde669ade
python3.11 -m venv hermes-env
hermes-env/bin/python -m pip install -e ./hermes-source ./coretex-client/integrations/hermes
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
`coretex-client/integrations/hermes/qualify_models.py --help` for the bounded three-turn-per-model
fixture; use only a dedicated synthetic test store. Qualification results are
small-sample evidence, not general guarantees or a substitute for your application's tests.
