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
Re-running setup or installing the optional addon without `--profile` keeps the
existing installation's profile.

The helper is also available from the [public client source](https://github.com/botcoinmoney/coretex-client/blob/main/tools/coretex-setup.py).
It carries exactly one pin — the generated release inventory
(`tools/release-inventory.json`) — and reads the version, the release root, every
wheel name and every digest from it, refusing any artifact whose bytes do not match
what the inventory declares. A new release is published by regenerating that
inventory, not by editing the installer. Its private environment uses the
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

## Upgrade to a new release, and roll back

An installation is **generational**. The tools, the private environment and the
verified release of one release root live under `<install>/gen/<release_root>/`;
the memory store, its configuration and the addon's enable state live at the top
and are never rewritten by an upgrade.

```sh
./coretex/bin/coretex upgrade      # new tools, SAME memories
./coretex/bin/coretex rollback     # previous tools, SAME memories
./coretex/bin/coretex which        # which generation is serving, and its extras
```

| upgraded | preserved |
|---|---|
| the verified release directory and its objects | `memory.db` — every record, its canonical ids and its history |
| the runtime, adapter and current-state client wheels | the store's profile and scope |
| the serving module generation and its retrieval binding | the addon's enable state and its `0600` key |
| the launcher and the installation's tools | the installation path and the configured store path |

**No re-ingestion and no cache rebuild is required**: the store opens under the new
release as it is. The previous generation is kept on disk, so `rollback` re-points
the launcher at it against the same store; `UPGRADE-HISTORY.json` records each
move with the configuration it replaced.

Earlier installations refused to proceed when the release changed and asked for a
new directory. That is gone: the release change is what `upgrade` is for.

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

## Replay one public report yourself

The validator re-executes a published fixed-suite report against your installed
release and accepts it only when the rebuilt report reaches the same content
address, byte for byte:

```
coretex-validator replay-report \
  --release ./coretex/release \
  --report ./report.json \
  --expect-root <sha256 of the report> \
  --incumbent-execution ./incumbent-execution.json \
  --parent-stored-vector ./determinism-witness.json \
  [--judge-rows ./sealed-judgments.jsonl]
```

A **judged report** carries a `judge` block: its scores were produced with a
sealed `cap.judge.v1` judgment table rather than from the suite alone. That
table is large and is not part of the release, so it is not shipped with it —
obtain it separately and point `--judge-rows` at it. The path is not a fact
about the release and does not need to be trusted: replay recomputes the table's
root and requires the value the report bound, so a replay pointed at a different
row set fails instead of passing.

Output fields: `reproduced` is the verdict, `report_root` the content address the
replay rebuilt, and — for a judged report — `judge_table_root` the table replay
actually answered from and `enhanced_replay_root` the fold the judged arm
re-executed to, which must equal the one the report bound. Exit status is 0 on
reproduction and 1 otherwise.

Replaying a judged report without `--judge-rows` is refused before anything runs
with `{"reproduced": false, "code": "judge_table_required"}`; replay never falls
back to scoring the judged arm locally. The reverse is refused too: an unjudged
report takes no table (`judge_table_unexpected`).

## Python integration

Use the active generation's Python, reported by `coretex which` (there is no
`./coretex/.venv` shortcut):

```sh
CORETEX_PYTHON="$(./coretex/bin/coretex which | python3 -c 'import json,sys; print(json.load(sys.stdin)["python"])')"
"$CORETEX_PYTHON" your_script.py
```

For example, `your_script.py` can use the consumer API:

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

## Optional: the Jev addon

The adapter is complete without it. Ingestion, retrieval, citation, history,
correction and packing are the local M1–M6 flow; no account, key, network call or
third-party service takes part in any of them. The **Jev addon** is a separate,
optional wheel that supplies *judgments* to that flow, and it is **default OFF**.

### How it composes (M5/M6), and what it is not

The addon is a provider for the host capability `cap.judge.v1`. When it is on, the
host offers a judgment of a candidate record to the mined module; **selection stays
in M6**, where the current CoreTex state decides what to pack. The addon never
filters, drops or rewrites anything on its own, and there is **no separate
post-filter stage** — earlier drafts of this guide described one, and it does not
exist in this release. Do not enable an old filter alongside the M6 policy.

* Conversation retrieval (`conv.pref.v1`) is **conservative**: judgments inform
  ordering, and the packed set is not trimmed on their account.
* Aggressive trimming is **explicit opt-in** and is not enabled by any flag in
  this release.
* No ingestion-time annotation or correction integration is part of this release.

### One control

```sh
./coretex/bin/coretex jev enable --key -     # reads one line from stdin; never echoed
./coretex/bin/coretex jev status
./coretex/bin/coretex jev disable
```

`./coretex/bin/coretex setup --jev-key -` is the same thing under the name the core
CLI uses. Enabling is **two-condition**: it takes effect only when you turned it on
*and* a key is resolvable. Either one missing leaves the complete local path
running, with no addon import, credential probe or socket.

What `enable` actually sets, for every serving process this launcher starts:

| variable | read by | why it is needed |
|---|---|---|
| `CORETEX_JUDGE_ENABLED=1` | `AgentMemory.open` | binds a provider to the **serving store**; without it nothing is bound, whatever the addon config says |
| `CORETEX_JEV_ENABLED=1` | the addon factory | the addon's own opt-in |
| `CORETEX_JEV_CONFIG` | the addon | this installation's key-free config |

`disable` sets the first two to `0`, and explicit off wins over anything inherited
from your environment. The key is never an argument, never exported by the
launcher and never printed: it is written to `<install>/.jev/jev.key` at mode
`0600`, and the config file beside it carries only `enabled`, `key_file` and
`cache_dir`. A key placed in the config *file* is refused.

`jev status` does **not** read that configuration back to you. It reports the
provider bound to this store's serving process — the running sidecar's own captured
binding when one is up, otherwise a real open of the store:

```json
{"provider_attached": true, "probe": "running-sidecar",
 "bound": {"bound": true, "available": true, "provider_id": "..."},
 "sets": {"CORETEX_JUDGE_ENABLED": "1", "CORETEX_JEV_ENABLED": "1"}}
```

A provider is resolved **once, when the store is opened**. After `enable` or
`disable`, restart `coretex serve`; `jev status` says `restart_required` when a
running process no longer matches the current decision.

### What "fully off" means on each path

| path | what it needs from Jev | what still works |
|---|---|---|
| **Standalone adapter** (addon absent, explicitly disabled, or no usable key) | nothing: no account, key, call or cache answer | the complete local M1–M6 flow — ingestion, retrieval, citation, history, correction, packing. Removing the addon after use leaves the same store usable, and the rendered bytes and receipt are identical to an installation that never had it |
| **Miner development and evaluation** | nothing: no Jev account, key or per-submission API call | judgments come from the **local sealed table**, which is fixture data. Local improvement stays rewardable under the declared dual-mode rules; an enhanced-only gain cannot pay for a local regression or resource growth |

Initial installation and module synchronization use the network; that traffic is
distinct from Jev traffic, and disabling the addon means zero Jev requests and no
cached-answer use.

### The sealed table is a separate download

The miner/validator kit tar (~22 MB) contains **no** sealed-table member. The table
is a separate verified download:

| | |
|---|---|
| file | `sealed-table.jsonl` |
| size | 105,797,400 bytes |
| SHA-256 | `7214033f9a10e21599f33358b90590e3502127383e916293e945f00381c9cb23` |
| table root | `30baa7d4248c79e7bc125fda8151f8275e5ce5b9e56fe525c6a0dc3a76680557` |

Verify both the file hash and the table root before use. Release 1.1.2 **declares
this table as a scoring input**: a judged evaluation with missing or mismatched rows
is refused, not silently downgraded. The table is local data, so a stored copy keeps
working unchanged if the live service ever disappears — that is a different question
from removing the declaration, which would need its own prospective release
identity.

### Cost, latency and privacy when it is on

Roughly $0.000057 per judged reference; the defaults cap a session at 2,000 calls
and $1.00, and one serve at 16 calls and 400 ms, at most 4 requests in flight.
Answers are cached per (store, scope), and the cache is invalidated automatically
when a record is deleted, retracted, superseded or re-scoped. If the service is
slow, down, or a cap is reached, the serve returns the **whole local pack** — never
blocked, never partially enhanced. When it runs, the query text and the text of the
references being judged are sent to `api.typesafe.ai`; receipts, cycle ids,
provenance roots, scope (tenant/user/agent/session), module identity and the
rendered context are not. If your records may not leave the host, leave it off.

The addon ships as `coretex-jev-addon`, a separate optional wheel that is not part
of the runtime or adapter release. Install it into the installation's private
environment:

```sh
python3 coretex-setup.py --dir ./coretex --install-addon ./coretex_jev_addon-0.1.0-py3-none-any.whl
```

### With Hermes

The addon lives in the **sidecar process** that owns the store, not in the Hermes
plugin. `hermes-home/config.yaml` is unchanged. Enable it with
`./coretex/bin/coretex jev enable` and restart `./coretex/bin/coretex serve`: the
sidecar captures the binding when it opens the store, and `jev status` reports what
that running process actually bound.

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
