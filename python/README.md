# coretex-validator

```bash
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.2/coretex_validator-0.4.2-py3-none-any.whl
coretex-validator setup
```

Version 0.4.2 independently resolves and re-hashes the parent composition, release, and module
bytes before replaying a new five-field incumbent identity. The frozen pre-cut code-root set is
embedded in the wheel so existing three-field production artifacts remain replayable without
opening a three-field path for new law roots.

## `setup` installs the admission law

`setup` ends with `law.synced: true`. It reads the publication root from the coordinator kit's
`law_publication` component, downloads the publication under the kit's hashes, and hands it to the
same verifier `sync-law` uses — which re-derives every address (the manifest's, each container's,
each extracted tree's) from the bytes that arrived. Deterministic admission then runs instead of
backlogging, on a machine that started with nothing but a URL.

An older coordinator that publishes no such component gets `law.synced: false` and a remedy, and
setup still succeeds. A publication that does **not** reproduce its address fails the command —
loudly, and with no flag that recovers it.

```bash
coretex-validator setup                                   # discovers + installs the live law
coretex-validator setup --skip-law                        # the old behaviour
coretex-validator sync-law --mirror URL --root ROOT       # a NAMED (e.g. historical) publication
```

`sync-law` has **no default root**. The one it used to carry was a 2026-08-04 rehearsal closure,
and verifying a publication only proves it hashes to the root you asked for — never that the root
is the one the chain head binds.

## `replay-latest` — the newest advance, in one command

```bash
coretex-validator replay-latest --rpc "$BASE_RPC_URL" --artifacts ./cas
```

Discovers the newest confirmed advance from the chain (by `(epoch, transitionIndex)`, which is the
chain's order — `transitionIndex` restarts each epoch, so the last log in block order is routinely
not the head), fetches every object it names under that object's committed hash rule, and replays
it. `PASS` / `FAIL` / `BACKLOG` are reported verbatim: exit 1 on a refutation, exit 0 on a
BACKLOG unless `--require-complete`, exit 2 when there was no confirmed advance to replay.
`--logs FILE` runs the same discovery offline against a feed file.

## `preview-current-parent` (optional, for miners)

The kit's `self_check` scores you against the **frozen reference baseline**. The live incumbent
has usually moved past it, so a candidate can pass the self-check and still lose the adjudicated
comparison. This command scores your module and the **current confirmed parent** on the identical
public dev cases, inside the pinned law trees:

```bash
coretex-validator setup                          # once: the pinned trees this scores inside
coretex-validator preview-current-parent module.py \
    --manifest manifest.json --profile doc.tool.v1 \
    --parent-root CONFIRMED_FRONTIER_ROOT --artifact-dir ./cas
```

Every object between the frontier root and the parent's module bytes is re-hashed under its own
rule before it is used, and the parent arm is scored with the **parent release manifest's**
capabilities and `max_compute_ms` — never yours.

It is a preview, not a prediction. The report carries `publicDevCasesOnly: true` and
`predictsAdmission: false`, because official evaluation re-runs on fresh confirmation cases drawn
from future public entropy and applies the full composite law including the prerequisites an
adjudicating host executes. **Losing to the current parent exits 0** — it is information, not an
error; non-zero means the comparison could not be made.

See the repository root README for commands and contracts.
