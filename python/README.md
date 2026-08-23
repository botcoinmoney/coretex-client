# coretex-validator

```bash
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.2/coretex_validator-0.4.2-py3-none-any.whl
coretex-validator setup
```

Version 0.4.2 independently resolves and re-hashes the parent composition, release, and module
bytes before replaying a new five-field incumbent identity. The frozen pre-cut code-root set is
embedded in the wheel so existing three-field production artifacts remain replayable without
opening a three-field path for new law roots.

## `preview-current-parent` (optional, for miners)

The kit's `self_check` scores you against the **frozen reference baseline**. The live incumbent
has usually moved past it, so a candidate can pass the self-check and still lose the adjudicated
comparison. This command scores your module and the **current confirmed parent** on the identical
public dev cases, inside the pinned law trees:

```bash
coretex-validator sync-law --mirror URL          # once: the pinned trees this scores inside
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
