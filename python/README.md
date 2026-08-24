# coretex-validator

```bash
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.3/coretex_validator-0.4.3-py3-none-any.whl
coretex-validator setup
```

Version 0.4.3 independently resolves and re-hashes the parent composition, release, and module
bytes before replaying a new five-field incumbent identity. The frozen pre-cut code-root set is
embedded in the wheel so existing three-field production artifacts remain replayable without
opening a three-field path for new law roots. It adds `setup`'s law install, `replay-latest`,
`preview-current-parent`, and a rule-carrying object transport; it removes the rehearsal default
publication root.

## `reproduce` — the whole verification, in one command

```bash
coretex-validator reproduce --rpc "$BASE_RPC_URL"
```

Eight steps against a live endpoint: authenticate the release, check contract bytecode and wiring,
replay per-rig receipt continuity, reconstruct the transition, run deterministic admission inside
the installed law, resolve the HISTORICAL law at that transition, rebuild the resolver snapshot,
and build the activation export. It is the command to reach for first; everything below is a
narrower slice of the same machinery.

`--epoch` / `--transition-index` select one advance; `--artifact-dir` points at the objects;
`--require-complete` turns "could not check" into exit 1.

## `setup` installs the admission law — and the miner-kit tar

`setup` ends with `law.synced: true`. It reads the publication root from the coordinator kit's
`law_publication` component, downloads the publication under the kit's hashes, and hands it to the
same verifier `sync-law` uses — which re-derives every address (the manifest's, each container's,
each extracted tree's) from the bytes that arrived. Deterministic admission then runs instead of
backlogging, on a machine that started with nothing but a URL.

**Seven sealed roots, six of them trees.** `benchmark-v2/validator/receipt.py::code_roots` computes
six with the tree-hash rule and one — `candidate_isolation_posture` — as the plain `sha256` of a
single FILE, opened at `<repo_root>/v5/production/CANDIDATE-ISOLATION.production.json`. For a
validator running on the law cache, `repo_root` *is* the cache, so that file is published as a
single-file object and installed at exactly that relative path. A publication that omits it is
refused: a cache that cannot compute `code_roots()` cannot replay a single receipt, and finding
that out at the first replay instead of at install time is worse than not installing.

**`setup` also caches and extracts the miner-kit tar**, under the sha256 the kit manifest binds.
That tar supplies the required `benchmark-v2/kit` and `benchmark-v2/integration` trees.
Do not pass `--skip-packages` if you intend to preview.

A canonical setup requires a production-release-bound kit envelope, exactly one current miner-kit
tar, and an explicit `law_publication.publicationRoot`. A partial/older envelope or publication
that does **not** reproduce its address fails the command loudly.

**`setup` also fetches and binds the compatibility lock.** The confirmed epoch's `coreVersionHash`
is the address of one `coretex.compatibility-lock/v1` document, and it is now obtainable publicly:
`GET /coretex/v5/object/<coreVersionHash>?hashRule=compatibility-lock-root`. Setup fetches it,
requires the served bytes to BE the canonical serialisation, re-addresses the document
(`keccak256(0x19 ‖ "coretex.compatibility-lock/v1" ‖ 0x0a ‖ canonical-body-without-lock_root)`)
and requires the recomputation, the document's own `lock_root` and the chain's word to be the same
value. The server's `verified: true` is never read. The verified bytes are cached under their root
in `<packages-dir>/artifacts/`, so a later `reproduce-snapshot --artifacts` reads them offline, and
the root is recorded in `ACTIVE-INSTALL.json` so a later run can see which lock this installation
was bound to. The report's `lock` block is
`{verified, root, rawSha256, bytes, cachedAt}`.

The two negative outcomes are **not** one outcome. A coordinator that cannot serve the rule (404,
503, or an older image that 400s it) leaves `lock.verified: false` with a remedy and setup still
exits 0 — nothing was disproved. Bytes that arrive and contradict their address — non-canonical
encoding, a malformed document, a root that does not recompute — fail the command loudly.

```bash
coretex-validator setup                                   # discovers + installs the live law
coretex-validator setup --skip-law                        # explicit diagnostic; does not activate
coretex-validator sync-law --mirror URL --root ROOT       # verify a named publication explicitly
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

Discovery decodes the **deployed descriptor-v3 events** (`rig_events`) — the same decoder
`reproduce` uses, and the only live one. The report names it under `chain.decoder` and
`feed.decoder`, so "which decoder read this chain" is never a question you answer by reading
source. The `CoreTexMemory*` tables in `dispatch`/`sync` belong to the retired lane and no live
command consults them.

What this command does *not* do, and `reproduce` does: fetch the transaction calldata and join the
advance to its signed rig receipt. So `candidate_release_root` here is the eval artifact's rather
than the signed `artifactHash`. The report says so under `replayed.auxiliary.projection.binding`
instead of implying a check that did not run.

## `verify-receipt` — one signed receipt, no chain at all

```bash
coretex-validator verify-receipt ./cas/<REPORT_ROOT> --artifact ./cas/<ARTIFACT_ROOT>
```

A receipt check needs no RPC, but an exact-parent receipt is not self-contained in `receipt +
trees`: it also needs the eval artifact and the parent graph from the selected artifact store.
When the report names an EXACT PARENT, the incumbent's execution is
**resolved here** — frontier → composition → release → module, every hop re-hashed, compared for
exact equality against the identity the report binds — rather than demanded from the caller.
`--artifacts DIR` names the object store; it defaults to the directory holding the receipt, which
is where a content-addressed receipt normally sits.

Outcomes keep their meanings. An object that is not published, or a law tree this host does not
have, is `BACKLOG` / exit 0 — unresolved work. `FAIL` / exit 1 is reserved for a refutation: a
resolved parent that is not the one the report binds, or a report that did not reproduce.

## `preview-current-parent` (optional, for miners)

The kit's `self_check` scores you against the **frozen reference baseline**. The live incumbent
has usually moved past it, so a candidate can pass the self-check and still lose the adjudicated
comparison. This command scores your module and the **current confirmed parent** on the identical
public dev cases, inside the pinned law trees:

```bash
coretex-validator setup                          # once: BOTH publications this scores inside
coretex-validator preview-current-parent module.py \
    --manifest manifest.json --profile doc.tool.v1 \
    --parent-root CONFIRMED_FRONTIER_ROOT --artifact-dir ./cas
```

Every object between the frontier root and the parent's module bytes is re-hashed under its own
rule before it is used, and the parent arm is scored with the **parent release manifest's**
capabilities and `max_compute_ms` — never yours.

**Where the scoring trees come from.** Two publications, composed by path layering with the sealed
ones first:

| tree | source | why |
| --- | --- | --- |
| `benchmark-v2/{frontier,generators,miner_abi,scoring,validator}`, `coretex-memory` | the verified **law cache** | sealed code roots; their tree hash is what a signed receipt binds |
| `benchmark-v2/kit`, `benchmark-v2/integration` | the hash-pinned **current miner-kit tar** | required support code; not sealed roots |

The current tar contains only `benchmark-v2/kit` and `benchmark-v2/integration`; it carries no
sealed scorer tree to compete with the law cache. Path layering still gives the sealed directory
priority defensively, so a manually supplied package directory cannot override
`frontier`/`scoring`/`miner_abi`. `--packages-dir` points at an already-extracted tar;
`--repo-root` uses a full checkout instead of either.

Retained frozen packet tarballs are audit artifacts, not install candidates. A current miner-kit
missing either support tree is refused before preview starts.

It is a preview, not a prediction. The report carries `publicDevCasesOnly: true` and
`predictsAdmission: false`, because official evaluation re-runs on fresh confirmation cases drawn
from future public entropy and applies the full composite law including the prerequisites an
adjudicating host executes. **Losing to the current parent exits 0** — it is information, not an
error; non-zero means the comparison could not be made.

## Objects carry their hash rule; verification stays here

`ContentStore.get_for_rule(root, hash_rule)` sends the committed rule with the request, because the
coordinator's object route refuses one that names no rule, and because two of the four rules address
bytes that are not the bytes on the wire. The rule decides how the object is *served*. It never
decides whether the object is *correct*: `publication.read_back` recomputes the root here, from the
bytes that arrived, under the rule the caller committed to.

So a response carrying `transportVerified: true` and `canonicalVerification: "client_required"` (or
the `X-CoreTex-Transport-Verified` / `X-CoreTex-Canonical-Verification` headers on the raw path) is
read as a transport-level statement and nothing more — it is not evidence and this client does not
act on it. The gap is real for `sha256-benchmark-canonical-json`, the float-bearing rule: a server
can only check that `sha256(bytes)` equals the root, while this side also requires the bytes to
**be** the canonical serialisation that root names. A mismatch is `ReadBackMismatchError` — a
permanent refutation — never the retryable `ObjectNotFoundError`.

## Version status

0.4.3 is the one canonical validator production release; there is no supported prior/current
version split. `GET /coretex/v5/status` → `productionRelease.validatorWheel` is the deployment byte
authority: it names the exact wheel filename, version and sha256 parsed from the bytes the
coordinator will hand you. A deployment is current only when that tuple names the canonical 0.4.3
artifact.

See the repository root README for commands and contracts.
