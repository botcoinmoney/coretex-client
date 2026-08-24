# Cross-lane fixtures

Files here are immutable known-answer vectors. Their provenance and `sha256` are recorded so drift
is detectable rather than silent — which is the entire reason a shared vector is worth having.

| file | origin | sha256 at copy time |
| --- | --- | --- |
| `signing-vector.json` | resolver lane, `v5/resolver/tests/fixtures/signing-vector.json` | `e19b0f513b4ebeb66bdd698ed95a6cd72eb38cac8bd990d11b071d76d332ba1c` |
| `rig-descriptor-v3-vector.json` | independently derived from `botcoin-mining-rigs@a473f3fd1038a81f8ef456cd4c7ce1f7b9fbef6e` | `c9c6e86b23f34ba4c871d70f0c581b5019778f9fd8b187add0033e056339b1fb` |
| `e184-cas/*` | the nine published objects of the LIVE epoch-184 advance, copied verbatim from the production publication surface | each file is named by its own root; see below |
| `e184-rig-feed.json` | thirteen VERBATIM Base mainnet logs pulled with `eth_getLogs` over blocks 50330000-50372318 from the three addresses the canonical release pins, no topic0 filter | `26db6a75d82e3eedb3247e5282b11f6171106f6a2282ad2bf4eb1c90f543935e` |

## `e184-cas/` — real production bytes, not a synthesised set

Nine content-addressed objects, one directory laid out as a flat CAS (one file per root, named by
the root), exactly as `publication.FilesystemCAS` reads it. They are public protocol artifacts: an
advance's objects are what any validator fetches to replay it.

They are here because the object-transport tests must be run against bytes nobody could have
tuned. Two properties in particular cannot be manufactured convincingly:

* `8471202b8a272a1326170d3a7299ec418a03c2b57a0229a562e97ffbf908d83c` (29437 bytes) is the inner
  evaluation report, committed under `sha256-benchmark-canonical-json`. It carries **128 float
  tokens**, so the float-refusing frontier rule cannot address it at all — and its raw
  `sha256(bytes)` *does* equal its root, because the published bytes already are the canonical
  serialisation. That coincidence is exactly what makes it the honest test of the rule that a
  server's raw-sha agreement is a transport fact and never the canonical verification.
* `55cbb53387b8afe6b8d81a4768bbeecdd4912c856bb7ee6f128b0f9aaf6703c8` and
  `70714005941d58f1401f5e06f647179a47f416a336b21c92ffbe3127ce42bca8` are signed manifests, whose
  raw `sha256(bytes)` deliberately does **not** equal their root: the body they address excludes
  the self-hash and the signature. A client that "verified" by raw sha256 would reject both.

`test_object_transport.py` asserts both properties directly, so a change to either the rules or
the fixtures fails loudly rather than drifting.

## Why this is a fixture and not a recomputation

`test_signing_vector.py` asserts this package's signing digest against the **file**, not against
a value this package computes. The difference matters: a test that recomputed the digest with the
same code that produces it would pass no matter what the domain tag said, and a tag change would
silently re-key every signature both lanes can verify. Reading a committed vector makes such a
change fail loudly, on both sides, at the same moment.

The vector deliberately carries `superseded_signing_digest` — the digest under the retired tag
`\x19coretex.rig-resolver-snapshot/v1\n`. **Do not prune it.** It is what makes the tag flip
auditable: it lets a stale signature be *diagnosed* ("signed under the superseded domain") rather
than merely rejected, and it is the evidence that no published snapshot was ever signed under the
old tag.

## `e184-rig-feed.json` — the feed the shipped decoder could not see

Thirteen real logs, unedited, carrying the epoch-184 advance
(`CoreTexStateAdvanced`, tx `0xc77f8725…`, block 50357019) beside its
`RigCoreTexCreditAccepted`, `CoreTexEpochFinalized`, the epoch-185
`CoreTexEpochContextSet`/`EpochCommitSet`, the epoch-184 `EpochSecretRevealed`,
three `RigCreditAccepted` receipts and four logs whose topic0 no CoreTex decoder
knows.

They are a slice of the 21,544-log window a clean-box qualification fetched, kept
whole rather than synthesised, because D-2 was a decoder defect: `dispatch`'s two
tables decode NONE of the rig-lane events in this file, and a fixture built with
the encoder that has the bug would have agreed with it. `test_rig_discovery.py`
asserts both halves — that the retired table finds no advance in these bytes, and
that `rig_events` finds the one that is there.

The four unknown-topic logs are deliberate: an administrative event a field
validator has never heard of must be IGNORED, never fatal, and the counts in
`RigFeed.summary()` say so out loud.
