# Byzantine and storage-flood probes

Requires the [advanced runner foundation](README.md). This category is discovered
automatically by its existing Node/Chromium CI steps.

```sh
yarn verify:advanced --category byzantine
yarn verify:advanced:browser --grep tombstone-bomb
yarn verify:advanced --category byzantine --profile full
PEERBORNE_VERIFY_PROFILE=full yarn verify:advanced:browser --grep tombstone-bomb
```

- `operation-authorization` sends raw Yjs updates in actual signed/encrypted
  envelopes. Non-writers, ACL self-grants and locally revoked writers must be
  rejected without changing state. A document writer also attempts synthetic
  role and another-user field writes. Current document-wide authority is not
  described as a field-level policy or append-only permission log.
- `causal-poisoning` admits 32/1,024 independent signed orphans, measures the
  actual pending CRDT bytes and releases them with their real ancestors. It
  tries a nonexistent deferred parent, checks depth/cycle/CID bounds, and in
  full mode checks both sides of the 32,768-node walker boundary. Yjs and
  Automerge wire counters include `Number.MAX_SAFE_INTEGER`; a benign writer
  must continue after inflation. Walker limits are per tree, not a global
  resource budget or peer quarantine.
- `tombstone-bomb` sends 400/100,000 total alternating insert/delete mutations
  over native ordered RTC into independent IndexedDB stores. Actual encrypted
  blocks are carried over the channel as a substitute for Bitswap; the stores
  are not shared. Five checkpoints report heap, quota usage, graph/CID counts,
  transactions and writes. Automatic snapshots, pruning and GC calls are
  counted separately from successful block deletion. The fixture's bounded
  sender backpressure is not claimed as a product denial-of-service defense.

Diagnostic mode reports missing field policies and aggregate resource bounds
as `gap`; strict mode rejects them. Reports contain counts and synthetic timing
measurements, not keys, raw operations, ciphertext dumps or private payloads.
Programmatic storage pressure in Chromium does not emulate an iOS quota policy.
