# MLS dependency qualification

This isolated project evaluates the RFC 9420 dependency needed by
[#186](https://github.com/peerborne/peerborne/issues/186). It is not a Peerborne
provider and does not change the library packages, document protocols, or
application dependencies.

From the repository root, using Node.js 22.19.0 and Yarn 4.5.0:

```sh
yarn install --immutable
yarn --cwd verification/mls-candidate install --immutable
yarn exec playwright install chromium
node verification/mls-candidate/run.mjs
```

Linux runners also need Playwright's Chromium system dependencies. The harness
runs the same three-member flow with native Web Crypto in Node and Chromium,
using the package's public root export. Browser modules are served only on a
temporary loopback port under a script CSP. There are no upstream source
patches, private imports, external services, persistent browser profiles, or
application data. The report contains only operation results, sizes, dependency
integrities, and runtime/crypto-operation metadata. Private state and message
contents are never written to the report.

The separate `yarn.lock` pins the complete candidate toolchain. Explicit
`@noble/hashes` and `@noble/ciphers` dependencies satisfy the published root
module's imports and non-optional peer requirement. These are evaluation tools;
none of the six library manifests or the root lockfile includes MLS.

`run.mjs` writes an ignored `report.json` and exits nonzero if an exercised
security gate fails. Even a zero exit status means only that the exercised
gates passed; the remaining ADR 0001/0002 gates still prevent selection. This
diagnostic is separate from the normal passing repository tests.

## Recorded result: rejected

The 2026-10-31 run used `ts-mls` 1.6.4, Node 22.19.0, Chromium 145.0.7632.6,
and cipher suite 1 on macOS arm64. The checked-in
[report](results/2026-10-31-darwin-arm64.json) records the exact toolchain and
observations. This is one functional run, not a resource-budget benchmark.

Both environments successfully exercised sequential Alice/Bob/Carol joins,
a self-update, matching epoch exporters, application messages, replay
rejection, removing Carol, exclusion from post-removal content, and a complete
state-codec round trip. Unknown, substituted, expired, and revoked credentials
were rejected during Add against the harness's explicitly pinned identity
policy. Tampered and replayed Commits were rejected. These results do not
establish the complete Peerborne credential policy or independent MLS
interoperability.

With both epoch and generation retention configured to **zero**, an application
message withheld in an earlier epoch was still decrypted after a later Add and
self-update. The three members retained 3, 2, and 1 historical epochs. The
failure occurs in both runtimes while returned `consumed` buffers are zeroed
after each successful operation. This fails ADR 0002's retention gate. The
candidate is not selected, and this evidence makes no forward-secrecy claim.

The pinned implementation's historical-retention helper constructs a pruned
map and deletion list but returns a slice using `-max` and an empty deletion
list. With `max === 0`, that slice retains the entire historical map. The
functional old-message test above is the evidence; this source observation
explains it. The harness does not patch the implementation or work around the
failure by reaching into a cryptographic secret tree.

## Full #186 scope

| Work                                    | Current state and next acceptance boundary                                                                                                                                                                               |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Select an MLS implementation            | The issue's River npm package still returns 404. This pinned stable candidate fails retention. Resolve the candidate failure or qualify another maintained stable implementation before adding a runtime dependency.     |
| RFC and independent interoperability    | Required; this harness uses one implementation in two runtimes and does not replace independent vectors/byte-level interoperability.                                                                                     |
| Provider integration and key ratcheting | Required; adapt authenticated credentials, applied deltas, one-time packages, encrypted state, and exporter-derived document keys through `GroupSecurityProvider`.                                                       |
| ACL chain as runtime authority          | Required; bind immutable genesis, controller/roles, group transitions, and the content epoch/head in one accepted state.                                                                                                 |
| Initial-load quorum                     | Existing V4 locally pinned commitments remain; MLS genesis/control replay and authenticated suffix recovery must supply and verify the real tuple.                                                                       |
| Add/remove delivery and recovery        | Required; persist group/control/keys/replay/outbox atomically, use authenticated durable ACKs, and exercise partition/rejoin plus failure injection.                                                                     |
| Restart and rollback resistance         | Required; prove actual process/Chromium restart with an encrypted store, keystore, and independently protected persistent monotonic anchor. An in-memory or same-database anchor does not satisfy this.                  |
| Retention and erasure                   | Candidate currently fails zero-epoch retention. Retained document history and materialized plaintext must remain explicit in any eventual claim.                                                                         |
| ZKP evaluation                          | ADR 0003 explains why a proving toolkit does not supply identity, revocation, or group-key security. No proof statement/privacy requirement is defined by #186; no ZKP dependency is needed for this MLS implementation. |
| Release qualification                   | Required; adversarial native/browser tests, budgets for 2/3/32/256 members, supply-chain/license review, and external security review before production claims.                                                          |

The protocol-neutral coordinator and stores remain useful foundations. Their
fake-provider tests are not replaced by this dependency probe, and this probe
does not complete #186.
