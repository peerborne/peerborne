---
title: "ADR 0002: MLS implementation dependency"
description: Evaluation procedure, findings, and acceptance gates for selecting an RFC 9420 implementation for Peerborne.
---

- Status: Proposed; no dependency selected
- Date: 2026-08-21
- Tracks: [issue #186](https://github.com/Peerborne/peerborne/issues/186)
- Parent decision: [ADR 0001](../0001-mls-document-security-architecture/)

## Context

Issue #186 names `@river-build/mls-rs-wasm`, but that package name returned
`404 Not Found` from the [npm registry](https://registry.npmjs.org/@river-build%2Fmls-rs-wasm)
when this evaluation was performed. Adding a dependency that was unavailable
at evaluation time cannot be the basis of a migration plan.

Registry availability, release status, package metadata, and upstream audit
statements in this ADR were checked on 2026-08-21. They are dated observations,
not claims about the current package ecosystem; selection requires repeating
the review against pinned artifacts.

An MLS library also does not supply Peerborne's identity policy, serialized
membership controller, durable transaction/outbox boundary, CRDT binding, or
initial-load fork policy. The provider boundary in ADR 0001 intentionally keeps
those responsibilities in Peerborne and prevents application code from
depending on one candidate's internal tree or state representation.

This evaluation asks whether a maintained implementation can satisfy that
boundary in Node.js and Chromium. It does not treat a successful API spike as
evidence of production security.

## Candidates examined

### `mls-rs` and the unavailable River package

[AWS Labs `mls-rs`](https://github.com/awslabs/mls-rs) is an RFC 9420 Rust
implementation with a configurable state layer and WebAssembly support. Its
documented Web Crypto provider is experimental, and the project does not
provide the maintained JavaScript package named by the issue. Its repository
also stated at the evaluation date that it had not undergone a full security
audit. Building and maintaining a private wrapper would transfer compatibility,
packaging, zeroization, browser-storage, and supply-chain responsibility to
this project. That is not an acceptable shortcut around the selection gates
below.

### `ts-mls`

[`ts-mls`](https://www.npmjs.com/package/ts-mls) is a TypeScript MLS
implementation. Version 1.6.2 was the current stable release during this
evaluation and advertised npm provenance. Its API exposes configurable
[authentication](https://github.com/LukaJCB/ts-mls/blob/v1.6.2/src/authenticationService.ts),
[client configuration](https://github.com/LukaJCB/ts-mls/blob/v1.6.2/src/clientConfig.ts),
and [key-retention policy](https://github.com/LukaJCB/ts-mls/blob/v1.6.2/src/keyRetentionConfig.ts).
The defaults are unsafe as a Peerborne policy: the default authentication
service accepts every credential, and the default retention policy keeps ten
generations across four epochs. Peerborne would have to replace both and prove
the resulting behavior.

An isolated Alice/Bob/Carol API spike using strict self-certifying
authentication and zero key retention reached one shared epoch after two adds,
converged before removal, converged between the two survivors after removal,
reported the third client as removed, and round-tripped encoded state while
consuming the complete input. The repository does not retain a reproducible raw
size artifact for that spike, so no exact byte result is claimed. This is useful
API-feasibility evidence only.

The same stable release failed a clean package-root import because a root
re-export loaded its Noble provider while `@noble/hashes` was not installed as
a runtime dependency. Importing undocumented internal files made the spike run,
but internal package paths are not a supportable integration boundary.
Version 2.0.0 release candidates improved parts of the API but were not stable
and did not remove the need for the gates below. No independent formal audit
was located for the TypeScript implementation.

### `@vanishing.page/webcrypto-mls`

[`@vanishing.page/webcrypto-mls`](https://www.npmjs.com/package/@vanishing.page/webcrypto-mls)
was a very recent 0.0.x package during the dated evaluation. Its reported
unpacked size was roughly 25 MB and it was distributed under the project's
[MIT license](https://github.com/vanishing-page/webcrypto-mls/blob/main/LICENSE).
Its age, maturity, assurance evidence, and footprint do not yet justify
integrating it into the runtime.

The [MLS implementation registry](https://messaginglayersecurity.rocks/implementations/)
is useful discovery input, not certification. Candidates absent from this
shortlist may be evaluated by the same procedure.

## Decision

Do not add an MLS dependency yet. Keep the protocol-neutral
`GroupSecurityProvider` boundary and evaluate candidates through a disposable
adapter/spike before a package or lockfile change. Do not expose undocumented
package internals or implement a custom TreeKEM as a fallback.

A candidate must provide or permit the adapter to provide:

- create, join, KeyPackage, Add, Update, Remove, Commit, Welcome, and application
  message operations with explicit epoch checks;
- application-supplied credential authentication that fails closed;
- a canonical applied membership delta (or equivalently strong member-set
  commitment) returned after both local Commit creation and received Commit
  application, so signed action/subject metadata cannot diverge from the
  protocol transition;
- deterministic public group commitments and complete, bounded state encoding;
- explicit retention/deletion control for old epoch, generation, proposal, and
  KeyPackage material;
- encrypted export/import of pending one-time KeyPackage private state, bound
  to the complete public package and intended document group, plus a durable
  operation/request binding for ambiguous-write retry and an atomic
  irreversible consumed-reference transition;
- clone/checkpoint or prepare/apply semantics compatible with atomic rollback;
- Web Crypto operation in Node.js 22 and current Chromium without secret export
  through JavaScript-facing diagnostics; and
- versioned wire inputs that can be strictly decoded before invoking expensive
  cryptography.

## Selection gates

The dependency is not selected until a pinned stable release passes all of
these gates:

1. Required RFC 9420 operations and cipher suites are implemented without
   relying on private package paths.
2. Peerborne authentication rejects unknown, substituted, expired, revoked, or
   changed credential bindings at every entry point.
3. Serialized state is complete, bounded, versioned, strictly decoded, and
   safely recoverable across process and browser restarts.
4. Retention can be set to the documented history policy, and tests show that
   obsolete epoch, generation, proposal, KeyPackage, and exporter material is
   no longer usable after deletion.
5. RFC vectors pass and byte-level create/add/update/remove/application-message
   interoperability succeeds with an independent implementation.
6. Malformed encodings, invalid confirmations/signatures, replay, reordering,
   duplicate proposals, conflicting Commits, and removed-member traffic fail
   closed within explicit CPU, memory, and input-size limits.
7. The same adapter passes under native Web Crypto in Node.js 22 and Chromium;
   it does not silently substitute an unrelated crypto implementation.
8. An IndexedDB-backed crash/restart test covers transactional state, pending
   and consumed KeyPackages, replay metadata, a durable outbox, a persistent
   keystore, and a separately protected monotonic rollback anchor, including
   injected write/send/ACK failures and strict CSP/worker/bundler behavior.
9. The stable release, maintainers, provenance, transitive dependencies,
   vulnerability response, update cadence, and abandonment plan receive a
   supply-chain review.
10. The license is compatible and the implementation has credible independent
    security-review evidence appropriate to the claims Peerborne intends to
    make.
11. Bundle size, initial and incremental latency, peak memory, wire size, and
    stored-state size stay within recorded budgets for 2, 3, 32, and 256
    members in both environments.

The spike report must record exact package and transitive versions, source
revision, runtime/browser versions, cipher suite, authentication and retention
configuration, commands, raw size/timing results, failures, and any patches or
internal imports. A passing spike then becomes a normal source adapter with
adversarial tests; it is never copied wholesale into the security boundary.

## Consequences

No repository dependency, lockfile, protocol, or user-facing MLS claim follows
from this evaluation. The generic provider and coordinator can be reviewed and
tested independently while candidate risk remains visible. Their current
applied-delta binding, group-bound encrypted pending/consumed KeyPackage seam,
and one-change coordinator rule are exercised with fake providers. They are
adapter acceptance constraints, not evidence that an RFC 9420 transition or
real onboarding has occurred.

This delays the MLS migration, but avoids anchoring persisted state and wire
formats to an unavailable, unstable, incorrectly packaged, or insufficiently
reviewed implementation. BeeKEM remains explicitly legacy until a complete
migration meets ADR 0001; improving its tests does not turn it into MLS or
establish RFC 9420 forward-secrecy or post-compromise-security guarantees.

## References

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750.html)
- [`mls-rs`](https://github.com/awslabs/mls-rs)
- [`ts-mls`](https://www.npmjs.com/package/ts-mls)
- [MLS implementation registry](https://messaginglayersecurity.rocks/implementations/)
- [ADR 0001: MLS document security architecture](../0001-mls-document-security-architecture/)
