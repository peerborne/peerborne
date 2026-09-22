---
title: "ADR 0002: MLS implementation dependency"
description: Evaluation procedure, findings, and acceptance gates for selecting an RFC 9420 implementation for Peerborne.
---

- Status: Proposed; no dependency selected
- Date: 2026-08-21
- Dependency facts revalidated: 2026-09-10
- Tracks: [issue #186](https://github.com/Peerborne/peerborne/issues/186)
- Parent decision: [ADR 0001](../0001-mls-document-security-architecture/)

## Context

Issue #186 names `@river-build/mls-rs-wasm`, but that package name returned
`404 Not Found` from the [npm registry](https://registry.npmjs.org/@river-build%2Fmls-rs-wasm)
when this evaluation was performed and again during the 2026-09-10
revalidation. Adding a dependency that is unavailable cannot be the basis of a
migration plan.

Registry availability, release status, package metadata, and upstream audit
statements in this ADR were checked on 2026-08-21 and revalidated on
2026-09-10. They are dated observations, not durable claims about the package
ecosystem; selection requires repeating the review against pinned artifacts.

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
implementation with a configurable state layer and WebAssembly support. The
2026-09-10 revalidation pinned upstream commit
[`8f1b43f`](https://github.com/awslabs/mls-rs/tree/8f1b43f447a792ff9307f1c2c7f54da63914870e):
its [crate metadata](https://github.com/awslabs/mls-rs/blob/8f1b43f447a792ff9307f1c2c7f54da63914870e/mls-rs/Cargo.toml)
reports version 0.56.0, while its
[README](https://github.com/awslabs/mls-rs/blob/8f1b43f447a792ff9307f1c2c7f54da63914870e/mls-rs/README.md)
documents WASM builds, marks Web Crypto cipher suites 2, 5, and 7 as
experimental, and says the library has not received a full third-party
security audit. The project does not provide the maintained JavaScript package
named by the issue. Building and maintaining a private wrapper would transfer
compatibility, packaging, zeroization, browser-storage, and supply-chain
responsibility to this project. That is not an acceptable shortcut around the
selection gates below.

### `ts-mls`

[`ts-mls`](https://www.npmjs.com/package/ts-mls) is a TypeScript MLS
implementation. Version 1.6.2 was the current stable release during this
evaluation and advertised npm provenance. The 2026-09-10 revalidation found
stable version 1.6.4 and prerelease version 2.0.0-rc.16. The pinned
[1.6.4 package metadata](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/package.json)
and source expose configurable
[authentication](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/src/authenticationService.ts),
[client configuration](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/src/clientConfig.ts),
and [key-retention policy](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/src/keyRetentionConfig.ts).
The defaults remain unsafe as a Peerborne policy: the default authentication
service accepts every credential, and the default retention policy keeps ten
generations across four epochs. Peerborne would have to replace both and prove
the resulting behavior. The
[upstream 1.6.4 documentation](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/README.md)
still says the library has not undergone a formal security audit.

The original 1.6.2 Alice/Bob/Carol API spike used strict self-certifying
authentication and zero key retention reached one shared epoch after two adds,
converged before removal, converged between the two survivors after removal,
reported the third client as removed, and round-tripped encoded state while
consuming the complete input. The repository does not retain a reproducible raw
size artifact for that spike, so no exact byte result is claimed. This is useful
API-feasibility evidence only.

A separate 2026-09-10 smoke in a clean Node.js 22 environment found that the
1.6.4 package-root ESM import still failed with `ERR_MODULE_NOT_FOUND` for
`@noble/hashes`; the tagged metadata lists `@noble/hashes` 2.3.0 only as a
development dependency. Installing that exact package made the root import and
a one-member cipher-suite-1 `createGroup` smoke succeed. That narrower smoke
did not repeat the historical multi-member flow or test removal, persistence,
Chromium, interoperability, the Peerborne adapter contract, or any security
property. Undocumented internal package paths remain an unacceptable
integration boundary, and the 2.0.0 release candidate does not remove any
selection gate below.

### `@vanishing.page/webcrypto-mls`

The 2026-09-22 metadata recheck pins
[`@vanishing.page/webcrypto-mls` 0.0.11](https://registry.npmjs.org/@vanishing.page/webcrypto-mls/0.0.11),
published on 2026-08-13, to the registry's source revision
[`87af3eb1b1ea4a81e37b1daf5aa2329c75974f15`](https://github.com/vanishing-page/webcrypto-mls/tree/87af3eb1b1ea4a81e37b1daf5aa2329c75974f15).
Its [immutable npm artifact](https://registry.npmjs.org/@vanishing.page/webcrypto-mls/-/webcrypto-mls-0.0.11.tgz)
contains 1,182 files with a reported unpacked size of 25,332,557 bytes. This is
package metadata, not a measured browser bundle size. Its metadata says
`SEE LICENSE IN LICENSE`; that revision's
[LICENSE file](https://github.com/vanishing-page/webcrypto-mls/blob/87af3eb1b1ea4a81e37b1daf5aa2329c75974f15/LICENSE)
is titled Big Time Public License 2.0.2, so the earlier MIT characterization is
withdrawn. License compatibility remains an unmet selection gate. No runtime,
security, or interoperability evaluation of this artifact is claimed.

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
    stored-state size meet the proposed acceptance budgets below for 2, 3, 32,
    and 256 members in both environments.

### Proposed resource budgets and measurement procedure

These are acceptance limits for the next spike, not measurements or claims
about any candidate. Changes to a limit must be recorded in this ADR before a
candidate is judged against it.

| Metric | Proposed maximum |
| --- | --- |
| Gzip-compressed browser entry, including the provider's transitive dependencies but excluding Peerborne and the harness | 1 MiB |
| Create, join, Add, Update, or Remove wall time (p95), 2 or 3 members | 1 second per operation |
| Same operation wall time (p95), 32 members | 2 seconds per operation |
| Same operation wall time (p95), 256 members | 5 seconds per operation |
| Incremental 1 KiB application-message protect or open wall time (p95) | 50 ms |
| Peak memory above the idle initialized harness | 128 MiB |
| One encoded Commit or Welcome | 4 MiB |
| One member's serialized current private/public state, excluding archived records | 16 MiB |

Use the same cipher suite and zero obsolete-key retention for all group sizes.
Record CPU, RAM, OS, power settings, exact Node.js/Chromium versions, and bundler
configuration; run both environments on the same otherwise idle machine.
Report cold import/initialization separately. After five warm-up runs, collect
at least 30 independent samples per operation and group size, restoring a fresh
fixture for each sample; report raw durations, median, p95, and maximum. Measure
end-to-end elapsed operation time including worker messaging, with no network
latency in these provider-only measurements. Record the compressed production
bundle and exact encoded byte counts. Sample process memory during operations
(Node.js RSS and the isolated Chromium renderer plus worker processes), subtract
the measured idle baseline, and record the sampling interval alongside heap
profiles; a heap-only sample is not evidence of total peak-memory compliance.
Network, durable-storage, and Peerborne end-to-end costs require separate tests.

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

This delays MLS integration while the dependency and provider gates remain
unmet. BeeKEM is the current runtime protocol; its tests do not establish MLS
support or RFC 9420 forward-secrecy or post-compromise-security guarantees.
A future provider integration must follow ADR 0001's single-family replacement
policy rather than preserve old wire formats for nonexistent deployed users.

## References

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750.html)
- [`mls-rs`](https://github.com/awslabs/mls-rs)
- [`ts-mls`](https://www.npmjs.com/package/ts-mls)
- [`ts-mls` 1.6.4 package metadata](https://github.com/LukaJCB/ts-mls/blob/v1.6.4/package.json)
- [MLS implementation registry](https://messaginglayersecurity.rocks/implementations/)
- [ADR 0001: MLS document security architecture](../0001-mls-document-security-architecture/)
