# Formal policy verification

The 135 selected production functions in 34 proof units are compiled from their
actual TypeScript implementations to Dafny by LemmaScript. These include the
core policy directory and selected functions in core, index and React modules.
The runtime calls those same functions; there is no parallel executable model.
See the [assessment and scope](../../docs/formal-verification.md).

```sh
yarn verify:formal:setup
yarn verify:formal
yarn verify:formal:controls
yarn verify:formal:inventory
```

Setup installs tools locally under `.tools/`, without changing global settings
or application dependencies. LemmaScript is pinned to a Git revision and its
npm lockfile; Dafny 4.11.0 archives have pinned SHA-256 digests. Linux x64 and
macOS arm64/x64 are supported. `PEERBORNE_FORMAL_TOOLS` selects another cache
directory. Setup requires network access, Git, npm and unzip. Normal verification
uses the installed tools without downloads. CI can run the Node commands
directly without installing Peerborne's browser/transport dependencies.

`verify:formal` requires every manifest function to be selected and every core
policy file to be registered. AST checks find real selection comments even
after template literals, reject selections absent from the manifest and verify
the named consumers' actual relative imports/re-exports. Unselected functions
in the same file are outside the proof. Selected call graphs stay closed within
each unit; unrelated imports elsewhere in the file do not become proof evidence.

The runner rejects missing proof files, generated-file drift, unverified
declarations, partial verification, proof escape annotations, a missing domain
witness, and incorrect number/string/slicing configuration. The tree, Welcome-admission, invitation-replay and
sync-response units also run complete verification under fixed solver seeds 1, 2, 7 and 19 with a
10-second per-obligation limit; this changes solver search, not the contracts. Dafny's assumption
audit must report zero findings, including no body-less declarations or
unproved imported contracts.

The manifest names the actual verified obligations because Dafny need not
emit a separate verification task for a straight-line function whose body has
no well-formedness obligations. Its generated `_ensures` lemma proves the
functional contract. Loop methods carry contracts directly. Witness methods
call the generated functions with valid boundary inputs; a contradictory
precondition cannot make the verification green vacuously.

## Editing production code or contracts

```sh
yarn verify:formal:regen
yarn verify:formal
yarn verify:formal:controls
```

`.dfy.gen` files are generated and must not be edited. `.dfy` files contain
the generated program plus proof additions and domain witnesses. The
additions-only check prevents changing the program inside its proof. Use
`regen` to preserve proof additions after a source edit. Do not delete the
proof files to make regeneration succeed. Recovery files `.dfy.base` and
`.dfy.merged` are ignored and should be handled using the pinned tool's
[regen guidance](https://github.com/midspiral/LemmaScript/blob/f245e9878aa23a3c4a2d3f75ade4a44cebd545dc/AGENTS.md).

The control runner copies selected sources and proofs into temporary
directories. Its 193 controls cover 34 accepted originals, map-comparison and native-map-alias
calibrations, 153 semantic/vacuity mutations, stale generated code, `assume false`,
body-less lemmas and unproved imports. Semantic mutations must reach the verifier and fail an obligation;
a parser error, a timeout alone or a drift-only rejection is insufficient.
All accepted originals receive full-unit verification. Four tree, fourteen invitation-replay and seventeen Welcome-admission
mutations check only the changed function and require that exact function to
fail an obligation; the report labels these counterexample checks explicitly.
The checked production program is always verified in full. This avoids
reproving unchanged arithmetic and history helpers for each deliberately broken program.

The native-map-alias calibration intentionally verifies a candidate that aliases
its parent, then confirms that the JavaScript parent is mutated. Dafny maps model
values, so the separate native ownership properties are necessary to check the
production copies; this calibration is not an additional verified security claim.

`verify:formal:inventory` audits all library selections against the manifest.
It also audits all fast-check imports/assertions for explicit fixed seeds and
bounded run counts, and requires every property suite to have evidence paths
and a formal-boundary explanation in the
[fallback catalog](../strategy.json). It reports 52 property-suite files and
137 assertion declarations; parameterized suites can execute declarations more
than once. Remaining named top-level functions are listed for future
specification work. These are structural counts, not semantic coverage.

The property audit includes JavaScript test files and native `.fixture.mjs`
files. The binary chunk fixture runs through Node/tsx from the normal Jest
suite so the actual ESM Uint8ArrayList dependency is exercised on Node 22.

Reports, source/proof digests, tool versions, per-member verification results,
assumption audits, fixed solver-seed checks and control results go under `verification/results/formal/`.
CI runs complete proof/audit/inventory checks and complete counterexample controls
in parallel jobs with separate `formal-verification` and `formal-controls`
evidence artifacts. The existing `Formal policy verification` gate requires both
jobs to succeed, including after a failure or cancellation. Solver limits and
the full verification scope are unchanged. These reports contain
source metadata and synthetic proof cases, never live keys or document data.

## Proof domain

The default number domain is mathematical integers; the base64 helpers also use
the supported real division/ceiling model, and finite-number ordering uses
real comparisons without real arithmetic on the values. Contracts bound production arithmetic
to exact safe-integer ranges; runtime adapters supply validated counters,
timestamps, uint32 generations, uint64 BigInt epochs and capacities. Native
IEEE-754 behavior is calibrated with independent BigInt properties. Strings
explicitly use JavaScript UTF-16 semantics and safe slicing.

The additional units cover partition-preserving package maps, committed byte
and epoch bounds, claim/recovery decisions, replay/outbox retention, least graph
reachability with edge-linear queue accounting, bounded BeeKEM tree geometry,
and scalar/lexicographic ordering and prefix pages. Their exact bounds and
runtime gaps are listed in the [scope assessment](../../docs/formal-verification.md).
Authentication work reservation, membership-control epoch/parent admission
and binary field/copy bounds also have checked history or composition laws.
Signature verification, authorizers, queue scheduling, fork latching and
native byte APIs remain explicit property-test boundaries.

Welcome admission additionally proves exact byte totals and protected budgets,
pressure trimming, removal and value-map projection/insertion. Checked
finite histories preserve authenticated bindings under unverified traffic,
bound count/bytes and exclude newly authenticated bindings introduced only by
unverified or failed preparations. Minimal-body header checks cannot reject an
otherwise admissible body. The runtime validates strict keys/flags, rejects
before copying or avoidable serialization, replans after serializer callbacks,
and installs prepared state only after owned-body copying succeeds. Native
properties inject preparation failures and calibrate byte/map ownership and
ranked eviction order.

Three additional helpers verify strict expiry membership, exact retained bytes
and a nondecreasing sampled clock. Finite histories compose these decisions with
admission and deletion, preserving timestamp/map coherence and unchanged state
after failed preparations or rejected stores. The runtime stamps successful
arrivals with the observed clock and prunes metadata before replay-body copying.
Native BigInt properties cover backward and malformed clock samples,
safe-integer boundaries, injected expiry failures and cancellation in the actual
drain. Authentication, clock progress, periodic pruning, asynchronous replay,
native heap usage and delivery remain outside this retention proof.

Invitation-replay histories preserve one signed join binding and at most one
acceptance per offer, including after expiry retirement and clock rollback.
All four indexes remain coherent and individually bounded by capacity.
A checked expiry frontier skips enumeration while every claim is live; due
sweeps still visit up to the configured capacity (at most 65,536 entries).
Native properties check in-place map ownership, real signature/wire bindings,
immutable capacity, malformed clocks and expiry during asynchronous hashing.
The fixed offer catalog models digest binding; signature verification remains
the caller's responsibility. These are per-instance replay guarantees, with
no claim of durable replay protection or browser latency.

Sync-response histories additionally preserve live replay bindings under
nondecreasing effective time and derive a 46-entry ledger bound from freshness
and response spacing. Native properties exercise expiry during asynchronous
preparation, failed preparation, clock rollback and strict authorization. These
are per-instance logical bounds, not durable replay or UI-latency guarantees.
Registered GossipSub validation also has a native property separating local
response history and expiry from cryptographic rejection and peer penalties.
Quorum verification now also covers exact digest counts, first-eligible peer
selection, stable cohort projection and failure precedence. A checked
occurrence-count lemma rules out two distinct strict-majority winners. Native
map ordering, response ownership, candidate capture and asynchronous probes
remain property-tested boundaries.

Document admission adds checked finite-history models for counter bounds,
context- and authorization-matching commits, at-most-once finalization and
absorbing terminal phases. Runtime preparation promises, current-authorization
guards, exact native reservation ownership,
protected anchor reads, private authentication certificates and queue ordering
remain property-tested boundaries. The model does not establish cryptographic
secrecy, arbitrary callback correctness or document-engine integration.

Inputs are detached records, arrays and native string sets/maps; property getters,
proxies and concurrent alias mutation are outside the model. Constant capability
tables are frozen. Owned invitation indexes intentionally mutate in place; their native map identity
and distinct ownership are checked separately. Candidate collections elsewhere
must preserve their stated copy/ownership contracts.
Runtime parsing, callback authentication, scheduling, I/O, cryptographic
primitives, side channels and browser resource limits are outside these proofs.
The generated inventory is a scope inventory, not a security coverage
percentage or an end-to-end verification claim. Keep the fallback evidence
listed in the catalog for those boundaries.

Keep map-index lookups on the left of ordered comparisons in contracts. The
pinned compiler can reverse an inequality when lifting a partial map-index
lookup from its right operand. The map-comparison control checks all four
supported left-operand comparisons against independent scalar comparisons,
with a checked domain witness and zero-assumption audit. Guarded `Map.get`
contracts and map-index equality do not use that problematic expression form.
