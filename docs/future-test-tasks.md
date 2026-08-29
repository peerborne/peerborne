# Deferred Peerborne verification tasks

The required cross-NAT acceptance proof is tracked by
`e2e/peerborne-nat.spec.ts`. The following work is intentionally deferred and
should be selected as explicit future tasks rather than being mistaken for
current coverage.

- Revocation after invitation: remove the invited collaborator, deliver the
  BeeKEM PathUpdate, and reject post-revocation reads and writes.
- Invitation durability: restart the inviter and recipient around offer
  creation/acceptance, persist KEM and replay state, and test offline expiry.
- Partition/rejoin: make concurrent document edits while both browser network
  namespaces are disconnected from the relay, restore it, and assert exact
  Automerge convergence.
- Persistence: restart one persistent Chromium profile offline and recover the
  document from IndexedDB before reconnecting.
- Transport matrix: force WebSocket relay, WebRTC/DCUtR, TURN, and WebTransport
  separately and assert document synchronization for each.
- Hostile peers: invalid signatures, stale ACLs, replayed updates, conflicting
  quorum tips, oversized messages, and explicit processing/memory limits.
- Packaging: install packed artifacts in clean Node, Vite, React, and Redux
  consumer fixtures and exercise public imports at runtime.
- Lifecycle and indexing: React StrictMode reconnect/leak assertions, schema
  migration fixtures, distributed blind-index search, and token rotation.
- Operations: container health/readiness, graceful shutdown, persisted-data
  upgrade, rollback policy, dependency scanning, and performance budgets.

Completion rule: a task is covered only when its assertion runs from a named
CI job. Documentation or an opt-in local script alone does not count.
