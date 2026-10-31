---
title: Integration status and candidates
description: Scope and acceptance boundaries for frontend and CRDT integrations.
---

Peerborne remains alpha software. The new integrations are source workspaces;
they are not published to npm. Local mutation tests and isolated provider tests
do not establish end-to-end peer convergence, durable recovery, or production readiness.

| Integration | Current scope | Remaining acceptance |
| --- | --- | --- |
| Plain web / document store | Dependency-free document snapshots, lifecycle/error tests, and a plain DOM browser example | Live multi-peer behavior, restart recovery, and deployment acceptance |
| React | External-store hook, shared ownership, StrictMode test, and browser example | Live multi-peer behavior, restart recovery, and deployment acceptance |
| Vue | Shallow composable, SSR/lifecycle tests, and browser example | Live multi-peer behavior, restart recovery, and deployment acceptance |
| Svelte | Svelte 5 readable, server/lifecycle tests, and compiled browser example | Live multi-peer behavior, restart recovery, and deployment acceptance |
| Loro | Experimental provider: concurrency, snapshot, replay, reordered/corrupt updates, and local browser mutation | Live multi-peer behavior, restart recovery, and deployment acceptance |

## Additional candidates

[Yrs](https://github.com/y-crdt/y-crdt) is a Rust/native Yjs-family candidate.
Prove update-v2 and snapshot interoperability, then supply Peerborne's crypto,
membership, storage, and transport layers; CRDT byte compatibility alone is not
a native Peerborne client. [Diamond Types](https://github.com/josephg/diamond-types)
remains a text-focused candidate requiring a measured workload, browser/WASM,
snapshot, undo, cursor, and malformed-input evaluation.

Angular/RxJS, Solid, and Preact remain demand-led frontend candidates. Nuxt and
SvelteKit need complete application acceptance beyond underlying Vue/Svelte
server tests. Tailwind and shadcn/ui need styling recipes rather than Peerborne
adapters. A dedicated Vite plugin is deferred until recurring configuration
warrants one. The full runtime still needs browser dependency resolution;
no published CDN bundle is claimed.

Loro snapshots retain full application operation history. Use separate paths for separate engines. The example retains the existing Yjs ACL, keychain, and byte serializers; it does not provide content-history redaction.
