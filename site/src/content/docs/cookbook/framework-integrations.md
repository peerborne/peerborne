---
title: Frontend framework integrations
description: Framework bindings and state projections over a common document store.
---

Start with the [framework-free store](../../getting-started/vanilla/).
Create one store per node/document path and share it between consumers.
A store that opens and closes the document takes a handle factory, such as
`createDocumentStore(() => peerborne.doc(path))`, and opens a fresh handle
after a remount closed the previous one. A closed handle does not reopen when
`beekemForkStore` is configured or the document is coordinated. A fresh handle
loads from a connected peer, so a remount after the close needs one, or a
factory that restores the latest checkpoint; see the
[store README](https://github.com/peerborne/peerborne/blob/main/packages/store/README.md).
The `closeDelay` option keeps the document open across a quick remount, and
the final release keeps a document with an undelivered change open for up to
`undeliveredCloseDelay`. Pass an
existing handle only with `{ manageLifecycle: false }`.
Every mutation returns a promise; await `store.change(...)` to handle failures.
A change never opens the document, and a store whose document was retired
reports the `retired` status instead of the discarded edit.

## React

External-store hook, shared ownership, StrictMode test, and browser example. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Vue

Shallow composable, SSR/lifecycle tests, and browser example. Pass a getter such as `usePeerborneStore(() => props.store)` to follow a store prop. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Svelte

Svelte 5 readable, server/lifecycle tests, and compiled browser example. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## TanStack DB

Experimental collection adapter for `^1.0.0-rc.1.5`, tested with 1.0.0-rc.1.5; CRUD, rollback, retired-document failure, and browser exercise. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Zustand

Vanilla-API snapshot projection recipe with explicit cleanup. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Jotai

Vanilla-API atom projection recipe with explicit cleanup. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Next.js

Server-rendered starter and hydrated browser mutation, using webpack. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/nextjs) and [integration status](../../reference/integration-status/).

## TanStack Start

Server-rendered starter and hydrated browser mutation, using the Hono Node adapter. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/tanstack-start) and [integration status](../../reference/integration-status/).

The React hook uses `@peerborne/react/store`, requires no context caches, and returns a stable server snapshot. Initialize the node only in the browser. Bindings acquire ownership after mounting; state projections keep the CRDT authoritative rather than creating another mutation/sync authority.
