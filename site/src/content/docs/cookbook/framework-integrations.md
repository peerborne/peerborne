---
title: Frontend framework integrations
description: Framework bindings and state projections over a common document store.
---

Start with the [framework-free store](../../getting-started/vanilla/).
Create one store per node/document path and share it between consumers.
Every mutation returns a promise; await `store.change(...)` to handle failures.

## React

External-store hook, shared ownership, StrictMode test, and browser example. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Vue

Shallow composable, SSR/lifecycle tests, and browser example. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

The React hook uses `@peerborne/react/store`, requires no context caches, and returns a stable server snapshot. Initialize the node only in the browser. Bindings acquire ownership after mounting; state projections keep the CRDT authoritative rather than creating another mutation/sync authority.
