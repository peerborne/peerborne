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

## Svelte

Svelte 5 readable, server/lifecycle tests, and compiled browser example. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## TanStack DB

Experimental collection adapter pinned to 1.0.0-rc.1.1; CRUD, rollback, and browser exercise. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Zustand

Vanilla-API snapshot projection recipe with explicit cleanup. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Jotai

Vanilla-API atom projection recipe with explicit cleanup. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

## Next.js

Server-rendered starter and hydrated browser mutation, using webpack. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/nextjs) and [integration status](../../reference/integration-status/).

## TanStack Start

Server-rendered starter and hydrated browser mutation, using the Hono Node adapter. See the [source examples](https://github.com/Peerborne/peerborne/tree/main/examples/integrations) and [integration status](../../reference/integration-status/).

The React hook uses `@peerborne/react/store`, requires no context caches, and returns a stable server snapshot. Initialize the node only in the browser. Bindings acquire ownership after mounting; state projections keep the CRDT authoritative rather than creating another mutation/sync authority.
