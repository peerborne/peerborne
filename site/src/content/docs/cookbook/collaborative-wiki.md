---
title: Build a collaborative wiki
description: Run and assess the repository's Vite, Redux, and Automerge wiki example.
---

**Status: Runnable from source (single-browser startup smoke only).**

The current wiki is [`examples/wiki-swarm`](https://github.com/Peerborne/peerborne/tree/main/examples/wiki-swarm): a Vite application using Redux and Automerge. Its production build and strict Chromium startup smoke test pass. This evidence does **not** prove article mutation, two-browser synchronization, convergence, restart recovery, or a multi-user Yjs application. See [Limitations](../../concepts/limitations/).

The workspace packages are unpublished. Work from a repository checkout with Node.js 22.19.0 and the locked dependencies installed as described in the [quick start](../../getting-started/quick-start/).

## Run and verify the source example

From the repository root:

```sh
yarn build
yarn workspace @peerborne/wiki-swarm start
```

Vite prints the local URL. To build without starting a server:

```sh
yarn workspace @peerborne/wiki-swarm build
```

To run the exact application smoke path:

```sh
yarn exec playwright install chromium
yarn test:e2e:wiki-swarm
```

The last command builds the wiki and checks that it starts in Chromium without browser runtime errors. It is not a collaboration test.

## Relay configuration

The example reads a browser-safe Vite variable:

```sh
VITE_RELAY_MULTIADDR='/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW...' \
  yarn workspace @peerborne/wiki-swarm start
```

Use the public, dialable multiaddr from [Run your own relay](../running-a-relay/), not a `0.0.0.0` listen address. A relay helps browser peers discover and reach one another; it does not store wiki data durably.

## What the example demonstrates

- Vite can bundle the Automerge WASM application.
- The current Redux reducer/provider stack initializes far enough to render the wiki shell.
- The source maps a route document ID to one Automerge document, but the smoke test does not open or mutate an article.
- Title, Slate content, metadata, and ACL display are application-level patterns.

The example must use one **stable, application-persisted ECDSA P-384 signing identity** across reloads. Generating a new key pair on each mount creates a new ACL identity and is not an account or recovery flow. Signing identity, KEM identity, document keys, and libp2p peer identity are distinct; see [Security](../../concepts/security/).

## Multi-user work still required

**Status: Deferred/incomplete integration.** The wiki has no automatic invitation, identity directory, key exchange, or account recovery. Sharing an article path or signing public key does not transfer its document key. A real invitation flow must authenticate the recipient out of band, exchange the recipient's signing and P-256 ECDH KEM public keys, persist both parties' key material, and exercise the core onboarding APIs described in the [password-manager recipe](../password-manager/).

Do not describe full-string or editor-state replacement as a production-safe collaborative delta strategy. The current smoke test does not assert concurrent editor behavior. If adapting the design to Yjs, choose shared types and operations deliberately; see [Designing Yjs schemas](../yjs-schema-design/).

## Application design cautions

A wiki commonly uses one article document plus a separate article-index document. Updating both is a dual write: Peerborne does not provide a transaction spanning documents, so one update can succeed while the other rejects. Make index repair and reconciliation explicit.

Do not infer durability from content-addressed blocks or recommend pinning as an available fix. The current pinning path is incomplete; retained blocks alone also omit identity, keys, graph state, and recovery metadata. See [Storage](../../concepts/storage/) and [Keeping data alive](../pinning/).
