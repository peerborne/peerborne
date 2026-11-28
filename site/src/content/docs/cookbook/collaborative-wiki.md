---
title: Build a collaborative wiki
description: Run and assess the repository's Vite, Redux, and Automerge wiki example.
---

**Status: Runnable from source (single-browser tests only).**

The current wiki is [`examples/wiki-swarm`](https://github.com/Peerborne/peerborne/tree/main/examples/wiki-swarm): a Vite application using Redux and Automerge. Its production build and single-browser Chromium tests pass: startup, article creation, title typing, reload from an encrypted checkpoint, reopening in the same tab, and refusing to create an existing article again. This evidence does **not** prove two-browser synchronization, convergence, concurrent editing, or a multi-user Yjs application. See [Limitations](../../concepts/limitations/).

The workspace packages are unpublished. Work from a repository checkout with Node.js 26.13.1 and the locked dependencies installed as described in the [quick start](../../getting-started/quick-start/).

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

To run the application tests:

```sh
yarn exec playwright install chromium
yarn test:e2e:wiki-swarm
```

The last command builds the wiki and exercises it in one Chromium page. It is not a collaboration test.

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
- The source maps a route document ID to one Automerge document. An opened article stays open for the tab, and each change saves an encrypted, self-signed checkpoint in IndexedDB, so the article reopens after navigation or a reload. Creating an ID that this browser already holds is refused with a warning.
- Title edits are applied as text splices, and the Redux store receives the document only after each change is applied. Slate content, metadata, and ACL display are application-level patterns.

The example keeps one **stable, non-extractable ECDSA P-384 signing identity** in IndexedDB, with a P-256 KEM key pair and an AES-GCM storage key, through the same browser checkpoint store as the password-manager and Peerborne Note examples. Clearing site data removes the identity and saved articles; this is not an account or recovery flow. Signing identity, KEM identity, document keys, and libp2p peer identity are distinct; see [Security](../../concepts/security/).

## Multi-user work still required

**Status: Deferred/incomplete integration.** The wiki has no invitation UI,
identity directory, key backup, or account recovery. Sharing an article
path or signing public key does not transfer its document key. An application
can use the core founder-plus-one onboarding API described in [Invite a
collaborator](../invitations/), but it must still authenticate invitation
delivery and persist both parties' signing and KEM key material.

The Slate body still replaces the whole editor value on each edit. Do not describe editor-state replacement as a production-safe collaborative delta strategy. The tests do not assert concurrent editor behavior. If adapting the design to Yjs, choose shared types and operations deliberately; see [Designing Yjs schemas](../yjs-schema-design/).

## Application design cautions

A wiki commonly uses one article document plus a separate article-index document. Updating both is a dual write: Peerborne does not provide a transaction spanning documents, so one update can succeed while the other rejects. Make index repair and reconciliation explicit.

Do not infer durability from content-addressed blocks or recommend pinning as an available fix. The current pinning path is incomplete; retained blocks alone also omit identity, keys, graph state, and recovery metadata. See [Storage](../../concepts/storage/) and [Keeping data alive](../pinning/).
