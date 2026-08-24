---
title: Redux integration
description: Initialize and read Peerborne state through Redux while accounting for the current local-change ordering bug.
---

**Status: Runnable from source for setup, open, read, and remote subscription; local editing is illustrative/deferred.**

The package is unpublished. Use repository workspaces and build them with `yarn build`. Unit tests cover Redux actions/reducers, and the Automerge examples build and smoke-test, but live multi-peer propagation is not asserted in a browser.

## Store setup

The reducer factory needs a stable ECDSA P-384 identity before store creation. With redux-thunk 3, use its named export:

```ts
import { applyMiddleware, combineReducers, createStore } from 'redux';
import { thunk } from 'redux-thunk';
import {
  SubtleCrypto,
  defaultBootstrapConfig,
  defaultConfig,
} from '@peerborne/core';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
} from '@peerborne/yjs';
import {
  PeerborneState,
  closeDocumentAsync,
  peerborneReducer,
  initializeAsync,
  openDocumentAsync,
} from '@peerborne/redux';
import * as Y from 'yjs';

type SwarmState = PeerborneState<
  Y.Doc,
  Uint8Array,
  (doc: Y.Doc) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
type RootState = { swarm: SwarmState };

const selectSwarm = (state: RootState) => state.swarm;

function createSwarmStore(identity: CryptoKeyPair) {
  const serializer = new YjsJSONSerializer();
  const reducer = combineReducers({
    swarm: peerborneReducer(
      identity.privateKey,
      identity.publicKey,
      new YjsProvider(),
      serializer,
      serializer,
      serializer,
      new SubtleCrypto(),
      new YjsACLProvider(),
      new YjsKeychainProvider(),
    ),
  });
  return createStore(reducer, applyMiddleware(thunk));
}
```

Persist `identity`; regenerating it changes ACL identity. The store intentionally contains non-serializable live node, document-ref, and Yjs values.

## Initialize once, then open and read

```ts
async function openNote(identity: CryptoKeyPair) {
  const store = createSwarmStore(identity);
  const config = defaultConfig(defaultBootstrapConfig(
    import.meta.env.VITE_RELAY_MULTIADDR
      ? [import.meta.env.VITE_RELAY_MULTIADDR]
      : [],
  ));

  await store.dispatch<any>(initializeAsync(config, selectSwarm));
  await store.dispatch<any>(openDocumentAsync('/notes/hello', selectSwarm));

  const opened = selectSwarm(store.getState()).documents['/notes/hello'];
  const text = opened.document.getText('content').toString();
  return { store, text };
}
```

Initialize the node once at application startup. `initializeAsync` installs peer listeners and has no matching Redux shutdown action; repeated component effects can duplicate initialization/listeners. `openDocumentAsync` subscribes with the `'remote'` filter and dispatches `SYNC_DOCUMENT` for subsequent remote events. Always pass the selector when the slice is nested.

On teardown:

```ts
async function closeNote(store: ReturnType<typeof createSwarmStore>) {
  await store.dispatch<any>(closeDocumentAsync('/notes/hello', selectSwarm));
}
```

Cancellation is application-owned. If a component unmounts while initialization or open is pending, Redux does not abort that work; guard late continuations and avoid closing a newer open for the same path.

## Current local-edit bug

**Status: Deferred/incomplete integration for reliable local Yjs rendering.** `changeDocumentAsync` currently starts `documentRef.change(...)`, immediately dispatches `CHANGE_DOCUMENT` with `documentRef.document`, and only then awaits the change promise. The dispatched value can therefore be stale. Because the document subscription listens only for `'remote'` changes, no local subscription is guaranteed to repair the Redux state after the awaited mutation.

Yjs also mutates a `Y.Doc` in place, so selecting the document object does not guarantee a rerender from reference identity. Do not claim reliable local Yjs rerenders from the current thunk. Until the thunk dispatches after the awaited mutation (and has focused tests), perform local editing through an application layer that awaits the direct document ref, reports rejection, and explicitly publishes derived Redux state.

Remote read state remains useful, but select derived primitives such as text strings rather than memoizing on the `Y.Doc` reference. See [Limitations](../../concepts/limitations/) for mutation and delivery semantics.
