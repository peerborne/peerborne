# `@peerborne/redux`

Redux bindings for Peerborne — actions, thunks, and reducers that manage node lifecycle, document open/close, peer connections, and change dispatch from a Redux store.

## What you get

- **Async thunks** — `initializeAsync`, `openDocumentAsync`, `connectAsync`, `changeDocumentAsync` — for every Peerborne lifecycle operation
- **Synchronous actions** — `CHANGE_DOCUMENT`, `SYNC_DOCUMENT`, `PEER_CONNECT`, etc. for direct Redux dispatching
- **`peerborneReducer`** — handles document cache, peer state, readers/writers, and change subscriptions
- **Selector helpers** — typed access to `state.peerborne.documents[id]` with TypeScript inference

## Choose this package

Use these bindings when Peerborne state belongs in a Redux store. The package declares `@peerborne/core`, Redux, and Redux Thunk as peer dependencies. The application must also supply compatible CRDT provider, serializer, ACL, and keychain implementations; the shipped Automerge and Yjs adapters provide them.

The current local-change thunk has a documented ordering limitation; review the integration guide before relying on local Redux rendering.

## Entry point

`@peerborne/redux` exports synchronous and asynchronous action creators, action constants and types, `initialState`, and `peerborneReducer`.

## Start here

- [Redux integration guide](https://peerborne.io/cookbook/redux/)
- [Automerge + Redux example](https://github.com/Peerborne/peerborne/tree/main/examples/wiki-swarm)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
