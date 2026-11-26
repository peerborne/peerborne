# `@peerborne/redux`

Version 0.1.0 is alpha software, not production-ready. Packages ship one ESM build, with native CommonJS `require()` interoperability on Node.js 26.13.1 or newer.

Redux bindings for Peerborne — actions, thunks, and reducers that manage node lifecycle, document open/close, peer connections, and change dispatch from a Redux store.

## What you get

- **Async thunks** — `initializeAsync`, `connectAsync`, `openDocumentAsync`, `closeDocumentAsync`, and `changeDocumentAsync`
- **Synchronous actions** — `CHANGE_DOCUMENT`, `SYNC_DOCUMENT`, `PEER_CONNECT`, etc. for direct Redux dispatching
- **`peerborneReducer`** — holds the node, each open document's reference and latest state, and connected peer addresses
- **`PeerborneState`** — the reducer's state type, for typing your own selector

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

## Configure the node

`initializeAsync(config, selector)` passes `config` to the node. Without a config it uses the browser-only `defaultConfig`, which needs IndexedDB. In Node.js, pass a configuration built with `defaultNodeConfig` from `@peerborne/core/node`.

## Selecting the Peerborne state

Every async thunk takes a selector that returns the `PeerborneState` from the root state. The default selector expects `peerborneReducer(...)` to be the root reducer. When you mount it under a key, such as `combineReducers({ peerborne: peerborneReducer(...) })`, pass `(state) => state.peerborne` to each thunk. A thunk whose selector does not return Peerborne state (an object with `node`, `documents`, and a `peers` array) rejects with a `TypeError` before it touches the node.

The package does not provide reader or writer selectors; read ACL state from the open document reference.

## Opening documents

Use `openDocumentAsync(path, selector, 'create')` to explicitly create a new document. The default `'open'` mode loads existing state from peers and propagates load failures without creating a replacement. That load requires `resolveLoadSecurityCommitments` and `resolveTrustedDocumentWriters` in the node configuration. If no connected peer can serve the path (a relay cannot), the thunk rejects with `No document state is available…`; if one can and `resolveLoadSecurityCommitments` is missing, it rejects with `TrustedLoadSecurityCommitmentsError`. To share a document with another identity, use [invitations](https://peerborne.io/cookbook/invitations/). See [Open existing documents](https://peerborne.io/concepts/documents/#open-existing-documents).
