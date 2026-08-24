# `@peerborne/react`

React hooks and context for Peerborne — initialize the node, open documents, subscribe to changes, and manage ACL state, all from your component tree.

## What you get

- **`usePeerborne`** — initialize the Peerborne node with signing keys, providers, and bootstrap config
- **`usePeerborneDocumentState`** — open a document, subscribe to remote updates, and access the current CRDT state
- **`PeerborneContext`** — provider for document cache, readers/writers state, and shared configuration
- **Works with any CRDT adapter** — pair with `@peerborne/yjs` or `@peerborne/automerge`

## Choose this package

Use these bindings in a React application. It depends on `@peerborne/core`, declares React as a peer dependency, and requires compatible CRDT provider, serializer, ACL, and keychain implementations. The shipped Automerge and Yjs adapters provide those implementations.

## Entry point

`@peerborne/react` exports `usePeerborne`, `usePeerborneDocumentState`, `PeerborneContext`, and the context result type.

## Start here

- [React integration guide](https://peerborne.io/cookbook/react/)
- [Yjs + React example](https://github.com/Peerborne/peerborne/tree/main/examples/password-manager)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
