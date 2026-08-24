# `@peerborne/yjs`

Build collaborative applications with Yjs shared types. This package provides the CRDT provider, serialization, ACL, and keychain adapters that connect Yjs documents to Peerborne's encrypted peer-to-peer sync engine.

## What you get

- **Yjs adapter** — wraps Yjs `Doc`, shared types (Y.Map, Y.Array, Y.Text), and merge semantics with Peerborne's encryption and signing
- **Deterministic merging** — concurrent edits resolve without conflicts using Yjs's battle-tested CRDT algorithms
- **Works with any Yjs editor binding** — ProseMirror, Tiptap, CodeMirror, Quill, Monaco

## Choose this package

Use this adapter for Yjs-backed collaborative documents. It works with:

- `@peerborne/core`, included as a package dependency
- `yjs`, required as a peer dependency
- optional React or Redux bindings for application state

## Entry point

`@peerborne/yjs` exports `YjsProvider`, `YjsJSONSerializer`, Yjs-backed ACL and keychain implementations, the document change handler, and key serialization helpers.

## Start here

- [Yjs schema design guide](https://peerborne.io/cookbook/yjs-schema-design/)
- [Yjs + React example](https://github.com/Peerborne/peerborne/tree/main/examples/password-manager)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
