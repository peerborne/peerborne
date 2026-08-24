# `@peerborne/automerge`

Build collaborative applications with Automerge's JSON-like CRDT documents. This package provides the CRDT provider, serialization, ACL, and keychain adapters that connect Automerge documents to Peerborne's encrypted peer-to-peer sync engine.

## What you get

- **Automerge adapter** — wraps Automerge documents with Peerborne's encryption, signing, and peer-to-peer networking
- **JSON-like data model** — familiar document structure with automatic merge of concurrent edits
- **Rich text support** — built-in Automerge Text type for collaborative editing

## Choose this package

Use this adapter for Automerge-backed collaborative documents. It works with:

- `@peerborne/core`, included as a package dependency
- `@automerge/automerge`, required as a peer dependency
- optional React or Redux bindings for application state

## Entry point

`@peerborne/automerge` exports `AutomergeProvider`, `AutomergeJSONSerializer`, Automerge-backed ACL and keychain implementations, and the document change handler.

## Start here

- [Collaborative wiki guide](https://peerborne.io/cookbook/collaborative-wiki/)
- [Automerge + Redux example](https://github.com/Peerborne/peerborne/tree/main/examples/wiki-swarm)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
