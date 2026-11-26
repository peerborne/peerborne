# `@peerborne/automerge`

Version 0.1.0 is alpha software, not production-ready. Packages ship one ESM build, with native CommonJS `require()` interoperability on Node.js 26.13.1 or newer.

Build collaborative applications with Automerge's JSON-like CRDT documents. This package provides the CRDT provider, serialization, ACL, and keychain adapters that connect Automerge documents to Peerborne's encrypted peer-to-peer sync engine.

## What you get

- **Automerge adapter** — wraps Automerge documents with Peerborne's encryption, signing, and peer-to-peer networking
- **JSON-like data model** — familiar document structure with automatic merge of concurrent edits
- **Rich text support** — built-in Automerge Text type for collaborative editing

## Choose this package

Use this adapter for Automerge-backed collaborative documents. It works with:

- `@peerborne/core`, included as a package dependency
- `@automerge/automerge` `^3.5.0`, required as a peer dependency
- optional React or Redux bindings for application state

The keychain and ACL validators accept a canonical change only when the local
Automerge release re-encodes it to the received bytes, so peers must use
releases that encode those changes identically. A repository test pins the
encoder's canonical seed and append hashes, so a release that changes them
fails CI.

## Entry point

`@peerborne/automerge` exports `AutomergeProvider`, `AutomergeJSONSerializer`, Automerge-backed ACL and keychain implementations, and the document change handler.

## Start here

- [Collaborative wiki guide](https://peerborne.io/cookbook/collaborative-wiki/)
- [Automerge + Redux example](https://github.com/Peerborne/peerborne/tree/main/examples/wiki-swarm)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
