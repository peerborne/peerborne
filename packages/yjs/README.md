# `@peerborne/yjs`

Version 0.1.0 is alpha software, not production-ready. Packages ship one ESM build, with native CommonJS `require()` interoperability on Node.js 26.13.1 or newer.

Build collaborative applications with Yjs shared types. This package provides the CRDT provider, serialization, ACL, and keychain adapters that connect Yjs documents to Peerborne's encrypted peer-to-peer sync engine.

## What you get

- **Yjs adapter** — wraps Yjs `Doc`, shared types (Y.Map, Y.Array, Y.Text), and merge semantics with Peerborne's encryption and signing
- **Deterministic merging** — concurrent edits resolve without conflicts using Yjs's battle-tested CRDT algorithms
- **Experimental editor bridge** — route upstream editor mutations through the Peerborne change boundary using a private Yjs mirror; awareness transport is not provided.

## Choose this package

Use this adapter for Yjs-backed documents. In the default document mode a Yjs
document cannot be shared with another identity: invitations require the
Automerge provider profile, so only the founder's identity can open it. Use
`@peerborne/automerge` for documents that collaborators join. It works with:

- `@peerborne/core`, included as a package dependency
- `yjs`, required as a peer dependency
- optional React or Redux bindings for application state

## Entry point

`@peerborne/yjs` exports `YjsProvider`, `YjsJSONSerializer`, Yjs-backed ACL and keychain implementations, the document change handler, and key serialization helpers.

## Authenticated ACL history

`YjsACL` records each revocation as an immutable receipt. A grant is effective
when it covers every retained revocation for that member. A grant issued
during a partition can therefore be displaced by a revocation it had yet to
observe. A subsequent grant that includes all receipts can restore the member.
The ACL evaluates the retained grants, including those overwritten in Yjs,
so the native map conflict order does not select the effective grant.

The adapter disables Yjs garbage collection for this history and rejects
erased membership values. Reopening requires the full authenticated ACL
history. Encoded updates and retained state are capped at 4 MiB, with at most
8,192 structures and 4,096 member identities. Receipts occupy that budget for
the life of the ACL, and regrant size grows with the target member's receipt
count. Membership checks use the accepted member index. Merge and local
staging validate the bounded retained history.

## Start here

- [Yjs schema design guide](https://peerborne.io/cookbook/yjs-schema-design/)
- [Yjs + React example](https://github.com/Peerborne/peerborne/tree/main/examples/password-manager)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)

## Editor mutation boundary

Await `createYjsEditorBridge` from `@peerborne/yjs/editor` with an
already-created or opened document. The mirror writes under an actor the
document reserves for its signer. Bind upstream editors to the bridge's private mirror,
await `flush()` to observe write failures, and drain `destroy()` on teardown.
Directly binding an editor to the authoritative CRDT bypasses change capture.
See the [editor guide](https://peerborne.io/cookbook/editor-integrations/).
