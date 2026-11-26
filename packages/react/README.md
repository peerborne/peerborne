# `@peerborne/react`

Version 0.1.0 is alpha software, not production-ready. Packages ship one ESM build, with native CommonJS `require()` interoperability on Node.js 26.13.1 or newer.

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

Pass `'create'` as the fourth argument to `usePeerborneDocumentState` when the application explicitly authorizes a new path. The default `'open'` mode loads existing state from peers, so the node configuration must include `resolveLoadSecurityCommitments` and `resolveTrustedDocumentWriters`. If no connected peer can serve the path (a relay cannot), the hook's activation error is `No document state is available…`; if one can and `resolveLoadSecurityCommitments` is missing, it is a `TrustedLoadSecurityCommitmentsError`. See [Open existing documents](https://peerborne.io/concepts/documents/#open-existing-documents). A failed open never creates a replacement on its own. Concurrent subscribers share one activation for that path. A `'create'` subscriber that joins an in-flight open creates the document only if that open fails, and a failed activation is dropped so the next mount retries it. A document the hook created stays open after its last subscriber unmounts, so a remount reuses it; a later `'create'` mount of a path the node created opens it instead of founding another document. The fifth tuple element, `deliveryFailure`, is the document's latest local change that has not reached peers, until a later local change's frame is published.

## Shared document stores

`@peerborne/react/store` exports `usePeerborneStore` without importing the
networking runtime. Pass one shared `@peerborne/store` per node/document path;
the hook needs no context caches and retains ownership after mounting. Await
`store.change` to handle mutation failures. See the
[framework guide](https://peerborne.io/cookbook/framework-integrations/) and
[browser examples](https://github.com/peerborne/peerborne/blob/main/examples/integrations/README.md).
A document returned by `acceptInvitation()` is already open; wrap it with
`createDocumentStore(document, { manageLifecycle: false })` and use this hook
instead of opening its path again.
