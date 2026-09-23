# Alpha compatibility policy

Peerborne has no deployed users and its six library packages have not been
published to npm. The codebase supports the current APIs and formats only.
Obsolete handlers, schemas, dependency aliases, and fallback decoders are
removed instead of retained for compatibility.

## Wire and stored state

All Peerborne libp2p protocol IDs use the `/peerborne/` namespace. Document
key-derivation domains, discovery topics, default IndexedDB locations, and
Redux action strings also use Peerborne identifiers. Old experimental
identifiers are not aliases for the current ones.

Every admitted sync message must carry the exact `signatureContext` required
by its receiving handler. Authenticated operations sign that tag along with
the message. Ordinary application sync uses `ordinary-sync-v1`; BeeKEM uses
parent-bound V2 PathUpdates and generation-bearing V2 Welcomes. Receivers
reject unsupported forms before applying state.

Normal document and snapshot loads use V4 only. They require signing, a fresh
request challenge, a captured trusted writer, and locally trusted security
commitments; load quorum configuration does not disable those checks.
Invitation catch-up uses a separate issuer-pinned protocol.

`document.create()` explicitly founds a document. `document.open()` loads an
existing document and fails when it cannot authenticate one; it never creates
an empty document after an unsuccessful load.

The document GossipSub prefix is `/peerborne/document/v3/`. Custom document
prefixes must be admitted by the relay's `TOPIC_ALLOWLIST`; changing a topic
does not select another wire format. Topic names are public routing labels,
and never replace signature verification or authorization.

## Development data

Use fresh local state when changing protocol or storage formats during alpha
work. The project does not provide dual-read migrations for old experimental
databases. Keep any data needed for debugging outside the active application
storage; do not infer compatibility from a matching document path.

Capability and limitation claims belong in [the feature audit](docs/feature-audit.md).
