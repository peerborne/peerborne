# Next.js browser document starter

From the repository root, run `yarn build`, then
`yarn workspace @peerborne/nextjs-starter start`. For a production build use
`yarn workspace @peerborne/nextjs-starter build`, followed by
`yarn workspace @peerborne/nextjs-starter preview`.

The page renders on the server. The shared client component imports the browser
session factory only after **Start local document** is clicked. No signing
identity, document, or peer node is created during server rendering. The store
hook uses a stable server snapshot and shares document ownership after mounting.

This starter uses Next's webpack build. Its config normalizes the `node:stream`
specifier used by a libp2p HTTP utility to `stream`, allowing Next's existing
browser stream fallback to resolve it. Turbopack is not verified.

Each reload creates a fresh non-extractable identity. This local exercise does
not implement identity persistence, membership onboarding, server-side access to
private documents, or multi-peer synchronization acceptance.

Run `yarn test:e2e:integrations` to build and verify both SSR starters alongside
the plain-browser and framework examples. Peerborne is unpublished alpha
software and not production-ready.
