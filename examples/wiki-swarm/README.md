# Peerborne wiki

This Vite and React example explores a collaborative wiki interface with the
Peerborne Automerge and Redux packages.

This workspace is a source example with startup coverage, not a complete collaborative product.

## Run from source

Use Node.js 22.19.0 and Yarn 4.5.0 through Corepack. From the repository root:

```sh
corepack enable
yarn install --immutable
yarn build
yarn workspace @peerborne/wiki-swarm start
```

Open the URL printed by Vite. The landing page provides a document ID field for
navigating to the wiki editor.

## Verify the current example

```sh
yarn exec playwright install chromium
yarn test:e2e:wiki-swarm
```

The smoke test builds this workspace and verifies that Automerge WASM loads and
the wiki interface renders in Chromium without runtime errors. It does not
assert article mutation, two-browser synchronization, concurrent editing,
restart recovery, or invitation delivery.

- [Collaborative wiki guide](https://peerborne.io/cookbook/collaborative-wiki/)
- [Verified quick start](https://peerborne.io/getting-started/quick-start/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
