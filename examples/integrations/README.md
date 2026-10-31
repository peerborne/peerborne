# Browser integration examples

Available views: Plain JavaScript, React, Vue, Svelte.

The default view uses plain DOM APIs. Vite builds and serves the files;
Peerborne and the document store do not require a frontend framework.

```sh
yarn install --immutable
yarn build
yarn workspace @peerborne/integration-examples start
```

Choose a view, click **Start local document**, and save a title or type in the
editor. The output reflects the authoritative local Peerborne document. Each
reload creates a fresh non-extractable signing identity. Bootstrap peers,
durable identity, invitations, and presence are outside this local exercise.

```sh
yarn exec playwright install chromium
yarn test:e2e:integrations
```

The suite asserts actual local mutations.
It does not establish live multi-peer convergence, restart recovery, or production readiness.
The per-view modules and shared session helper own their teardown explicitly.
