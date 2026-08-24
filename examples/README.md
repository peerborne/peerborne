# Peerborne examples

These Vite and React workspaces show the current Peerborne integrations from a
source checkout. Use the smallest example that matches what you want to inspect:

| Example                                   | Stack               | Best starting point for                                               | Automated evidence                                        |
| ----------------------------------------- | ------------------- | --------------------------------------------------------------------- | --------------------------------------------------------- |
| [`browser-test`](./browser-test/)         | Automerge and Redux | Core node setup, document controls, peer controls, and ACL inspection | Opens one real encrypted document in one Chromium process |
| [`wiki-swarm`](./wiki-swarm/)             | Automerge and Redux | A larger editor and routing pattern                                   | Builds and renders the wiki interface in Chromium         |
| [`password-manager`](./password-manager/) | Yjs and React       | React hooks and item-specific access-control UI                       | Builds and renders the login interface in Chromium        |

These are source examples for evaluation and development, not application
templates or production showcases. Never enter real credentials into the
password-manager example.

## Run from source

Use Node.js 22.19.0 and Yarn 4.5.0 through Corepack. From the repository root:

```sh
corepack enable
yarn install --immutable
yarn build
```

Then start one workspace:

```sh
yarn workspace @peerborne/browser-test start
yarn workspace @peerborne/wiki-swarm start
yarn workspace @peerborne/password-manager start
```

Run one of those three commands at a time and open the URL printed by Vite. The
[verified quick start](https://peerborne.io/getting-started/quick-start/)
walks through the browser-test controls and their evidence boundary.

## Verify the examples

Install Chromium once, then run all three smoke suites:

```sh
yarn exec playwright install chromium
yarn test:e2e
```

On Linux hosts that need browser system libraries, install Chromium with:

```sh
yarn exec playwright install chromium --with-deps
```

This builds each example and opens it in a single Chromium page. Docker is not
required. The suites do not prove two-peer convergence, invitation delivery,
restart recovery, revocation, or production deployment behavior. The separate
cross-NAT initial-load suite has a narrower topology and is not part of
`yarn test:e2e`.

For one example at a time, use its focused guide and test command:

- [`browser-test` guide](./browser-test/README.md)
- [`wiki-swarm` guide](./wiki-swarm/README.md) and
  [collaborative wiki cookbook](https://peerborne.io/cookbook/collaborative-wiki/)
- [`password-manager` guide](./password-manager/README.md) and
  [shared-secrets cookbook](https://peerborne.io/cookbook/password-manager/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
