# Running tests

Use Node.js 22.19.0 and Yarn 4.5.0 through Corepack. From the repository root:

```sh
corepack enable
yarn install --immutable
yarn build
yarn test
yarn test:relay
yarn build:examples
yarn workspace @peerborne/site build
```

The root test command runs the six library workspaces. Inspect each workspace's
result. To test one package, use its current name:

```sh
yarn workspace @peerborne/core test
yarn workspace @peerborne/yjs test
yarn workspace @peerborne/react test
```

For the four examples' Chromium smoke suites:

```sh
yarn exec playwright install chromium
yarn test:e2e
```

These smoke suites do not require Docker. The separate integration, transport
NAT, and Peerborne cross-NAT suites require their matching Docker topology.
Follow the bounded readiness checks and teardown in
[the CI workflow](../.github/workflows/ci.yml); starting containers alone does
not establish readiness.

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [the E2E guide](../e2e/README.md)
for commands, and [the feature audit](../docs/feature-audit.md) for the scope and
limits of the available evidence. Passing primitive tests does not establish an
end-to-end capability.
