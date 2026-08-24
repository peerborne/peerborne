# Peerborne browser test

This Vite and React harness exercises the core Peerborne package with its
Automerge and Redux integrations. It exposes node addresses, peer connection
controls, document open/edit controls, and ACL inspection for development and
testing.

This example is a test harness, not an application template or a production deployment.

## Run from source

Use Node.js 22.19.0 and Yarn 4.5.0 through Corepack. From the repository root:

```sh
corepack enable
yarn install --immutable
yarn build
yarn workspace @peerborne/browser-test start
```

Open the URL printed by Vite. Enter a document path such as `/demo/document` in
the text field beside **Open**, then select **Open**.

## Verify the supported browser path

```sh
yarn exec playwright install chromium
yarn test:e2e:browser-test
```

The smoke test builds this workspace, starts its Vite preview, and opens one
real encrypted Automerge document in a single Chromium process. It fails on
browser runtime errors.

This does not prove two-peer live convergence, restart persistence, invitation
delivery, or production networking. The separate cross-NAT suite uses this
harness with test-only document-key transfer and has its own narrower evidence
boundary.

- [Verified quick start](https://peerborne.io/getting-started/quick-start/)
- [Networking model](https://peerborne.io/concepts/networking/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
