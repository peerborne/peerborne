# TanStack Start browser document starter

From the repository root, run `yarn build`, then
`yarn workspace @peerborne/tanstack-start-starter start`. For a production build:

```sh
yarn workspace @peerborne/tanstack-start-starter build
yarn workspace @peerborne/tanstack-start-starter preview
```

The preview binds to `127.0.0.1:4192`; set `PORT` to choose another port. Hono's
Node adapter serves the built client assets and TanStack Start's server handler.

The route renders on the server and shares the same React browser component as
the Next.js starter. Node/identity initialization happens only after a browser
action, through a dynamic import. Generated routes and build outputs are ignored.

This exercise creates a fresh non-extractable signing identity on reload and
does not configure bootstrap peers. It does not demonstrate durable identities,
invitations, server-side private document access, or live multi-peer convergence.

Run `yarn test:e2e:integrations` for server HTML and hydrated local mutation
acceptance. Peerborne remains unpublished alpha software, not production-ready.
