# Peerborne Note

Peerborne Note is a zero-install, two-browser demonstration of the initial
Peerborne invitation flow. It creates an encrypted Automerge document locally,
then uses a configured Circuit Relay rendezvous to invite one distinct browser
identity as an editor or reader.

Alpha source demo. See the [current limitations](https://peerborne.io/concepts/limitations/).

Notes are saved as encrypted, self-signed checkpoints in this browser. After a
refresh or browser restart, choose a saved note on the home screen. Signing,
KEM, and storage keys remain non-extractable browser key handles. Wait for
**Saved in this browser** before closing the tab. A failed write shows a retry
action, and damaged data is retained without an empty replacement.

This verifies local reopening with the saved reader/editor permissions.
Invitations still originate in the session that creates a note. Reconnecting to peers after restart, recovering
missed group-key changes, and backup across devices remain separate work.

## Run locally

Build the library workspaces from the repository root, then provide a complete,
peer-ID-qualified relay multiaddr:

```sh
yarn build
VITE_PEERBORNE_RELAY_MULTIADDR=/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW... \
  yarn workspace @peerborne/peerborne-note start
```

The relay address is public deployment configuration, not a secret. Production
pages served over HTTPS require a `/wss/` relay address.

## Verify

```sh
yarn workspace @peerborne/peerborne-note test
yarn workspace @peerborne/peerborne-note build
yarn test:e2e:peerborne-note
```

The focused tests cover canonical invitation fragments and the versioned
IndexedDB identity and encrypted checkpoint boundaries. Chromium tests verify
note contents after reload, edit/reopen, full browser-process relaunch, damaged
storage, failed-write retry, and single-tab ownership. The repository's separate NAT-isolated Playwright
suite is the end-to-end evidence for distinct-identity invitation acceptance
and bidirectional encrypted convergence; these utility tests do not replace it.

After deployment, the mandatory live gate uses separate browser contexts to
exercise editor and reader invitations, explicit acceptance, read-only UX, and
fresh edits through the public WSS relay:

```sh
PEERBORNE_NOTE_LIVE_URL=https://try.peerborne.io/ \
  yarn test:e2e:peerborne-note:live
```

Hosted builds must fail closed when the relay configuration is absent or not a
complete DNS/TCP 443/WSS/peer-ID multiaddr. The deployment build also renders
the emitted `_headers` CSP with only that relay WebSocket origin:

```sh
VITE_PEERBORNE_RELAY_MULTIADDR=/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW... \
  yarn workspace @peerborne/peerborne-note build:deployment
```

## Cloudflare Pages deployment

[`try.peerborne.io`](https://try.peerborne.io/) uses the `peerborne-note`
Cloudflare Pages project. It serves static HTML, JavaScript, CSS, and WebAssembly;
there are no Pages Functions, Workers scripts, or database bindings. Static
requests do not consume the Workers invocation allowance. See
[Cloudflare's static asset pricing](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/).

The checked-in [`.env.deployment`](.env.deployment) contains the public Render
relay multiaddr. It contains no credentials. If the relay identity changes,
update that address and rebuild. Never put the relay's private origin credential,
identity seed, or application keys in any `VITE_` variable.

From the repository root:

```sh
yarn install --immutable
yarn build
yarn workspace @peerborne/peerborne-note build:deployment
npx wrangler@4.156.0 login --scopes account:read user:read pages:write
npx wrangler@4.156.0 pages deploy --cwd examples/peerborne-note --branch main
```

The [Wrangler configuration](wrangler.toml) selects only the generated `dist`
directory. The deployment build renders its existing `_headers` policy, allowing
connections only to this origin and the configured relay. The homepage is not
cached; content-hashed assets have an immutable cache policy. No source maps or
private local data are uploaded.

The Pages project already exists. To reproduce it in a different Cloudflare
account, create it once from `examples/peerborne-note`:

```sh
npx wrangler@4.156.0 pages project create peerborne-note --production-branch main --force
```

In this Wrangler version, `--force` keeps new project creation on Pages instead
of delegating it to Workers. It is not needed for subsequent uploads. This is a
[Direct Upload project](https://developers.cloudflare.com/pages/get-started/direct-upload/);
updates use the deployment command above rather than automatic Git builds.

Add `try.peerborne.io` in the project's **Custom domains** tab and let Cloudflare
create its proxied CNAME. The hostname's custom Block rule permits GET/HEAD
requests for `/`, `/favicon.svg`, `/robots.txt`, `/assets/*`, and TLS certificate
challenges. It leaves other hostnames unchanged. The relay separately enforces
its connection and byte limits; its Free Render instance can sleep between visits.

Run the live gate after each deployment:

```sh
PEERBORNE_NOTE_LIVE_URL=https://try.peerborne.io/ yarn test:e2e:peerborne-note:live
```
