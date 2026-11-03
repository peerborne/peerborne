# Installed release acceptance

This gate installs the eleven exact release tarballs in a fresh npm project
outside the checkout. It checks their package identities, lockfile integrity,
and every packed file's SHA-512 digest before and after browser acceptance,
rejects workspace symlinks, and audits production dependencies before adding any
application tooling. The browser applications have a separate dependency audit.
The application and plain-app graphs are audited after acceptance as well.
Audits fail on high or critical findings and fail closed if npm cannot complete
its audit.

Release CI also checks the workspace, relay and network-test lockfiles for high
and critical advisories, including development dependencies.

The consumer checks ESM and native CommonJS imports, shared export identity,
strict NodeNext declarations and a Vite build. It then copies the public examples
into that external project, installs their application dependencies, and builds
them against the installed packages. No Peerborne source alias is used.

A separate sibling npm project installs only core, Yjs and the document store,
then typechecks, builds and runs a plain TypeScript/DOM app in each selected
browser. Its bundle gate rejects React, React Native, Vue, Svelte and Next.js
modules. npm currently installs React Native peer dependencies transitively
through libp2p; those packages are recorded and excluded from the browser bundle.

The browser gate exercises:

- Framework-free, React, Vue, Svelte, Loro, TanStack DB, Zustand and Jotai local
  document mutations, plus CodeMirror, Tiptap and Monaco edits.
- Next.js and TanStack Start server rendering and hydrated document mutations.
- Separate-identity Note invitations, reader/editor roles, browser-process
  relaunch, encrypted checkpoint recovery, failed writes and damaged storage.
- Both writers editing during an owned relay outage, both browser processes
  restarting, automatic same-epoch history repair after the relay returns,
  convergence without duplicated additions and a fresh post-recovery edit.
- First-WebSocket timeout and retry without treating an open connection as a
  delivery receipt.
- Saved-note catch-up and a fresh bidirectional edit after browser relaunch
  while the owned relay's only inbound circuit reservation is occupied.
- An acknowledged checkpoint surviving forced termination of the exact owned
  Chromium process. The other engines skip this Chromium-CDP-specific case.

## Reproduce

Use the repository's Node and Yarn versions. The relay is a separate project.

```sh
yarn install --immutable
yarn build
yarn --cwd relay-server install --immutable
yarn --cwd relay-server build
yarn exec playwright install chromium firefox webkit
RELEASE_CHECK_DIR="$(mktemp -d)"
yarn release:prepare "$RELEASE_CHECK_DIR/artifacts"
PEERBORNE_RELEASE_BROWSERS=chromium,firefox,webkit \
  yarn release:validate-consumer "$RELEASE_CHECK_DIR/artifacts" "$RELEASE_CHECK_DIR"
```

Linux requires the browser system dependencies; use `playwright install` with
`--with-deps`, as the Release workflow does. That workflow runs all three engines
and uploads only metadata evidence under `verification/results/release/`.
Invitations are excluded from traces, screenshots and recordings; diagnostic
URLs have their fragments redacted. Reports contain case status, timing, selected
engines, dependency findings and the consumer lockfile hash, without application
payloads or keys.

The normal consumer directory is deleted after the run. Set
`PEERBORNE_RELEASE_KEEP_CONSUMER=1` to inspect it; the command prints the uniquely
allocated directory. An existing retained consumer can be checked again with:

```sh
PEERBORNE_RELEASE_PROFILE=repeat-pilot \
  node verification/release/run.mjs /path/to/retained-consumer --repeat-each=3
```

The runner rechecks artifact identity and integrity before every invocation.
Use `PEERBORNE_RELEASE_PROFILE` to retain separate reports for independent runs.

## Public-relay pilot

The same installed app can use an explicitly configured external relay without
publishing packages or restarting public infrastructure. Use its full multiaddr
and WebSocket origin, then select the existing invitation/restart cases:

```sh
PEERBORNE_RELEASE_PROFILE=public-pilot \
PEERBORNE_RELEASE_RELAY_MULTIADDR='/dns4/relay.example.com/tcp/443/wss/p2p/REPLACE_WITH_PEER_ID' \
PEERBORNE_RELEASE_RELAY_ORIGIN='wss://relay.example.com' \
  node verification/release/run.mjs /path/to/retained-consumer \
  --grep 'deployed (editor|founding|reader)'
```

Public-relay sessions retain the live suite's cooldown. Fault injection is
restricted to the owned local relay, so an external configuration cannot produce
a misleading relay-outage result. The reports distinguish the two topologies.

## Boundaries

These are automated pilot users, not independent human usability feedback.
Local browser processes share a host and use loopback unless the external relay
is explicitly configured. Playwright WebKit coverage is not a claim about every
Safari/device combination. The gate covers one note, one founder and one
collaborator, retained browser identities and the same group-key epoch.

A Linux/WebKit readiness run previously timed out during missed-edit catch-up.
Investigation reproduced that symptom with exhausted circuit reservations:
Note waited for its own inbound reservation before requesting history over an
already usable pubsub connection. Recovery now requests history without that
reservation; creating an invitation still waits for its circuit rendezvous.
The capacity regression checks this failure mode in every selected engine. The
earlier timeout did not retain enough diagnostics to establish the same cause.

It does not establish multi-document/many-peer recovery, key-loss recovery,
revocation across a partition, relay failover, storage rollback resistance,
remote delivery acknowledgment, offline page availability, performance budgets
or the experimental coordinated-document protocol's real-network behavior.
Actual npm bootstrap authorization and registry availability remain publication
checks; the publish workflow compares registry bytes with these validated
tarball integrities before promotion.

The clean installed library graph has no reported production advisories in the
November 2 readiness run. The broader applications/build graph retains a low
severity [deepmerge advisory](https://github.com/advisories/GHSA-gcqx-w48m-w2h4)
through Svelte's Vite plugin; upstream has no patched release. The workspace also
uses patched [glob](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4) 14.0.3 and
[minimatch](https://github.com/advisories/GHSA-g3hv-75wg-m249) 11.0.4 resolutions
for its Jest and ESLint tooling. These cross-major resolutions require build,
test-discovery and coverage validation when updated. Audit findings in the
separate relay and network-test projects remain recorded by their own gates.
Build-tool findings are separate from the audited installed-library runtime graph.

TypeDoc 0.28.20 calls the `Minimatch.matchOne` method removed in minimatch 11.
The repository's Yarn patch switches its directory traversal to the supported
`match(path, true)` partial-match API. The site build validates package discovery
and generated API output; remove the patch when TypeDoc supports minimatch 11.
