# AGENTS.md

## Project

Peerborne is alpha software for encrypted, local-first CRDT documents synchronized over peer-to-peer networks. It is not production-ready. The six `@peerborne/*` library packages are source workspaces and are not published to npm.

Use `docs/feature-audit.md` and `site/src/content/docs/concepts/` for architecture, evidence, security, and limitation details. Do not turn isolated primitive tests into end-to-end capability claims.

## Toolchain and setup

- Node.js 22.19.0
- Yarn 4.5.0 through Corepack
- `corepack enable`
- `yarn install --immutable`
- Playwright Chromium: `yarn exec playwright install chromium`
- Linux browser dependencies: `yarn exec playwright install chromium --with-deps`

## Repository map

- `packages/`: six library workspaces
- `examples/`: browser-test, wiki-swarm, and password-manager Vite workspaces
- `site/`: Astro Starlight workspace and TypeDoc integration
- `relay-server/`: separate relay project and lockfile
- `e2e/test-app/`: separate integration-test project and lockfile
- `e2e/integration/`: integration and transport NAT specs
- `e2e/peerborne-nat.spec.ts`: real Peerborne cross-NAT spec
- `docs/feature-audit.md`: capability/evidence map

The root has ten workspaces: six libraries, three examples, and the site.

## Commands

```sh
yarn build
yarn build:examples
yarn test
yarn test:relay
yarn workspace @peerborne/site build
yarn test:e2e
yarn test:e2e:browser-test
yarn test:e2e:wiki-swarm
yarn test:e2e:password-manager
```

`yarn test:e2e` runs three Vite/Chromium smoke suites and does not require Docker.

Docker-backed suites require their matching topology and readiness checks. Do not run the test command immediately after `docker compose up -d`; follow the exact bounded wait and teardown sequence in the corresponding `.github/workflows/ci.yml` job. The contributor guide also provides local readiness helpers.

Do not describe `yarn benchmark:all` as working until its runner module mismatch is fixed.

## Documentation

The Site build generates API Markdown with Starlight TypeDoc under `site/src/content/docs/reference/api/`. That directory is ignored. Never edit generated API Markdown; change source comments or `site/astro.config.mjs` and rebuild the site. There is no legacy TypeDoc workflow.

## Engineering rules

- Preserve established TypeScript, Jest, Playwright, Prettier, and workspace patterns.
- Do not add unnecessary comments.
- Never expose or log credentials, signing keys, KEM keys, document keys, private payloads, or other secrets.
- Treat serializers, wire protocols, ACL/key formats, and persisted state as compatibility boundaries. Add focused migration, malformed-input, replay, and adversarial tests when changing them.
- Keep changes and commits focused. Do not add automatic co-author or AI-attribution trailers unless explicitly requested by the contributor.
- Do not commit or push unless the task explicitly requests it.

## Completion checklist

- Run `yarn install --immutable` when dependency integrity matters.
- Run `yarn build`, `yarn test`, `yarn test:relay`, and `yarn workspace @peerborne/site build` for repository-wide changes.
- Run relevant example or Docker-backed suites for affected behavior.
- Run `git diff --check` and validate changed documentation links.
- Confirm generated files, lockfiles, and unrelated source are unchanged unless required.
- Address review findings. Repository policy expects CI to pass and Copilot review to return no comments on the latest head.
