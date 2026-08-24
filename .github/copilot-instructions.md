# GitHub Copilot instructions for Peerborne

Follow the repository-root `AGENTS.md`; it is the authoritative setup, command, validation, and completion guide.

## Project status

Peerborne provides encrypted, local-first CRDT documents over peer-to-peer networks. The six `@peerborne/*` libraries are source workspaces and are not published to npm.

Use `docs/feature-audit.md` and the site concept pages as the evidence baseline. Do not present isolated CRDT, crypto, ACL, BeeKEM, storage, or networking tests as proof of complete multi-peer behavior.

## Toolchain

```sh
corepack enable
yarn install --immutable
yarn build
yarn test
yarn workspace @peerborne/site build
```

Use Node.js 22.19.0 and Yarn 4.5.0. Run `yarn test:relay` and the relevant example or Docker-backed suite when affected. `yarn test:e2e` runs three Vite/Chromium smoke suites without Docker. Integration, NAT, and cross-NAT tests require their matching Compose topologies; follow `.github/workflows/ci.yml`.

## Repository boundaries

- `packages/`: six root library workspaces
- `examples/`: three root Vite workspaces
- `site/`: Starlight and generated TypeDoc
- `relay-server/`: separate project and lockfile
- `e2e/test-app/`: separate project and lockfile

Generated API Markdown under `site/src/content/docs/reference/api/` is ignored. Change exported source comments or TypeDoc configuration, then rebuild the site; never edit generated API pages directly.

## Engineering rules

- Preserve existing TypeScript, Jest, Playwright, formatting, and workspace patterns.
- Do not add unnecessary comments.
- Never expose or log credentials, signing keys, KEM keys, document keys, private payloads, or other secrets.
- Treat serializers, wire protocols, ACL/key formats, and persisted state as compatibility boundaries.
- Add focused malformed-input, replay, migration, and adversarial tests for security-sensitive changes.
- Keep changes focused and leave unrelated or untracked files untouched.
- Do not commit or push unless the task explicitly requests it.
- Use normal project-style commit messages. Do not add automatic co-author or AI-attribution trailers unless explicitly requested.
- Address review findings until Copilot reports no comments on the latest head, and ensure applicable CI checks pass.
