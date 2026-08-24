---
title: Contributing to Peerborne
description: Set up the repository, run the correct validation, and prepare a focused Peerborne contribution.
---

Discuss non-trivial, architecture-changing, or security-sensitive work before implementation. Questions and early ideas belong in [Discussions](https://github.com/Peerborne/peerborne/discussions); reproducible bugs and actionable proposals belong in [Issues](https://github.com/Peerborne/peerborne/issues). Suspected vulnerabilities must use private vulnerability reporting from the repository **Security** tab, never a public issue or discussion.

## Setup

Use Node.js **22.19.0** and Yarn **4.5.0**, as pinned by `.tool-versions` and `package.json`.

```sh
git clone https://github.com/Peerborne/peerborne.git
cd peerborne
corepack enable
yarn install --immutable
```

The ten root workspaces are six libraries under `packages/`, three Vite examples under `examples/`, and `site/`. `relay-server/` and `e2e/test-app/` are separate projects with their own manifests and lockfiles; they are not root workspaces.

Current workspace package names use `@peerborne/*`. They are not published to npm, so develop and test against repository workspaces only.

## Repository map

| Path | Purpose |
| --- | --- |
| `packages/core/` | Core documents, storage, networking, crypto, ACL, UCAN, epoch, and BeeKEM primitives |
| `packages/{automerge,yjs}/` | CRDT adapters; both contain headless daemon binaries |
| `packages/{react,redux,index}/` | Framework bindings and distributed-index primitives |
| `examples/{browser-test,wiki-swarm,password-manager}/` | Vite applications used by the three smoke suites |
| `site/` | Astro Starlight documentation and TypeDoc integration |
| `relay-server/` | Separate relay project and unit suite |
| `e2e/integration/` | Playwright transport integration and NAT specs using `e2e/test-app/` |
| `e2e/test-app/` | Separate minimal browser project for integration topologies |
| `e2e/peerborne-nat.spec.ts` | Real Peerborne cross-NAT acceptance spec |
| `docker-compose.integration.yaml` | Integration service topology |
| `docker-compose.nat-test.yaml` | isolated transport NAT topology |
| `docker-compose.peerborne-nat.yaml` | Two isolated browsers and real Peerborne apps |
| `docs/feature-audit.md` | Capability-to-evidence audit and known end-to-end gaps |

There is no `multi-user.spec.ts`; the current example suites are smoke tests, not complete multi-user showcases.

## Build and test commands

```sh
yarn build                         # six library workspaces
yarn build:examples                # libraries, then all three Vite examples
yarn test                          # six library Jest suites
yarn test:relay                    # separate relay-server Jest suite
yarn workspace @peerborne/site build
yarn exec playwright install chromium
yarn test:e2e                     # three Vite example smoke suites; no Docker
```

Use `yarn exec playwright install chromium --with-deps` when Linux system browser dependencies are also needed.

The benchmark sources currently have a runner module mismatch. Do not present `yarn benchmark:all` as working until that is fixed; benchmark work should also define repeatable budgets.

## Docker-backed suites

The test command alone does not create the required service topology. GitHub CI is the canonical sequence.

Define bounded readiness helpers in Bash:

```bash
wait_http() {
  local attempts=0
  until curl -fsS "$1" >/dev/null; do
    attempts=$((attempts + 1))
    [ "$attempts" -ge 60 ] && return 1
    sleep 2
  done
}

wait_tcp() {
  local attempts=0
  until (echo > "/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    [ "$attempts" -ge 60 ] && return 1
    sleep 2
  done
}
```

Run one topology at a time and always tear it down afterward:

```bash
docker compose -f docker-compose.integration.yaml up -d --build
for port in 3001 3002; do wait_http "http://127.0.0.1:$port"; done
CI=true yarn test:integration
docker compose -f docker-compose.integration.yaml down -v

docker compose -f docker-compose.nat-test.yaml up -d --build
for port in 3001 3002 3003; do wait_http "http://127.0.0.1:$port"; done
CI=true yarn test:nat
docker compose -f docker-compose.nat-test.yaml down -v

docker compose -f docker-compose.peerborne-nat.yaml up -d --build
for port in 3101 3102; do wait_tcp "$port"; done
CI=true yarn test:peerborne-nat
docker compose -f docker-compose.peerborne-nat.yaml down -v
```

These helpers mirror CI's 120-second readiness budget. The workflow remains the canonical sequence, including failure logs and unconditional cleanup.

Integration checks transport discovery, bidirectional messaging, resilience, and NAT behavior through the test app. Cross-NAT checks encrypted document retrieval between real Peerborne apps; it does not prove invitation delivery or live post-load convergence.

## Generated API reference

The **Site** workflow runs `yarn workspace @peerborne/site build`. Starlight TypeDoc generates package API Markdown during that build into `site/src/content/docs/reference/api/`; the directory is ignored. Do not edit generated Markdown. Change exported source comments or `site/astro.config.mjs`, then rebuild the site. There is no legacy TypeDoc workflow.

## Pull request expectations

- Keep commits and pull requests focused. Add regression tests for fixes and focused adversarial tests for security-sensitive behavior.
- Never expose or log credentials, signing keys, KEM keys, document keys, private payloads, or other secrets.
- Preserve wire compatibility deliberately: serializer, protocol, key, ACL, and persistence changes need migration/compatibility analysis.
- Run the relevant commands locally and report evidence without overstating what it proves.
- Address review findings. Repository policy expects Copilot review to return no comments on the latest head and all applicable CI checks to pass.
- Use normal project-style commit messages. Do not add automatic co-author or AI-attribution trailers unless the contributor explicitly requests them.

The CI workflow runs the six-package build and unit-test matrix, Docker integration, NAT traversal, and real Peerborne cross-NAT jobs. The separate Site workflow builds generated TypeDoc and the site. CI currently does **not** run the three example smoke suites or `test:relay`; run those locally when relevant unless the workflows are changed.

Review timing depends on maintainer availability; there is no response or review-time SLA.

## License

Peerborne and all six package manifests use the MIT License.
