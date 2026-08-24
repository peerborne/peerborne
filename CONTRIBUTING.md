# Contributing to Peerborne

Peerborne is under active development. Contributions should distinguish implemented primitives from behavior verified end to end.

Read the [full contributing guide](https://peerborne.io/community/contributing/) before starting. It contains the repository map, exact setup commands, Docker readiness sequence, generated-documentation boundaries, and pull request expectations. The repository's [AGENTS.md](AGENTS.md) provides the same operational baseline for coding tools.

## Choose the right channel

- Use [GitHub Discussions](https://github.com/Peerborne/peerborne/discussions) for questions, use cases, design exploration, and ideas that are not yet actionable work.
- Use [GitHub Issues](https://github.com/Peerborne/peerborne/issues) for reproducible bugs and scoped work.
- Use [private vulnerability reporting](https://github.com/Peerborne/peerborne/security/advisories/new) for suspected security issues. Never disclose them in public issues or discussions.

Discuss architecture-changing, compatibility-sensitive, or security-sensitive work before implementation.

## Development baseline

Use Node.js 22.19.0 and Yarn 4.5.0 through Corepack.

```sh
corepack enable
yarn install --immutable
yarn build
yarn test
yarn test:relay
yarn workspace @peerborne/site build
```

Run the relevant example or Docker-backed suite for affected behavior. Follow the bounded topology setup and teardown sequence in the [contributing guide](https://peerborne.io/community/contributing/#docker-backed-suites); the test command alone does not start the required services.

## Pull requests

- Keep changes and commits focused.
- State what the validation demonstrates and what remains outside its evidence boundary.
- Add focused migration, malformed-input, replay, and adversarial tests when changing serializers, protocols, ACL or key formats, persisted state, or other compatibility boundaries.
- Never expose credentials, signing keys, KEM keys, document keys, private payloads, or other secrets in code, tests, logs, issues, or pull requests.
- Do not edit generated API Markdown under `site/src/content/docs/reference/api/`; change source comments or TypeDoc configuration and rebuild the site.
- Run `git diff --check` and confirm unrelated files, generated output, and lockfiles are unchanged unless required.

Use the [feature and verification audit](docs/feature-audit.md) as the authority for capability claims.
