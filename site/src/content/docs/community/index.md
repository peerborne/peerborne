---
title: Community
description: Where to ask questions, report actionable work, and contribute to Peerborne.
---

Peerborne is under active development. APIs may change, and documentation should distinguish implemented primitives from behavior verified end to end. Contributions that improve evidence, tests, and honest capability boundaries are especially valuable.

## Choose the right channel

- Use [GitHub Discussions](https://github.com/Peerborne/peerborne/discussions) for questions, use cases, design exploration, and ideas that are not yet actionable work.
- Use [GitHub Issues](https://github.com/Peerborne/peerborne/issues) for reproducible bugs and scoped, actionable work. Include versions, reproduction steps, expected behavior, actual behavior, and relevant sanitized logs.
- Read the [contributing guide](contributing/) before preparing a pull request.
- See [help wanted](help-wanted/) for current technical gaps. The issue tracker may not contain curated beginner tasks.

Maintainers review contributions as availability permits. There is no response or review-time SLA.

## Security reports

If you suspect a vulnerability, open this repository's **Security** tab and use GitHub private vulnerability reporting. Never disclose suspected vulnerabilities in public issues or discussions. Avoid including secrets, private keys, document keys, credentials, or sensitive user data in any report or log.

## Evidence standards

State exactly what a change or test demonstrates. A unit test for a cryptographic or CRDT primitive does not by itself prove browser interoperability, persistence, multi-peer convergence, invitation acceptance, revocation under attack, or production suitability. Use the [feature and verification audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) as the current evidence map.

Peerborne and all six package manifests use the MIT License.

## More resources

- [FAQ](faq/) — answers to common questions about production readiness, key management, relay requirements, and more
- [Roadmap](roadmap/) — current development priorities and future directions
- [Contributing](contributing/) — development setup, build commands, and PR expectations
- [Help wanted](help-wanted/) — specific contribution areas with the highest impact
