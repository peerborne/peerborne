# Security policy

## Supported versions

Peerborne is under active development. APIs and persisted formats may change. Security fixes are developed on the default branch; no release line currently receives backported fixes.

## Reporting a vulnerability

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/Peerborne/peerborne/security/advisories/new).

Do not open a public issue or discussion for a suspected vulnerability. Do not include live credentials, signing keys, KEM keys, document keys, private payloads, or sensitive user data in reports or logs. Use minimal test fixtures and sanitized reproduction details.

Maintainers review reports as availability permits. There is no response or remediation-time SLA.

## Assessment boundaries

Review the documented [security model](https://peerborne.io/concepts/security/), [current limitations](https://peerborne.io/concepts/limitations/), and [feature and verification audit](docs/feature-audit.md) before assessing impact. Focused tests for a cryptographic, ACL, key-management, CRDT, storage, or networking primitive do not by themselves establish a complete secure multi-peer workflow.
