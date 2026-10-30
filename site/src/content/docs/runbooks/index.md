---
title: Production Runbooks
description: Evaluate persistence, relay operation, and recovery boundaries before planning a deployment.
---

These runbooks help evaluate operational requirements. **Peerborne is alpha
software and is not production-ready.** The section name describes the work a
deployment would require; these procedures do not establish production safety.

1. [Offline persistence and size limits](./offline-persistence/) — choose
   document budgets, inspect browser quota, and verify recovery independently
   of a successful write.
2. [Run your own relay](../cookbook/running-a-relay/) — configure a reachable
   relay, TLS, and clients; understand identity and failover limitations.
3. [Pinning and recovery](../cookbook/pinning/) — inspect the incomplete
   remote-persistence integration before relying on an always-on copy.

Relays carry encrypted document payloads and can observe connection and traffic
metadata. “Zero-knowledge relay” is not a claim of zero-knowledge proofs,
metadata privacy, durable storage, or reliable delivery.

Use [Limitations](../concepts/limitations/) and the
[feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md)
to distinguish tested components from unverified deployment behavior.
