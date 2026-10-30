---
title: Epoch Transitions
description: What document key rotation does today and which group-secrecy guarantees are not implemented.
---

An epoch names a generation of document encryption keys. Retained changes may
need keys from earlier epochs; a new epoch does not erase plaintext or keys
that a reader already possessed.

## What is implemented

Peerborne includes epoch key rotation, legacy BeeKEM group-key primitives,
encrypted Welcomes, and membership PathUpdates. Focused tests exercise codecs,
rotation, replay checks, and selected rollback paths. The document membership
path has limits across ACL updates, key state, and network delivery.

| Event | What to expect |
| --- | --- |
| Edit a document | Updates use the document's applicable key material |
| Add a reader | Explicit key onboarding and permissions are required |
| Remove a member | A group/key transition is needed; live hostile-peer exclusion is not yet proven |
| Reconnect a client | Connectivity resumes; it does not itself imply an epoch change |
| Restart a client | Encrypted blocks alone do not restore all membership or replay state |

## Rotation is not forward secrecy

**RFC 9420 MLS, forward secrecy, and post-compromise security are not
implemented.** Neither an epoch counter nor a passing key-rotation test
establishes those properties. The protocol-neutral group-security interfaces
and decision records describe work toward a reviewed provider; they are not a
supported MLS runtime.

The current BeeKEM generation/replay state is not durably anchored. Old valid
Welcomes can rebootstrap stale state after restart, and same-generation
concurrent branches have no convergence rule. Membership and delivery must be
evaluated as a system, including failed operations and removed peers.

For exact supported behavior, read [Security](../security/), the
[feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md#security-and-membership),
and the [security design decisions](../../reference/security-design/0001-mls-document-security-architecture/).
