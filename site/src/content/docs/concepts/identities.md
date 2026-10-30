---
title: Identities
description: Distinguish signing identities, document encryption keys, and group key state before sharing a document.
---

Peerborne does not provide an account service. Your application chooses how to
create, authenticate, store, and restore a user's keys.

| Material | Purpose | Application responsibility |
| --- | --- | --- |
| ECDSA P-384 signing key pair | Identify a writer and sign updates | Preserve the identity securely; new keys create a new ACL identity |
| AES-GCM document keys | Encrypt and decrypt document payloads for an epoch | Preserve the key history needed to read retained history |
| BeeKEM/KEM material | Participate in the legacy group onboarding and membership flow | Manage separate KEM setup and state; current restart/replay limitations apply |
| libp2p peer identity | Address a network node | Keep separate from document authorization; a connection is not access |

## Start with one local identity

The [React tutorial](../../getting-started/react-workspace/) generates a fresh
signing key to make the exercise self-contained. It does not persist it.
Reloading starts a different identity; this is unsuitable as account recovery.

Choose an explicit identity-storage design before retaining important data.
Never put private keys, document keys, KEM material, or plaintext document
payloads into console output, relay configuration, URLs, or bug reports.

## Connecting is separate from sharing

A bootstrap or relay address gets clients onto a reachable network. It does
not authenticate a collaborator, grant document permissions, or deliver a
document key. Distinct identities require explicit onboarding. Use the
[signed invitation flow](../../cookbook/invitations/) for the bounded initial
online founder-plus-one case; ACL helpers alone are not an invitation UI.

The [shared-secrets recipe](../../cookbook/password-manager/) describes the
direct API and its current boundaries. Do not use that development example
as evidence that general invitation delivery, hostile-peer exclusion, or recovery
across devices is complete.

## Recovery needs more than a password

Retaining encrypted blocks without their document keys does not recover
plaintext. Retaining a signing key without the document key history is also
insufficient. Group membership adds state with its own durability and replay
requirements; the legacy BeeKEM path does not currently provide restart-safe
replay protection.

Read [Security](../security/) for the full threat model and
[Epoch Transitions](../epoch-transitions/) before changing group membership.
