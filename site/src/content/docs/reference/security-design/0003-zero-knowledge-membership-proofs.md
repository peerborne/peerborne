---
title: "ADR 0003: Zero-knowledge membership proofs"
description: Decision not to add a zero-knowledge proof system to the MLS migration without a concrete privacy statement and threat model.
---

- Status: Proposed; rejected from the current MLS scope
- Date: 2026-08-21
- Tracks: [issue #186](https://github.com/Peerborne/peerborne/issues/186)
- Parent decision: [ADR 0001](../0001-mls-document-security-architecture/)

## Context

Issue #186 suggests `snarkjs` for privacy-preserving membership proofs, but it
does not define a statement, witness, verifier, disclosure policy, setup model,
revocation mechanism, or metadata adversary. A proving toolkit is not a privacy
policy. Adding one before those choices would introduce circuits, parameters,
serialization formats, denial-of-service costs, and potentially trusted setup
material without establishing which observable fact should become private.

MLS already requires authenticated credentials and an application-defined
authorization policy. Peerborne additionally needs a public, hash-linked
control history so a newly loaded or partitioned peer can detect forks and
verify the exact role and group transition it is accepting. Hiding the actor or
membership delta can conflict with that audit requirement unless the system
defines a different accountable-anonymity model.

## Decision

Do not add `snarkjs`, circuits, proving parameters, proof fields, or a ZKP wire
protocol as part of the MLS migration. First implement and review the explicit
identity, authorization, control-chain, persistence, and group-transition
model in ADR 0001. The generic provider and coordinator do not imply anonymous
or privacy-preserving membership.

The proposed goals have different relationships to zero-knowledge proofs:

| Goal | Does a membership ZKP solve it? | Reason |
| --- | --- | --- |
| Bind a device to an application identity | No | A trusted credential binding and revocation policy are still required. |
| Authorize Add, Remove, or role changes | No | The controller policy and exact state transition must still be enforced. |
| Prevent a removed member reading future content | No | This depends on group-key updates, delivery, and key deletion. |
| Provide forward secrecy or post-compromise security | No | Those depend on the group key schedule, fresh entropy, and erasure. |
| Detect control-history forks | No | Peers need authenticated linkage and a conflict policy. |
| Hide network metadata | No | Peer IDs, timing, size, relays, and traffic patterns remain observable. |
| Hide the controller identity | Conflicts with the current design | Public accountability and authorization verification name the controller credential. |
| Prove possession of a selectively disclosed attribute | Potentially | This needs a concrete issuer, predicate, revocation, and disclosure model. |
| Provide anonymous, rate-limited participation | Potentially | Nullifiers or equivalent state may help, but introduce linkability and replay-policy choices. |

A proof that “some hidden leaf belongs to this root” is insufficient. It does
not prove that the hidden credential is currently authorized for the requested
operation, that it was not revoked, that the root is the accepted non-forked
control head, that the request is fresh and document-bound, or that disclosure
through the resulting control delta is acceptable.

## Near-term privacy work

Lower-cost work should precede a proof system:

- document what peer IDs, topics, timing, message sizes, group size, control
  cadence, and relay observations leak;
- keep credentials, group state, document keys, payloads, and private proofs
  out of replicated storage, logs, analytics, and errors;
- minimize stable identifiers and unnecessary control fields while preserving
  deterministic verification;
- pad or batch only after measuring the traffic patterns and availability cost;
- define credential rotation and multi-device unlinkability expectations; and
- separate content confidentiality, membership confidentiality, sender
  anonymity, relationship anonymity, and network anonymity in every claim.

## Reconsideration requirements

A later ADR may propose a proof system only after it answers all of these
questions:

1. What exact deterministic statement is verified, and what is the private
   witness?
2. Which observer learns less: a group member, removed member, bootstrap peer,
   relay, passive network observer, or public-log reader?
3. What information remains public so peers can authorize transitions and
   detect same-parent forks?
4. Who issues credentials, how are keys rotated, and how do expiry and
   revocation work without deanonymizing every proof?
5. How are document ID, group ID, control head, epoch, action, subject, and
   request nonce bound to prevent cross-document and replay attacks?
6. Is setup transparent or trusted, who produces parameters, how are artifacts
   reproduced, pinned, distributed, and upgraded, and what happens if they are
   compromised?
7. What proof-system and circuit assumptions are acceptable, and what
   independent circuit and implementation audits exist?
8. What are worst-case proving and verification time, memory, proof size, and
   denial-of-service limits in Node.js and Chromium, including low-end devices?
9. How will circuit, verifier, credential, and protocol versions migrate while
   offline peers and persisted documents still exist?
10. Which user-visible privacy claim follows, and which metadata and collusion
    attacks explicitly remain out of scope?

Acceptance tests must include false statements; altered public inputs; replay
and cross-document reuse; stale/revoked credentials; malformed points, fields,
and lengths; non-canonical encodings; verifier exceptions; oversized batches;
parameter substitution; control forks; colluding issuers/verifiers; and
browser resource exhaustion. An independently reproducible circuit build and
an external security/privacy review are required before a user-facing claim.

## Consequences

Peerborne makes no zero-knowledge, anonymous-membership, unlinkability, or
metadata-privacy claim. The MLS architecture can proceed with explicit
authenticated identities and auditable authorization, while leaving a
versioned extension point for a later, threat-model-driven credential proof.

This prevents an underspecified privacy feature from expanding the critical
path or weakening control-chain accountability. It also means membership and
control metadata remain visible to authorized participants and to any storage
or transport layer explicitly documented as receiving them.

## References

- [`snarkjs`](https://github.com/iden3/snarkjs)
- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750.html)
- [ADR 0001: MLS document security architecture](../0001-mls-document-security-architecture/)
