---
title: Keeping data alive (pinning)
description: Requirements and current limitations for an authenticated pinning integration.
---

**Status: Deferred/incomplete integration.**

Peerborne does not currently provide a runnable, end-to-end pinning daemon or durability guarantee. Do not rely on this recipe to preserve important data. See [Storage](../../concepts/storage/) and [Limitations](../../concepts/limitations/).

## What exists

The Node-only `PeerborneNode` has no document-announcement receiver, decoder, or compatibility setting. Remote announcements cannot create or open documents, attach subscriptions, or request pinning.

A remotely initiated pinning protocol needs an authenticated envelope with an explicit signed purpose, signer authorization, local pin policy, and replay protection. An ordinary signed sync message does not grant pinning authority to a node that has not opened the document and has no trusted writer ACL.

The normal document commit path does not publish document announcements. There is also no integrated generic IPFS pinning-service client, packaged pinning service, supported CLI, or hosted service.

The default Node configuration uses the repository's IndexedDB-backed stores. Durable restart/recovery for a Node pinning process has not been validated, including stable storage paths, process identity, graph restoration, subscriptions, keys, and serving retained data after restart.

## Why blocks alone are insufficient

Pinning ciphertext CIDs preserves bytes, not a recoverable application. Recovery may also require:

- discoverable root, frontier, snapshot, and change CIDs;
- enough shadow-graph or index state to traverse retained history;
- document epoch keys and keychain state;
- persisted signing identity and KEM membership state;
- compatible CRDT, ACL, serializer, quorum, and network configuration;
- reachable providers able to serve the retained blocks.

A generic pinning service can retain CIDs explicitly sent to it, but Peerborne has no generic client that discovers and exports every required block or restores the associated metadata.

## Integration checklist

Before calling a custom service “pinning,” implement and test all of the following:

1. Define an authenticated, authorized publication/request protocol.
2. Publish every relevant document frontier and subsequent update from the core/application path.
3. Traverse and retain all required blocks, including snapshots and retained tails.
4. Persist the service's blockstore, datastore, identity, subscriptions, and recovery index.
5. Bound storage with explicit quota, retention, compaction, and deletion policies.
6. Monitor publication failures, missing blocks, provider reachability, disk use, and restore readiness.
7. Reconcile changes missed while the service was offline.
8. Restore into a clean client with the same key, ACL, quorum, and history settings.
9. Repeat restore after service restart and after compaction or block garbage collection.
10. Test loss of every browser replica; retained blocks must still be discoverable and decryptable.

Until this acceptance path exists, keep independent conventional backups of data and key material. A [relay](../running-a-relay/) forwards traffic but is not storage, backup, or pinning.
