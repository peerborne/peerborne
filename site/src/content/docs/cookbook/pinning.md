---
title: Keeping data alive (pinning)
description: Design and validate a pinning integration with the legacy topic and decoder boundaries made explicit.
---

**Status: Deferred/incomplete integration.**

Peerborne does not currently provide a runnable, end-to-end pinning daemon or durability guarantee. Do not rely on this recipe to preserve important data. See [Storage](../../concepts/storage/) and [Limitations](../../concepts/limitations/).

## What exists

The Node-only `PeerborneNode` retains the `pubsubDocumentPublishPath` compatibility setting, but it does not subscribe to the legacy `/peerborne/documents/v3` V1 topic. The source retains an isolated, bounded decoder to make the rejected wire shape explicit; no runtime receiver invokes it. A V1 announcement therefore cannot create or open a document, attach a document subscription, or pin either supplied or later CIDs.
