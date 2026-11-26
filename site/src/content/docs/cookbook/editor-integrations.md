---
title: Editor integrations
description: Connect CodeMirror, Tiptap, and Monaco through Peerborne's Yjs editor bridge.
---

`@peerborne/yjs/editor` supplies an experimental editor bridge. It binds an
editor to a separate Yjs document and routes local updates through the opened
Peerborne document's `change()` method. This captures deltas before the
authoritative CRDT changes and retains authorization, encryption, signing, and
publication behavior.

Do not bind an editor directly to `peerborneDocument.document`: ordinary editor
mutations would bypass Peerborne's change capture.

The bridge needs an open document. This example creates a new one:

```ts
import { createYjsEditorBridge } from '@peerborne/yjs/editor';

const document = peerborne.doc('/notes/launch-plan');
await document.create();
const bridge = await createYjsEditorBridge(document, {
  onError: () => { showEditorError(); },
});

// Give bridge.document to the upstream editor binding.
const text = bridge.document.getText('body');
await bridge.flush();

// Dispose the editor binding first, then drain writes and destroy its mirror.
await bridge.destroy();
await document.close();
```

A collaborator binds the open document that
[`acceptInvitation()`](../invitations/) returns. Without a restored checkpoint,
`document.open()` loads the path from peers and requires
`resolveLoadSecurityCommitments` and `resolveTrustedDocumentWriters` in the
node configuration. If no connected peer can serve the path (a relay cannot),
it rejects with `No document state is available…`; if one can and
`resolveLoadSecurityCommitments` is missing, it rejects with
`TrustedLoadSecurityCommitmentsError`. See
[Open existing documents](../../concepts/documents/#open-existing-documents).

The mirror writes under a Yjs client ID that `document.reserveActor()` binds
to the document's signer, so its edits pass
[actor binding](../../concepts/security/#crdt-actors-are-bound-to-change-signers).
Remote document notifications update the mirror without generating another
local write. Local updates are queued in order. `flush()` and `destroy()` reject
on failed document writes. The first failure halts later queued writes, and the
mirror can contain unaccepted edits; recreate it from authoritative state after
the application handles the error. This is not a transaction rollback mechanism.

## Runnable editor examples

The
[browser workspace](https://github.com/Peerborne/peerborne/tree/main/examples/integrations)
contains the following editor integrations:

| Editor | Binding |
| --- | --- |
| CodeMirror 6 | `y-codemirror.next`, using the mirror's `Y.Text` |
| Tiptap / ProseMirror | Collaboration extension, with StarterKit undo/redo disabled |
| Monaco | `y-monaco`, with an editor worker and the documented module-path alias |

From a built source checkout, start
`yarn workspace @peerborne/integration-examples start` and choose the editor.
Playwright types into each editor and asserts that the authoritative local
Peerborne document changes. Focused bridge tests separately verify delta
capture, remote echo suppression, write rejection, and teardown while writes
are pending.

Cursor presence and awareness transport are not implemented. These local tests
do not establish cross-browser editor convergence, low-latency typing under
partitions, or production suitability. The examples use fresh identities and
no bootstrap peers. See [current limitations](../../concepts/limitations/) and
[integration evidence](../../reference/integration-status/).
