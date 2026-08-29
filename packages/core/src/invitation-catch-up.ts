import {
  INVITATION_STREAM_TIMEOUT_MS,
  withInvitationDeadline,
} from './invitation-policy.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import {
  crdtChangeNodeDeferred,
  type CRDTChangeNode,
} from './crdt-change-node.js';

interface AbortableInvitationStream {
  close(): Promise<void>;
  closeRead?(): Promise<void>;
  abort?(error: Error): void;
}

/** @internal Reject an invitation sync that did not install every advertised CID. */
export function assertInvitationCidsInstalled(
  expectedCids: readonly string[],
  installedCids: ReadonlySet<string>,
  phase: 'bootstrap' | 'catch-up',
): void {
  let missingCount = 0;
  for (const cid of expectedCids) {
    if (!installedCids.has(cid)) missingCount += 1;
  }
  if (missingCount > 0) {
    throw new Error(
      `Invitation ${phase} state is incomplete: ${missingCount} of ` +
        `${expectedCids.length} advertised CIDs were not installed`,
    );
  }
}

/** @internal Apply one invitation sync and require its full advertised tree. */
export async function syncInvitationMessageCompletely<
  ChangesType,
  PublicKey,
>(
  message: CRDTSyncMessage<ChangesType, PublicKey>,
  installedCids: ReadonlySet<string>,
  sync: () => Promise<boolean>,
  phase: 'bootstrap' | 'catch-up',
  options: {
    readonly provenSnapshotBoundariesBeforeSync?: ReadonlySet<string>;
    readonly isSnapshotApplied?: () => boolean;
  } = {},
): Promise<boolean> {
  const provenBeforeSync = new Set(
    options.provenSnapshotBoundariesBeforeSync,
  );
  const expectedWithoutNewSnapshot = new Set(
    collectInvitationCidsToInstall(
      message.changeId,
      message.changes,
      provenBeforeSync,
    ),
  );
  const snapshotBoundary = message.snapshot?.lastChangeNodeCID;
  if (snapshotBoundary !== undefined) {
    expectedWithoutNewSnapshot.add(snapshotBoundary);
  }
  const withNewSnapshot = new Set(provenBeforeSync);
  if (snapshotBoundary !== undefined) withNewSnapshot.add(snapshotBoundary);
  const expectedWithNewSnapshot = new Set(
    collectInvitationCidsToInstall(
      message.changeId,
      message.changes,
      withNewSnapshot,
    ),
  );
  if (snapshotBoundary !== undefined) {
    expectedWithNewSnapshot.add(snapshotBoundary);
  }
  const synced = await sync();
  if (!synced) return false;
  const snapshotCoversHistory =
    snapshotBoundary !== undefined &&
    options.isSnapshotApplied?.() === true;
  const expectedCids = snapshotCoversHistory
    ? expectedWithNewSnapshot
    : expectedWithoutNewSnapshot;
  assertInvitationCidsInstalled([...expectedCids], installedCids, phase);
  return true;
}

/** @internal Collect all advertised CIDs outside an applied snapshot boundary. */
export function collectInvitationCidsToInstall<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType> | undefined,
  provenSnapshotBoundaries: ReadonlySet<string>,
): string[] {
  const required = new Set<string>();
  const visited = new Set<string>();
  if (!root) {
    if (rootId !== undefined) required.add(rootId);
    return [...required];
  }
  if (rootId === undefined) {
    throw new Error('Invitation change tree is missing its root CID');
  }

  const walk = (
    nodeId: string | undefined,
    node: CRDTChangeNode<ChangesType>,
  ): void => {
    if (nodeId !== undefined) {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      required.add(nodeId);
      if (provenSnapshotBoundaries.has(nodeId)) {
        return;
      }
    }
    if (
      node.children === undefined ||
      node.children === crdtChangeNodeDeferred
    ) {
      return;
    }
    for (const [childId, child] of Object.entries(node.children)) {
      walk(childId, child);
    }
  };
  walk(rootId, root);
  return [...required];
}

/** @internal Give invitation streams one deadline and deterministic teardown. */
export async function withInvitationProtocolStream<
  Stream extends AbortableInvitationStream,
  Result,
>(
  open: (signal: AbortSignal) => Promise<Stream>,
  operation: (stream: Stream, signal: AbortSignal) => Promise<Result>,
  timeoutMs: number = INVITATION_STREAM_TIMEOUT_MS,
): Promise<Result> {
  const controller = new AbortController();
  let stream: Stream | undefined;
  let completed = false;
  let aborted = false;
  const abort = (error: Error): void => {
    if (!controller.signal.aborted) controller.abort(error);
    if (stream && !aborted) {
      aborted = true;
      stream.abort?.(error);
    }
  };

  try {
    const result = await withInvitationDeadline(
      async () => {
        stream = await open(controller.signal);
        if (controller.signal.aborted) {
          const error =
            controller.signal.reason instanceof Error
              ? controller.signal.reason
              : new Error('Invitation stream closed before opening');
          abort(error);
          throw error;
        }
        return operation(stream, controller.signal);
      },
      abort,
      timeoutMs,
    );
    completed = true;
    return result;
  } finally {
    if (stream) {
      if (completed) {
        try {
          await stream.close();
        } catch {
          /* already closed */
        }
        try {
          await stream.closeRead?.();
        } catch {
          /* already closed */
        }
      } else {
        abort(new Error('Invitation stream failed'));
      }
    } else if (!completed && !controller.signal.aborted) {
      controller.abort(new Error('Invitation stream failed before opening'));
    }
  }
}

/** @internal Direct one bounded, verified catch-up at the signed endpoint. */
export async function withIssuerPinnedInvitationStream<
  Stream extends AbortableInvitationStream,
  Result,
>(
  founderAddress: string,
  dial: (address: string, signal: AbortSignal) => Promise<Stream>,
  loadAndVerify: (stream: Stream) => Promise<Result>,
  timeoutMs: number = INVITATION_STREAM_TIMEOUT_MS,
): Promise<Result> {
  return withInvitationProtocolStream(
    (signal) => dial(founderAddress, signal),
    (stream) => loadAndVerify(stream),
    timeoutMs,
  );
}
