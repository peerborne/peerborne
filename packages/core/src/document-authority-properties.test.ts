import { describe, expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from './document-authority-log.js';
import { GroupSecurityCoordinator } from './group-security-coordinator.js';
import { CoordinatedDocument } from './coordinated-document.js';
import {
  context,
  config,
  control,
  createGroupInput,
  protocol,
  groupId,
  id,
  flushAndCollect,
} from './__testutils__/group-security-coordinator.js';
import {
  testAuth,
  testCRDT,
  testChanges,
} from './__testutils__/coordinated-document.js';
import { documentBytesId } from './internal/document-binary.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
} from './document-replay-journal.js';
import { InMemoryDocumentJournalStore } from './document-journal-store.js';

describe('causal document controller authority', () => {
  test('checks pinned roots, role signatures, causal heads and controller transfer across generated histories', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.boolean(), { minLength: 1, maxLength: 10 }),
        async (transfers) => {
          const f = await context(),
            auth = testAuth(f),
            authority = new DocumentGroupControlAuthority(
              protocol,
              groupId,
              f.identities.actorId,
            );
          const coordinator = await GroupSecurityCoordinator.bootstrap(
            { ...config(f), authorizeControl: authority.authorize },
            createGroupInput,
            { operationId: id(1), subjectId: f.identities.actorId },
          );
          let controller = f.identities.actorId,
            other = f.identities.attackerId;
          const members = () => [
            {
              memberId: controller,
              publicKey: documentBytesId(controller),
              role: 3 as const,
            },
            {
              memberId: other,
              publicKey: documentBytesId(other),
              role: 1 as const,
            },
          ];
          const log = await DocumentAuthorityLog.create(
            '/private',
            coordinator.documentContext,
            members(),
            controller,
            auth,
            authority,
          );
          const root = log.genesisId;
          for (let index = 0; index < transfers.length; index++) {
            await flushAndCollect(coordinator);
            // The coordinator's local signing actor stays fixed. After transferring
            // authority away, direct control requests from that actor must fail.
            if (
              documentBytesId(controller) !==
              documentBytesId(f.identities.actorId)
            ) {
              await expect(
                coordinator.createCommit(
                  { changes: [] },
                  control(index + 2, 'update', f.identities.actorId),
                ),
              ).rejects.toThrow();
              break;
            }
            const oldContext = coordinator.documentContext;
            await expect(
              log.signUpdate(oldContext, members(), controller),
            ).rejects.toThrow('fresh');
            await coordinator.createCommit(
              { changes: [] },
              control(index + 2, 'update', f.identities.actorId),
            );
            expect(() => log.capture(coordinator.documentContext)).toThrow(
              'history',
            );
            const nextController = transfers[index] ? other : controller;
            const roster = [
              {
                memberId: nextController,
                publicKey: documentBytesId(nextController),
                role: 3 as const,
              },
              {
                memberId: transfers[index] ? controller : other,
                publicKey: documentBytesId(
                  transfers[index] ? controller : other,
                ),
                role: 1 as const,
              },
            ];
            const update = await log.signUpdate(
              coordinator.documentContext,
              roster,
              controller,
            );
            const corrupt = update.slice();
            corrupt[corrupt.length - 1] ^= 1;
            await expect(
              log.applyUpdate(coordinator, corrupt),
            ).rejects.toThrow();
            await log.applyUpdate(coordinator, update);
            await expect(log.applyUpdate(coordinator, update)).rejects.toThrow(
              'forked',
            );
            if (transfers[index]) [controller, other] = [other, controller];
            expect(
              log
                .capture(coordinator.documentContext)
                .members.find((member) => member.role === 3)!.memberId,
            ).toEqual(controller);
          }
          const restored = await DocumentAuthorityLog.restore(
            log.exportRecords(),
            root,
            auth,
            new DocumentGroupControlAuthority(
              protocol,
              groupId,
              f.identities.actorId,
            ),
          );
          expect(restored.headId).toEqual(log.headId);
          const badRoot = root.slice();
          badRoot[0] ^= 1;
          await expect(
            DocumentAuthorityLog.restore(
              log.exportRecords(),
              badRoot,
              auth,
              new DocumentGroupControlAuthority(
                protocol,
                groupId,
                f.identities.actorId,
              ),
            ),
          ).rejects.toThrow('genesis');
        },
      ),
      { seed: 2011151, numRuns: 24 },
    );
  });

  test('persists an acknowledged controller transfer and rejects local writes after restart', async () => {
    const f = await context(),
      auth = testAuth(f),
      authority = new DocumentGroupControlAuthority(
        protocol,
        groupId,
        f.identities.actorId,
      );
    const coordinator = await GroupSecurityCoordinator.bootstrap(
      { ...config(f), authorizeControl: authority.authorize },
      createGroupInput,
      { operationId: id(1), subjectId: f.identities.actorId },
    );
    const roster = [
      {
        memberId: f.identities.actorId,
        publicKey: documentBytesId(f.identities.actorId),
        role: 3 as const,
      },
      {
        memberId: f.identities.attackerId,
        publicKey: documentBytesId(f.identities.attackerId),
        role: 1 as const,
      },
    ];
    const log = await DocumentAuthorityLog.create(
      '/private',
      coordinator.documentContext,
      roster,
      f.identities.actorId,
      auth,
      authority,
    );
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      ),
      store = new InMemoryDocumentJournalStore(),
      anchor = new InMemoryDocumentJournalRollbackAnchor();
    const makeJournal = () =>
      new DocumentReplayJournal('/private', log.genesisId, key, store, anchor);
    const document = new CoordinatedDocument(
      '/private',
      [],
      testCRDT,
      testChanges,
      auth,
      f.identities.actorId,
      f.identities.actorId,
      { coordinator, authority: log, journal: makeJournal() },
    );
    await document.activate();
    await document.change((doc) => {
      doc.push(1);
    });
    await coordinator.createCommit(
      { changes: [] },
      control(2, 'update', f.identities.actorId),
    );
    const nextRoster = [
      { ...roster[0], role: 1 as const },
      { ...roster[1], role: 3 as const },
    ];
    await document.applyAuthorityUpdate(
      await log.signUpdate(
        coordinator.documentContext,
        nextRoster,
        f.identities.actorId,
      ),
    );
    await expect(
      document.change((doc) => {
        doc.push(2);
      }),
    ).rejects.toThrow('cannot write');
    await document.close();
    const entries = await makeJournal().restore();
    const restored = await DocumentAuthorityLog.restore(
      entries.at(-1)!.authorityRecords,
      log.genesisId,
      auth,
      new DocumentGroupControlAuthority(
        protocol,
        groupId,
        f.identities.actorId,
      ),
    );
    expect(
      restored
        .capture(coordinator.documentContext)
        .members.find((member) => member.role === 3)!.memberId,
    ).toEqual(f.identities.attackerId);
    const reopened = new CoordinatedDocument(
      '/private',
      [],
      testCRDT,
      testChanges,
      auth,
      f.identities.actorId,
      f.identities.actorId,
      { coordinator, authority: log, journal: makeJournal() },
    );
    await reopened.activate();
    expect(reopened.document).toEqual([1]);
    await expect(
      reopened.change((doc) => {
        doc.push(2);
      }),
    ).rejects.toThrow('cannot write');
    await reopened.close();
  });
});
