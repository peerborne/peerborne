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
  ContractTestProvider,
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

async function strictRosterFixture(persistPublications = false) {
  const f = await context();
  const auth = testAuth(f);
  const own = f.identities.actorId;
  const controller = new DocumentGroupControlAuthority(protocol, groupId, own);
  let providerReads = 0;
  Object.assign(f.provider, {
    async getAuthenticatedMemberIds() {
      providerReads++;
      return [own.slice()];
    },
  });
  const coordinator = await GroupSecurityCoordinator.bootstrap(
    { ...config(f), authorizeControl: controller.authorize },
    createGroupInput,
    { operationId: id(1), subjectId: own },
  );
  const roster = [
    { memberId: own, publicKey: documentBytesId(own), role: 3 as const },
  ];
  const path = '/strict-roster-schedule';
  const log = await DocumentAuthorityLog.create(
    path,
    coordinator.documentContext,
    roster,
    own,
    auth,
    controller,
  );
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const store = new InMemoryDocumentJournalStore();
  const anchor = new InMemoryDocumentJournalRollbackAnchor();
  const reopen = () => new CoordinatedDocument(
    path, [], testCRDT, testChanges, auth, own, own,
    {
      coordinator,
      authority: log,
      requireGroupRosterMatch: true,
      persistPublications,
      journal: new DocumentReplayJournal(path, log.genesisId, key, store, anchor),
    },
  );
  const advance = async (operation: number) => {
    await coordinator.createCommit(
      { changes: [] },
      control(operation, 'update', own),
    );
    await flushAndCollect(coordinator);
    return log.signUpdate(coordinator.documentContext, roster, own);
  };
  return { auth, own, coordinator, log, reopen, advance, store, reads: () => providerReads };
}

describe('causal document controller authority', () => {
  test.each([0, 1, 2, 3, 4, 5])(
    'checks pinned roots, role signatures, causal heads and controller transfer across generated histories (batch %s)',
    async (batch) => {
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
              await expect(
                log.applyUpdate(coordinator, update),
              ).rejects.toThrow('forked');
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
        {
          seed:
            batch === 0
              ? 2011151
              : batch === 1
                ? 2012151
                : batch === 2
                  ? 2013151
                  : batch === 3
                    ? 2014151
                    : batch === 4
                      ? 2015151
                      : 2016151,
          numRuns: 4,
        },
      );
    },
  );

  test('requires a fresh authenticated roster across delayed role delivery and restart', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            restart: fc.constantFrom('none', 'before-role', 'after-role'),
            value: fc.integer(),
          }),
          { minLength: 1, maxLength: 5 },
        ),
        async (schedule) => {
          const f = await strictRosterFixture();
          let doc = f.reopen();
          let callbacks = 0;
          const accepted: number[] = [];
          await doc.activate();
          try {
            for (const [index, step] of schedule.entries()) {
              const role = await f.advance(index + 2);
              expect(() => doc.document).toThrow();
              const before = callbacks;
              const countCallback = () => { callbacks++; };
              await expect(doc.change(countCallback)).rejects.toThrow();
              if (step.restart === 'before-role') {
                await doc.close();
                doc = f.reopen();
                await doc.applyAuthorityUpdateBeforeOpen(role);
                expect(() => doc.document).toThrow(/activation/);
                await expect(doc.change(countCallback)).rejects.toThrow(/activation/);
                await expect(doc.publicKeys(true)).rejects.toThrow(/activation/);
                await expect(doc.pendingPublications()).rejects.toThrow(/activation/);
                await doc.activate();
              } else {
                await doc.applyAuthorityUpdate(role);
                if (step.restart === 'after-role') {
                  await doc.close();
                  doc = f.reopen();
                  await doc.activate();
                }
              }
              expect(callbacks).toBe(before);
              const reads = f.reads();
              await doc.change((draft) => {
                callbacks++;
                draft.push(step.value);
              });
              expect(f.reads()).toBe(reads);
              accepted.push(step.value);
              expect(doc.document).toEqual(accepted);
            }
            expect(callbacks).toBe(schedule.length);
          } finally {
            await doc.close();
          }
        },
      ),
      {
        seed: 20261122,
        numRuns: 12,
        examples: [[[
          { restart: 'before-role', value: 1 },
          { restart: 'after-role', value: 2 },
        ]]],
      },
    );
  });

  test.each([true, false])(
    'holds the next controller behind the journal acknowledgement (accepted=%s)',
    async (accepted) => {
      const f = await strictRosterFixture();
      const doc = f.reopen();
      await doc.activate();
      await doc.change((draft) => { draft.push(7); });
      const role = await f.advance(2);
      const groupHead = f.coordinator.documentContext.controlHead;
      const oldRoleHead = f.log.headId;
      const storeCommit = f.store.commit.bind(f.store);
      let entered!: () => void;
      let resume!: () => void;
      const started = new Promise<void>((resolve) => { entered = resolve; });
      const paused = new Promise<void>((resolve) => { resume = resolve; });
      f.store.commit = async (...args) => {
        entered();
        await paused;
        if (!accepted) throw new Error('journal did not acknowledge the role');
        await storeCommit(...args);
      };
      const applying = doc.applyAuthorityUpdate(role);
      const result = applying.then(() => true, () => false);
      try {
        await Promise.race([
          started,
          result.then(() => {
            throw new Error('Role transition finished before journal acknowledgement');
          }),
        ]);
        const readsBeforeAcknowledgement = f.reads();
        expect(f.log.headId).toEqual(oldRoleHead);
        expect(f.log.controllerAtHead(groupHead)).toBeUndefined();
        await expect(f.log.applyUpdate(f.coordinator, role)).rejects.toThrow(/reserved/);
        await expect(
          f.coordinator.createCommit(
            { changes: [] },
            control(3, 'update', f.own),
          ),
        ).rejects.toThrow();
        expect(f.coordinator.documentContext.controlHead).toEqual(groupHead);
        resume();
        expect(await result).toBe(accepted);
        expect(f.reads()).toBe(readsBeforeAcknowledgement);
        if (accepted) {
          expect(f.log.controllerAtHead(groupHead)).toEqual(f.own);
          expect(doc.document).toEqual([7]);
          await f.advance(3);
        } else {
          expect(f.log.controllerAtHead(groupHead)).toBeUndefined();
          expect(f.log.headId).toEqual(oldRoleHead);
          expect(() => doc.document).toThrow();
        }
      } finally {
        resume();
        await result;
        await doc.close();
      }
    },
  );

  test('refuses a strict authority lookup that outlives its group context', async () => {
    const f = await strictRosterFixture();
    const doc = f.reopen();
    await doc.activate();
    const decode = f.auth.deserializePublicKey;
    let enter!: () => void;
    let resume!: () => void;
    const decoding = new Promise<void>((resolve) => { enter = resolve; });
    const paused = new Promise<void>((resolve) => { resume = resolve; });
    f.auth.deserializePublicKey = async (value) => {
      enter();
      await paused;
      return decode(value);
    };
    const result = doc.publicKeys(true).then(() => true, () => false);
    try {
      await Promise.race([
        decoding,
        result.then(() => {
          throw new Error('Authority lookup finished before its key was decoded');
        }),
      ]);
      await f.coordinator.createCommit(
        { changes: [] },
        control(2, 'update', f.own),
      );
      resume();
      expect(await result).toBe(false);
    } finally {
      resume();
      await result;
      await doc.close();
    }
  });

  test('fences pending publication reads and dispatch while the roster is stale', async () => {
    const f = await strictRosterFixture(true);
    const doc = f.reopen();
    await doc.activate();
    const frame = await doc.change((draft) => { draft.push(7); });
    let enter!: () => void;
    let resume!: () => void;
    const reading = new Promise<void>((resolve) => { enter = resolve; });
    const paused = new Promise<void>((resolve) => { resume = resolve; });
    const load = f.store.loadPublications.bind(f.store);
    f.store.loadPublications = async (...args) => {
      const rows = await load(...args);
      enter();
      await paused;
      return rows;
    };
    const pending = doc.pendingPublications().then(() => true, () => false);
    try {
      await Promise.race([
        reading,
        pending.then(() => {
          throw new Error('Publication read finished before its durable lookup');
        }),
      ]);
      const role = await f.advance(2);
      expect(() => doc.assertPublicationDispatchAllowed()).toThrow(/roster/);
      resume();
      expect(await pending).toBe(false);
      await doc.applyAuthorityUpdate(role);
      expect(() => doc.assertPublicationDispatchAllowed()).not.toThrow();
      expect(await doc.pendingPublications()).toEqual([frame]);
    } finally {
      resume();
      await pending;
      await doc.close();
    }
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

test('rejects a validly signed role fork that does not extend the accepted checkpoint authority', async () => {
  const f = await context(),
    auth = testAuth(f),
    controlAuthority = new DocumentGroupControlAuthority(
      protocol,
      groupId,
      f.identities.actorId,
    );
  const coordinator = await GroupSecurityCoordinator.bootstrap(
    { ...config(f), authorizeControl: controlAuthority.authorize },
    createGroupInput,
    { operationId: id(1), subjectId: f.identities.actorId },
  );
  const writer = {
    memberId: f.identities.attackerId,
    publicKey: documentBytesId(f.identities.attackerId),
    role: 2 as const,
  };
  const roster = [
    {
      memberId: f.identities.actorId,
      publicKey: documentBytesId(f.identities.actorId),
      role: 3 as const,
    },
    writer,
  ];
  const log = await DocumentAuthorityLog.create(
    '/fork',
    coordinator.documentContext,
    roster,
    f.identities.actorId,
    auth,
    controlAuthority,
  );
  const genesis = log.exportRecords()[0],
    pin = log.genesisId,
    store = new InMemoryDocumentJournalStore(),
    anchor = new InMemoryDocumentJournalRollbackAnchor();
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const journal = () =>
    new DocumentReplayJournal('/fork', pin, key, store, anchor);
  const first = new CoordinatedDocument(
    '/fork',
    [],
    testCRDT,
    testChanges,
    auth,
    f.identities.actorId,
    f.identities.actorId,
    { coordinator, authority: log, journal: journal() },
  );
  await first.activate();
  await first.change((doc) => {
    doc.push(1);
  });
  await coordinator.createCommit(
    { changes: [] },
    control(2, 'update', f.identities.actorId),
  );
  const revoked = await log.signUpdate(
    coordinator.documentContext,
    [roster[0], { ...writer, role: 1 as const }],
    f.identities.actorId,
  );
  const alternate = await log.signUpdate(
    coordinator.documentContext,
    roster,
    f.identities.actorId,
  );
  await first.applyAuthorityUpdate(revoked);
  await first.close();
  const forkControl = new DocumentGroupControlAuthority(
    protocol,
    groupId,
    f.identities.actorId,
  );
  const fork = await DocumentAuthorityLog.restore(
    [genesis, alternate],
    pin,
    auth,
    forkControl,
  );
  const restoredCoordinator = await GroupSecurityCoordinator.restore({
    ...config({ ...f, provider: new ContractTestProvider() }),
    authorizeControl: forkControl.authorize,
  });
  const recovered = new CoordinatedDocument(
    '/fork',
    [],
    testCRDT,
    testChanges,
    auth,
    f.identities.actorId,
    f.identities.actorId,
    { coordinator: restoredCoordinator, authority: fork, journal: journal() },
  );
  expect(fork.extendsHead(log.headId)).toBe(false);
  await expect(recovered.activate()).rejects.toThrow('forks the accepted');
  expect(() => recovered.document).toThrow();
  await recovered.close();
});
