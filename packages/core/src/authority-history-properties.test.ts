import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from './document-authority-log.js';
import {
  GroupSecurityCoordinator,
  type GroupSecurityDocumentContext,
} from './group-security-coordinator.js';
import type { DocumentMemberAuthority } from './coordinated-document.js';
import {
  context,
  config,
  createGroupInput,
  control,
  protocol,
  groupId,
  id,
  flushAndCollect,
} from './__testutils__/group-security-coordinator.js';
import { testAuth } from './__testutils__/coordinated-document.js';
import {
  DocumentBinaryWriter,
  documentBytesId,
  documentBytesEqual,
} from './internal/document-binary.js';
import {
  decodeSignedDocumentContent,
  encodeSignedDocumentContent,
  writeDocumentContext,
} from './document-security-wire.js';

const digest = async (bytes: Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>),
  );
const ordered = <T extends { memberId: Uint8Array }>(members: T[]) =>
  [...members].sort((a, b) =>
    documentBytesId(a.memberId) < documentBytesId(b.memberId)
      ? -1
      : documentBytesId(a.memberId) === documentBytesId(b.memberId)
        ? 0
        : 1,
  );

async function fixture() {
  const f = await context(),
    auth = testAuth(f);
  const authority = new DocumentGroupControlAuthority(
    protocol,
    groupId,
    f.identities.actorId,
  );
  const coordinator = await GroupSecurityCoordinator.bootstrap(
    { ...config(f), authorizeControl: authority.authorize },
    createGroupInput,
    { operationId: id(1), subjectId: f.identities.actorId },
  );
  const members: DocumentMemberAuthority[] = [
    {
      memberId: f.identities.actorId,
      publicKey: documentBytesId(f.identities.actorId),
      role: 3,
    },
    {
      memberId: f.identities.attackerId,
      publicKey: documentBytesId(f.identities.attackerId),
      role: 1,
    },
  ];
  const log = await DocumentAuthorityLog.create(
    '/authority-boundary',
    coordinator.documentContext,
    members,
    f.identities.actorId,
    auth,
    authority,
  );
  return { f, auth, coordinator, log, members };
}

// An attacker writes the current wire format directly, bypassing roster/API validation.
async function rawRecord(
  f: Awaited<ReturnType<typeof fixture>>,
  context: GroupSecurityDocumentContext,
  members: ReadonlyArray<{
    memberId: Uint8Array;
    publicKey: string;
    role: number;
  }>,
  sequence: number,
  parent: Uint8Array,
  signer: Uint8Array,
) {
  const writer = new DocumentBinaryWriter();
  writer
    .fixed(
      Uint8Array.from('peerborne/document-authority/v1\0', (c) =>
        c.charCodeAt(0),
      ),
    )
    .text('/authority-boundary')
    .integer(sequence, 8)
    .fixed(parent);
  writeDocumentContext(writer, context);
  writer.integer(members.length, 2);
  for (const member of members)
    writer
      .fixed(member.memberId)
      .text(member.publicKey, 4096)
      .integer(member.role, 1);
  const unsigned = writer.finish();
  return encodeSignedDocumentContent(
    unsigned,
    await f.auth.sign(unsigned, signer),
  );
}

const restore = (
  f: Awaited<ReturnType<typeof fixture>>,
  records: Uint8Array[],
) =>
  DocumentAuthorityLog.restore(
    records,
    f.log.genesisId,
    f.auth,
    new DocumentGroupControlAuthority(
      protocol,
      groupId,
      f.f.identities.actorId,
    ),
  );

test('preserves signed controller bindings through transfers and rejects historical control-head reuse', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.boolean(), { minLength: 1, maxLength: 6 }),
      async (transfers) => {
        const f = await fixture(),
          base = f.coordinator.documentContext;
        const records = f.log.exportRecords();
        let controller = f.f.identities.actorId,
          other = f.f.identities.attackerId;
        let head = f.log.headId,
          lastContext = base,
          restored = f.log;
        const bindings: Array<readonly [Uint8Array, Uint8Array]> = [
          [base.controlHead.slice(), controller.slice()],
        ];
        for (const [index, transfer] of transfers.entries()) {
          const nextContext = {
            state: {
              ...base.state,
              epoch: base.state.epoch + BigInt(index + 1),
            },
            controlHead: id(index + 90),
          };
          const nextController = transfer ? other : controller;
          const nextOther = transfer ? controller : other;
          const roster = ordered([
            {
              memberId: nextController,
              publicKey: documentBytesId(nextController),
              role: 3,
            },
            {
              memberId: nextOther,
              publicKey: documentBytesId(nextOther),
              role: 1,
            },
          ]);
          const unauthorized = await rawRecord(
            f,
            nextContext,
            roster,
            index + 2,
            head,
            other,
          );
          await expect(restore(f, [...records, unauthorized])).rejects.toThrow(
            'signature',
          );
          const record = await rawRecord(
            f,
            nextContext,
            roster,
            index + 2,
            head,
            controller,
          );
          records.push(record);
          head = await digest(decodeSignedDocumentContent(record).unsigned);
          bindings.push([
            nextContext.controlHead.slice(),
            nextController.slice(),
          ]);
          restored = await restore(f, records);
          for (const [controlHead, expected] of bindings) {
            expect(restored.controllerAtHead(controlHead)).toEqual(expected);
            restored.controllerAtHead(controlHead)!.fill(0);
            expect(restored.controllerAtHead(controlHead)).toEqual(expected);
          }
          const captured = restored.capture(nextContext);
          captured.headId.fill(0);
          captured.members.forEach((member) => member.memberId.fill(0));
          expect(
            restored
              .capture(nextContext)
              .members.find((member) => member.role === 3)!.memberId,
          ).toEqual(nextController);
          [controller, other] = [nextController, nextOther];
          lastContext = nextContext;
        }
        const reusedContext = {
          state: { ...lastContext.state, epoch: lastContext.state.epoch + 1n },
          controlHead: base.controlHead.slice(),
        };
        const rewrite = await rawRecord(
          f,
          reusedContext,
          ordered([
            { memberId: other, publicKey: documentBytesId(other), role: 3 },
            {
              memberId: controller,
              publicKey: documentBytesId(controller),
              role: 1,
            },
          ]),
          records.length + 1,
          head,
          controller,
        );
        await expect(restore(f, [...records, rewrite])).rejects.toThrow(
          'already bound',
        );
        expect(restored.controllerAtHead(base.controlHead)).toEqual(
          bindings[0][1],
        );
        const exported = restored.exportRecords();
        exported.forEach((record) => record.fill(0));
        expect(restored.exportRecords()).toEqual(records);
      },
    ),
    { seed: 2011213, numRuns: 6 },
  );
});

test('rejects signed malformed rosters before spending signature-verification work', async () => {
  const f = await fixture();
  const verify = f.auth.verify;
  let calls = 0;
  f.auth.verify = (...args) => {
    calls++;
    return verify(...args);
  };
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(
        'duplicate-key',
        'duplicate-id',
        'two-controllers',
        'no-controller',
        'invalid-role',
        'empty-key',
        'unordered',
        'empty',
        'oversized',
      ),
      fc.integer({ min: 4, max: 255 }),
      async (fault, invalidRole) => {
        let members: Array<{
          memberId: Uint8Array;
          publicKey: string;
          role: number;
        }> = ordered(
          f.members.map((member) => ({
            ...member,
            memberId: member.memberId.slice(),
          })),
        );
        if (fault === 'duplicate-key')
          members[1].publicKey = members[0].publicKey;
        if (fault === 'duplicate-id')
          members[1].memberId = members[0].memberId.slice();
        if (fault === 'two-controllers')
          members.forEach((member) => (member.role = 3));
        if (fault === 'no-controller')
          members.forEach((member) => (member.role = 1));
        if (fault === 'invalid-role') members[0].role = invalidRole;
        if (fault === 'empty-key') members[0].publicKey = '';
        if (fault === 'unordered') members.reverse();
        if (fault === 'empty') members = [];
        if (fault === 'oversized')
          members = Array.from({ length: 257 }, (_, index) => ({
            memberId: id(index),
            publicKey: `key-${index}`,
            role: index === 0 ? 3 : 1,
          }));
        const record = await rawRecord(
          f,
          f.coordinator.documentContext,
          members,
          1,
          new Uint8Array(32),
          f.f.identities.actorId,
        );
        const pin = await digest(decodeSignedDocumentContent(record).unsigned);
        const before = calls;
        await expect(
          DocumentAuthorityLog.restore(
            [record],
            pin,
            f.auth,
            new DocumentGroupControlAuthority(
              protocol,
              groupId,
              f.f.identities.actorId,
            ),
          ),
        ).rejects.toThrow(/authority (roster|record)/i);
        expect(calls).toBe(before);
        expect(f.log.exportRecords()).toHaveLength(1);
      },
    ),
    {
      seed: 2011214,
      numRuns: 30,
      examples: [
        ['duplicate-key', 4],
        ['duplicate-id', 4],
        ['two-controllers', 4],
        ['no-controller', 4],
        ['invalid-role', 255],
        ['empty-key', 4],
        ['unordered', 4],
        ['empty', 4],
        ['oversized', 4],
      ],
    },
  );
});

test.each([0, 1])(
  'commits one racing signed role update and preserves captured history (winner %i)',
  async (winner) => {
    await fc.assert(
      fc.asyncProperty(fc.boolean(), async (writer) => {
        const f = await fixture(),
          prior = f.coordinator.documentContext;
        const captured = f.log.capture(prior);
        await flushAndCollect(f.coordinator);
        await f.coordinator.createCommit(
          { changes: [] },
          control(2, 'update', f.f.identities.actorId),
        );
        const context = f.coordinator.documentContext;
        const frames = await Promise.all(
          [1, 2].map((role) =>
            f.log.signUpdate(
              context,
              [
                f.members[0],
                { ...f.members[1], role: (writer ? role : 3 - role) as 1 | 2 },
              ],
              f.f.identities.actorId,
            ),
          ),
        );
        const unsignedFrames = frames.map(
          (frame) => decodeSignedDocumentContent(frame).unsigned,
        );
        const native = f.auth.verify,
          releases: Array<(() => void) | undefined> = [undefined, undefined];
        let markReady!: () => void;
        const ready = new Promise<void>((resolve) => {
          markReady = resolve;
        });
        f.auth.verify = async (...args) => {
          const index = unsignedFrames.findIndex((value) =>
            documentBytesEqual(value, args[0]),
          );
          if (index < 0)
            throw new Error('Unexpected authority signature input');
          await new Promise<void>((resolve) => {
            releases[index] = resolve;
            if (releases.every(Boolean)) markReady();
          });
          return native(...args);
        };
        try {
          const operations = frames.map((frame) =>
            f.log.applyUpdate(f.coordinator, frame).then(
              () => true,
              (error) => error,
            ),
          );
          await Promise.race([
            ready,
            ...operations.map((operation) =>
              operation.then(() => {
                throw new Error(
                  'Authority update settled before authentication was released',
                );
              }),
            ),
          ]);
          expect(releases.every(Boolean)).toBe(true);
          frames.forEach((frame) => frame.fill(0));
          releases[winner]!();
          expect(await operations[winner]).toBe(true);
          expect(captured.isCurrent()).toBe(false);
          const accepted = f.log.headId;
          releases[1 - winner]!();
          expect(await operations[1 - winner]).toBeInstanceOf(Error);
          expect(f.log.headId).toEqual(accepted);
          const expectedRole = writer ? winner + 1 : 2 - winner;
          expect(
            f.log
              .capture(context)
              .members.find(
                (member) =>
                  documentBytesId(member.memberId) ===
                  documentBytesId(f.f.identities.attackerId),
              )!.role,
          ).toBe(expectedRole);
          expect(f.log.controllerAtHead(prior.controlHead)).toEqual(
            f.f.identities.actorId,
          );
          expect(f.log.exportRecords()).toHaveLength(2);
        } finally {
          releases.forEach((release) => release?.());
          f.auth.verify = native;
        }
        expect((await restore(f, f.log.exportRecords())).headId).toEqual(
          f.log.headId,
        );
      }),
      { seed: winner === 0 ? 2011215 : 2011216, numRuns: 3 },
    );
  },
);
