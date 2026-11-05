import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import {
  isFieldPathPrefix,
  grantsFieldPath,
  firstUnauthorizedFieldPath,
} from './policy/field-authorization.js';
import {
  captureDocumentWritePaths,
  copyDocumentFieldPaths,
  DocumentOperationTargets,
} from './document-field-authorization.js';
import { captureDocumentAuthorityLease } from './captured-document-authority.js';
import { CoordinatedDocument } from './coordinated-document.js';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from './document-authority-log.js';
import {
  documentFixture,
  testCRDT,
  testChanges,
  testAuth,
} from './__testutils__/coordinated-document.js';
import {
  context,
  config,
  createGroupInput,
  protocol,
  groupId,
  id,
  control,
  flushAndCollect,
} from './__testutils__/group-security-coordinator.js';
import { GroupSecurityCoordinator } from './group-security-coordinator.js';
import { documentBytesId } from './internal/document-binary.js';
import { DocumentBinaryWriter } from './internal/document-binary.js';
import {
  encodeSignedDocumentContent,
  writeDocumentContext,
} from './document-security-wire.js';

const path = fc.array(
  fc.oneof(
    fc.string({ maxLength: 8 }),
    fc.constantFrom('', '/', '~', '__proto__', '💻'),
  ),
  { maxLength: 6 },
);
const prefix = (grant: readonly string[], target: readonly string[]) =>
  grant.length <= target.length &&
  grant.every((key, index) => key === target[index]);

test('matches segment-prefix grants exactly and returns the first unauthorized native target', () => {
  fc.assert(
    fc.property(
      fc.array(path, { maxLength: 12 }),
      fc.array(path, { maxLength: 15 }),
      (grants, targets) => {
        for (const target of targets) {
          for (const grant of grants)
            expect(isFieldPathPrefix(grant, target)).toBe(
              prefix(grant, target),
            );
          expect(grantsFieldPath(grants, target)).toBe(
            grants.some((grant) => prefix(grant, target)),
          );
        }
        expect(firstUnauthorizedFieldPath(grants, targets)).toBe(
          targets.findIndex(
            (target) => !grants.some((grant) => prefix(grant, target)),
          ),
        );
      },
    ),
    { seed: 2012301, numRuns: 180 },
  );
});

test('captures signed scope as owned scalar data and refuses accessors, holes and malformed paths', () => {
  fc.assert(
    fc.property(
      fc.array(path, { maxLength: 12 }),
      fc.integer({ min: 0, max: 5 }),
      (paths, mode) => {
        const source = paths.map((entry) => [...entry]);
        const member = { writePaths: source };
        const captured = captureDocumentWritePaths(member);
        source.push(['injected']);
        if (source[0]) source[0].push('injected');
        expect(captured).toEqual(paths);
        let invoked = 0;
        const getter = () => {
          invoked++;
          throw new Error('must not execute');
        };
        const bad =
          mode === 0
            ? Object.defineProperty({}, 'writePaths', { get: getter })
            : {
                writePaths:
                  mode === 1
                    ? new Array(1)
                    : mode === 2
                      ? [Object.defineProperty([], '0', { get: getter })]
                      : mode === 3
                        ? [Array(33).fill('x')]
                        : mode === 4
                          ? [['x'.repeat(1025)]]
                          : [['\ud800']],
              };
        expect(() => captureDocumentWritePaths(bad)).toThrow();
        expect(invoked).toBe(0);
        expect(captureDocumentWritePaths({})).toBeUndefined();
        expect(captureDocumentWritePaths({ writePaths: [] })).toEqual([]);
        expect(Object.isFrozen(captured)).toBe(true);
      },
    ),
    {
      seed: 2012302,
      numRuns: 50,
      examples: [
        [[], 0],
        [[], 1],
        [[], 2],
        [[], 3],
        [[], 4],
        [[], 5],
      ],
    },
  );
});

test('bounds inspection work, distinct targets and path metadata without dropping rejected predecessors', () => {
  fc.assert(
    fc.property(fc.constantFrom('work', 'count', 'units'), (mode) => {
      const targets = new DocumentOperationTargets();
      if (mode === 'work') targets.add(['same'], 131072);
      if (mode === 'count')
        for (let index = 0; index < 4096; index++) targets.add([String(index)]);
      if (mode === 'units')
        for (let index = 0; index < 1024; index++)
          targets.add([String(index).padStart(1024, 'x')]);
      const before = targets.snapshot();
      expect(() => targets.add(['extra'])).toThrow(/bounds/);
      expect(targets.snapshot()).toEqual(before);
      expect(() => targets.add(['same'], Number.MAX_SAFE_INTEGER)).toThrow(
        /bounds/,
      );
      expect(() => targets.add(['same'], NaN)).toThrow(/bounds/);
      expect(() => targets.add(['same'], 0)).toThrow(/bounds/);
    }),
    { seed: 2012303, numRuns: 6, examples: [['work'], ['count'], ['units']] },
  );
});

test('bounds aggregate roster grants before retaining excessive path, segment or string data', () => {
  fc.assert(
    fc.property(fc.constantFrom('paths', 'segments', 'units'), (mode) => {
      const size = mode === 'paths' ? 65 : 17;
      const scopes = Array.from({ length: 64 }, () =>
        mode === 'paths'
          ? []
          : mode === 'segments'
            ? Array(32).fill('')
            : ['x'.repeat(1024)],
      );
      const members = Array.from({ length: size }, (_, index) => ({
        memberId: new Uint8Array(32).fill(index),
        publicKey: `member-${index}`,
        role: index === 0 ? (3 as const) : (2 as const),
        writePaths: scopes,
      }));
      expect(() =>
        captureDocumentAuthorityLease(
          { members, headId: new Uint8Array(32), isCurrent: () => true },
          '00'.repeat(32),
        ),
      ).toThrow(/aggregate bounds/);
      const smaller = members.slice(0, size - 1);
      expect(
        captureDocumentAuthorityLease(
          {
            members: smaller,
            headId: new Uint8Array(32),
            isCurrent: () => true,
          },
          '00'.repeat(32),
        ).members.size,
      ).toBe(size - 1);
    }),
    {
      seed: 2012307,
      numRuns: 6,
      examples: [['paths'], ['segments'], ['units']],
    },
  );
});

test('authority leases detach field grants and reject provider accessors before admission', async () => {
  await fc.assert(
    fc.asyncProperty(path, async (grant) => {
      const f = await documentFixture();
      const source = f.authority.capture(f.coordinator.documentContext);
      const mutable = [grant.slice()];
      const member = { ...source.members[0], writePaths: mutable };
      const captured = captureDocumentAuthorityLease(
        { ...source, members: [member] },
        documentBytesId(f.identity),
      );
      mutable.push(['escape']);
      mutable[0].push('escape');
      expect(captured.writePaths.get(documentBytesId(f.identity))).toEqual([
        grant,
      ]);
      let invoked = 0;
      Object.defineProperty(member, 'writePaths', {
        get: () => {
          invoked++;
          return [];
        },
      });
      expect(() =>
        captureDocumentAuthorityLease(
          { ...source, members: [member] },
          documentBytesId(f.identity),
        ),
      ).toThrow();
      expect(invoked).toBe(0);
    }),
    { seed: 2012304, numRuns: 12 },
  );
});

test('restricted authority fails closed with a provider that cannot inspect native operations', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: -1000, max: 1000 }), async (value) => {
      const f = await documentFixture();
      const capture = f.authority.capture.bind(f.authority);
      f.authority.capture = (state) => {
        const lease = capture(state);
        return {
          ...lease,
          members: lease.members.map((member) => ({
            ...member,
            writePaths: [['numbers']],
          })),
        };
      };
      const document = new CoordinatedDocument(
        f.authority.documentId,
        [],
        testCRDT,
        testChanges,
        f.auth,
        f.identity,
        f.identity,
        { coordinator: f.coordinator, authority: f.authority },
      );
      await expect(
        document.change((draft) => draft.push(value)),
      ).rejects.toThrow(/cannot inspect/);
      expect(document.document).toEqual([]);
      f.authority.capture = capture;
      await document.change((draft) => draft.push(value));
      expect(document.document).toEqual([value]);
      await document.close();
    }),
    { seed: 2012305, numRuns: 8 },
  );
});

test('field grants are authenticated by the pinned append-only role history across epoch transitions', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.array(path, { maxLength: 5 }), {
        minLength: 1,
        maxLength: 4,
      }),
      async (history) => {
        const f = await context(),
          auth = testAuth(f);
        const controlAuthority = new DocumentGroupControlAuthority(
          protocol,
          groupId,
          f.identities.actorId,
        );
        const coordinator = await GroupSecurityCoordinator.bootstrap(
          { ...config(f), authorizeControl: controlAuthority.authorize },
          createGroupInput,
          { operationId: id(1), subjectId: f.identities.actorId },
        );
        const members = (writePaths: readonly (readonly string[])[]) => [
          {
            memberId: f.identities.actorId,
            publicKey: documentBytesId(f.identities.actorId),
            role: 3 as const,
            writePaths,
          },
        ];
        const log = await DocumentAuthorityLog.create(
          '/fields',
          coordinator.documentContext,
          members(history[0]),
          f.identities.actorId,
          auth,
          controlAuthority,
        );
        let previous = log.capture(coordinator.documentContext);
        for (let index = 1; index < history.length; index++) {
          await coordinator.createCommit(
            { changes: [] },
            control(index + 2, 'update', f.identities.actorId),
          );
          const update = await log.signUpdate(
            coordinator.documentContext,
            members(history[index]),
            f.identities.actorId,
          );
          await log.applyUpdate(coordinator, update);
          expect(previous.isCurrent()).toBe(false);
          previous = log.capture(coordinator.documentContext);
          expect(previous.members[0].writePaths).toEqual(history[index]);
          await flushAndCollect(coordinator);
        }
        const records = log.exportRecords();
        const restored = await DocumentAuthorityLog.restore(
          records,
          log.genesisId,
          auth,
          new DocumentGroupControlAuthority(
            protocol,
            groupId,
            f.identities.actorId,
          ),
        );
        expect(
          restored.capture(coordinator.documentContext).members[0].writePaths,
        ).toEqual(history.at(-1));
        const damaged = records.map((record) => record.slice());
        damaged.at(-1)![damaged.at(-1)!.length - 1] ^= 1;
        await expect(
          DocumentAuthorityLog.restore(
            damaged,
            log.genesisId,
            auth,
            new DocumentGroupControlAuthority(
              protocol,
              groupId,
              f.identities.actorId,
            ),
          ),
        ).rejects.toThrow();
        expect(copyDocumentFieldPaths(history[0])).toEqual(history[0]);
      },
    ),
    { seed: 2012306, numRuns: 8 },
  );
});

test('current signed authority wire rejects malformed scope markers, lengths, text and trailing bytes', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 0, max: 8 }), async (mode) => {
      const f = await context(),
        auth = testAuth(f);
      const coordinator = await GroupSecurityCoordinator.bootstrap(
        config(f),
        createGroupInput,
        { operationId: id(1), subjectId: f.identities.actorId },
      );
      const writer = new DocumentBinaryWriter();
      writer
        .fixed(
          Uint8Array.from('peerborne/document-authority/v2\0', (char) =>
            char.charCodeAt(0),
          ),
        )
        .text('/field-wire')
        .integer(1, 8)
        .fixed(new Uint8Array(32));
      writeDocumentContext(writer, coordinator.documentContext);
      writer
        .integer(1, 2)
        .fixed(f.identities.actorId)
        .text(documentBytesId(f.identities.actorId), 4096)
        .integer(3, 1);
      writer.integer(mode === 0 ? 2 : mode === 4 || mode === 6 ? 0 : 1, 1);
      if (mode === 1) writer.integer(65, 2);
      if (mode === 2) writer.integer(1, 2).integer(33, 1);
      if (mode === 3)
        writer.integer(1, 2).integer(1, 1).text('x'.repeat(1025), 4096);
      if (mode === 4) writer.fixed(new Uint8Array([0]));
      if (mode === 5)
        writer
          .integer(1, 2)
          .integer(1, 1)
          .bytes(new Uint8Array([0xc0, 0xaf]), 4096);
      if (mode === 7) writer.integer(0, 2);
      if (mode === 8) writer.integer(1, 2).integer(0, 1);
      const unsigned = writer.finish();
      const root = new Uint8Array(
        await crypto.subtle.digest(
          'SHA-256',
          unsigned as Uint8Array<ArrayBuffer>,
        ),
      );
      const record = encodeSignedDocumentContent(
        unsigned,
        await auth.sign(unsigned, f.identities.actorId),
      );
      const restoring = DocumentAuthorityLog.restore(
        [record],
        root,
        auth,
        new DocumentGroupControlAuthority(
          protocol,
          groupId,
          f.identities.actorId,
        ),
      );
      if (mode < 6) await expect(restoring).rejects.toThrow();
      else {
        const restored = await restoring;
        expect(
          restored.capture(coordinator.documentContext).members[0].writePaths,
        ).toEqual(mode === 6 ? undefined : mode === 7 ? [] : [[]]);
      }
    }),
    {
      seed: 2012308,
      numRuns: 18,
      examples: [[0], [1], [2], [3], [4], [5], [6], [7], [8]],
    },
  );
});
