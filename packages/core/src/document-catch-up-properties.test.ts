import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import { CoordinatedDocument } from './coordinated-document.js';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from './document-authority-log.js';
import {
  GroupSecurityCoordinator,
  type GroupDocumentEncryptionMaterial,
  type GroupSecurityDocumentContext,
} from './group-security-coordinator.js';
import type { GroupSecurityProvider } from './group-security-provider.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
} from './document-replay-journal.js';
import { InMemoryDocumentJournalStore } from './document-journal-store.js';
import { DocumentBinaryWriter } from './internal/document-binary.js';
import { bytesToHex } from './internal/hex.js';
import { equalBytes } from './internal/bytes.js';
import {
  decodeDocumentCatchUpCheckpoint,
  decodeDocumentCatchUpRequest,
  documentCatchUpAAD,
  encodeDocumentCatchUpCheckpoint,
  encodeDocumentCatchUpRequest,
  type DocumentCatchUpCheckpoint,
  type DocumentCatchUpRequest,
} from './document-catch-up-wire.js';
import {
  MAX_DOCUMENT_CONTENT_BYTES,
  decodeEncryptedDocumentContent,
  decodeSignedDocumentContent,
  encodeEncryptedDocumentContent,
  encodeSignedDocumentContent,
} from './document-security-wire.js';
import {
  testAuth,
  testCRDT,
  testChanges,
} from './__testutils__/coordinated-document.js';
import {
  ContractTestProvider,
  config,
  context,
  control,
  createGroupInput,
  flushAndCollect,
  groupId,
  id,
  protocol,
  publicState,
} from './__testutils__/group-security-coordinator.js';

function catchUpRequest(
  documentId: string,
  epoch: bigint,
): DocumentCatchUpRequest {
  return {
    documentId,
    context: { state: publicState(epoch), controlHead: id(1) },
    genesisId: id(2),
    authorityHead: id(3),
    requesterId: id(4),
    challenge: id(5),
    receipts: [],
  };
}

function uncheckedCheckpoint(
  request: DocumentCatchUpRequest,
  receipts: readonly {
    memberId: Uint8Array;
    sequence: bigint;
    hash: Uint8Array;
  }[],
  snapshot: Uint8Array,
): Uint8Array {
  const writer = new DocumentBinaryWriter()
    .fixed(documentCatchUpAAD('checkpoint', request))
    .fixed(request.requesterId)
    .fixed(request.challenge)
    .fixed(id(6))
    .integer(receipts.length, 2);
  for (const receipt of receipts) {
    writer
      .fixed(receipt.memberId)
      .integer(receipt.sequence, 8)
      .fixed(receipt.hash);
  }
  return writer
    .integer(0, 2)
    .bytes(snapshot, MAX_DOCUMENT_CONTENT_BYTES + 1)
    .finish();
}

function withTrailer(frame: Uint8Array, byte: number): Uint8Array {
  const result = new Uint8Array(frame.length + 1);
  result.set(frame);
  result[frame.length] = byte;
  return result;
}

test('round trips owned canonical catch-up frames and rejects partial or extended encodings', () => {
  fc.assert(
    fc.property(
      fc.oneof(
        fc.string({ minLength: 1, maxLength: 60 }),
        fc.constant('\ufeffdocument'),
      ),
      fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
      fc.uniqueArray(
        fc.record({
          member: fc.integer({ min: 0, max: 255 }),
          sequence: fc.integer({ min: 1, max: Number.MAX_SAFE_INTEGER }),
          hash: fc.uint8Array({ minLength: 32, maxLength: 32 }),
        }),
        { selector: ({ member }) => member, maxLength: 8 },
      ),
      fc.uint8Array({ maxLength: 2048 }),
      fc.nat(65_535),
      fc.integer({ min: 0, max: 255 }),
      (documentId, epoch, heads, snapshot, cut, trailing) => {
        const request = {
          ...catchUpRequest(documentId, epoch),
          receipts: [...heads]
            .sort((a, b) => a.member - b.member)
            .map(({ member, sequence, hash }) => ({
              memberId: id(member),
              sequence,
              hash,
            })),
        };
        const checkpoint: DocumentCatchUpCheckpoint = {
          ...request,
          suffixes: heads.map(({ hash }) => hash.slice(0, 1 + (hash[0] % 31))),
          controllerId: id(6),
          receipts: [...heads]
            .sort((a, b) => a.member - b.member)
            .map(({ member, sequence, hash }) => ({
              memberId: id(member),
              sequence,
              hash,
            })),
          snapshot,
        };
        const requestBytes = encodeDocumentCatchUpRequest(request);
        const checkpointBytes = encodeDocumentCatchUpCheckpoint(checkpoint);
        const decodedRequest = decodeDocumentCatchUpRequest(requestBytes);
        const decodedCheckpoint =
          decodeDocumentCatchUpCheckpoint(checkpointBytes);
        expect(decodedRequest).toEqual(request);
        expect(decodedCheckpoint).toEqual(checkpoint);
        expect(encodeDocumentCatchUpRequest(decodedRequest)).toEqual(
          requestBytes,
        );
        expect(encodeDocumentCatchUpCheckpoint(decodedCheckpoint)).toEqual(
          checkpointBytes,
        );
        decodedRequest.challenge[0] ^= 1;
        decodedCheckpoint.snapshot.fill(0xff);
        decodedCheckpoint.receipts[0]?.hash.fill(0xff);
        expect(decodeDocumentCatchUpRequest(requestBytes)).toEqual(request);
        expect(decodeDocumentCatchUpCheckpoint(checkpointBytes)).toEqual(
          checkpoint,
        );
        expect(() =>
          decodeDocumentCatchUpRequest(
            requestBytes.subarray(0, cut % requestBytes.length),
          ),
        ).toThrow();
        expect(() =>
          decodeDocumentCatchUpCheckpoint(
            checkpointBytes.subarray(0, cut % checkpointBytes.length),
          ),
        ).toThrow();
        expect(() =>
          decodeDocumentCatchUpRequest(withTrailer(requestBytes, trailing)),
        ).toThrow('trailing');
        expect(() =>
          decodeDocumentCatchUpCheckpoint(
            withTrailer(checkpointBytes, trailing),
          ),
        ).toThrow('trailing');
        expect(() => decodeDocumentCatchUpCheckpoint(requestBytes)).toThrow(
          'domain',
        );
        expect(() => decodeDocumentCatchUpRequest(checkpointBytes)).toThrow(
          'domain',
        );
      },
    ),
    { seed: 202611242, numRuns: 80 },
  );
});

test('rejects noncanonical receipt order and unusable sequences at the codec boundary', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 254 }),
      fc.bigInt({ min: 1n, max: BigInt(Number.MAX_SAFE_INTEGER) }),
      (member, sequence) => {
        const request = catchUpRequest('/catch-up-boundary', 12n);
        const first = { memberId: id(member), sequence, hash: id(7) };
        const next = { ...first, memberId: id(member + 1) };
        const aboveSafe = {
          ...next,
          sequence: BigInt(Number.MAX_SAFE_INTEGER) + 1n,
        };
        const zero = { ...next, sequence: 0n };
        const snapshot = new Uint8Array();
        expect(
          decodeDocumentCatchUpCheckpoint(
            uncheckedCheckpoint(request, [first, next], snapshot),
          ).receipts,
        ).toHaveLength(2);
        for (const receipts of [
          [next, first],
          [first, first],
          [first, aboveSafe],
          [first, zero],
        ]) {
          expect(() =>
            decodeDocumentCatchUpCheckpoint(
              uncheckedCheckpoint(request, receipts, snapshot),
            ),
          ).toThrow();
          expect(() =>
            encodeDocumentCatchUpCheckpoint({
              ...request,
              controllerId: id(6),
              snapshot,
              suffixes: [],
              receipts: receipts.map((receipt) => ({
                ...receipt,
                sequence: Number(receipt.sequence),
              })),
            }),
          ).toThrow();
        }
        expect(() =>
          encodeDocumentCatchUpCheckpoint({
            ...request,
            controllerId: id(6),
            snapshot,
            suffixes: [],
            receipts: [{ ...first, sequence: sequence as unknown as number }],
          }),
        ).toThrow('receipt');
      },
    ),
    { seed: 202611243, numRuns: 50 },
  );
});

test('enforces the exact receipt and snapshot caps for encoding and decoding', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(255, 256, 257),
      fc.constantFrom(
        MAX_DOCUMENT_CONTENT_BYTES - 1,
        MAX_DOCUMENT_CONTENT_BYTES,
        MAX_DOCUMENT_CONTENT_BYTES + 1,
      ),
      (count, snapshotLength) => {
        const request = catchUpRequest('/catch-up-limits', 0n);
        const receipts = Array.from({ length: count }, (_, index) => {
          const memberId = new Uint8Array(32);
          new DataView(memberId.buffer).setUint16(0, index);
          return { memberId, sequence: 1, hash: id(8) };
        });
        const snapshot = new Uint8Array(snapshotLength).fill(9);
        const checkpoint = {
          ...request,
          controllerId: id(6),
          receipts,
          suffixes: [],
          snapshot,
        };
        const independent = uncheckedCheckpoint(
          request,
          receipts.map((receipt) => ({ ...receipt, sequence: 1n })),
          snapshot,
        );
        if (count > 256 || snapshotLength > MAX_DOCUMENT_CONTENT_BYTES) {
          expect(() => encodeDocumentCatchUpCheckpoint(checkpoint)).toThrow();
          expect(() => decodeDocumentCatchUpCheckpoint(independent)).toThrow();
        } else {
          const encoded = encodeDocumentCatchUpCheckpoint(checkpoint);
          const decoded = decodeDocumentCatchUpCheckpoint(encoded);
          expect(equalBytes(encoded, independent)).toBe(true);
          expect(decoded.receipts).toEqual(receipts);
          expect(equalBytes(decoded.snapshot, snapshot)).toBe(true);
        }
      },
    ),
    {
      seed: 202611244,
      numRuns: 8,
      examples: [
        [256, MAX_DOCUMENT_CONTENT_BYTES],
        [257, MAX_DOCUMENT_CONTENT_BYTES],
        [256, MAX_DOCUMENT_CONTENT_BYTES + 1],
      ],
    },
  );
});

const mergeCRDT: typeof testCRDT = {
  ...testCRDT,
  createDocumentSession(initial) {
    const session = testCRDT.createDocumentSession!(initial);
    return Object.assign(session, {
      prepareMergeSnapshot(snapshot: number[]) {
        return session.prepareSnapshot!([
          ...new Set([...session.document, ...snapshot]),
        ]);
      },
    });
  },
};

async function setup() {
  const [source, target] = await Promise.all([context(), context()]);
  const identities = source.identities;
  const members = [identities.actorId, identities.attackerId];
  const auth = testAuth(source);
  const path = '/catch-up-property';
  const [sourceControl, targetControl] = members.map(
    () => new DocumentGroupControlAuthority(protocol, groupId, members[0]),
  );
  const roster = members.map((memberId, index) => ({
    memberId,
    publicKey: bytesToHex(memberId),
    role: index === 0 ? (3 as const) : (2 as const),
  }));
  const providers: GroupSecurityProvider[] = [source.provider, target.provider];
  for (const provider of providers)
    provider.getAuthenticatedMemberIds = async () =>
      members.map((member) => member.slice());
  const sourceCoordinator = await GroupSecurityCoordinator.bootstrap(
    { ...config(source), authorizeControl: sourceControl.authorize },
    createGroupInput,
    { operationId: id(1), subjectId: members[0] },
  );
  const [genesis] = await flushAndCollect(sourceCoordinator);
  const sourceLog = await DocumentAuthorityLog.create(
    path,
    sourceCoordinator.documentContext,
    roster.slice(0, 1),
    members[0],
    auth,
    sourceControl,
  );
  const targetConfig = {
    ...config(target),
    actorId: members[1],
    signControlRecord: (bytes: Uint8Array) =>
      identities.signAs(members[1], bytes),
    verifyControlSignature: identities.verify,
    authorizeControl: targetControl.authorize,
  };
  const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
    targetConfig,
    {
      operationId: id(16),
      groupId,
      memberId: members[1],
      credential: members[1],
    },
  );
  await sourceCoordinator.createCommit(
    { changes: [{ kind: 'add', memberId: members[1], keyPackage }] },
    control(2, 'add', members[1]),
  );
  const [addition] = await flushAndCollect(sourceCoordinator);
  await sourceLog.applyUpdate(
    sourceCoordinator,
    await sourceLog.signUpdate(
      sourceCoordinator.documentContext,
      roster,
      members[0],
    ),
  );
  const targetLog = await DocumentAuthorityLog.restore(
    sourceLog.exportRecords(),
    sourceLog.genesisId,
    auth,
    targetControl,
  );
  const targetCoordinator = await GroupSecurityCoordinator.joinFromInvitation(
    targetConfig,
    {
      subjectId: members[1],
      keyPackageRef: keyPackage.reference,
      controlPrefix: [genesis.controlRecord, addition.controlRecord],
      commit: addition.commit!,
      welcome: addition.welcomes[0],
    },
  );
  const coordinators = [sourceCoordinator, targetCoordinator];
  const logs = [sourceLog, targetLog];
  const keys = await Promise.all(
    members.map(() =>
      crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ]),
    ),
  );
  const stores = members.map(() => new InMemoryDocumentJournalStore());
  const anchors = members.map(
    () => new InMemoryDocumentJournalRollbackAnchor(),
  );
  let targetJournalWrites = 0;
  const stageTarget = stores[1].stage.bind(stores[1]);
  stores[1].stage = (...args) => {
    targetJournalWrites += 1;
    return stageTarget(...args);
  };
  let beforeTargetAcceptance: (() => Promise<void>) | undefined;
  let afterTargetAuthorization: (() => Promise<void>) | undefined;
  const targetDocumentOperation =
    targetCoordinator.runDocumentOperation.bind(targetCoordinator);
  targetCoordinator.runDocumentOperation = async (...args) => {
    await targetDocumentOperation(...args);
    await afterTargetAuthorization?.();
  };
  const journal = (index: number) =>
    new DocumentReplayJournal(
      path,
      sourceLog.genesisId,
      keys[index],
      stores[index],
      {
        load: (key) => anchors[index].load(key),
        compareAndSwap: async (key, expected, next) => {
          if (index === 1) {
            targetJournalWrites += 1;
            await beforeTargetAcceptance?.();
          }
          return anchors[index].compareAndSwap(key, expected, next);
        },
      },
    );
  let failNativeMerge = false;
  const targetCRDT: typeof mergeCRDT = {
    ...mergeCRDT,
    createDocumentSession(initial) {
      const session = mergeCRDT.createDocumentSession!(initial);
      const prepareMerge = session.prepareMergeSnapshot!.bind(session);
      return Object.assign(session, {
        prepareMergeSnapshot(snapshot: number[]) {
          const plan = prepareMerge(snapshot);
          return {
            ...plan,
            commit() {
              plan.commit();
              if (failNativeMerge) throw new Error('Interrupted native merge');
            },
          };
        },
      });
    },
  };
  const open = async (index: number) => {
    const document = new CoordinatedDocument(
      path,
      [],
      index === 1 ? targetCRDT : mergeCRDT,
      testChanges,
      auth,
      members[index],
      members[index],
      {
        coordinator: coordinators[index],
        authority: logs[index],
        journal: journal(index),
        requireGroupRosterMatch: true,
        enableAuthenticatedCatchUp: true,
      },
    );
    try {
      await document.activate();
      return document;
    } catch (error) {
      await document.close();
      throw error;
    }
  };
  const renew = async () => {
    await sourceCoordinator.createCommit(
      { changes: [] },
      control(3, 'update', members[0]),
    );
    const [delivery] = await flushAndCollect(sourceCoordinator);
    await targetCoordinator.applyCommit(
      delivery.commit!,
      delivery.controlRecord,
      [],
    );
    return sourceLog.signUpdate(
      sourceCoordinator.documentContext,
      roster,
      members[0],
    );
  };
  const pauseTargetAcceptance = (
    stage: 'authorization' | 'anchor' = 'anchor',
  ) => {
    let pause!: (interrupted: boolean) => void;
    let entered!: () => void;
    const ready = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const paused = new Promise<boolean>((resolve) => {
      pause = resolve;
    });
    const hold = async () => {
      entered();
      if (await paused) throw new Error('Interrupted anchor write');
    };
    if (stage === 'anchor') beforeTargetAcceptance = hold;
    else afterTargetAuthorization = hold;
    return {
      ready,
      resume(interrupted = false) {
        beforeTargetAcceptance = undefined;
        afterTargetAuthorization = undefined;
        pause(interrupted);
      },
    };
  };
  const resealCheckpoint = async (
    checkpoint: Uint8Array,
    edit: (value: DocumentCatchUpCheckpoint) => DocumentCatchUpCheckpoint,
    signer: Uint8Array,
  ) => {
    let material!: GroupDocumentEncryptionMaterial;
    let captured!: GroupSecurityDocumentContext;
    await targetCoordinator.runDocumentOperation(
      targetCoordinator.documentContext,
      new Uint8Array(),
      async (documentContext, _input, _signal, work) => {
        captured = documentContext;
        material = await work.deriveEncryptionMaterial(path);
        return { isAuthorizationCurrent: () => true, commit: () => {} };
      },
    );
    const additionalData = documentCatchUpAAD('checkpoint', {
      documentId: path,
      genesisId: targetLog.genesisId,
      authorityHead: targetLog.headId,
      context: captured,
    }) as Uint8Array<ArrayBuffer>;
    const envelope = decodeEncryptedDocumentContent(checkpoint);
    const signed = decodeSignedDocumentContent(
      new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: envelope.nonce as Uint8Array<ArrayBuffer>,
            additionalData,
          },
          material.key,
          envelope.ciphertext as Uint8Array<ArrayBuffer>,
        ),
      ),
    );
    const claimed = decodeDocumentCatchUpCheckpoint(signed.unsigned);
    expect(equalBytes(claimed.controllerId, members[0])).toBe(true);
    const unsigned = encodeDocumentCatchUpCheckpoint(edit(claimed));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData },
      material.key,
      encodeSignedDocumentContent(
        unsigned,
        await auth.sign(unsigned, signer),
      ) as Uint8Array<ArrayBuffer>,
    );
    return encodeEncryptedDocumentContent(
      material.epochTag,
      nonce,
      new Uint8Array(ciphertext),
    );
  };
  const forgeControllerCheckpoint = (checkpoint: Uint8Array) =>
    resealCheckpoint(checkpoint, (value) => value, members[1]);
  const resealAsController = (
    checkpoint: Uint8Array,
    edit: (value: DocumentCatchUpCheckpoint) => DocumentCatchUpCheckpoint,
  ) => resealCheckpoint(checkpoint, edit, members[0]);
  return {
    open,
    renew,
    applyTargetAuthority: (record: Uint8Array) =>
      targetLog.applyUpdate(targetCoordinator, record),
    failTargetMerge: () => {
      failNativeMerge = true;
    },
    restoreTargetCoordinator: async () => {
      const provider = new ContractTestProvider();
      provider.getAuthenticatedMemberIds = async () =>
        members.map((member) => member.slice());
      coordinators[1] = await GroupSecurityCoordinator.restore({
        ...targetConfig,
        provider,
      });
    },
    pauseTargetAcceptance,
    forgeControllerCheckpoint,
    resealAsController,
    targetJournalWrites: () => targetJournalWrites,
  };
}

test('catch-up merges durably, keeps local receipts and rejects conflicting or stale responses', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 10, max: 1000 }),
      fc.boolean(),
      fc.boolean(),
      async (value, overlappingHead, closeBeforeAcceptance) => {
        const fixture = await setup();
        const source = await fixture.open(0);
        let target = await fixture.open(1);
        try {
          await source.change((draft) => {
            draft.push(value);
          });
          await target.change((draft) => {
            draft.push(-value);
          });
          const retiredRequest = await target.createCatchUpRequest();
          const retiredCheckpoint =
            await source.createCatchUpCheckpoint(retiredRequest);
          const renewal = await fixture.renew();
          await expect(
            source.createCatchUpCheckpoint(retiredRequest),
          ).rejects.toThrow();
          await source.applyAuthorityUpdate(renewal);
          await target.applyAuthorityUpdate(renewal);
          await target.close();
          target = await fixture.open(1);
          const incoming = await source.change((draft) => {
            draft.push(value + 1);
          });
          const local = await target.change((draft) => {
            draft.push(-value - 1);
          });
          const superseded = await target.createCatchUpRequest();
          const request = await target.createCatchUpRequest();
          await expect(target.createCatchUpCheckpoint(request)).rejects.toThrow(
            'unrestricted current controller',
          );
          await expect(
            target.applyCatchUpCheckpoint(request),
          ).rejects.toThrow();
          await expect(
            target.applyCatchUpCheckpoint(retiredCheckpoint),
          ).rejects.toThrow();
          await expect(
            target.applyCatchUpCheckpoint(
              await source.createCatchUpCheckpoint(superseded),
            ),
          ).rejects.toThrow('matching request');
          if (overlappingHead) {
            expect(await target.receive(incoming)).toBe(true);
            const next = await source.change((draft) => {
              draft.push(value + 2);
            });
            const conflict = await source.createCatchUpCheckpoint(request);
            await expect(
              target.applyCatchUpCheckpoint(conflict),
            ).rejects.toThrow('accepted head');
            expect(target.document).not.toContain(value + 2);
            expect(await target.receive(next)).toBe(true);
          }
          const checkpoint = await source.createCatchUpCheckpoint(request);
          await expect(target.receive(checkpoint)).rejects.toThrow();
          const forged = await fixture.forgeControllerCheckpoint(checkpoint);
          const unforged = [...target.document];
          const writes = fixture.targetJournalWrites();
          await expect(target.applyCatchUpCheckpoint(forged)).rejects.toThrow(
            'Invalid document catch-up signature',
          );
          expect(target.document).toEqual(unforged);
          expect(fixture.targetJournalWrites()).toBe(writes);
          const previous = [...target.document];
          const anchor = fixture.pauseTargetAcceptance();
          const merging = target.applyCatchUpCheckpoint(checkpoint);
          let closing: Promise<void> | undefined;
          try {
            await Promise.race([
              anchor.ready,
              merging.then(() => {
                throw new Error('Catch-up completed before the anchor');
              }),
            ]);
            expect(target.document).toEqual(previous);
            if (closeBeforeAcceptance) closing = target.close();
          } finally {
            anchor.resume();
          }
          if (closing) {
            await expect(merging).rejects.toThrow();
            await closing;
            target = await fixture.open(1);
          } else {
            await merging;
            expect(target.document).toEqual(
              expect.arrayContaining([value, value + 1, -value, -value - 1]),
            );
          }
          await expect(
            target.applyCatchUpCheckpoint(checkpoint),
          ).rejects.toThrow('No document catch-up request');
          await target.close();
          target = await fixture.open(1);
          expect(target.document).toEqual(
            expect.arrayContaining([value, value + 1, -value, -value - 1]),
          );
          expect(
            await target.receive(
              await source.change((draft) => {
                draft.push(value + 3);
              }),
            ),
          ).toBe(true);
          expect(await source.receive(local)).toBe(true);
          expect(
            await source.receive(
              await target.change((draft) => {
                draft.push(-value - 2);
              }),
            ),
          ).toBe(true);
        } finally {
          await Promise.all([source.close(), target.close()]);
        }
      },
    ),
    {
      seed: 202611241,
      numRuns: 8,
      examples: [
        [20, true, false],
        [40, false, true],
      ],
    },
  );
}, 30_000);

test('an interrupted or retired checkpoint stays private until authorized recovery', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 1, max: 10_000 }),
      fc.constantFrom(
        'interrupted-anchor',
        'failed-merge',
        'rotated-during-anchor',
        'rotated-before-acceptance',
      ),
      async (value, fault) => {
        const fixture = await setup();
        const source = await fixture.open(0);
        let target = await fixture.open(1);
        try {
          await target.change((draft) => draft.push(-value));
          await source.change((draft) => draft.push(value));
          const request = await target.createCatchUpRequest();
          const checkpoint = await source.createCatchUpCheckpoint(request);
          const beforeAcceptance = fault === 'rotated-before-acceptance';
          const anchor = fixture.pauseTargetAcceptance(
            beforeAcceptance ? 'authorization' : 'anchor',
          );
          const applying = target.applyCatchUpCheckpoint(checkpoint);
          let renewal: Uint8Array | undefined;
          let writes = 0;
          try {
            await Promise.race([
              anchor.ready,
              applying.then(() => {
                throw new Error('Catch-up completed before the anchor');
              }),
            ]);
            expect(target.document).toEqual([-value]);
            writes = fixture.targetJournalWrites();
            if (fault === 'failed-merge') fixture.failTargetMerge();
            if (fault === 'rotated-during-anchor' || beforeAcceptance)
              renewal = await fixture.renew();
          } finally {
            anchor.resume(fault === 'interrupted-anchor');
          }
          await expect(applying).rejects.toThrow();
          expect(() => target.document).toThrow();
          if (beforeAcceptance) expect(fixture.targetJournalWrites()).toBe(writes);

          await target.close();
          if (fault === 'failed-merge') await fixture.restoreTargetCoordinator();
          if (renewal) {
            await expect(fixture.open(1)).rejects.toThrow();
            await fixture.applyTargetAuthority(renewal);
          }
          target = await fixture.open(1);
          expect([...target.document].sort((a, b) => a - b)).toEqual(
            beforeAcceptance ? [-value] : [-value, value],
          );
          await expect(target.applyCatchUpCheckpoint(checkpoint)).rejects.toThrow();
        } finally {
          await Promise.all([source.close(), target.close()]);
        }
      },
    ),
    {
      seed: 202611273,
      numRuns: 8,
      examples: [
        [7, 'interrupted-anchor'],
        [8, 'failed-merge'],
        [9, 'rotated-during-anchor'],
        [11, 'rotated-before-acceptance'],
      ],
    },
  );
}, 30_000);

test('catch-up extends a head that missed the tail only with a signed causal suffix', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 1, max: 4 }),
      fc.integer({ min: 1, max: 5 }),
      fc.constantFrom('none', 'drop', 'tamper', 'truncate', 'reorder'),
      async (delivered, missed, forgery) => {
        const fixture = await setup();
        const source = await fixture.open(0);
        const target = await fixture.open(1);
        try {
          const frames: Uint8Array[] = [];
          for (let index = 0; index < delivered + missed; index++)
            frames.push(
              await source.change((draft) => {
                draft.push(1000 + index);
              }),
            );
          for (const frame of frames.slice(0, delivered))
            expect(await target.receive(frame)).toBe(true);
          const request = await target.createCatchUpRequest();
          let checkpoint = await source.createCatchUpCheckpoint(request);
          if (forgery !== 'none')
            checkpoint = await fixture.resealAsController(checkpoint, (value) => {
              const suffixes = [...value.suffixes];
              expect(suffixes).toHaveLength(missed);
              if (forgery === 'drop') suffixes.length = 0;
              if (forgery === 'truncate') suffixes.pop();
              if (forgery === 'reorder') suffixes.reverse();
              if (forgery === 'tamper') {
                const damaged = suffixes[0].slice();
                damaged[damaged.length - 1] ^= 1;
                suffixes[0] = damaged;
              }
              return { ...value, suffixes };
            });
          const rejected =
            forgery === 'drop' ||
            forgery === 'truncate' ||
            forgery === 'tamper' ||
            (forgery === 'reorder' && missed > 1);
          if (rejected) {
            await expect(target.applyCatchUpCheckpoint(checkpoint)).rejects.toThrow(
              'accepted head',
            );
            expect(target.document).not.toContain(1000 + delivered);
            return;
          }
          await target.applyCatchUpCheckpoint(checkpoint);
          expect(target.document).toEqual(
            Array.from({ length: delivered + missed }, (_, index) => 1000 + index),
          );
          for (const frame of frames) expect(await target.receive(frame)).toBe(false);
          expect(
            await target.receive(
              await source.change((draft) => {
                draft.push(2000);
              }),
            ),
          ).toBe(true);
        } finally {
          await Promise.all([source.close(), target.close()]);
        }
      },
    ),
    {
      seed: 202611254,
      numRuns: 10,
      examples: [
        [1, 1, 'none'],
        [2, 3, 'tamper'],
        [1, 2, 'reorder'],
        [3, 2, 'drop'],
      ],
    },
  );
}, 60_000);

test('bounds request receipts and checkpoint suffix frames at the codec boundary', () => {
  const request = catchUpRequest('/catch-up-suffix-limits', 3n);
  const receipt = (index: number) => {
    const memberId = new Uint8Array(32);
    new DataView(memberId.buffer).setUint16(0, index);
    return { memberId, sequence: 1, hash: id(8) };
  };
  const many = Array.from({ length: 257 }, (_, index) => receipt(index));
  expect(() =>
    encodeDocumentCatchUpRequest({ ...request, receipts: many }),
  ).toThrow('receipts');
  expect(
    decodeDocumentCatchUpRequest(
      encodeDocumentCatchUpRequest({ ...request, receipts: many.slice(0, 256) }),
    ).receipts,
  ).toHaveLength(256);
  expect(() =>
    encodeDocumentCatchUpRequest({
      ...request,
      receipts: [receipt(2), receipt(1)],
    }),
  ).toThrow('Noncanonical');
  const checkpoint = (suffixes: Uint8Array[]) => ({
    ...request,
    controllerId: id(6),
    receipts: [],
    suffixes,
    snapshot: new Uint8Array(),
  });
  const frame = new Uint8Array(1024).fill(3);
  const fits = Array.from({ length: 256 }, () => frame);
  const decoded = decodeDocumentCatchUpCheckpoint(
    encodeDocumentCatchUpCheckpoint(checkpoint(fits)),
  );
  expect(decoded.suffixes).toHaveLength(256);
  for (const suffixes of [
    [...fits, frame],
    [new Uint8Array()],
    [new Uint8Array(600 * 1024), new Uint8Array(500 * 1024)],
  ])
    expect(() =>
      encodeDocumentCatchUpCheckpoint(checkpoint(suffixes)),
    ).toThrow();
  const header = () =>
    new DocumentBinaryWriter()
      .fixed(documentCatchUpAAD('checkpoint', request))
      .fixed(request.requesterId)
      .fixed(request.challenge)
      .fixed(id(6))
      .integer(0, 2);
  expect(() =>
    decodeDocumentCatchUpCheckpoint(header().integer(257, 2).finish()),
  ).toThrow('suffix');
  expect(() =>
    decodeDocumentCatchUpCheckpoint(
      header()
        .integer(1, 2)
        .bytes(new Uint8Array())
        .bytes(new Uint8Array())
        .finish(),
    ),
  ).toThrow('suffix');
});
