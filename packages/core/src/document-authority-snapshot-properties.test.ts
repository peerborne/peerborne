import { expect, test } from '@jest/globals';
import fc from 'fast-check';
import { CoordinatedDocument } from './coordinated-document.js';
import { captureDocumentAuthorityLease } from './captured-document-authority.js';
import {
  captureDocumentRoster,
  type CapturedDocumentMember,
} from './policy/authority-capture.js';
import { documentBytesId } from './internal/document-binary.js';
import {
  documentFixture,
  testCRDT,
  testChanges,
} from './__testutils__/coordinated-document.js';

const create = (f: Awaited<ReturnType<typeof documentFixture>>) =>
  new CoordinatedDocument(
    f.authority.documentId,
    [],
    testCRDT,
    testChanges,
    f.auth,
    f.identity,
    f.identity,
    { coordinator: f.coordinator, authority: f.authority },
  );

test('a replaced lease method cannot turn revoked authorization into an accepted local change', async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: -1000, max: 1000 }), async (value) => {
      const f = await documentFixture();
      const capture = f.authority.capture.bind(f.authority);
      let lease!: ReturnType<typeof capture>;
      f.authority.capture = (context) => {
        lease = capture(context);
        return lease;
      };
      const sign = f.auth.sign;
      let originalGuardRejected = false;
      f.auth.sign = async (bytes, key) => {
        const originalGuard = lease.isCurrent;
        f.authority.role = 1;
        originalGuardRejected = originalGuard() === false;
        lease.isCurrent = () => true;
        return sign(bytes, key);
      };
      const document = create(f);
      try {
        await expect(
          document.change((values) => {
            values.push(value);
          }),
        ).rejects.toThrow();
        expect(originalGuardRejected).toBe(true);
        expect(document.document).toEqual([]);
        f.auth.sign = sign;
        f.authority.role = 3;
        await document.change((values) => {
          values.push(value + 1);
        });
        expect(document.document).toEqual([value + 1]);
      } finally {
        await document.close();
      }
    }),
    { seed: 2011401, numRuns: 12 },
  );
});

test('capturing genuine member bytes does not invoke an overridden slice property', async () => {
  await fc.assert(
    fc.asyncProperty(fc.boolean(), async (getter) => {
      const f = await documentFixture();
      const capture = f.authority.capture.bind(f.authority);
      const memberId = f.identity.slice();
      let calls = 0;
      const forbidden = () => {
        calls++;
        throw new Error('Synthetic untrusted slice invocation');
      };
      Object.defineProperty(
        memberId,
        'slice',
        getter ? { get: forbidden } : { value: forbidden },
      );
      f.authority.capture = (context) => {
        const lease = capture(context);
        lease.members[0].memberId = memberId;
        return lease;
      };
      const document = create(f);
      try {
        await expect(document.activate()).resolves.toBeUndefined();
        expect(calls).toBe(0);
      } finally {
        await document.close();
      }
    }),
    { seed: 2011402, numRuns: 12 },
  );
});

test('the bounded own roster entries are authoritative without invoking a custom array iterator', async () => {
  await fc.assert(
    fc.asyncProperty(fc.boolean(), async (getter) => {
      const f = await documentFixture();
      const capture = f.authority.capture.bind(f.authority);
      let calls = 0;
      const forbidden = () => {
        calls++;
        throw new Error('Synthetic untrusted roster iterator');
      };
      f.authority.capture = (context) => {
        const lease = capture(context);
        const original = lease.members[0];
        function* inflatedIterator() {
          calls++;
          yield original;
          for (let index = 1; index <= 512; index++) {
            const memberId = original.memberId.slice();
            memberId[30] ^= index >>> 8;
            memberId[31] ^= index & 255;
            yield { memberId, publicKey: `synthetic-key-${index}`, role: 1 };
          }
        }
        Object.defineProperty(
          lease.members,
          Symbol.iterator,
          getter ? { get: forbidden } : { value: inflatedIterator },
        );
        return lease;
      };
      const document = create(f);
      try {
        await expect(document.activate()).resolves.toBeUndefined();
        expect(calls).toBe(0);
      } finally {
        await document.close();
      }
    }),
    { seed: 2011403, numRuns: 12 },
  );
});

test.each(['activate', 'publicKeys', 'receive'] as const)(
  '%s keeps the original authority guard across asynchronous provider calls',
  async (boundary) => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: -1000, max: 1000 }), async (value) => {
        const f = await documentFixture();
        const sender = create(f);
        const receiver = create(f);
        try {
          const frame = await sender.change((values) => values.push(value));
          const capture = f.authority.capture.bind(f.authority);
          let lease!: ReturnType<typeof capture>;
          f.authority.capture = (context) => {
            lease = capture(context);
            return lease;
          };
          let originalGuardRejected = false;
          const replace = () => {
            const originalGuard = lease.isCurrent;
            f.authority.role = 1;
            originalGuardRejected = originalGuard() === false;
            lease.isCurrent = () => true;
          };
          const serialize = f.auth.serializePublicKey;
          const deserialize = f.auth.deserializePublicKey;
          const verify = f.auth.verify;
          if (boundary === 'activate') {
            f.auth.serializePublicKey = async (key) => {
              replace();
              return serialize(key);
            };
          } else if (boundary === 'publicKeys') {
            f.auth.deserializePublicKey = async (key) => {
              replace();
              return deserialize(key);
            };
          } else {
            f.auth.verify = async (bytes, key, signature) => {
              replace();
              return verify(bytes, key, signature);
            };
          }
          await expect(
            boundary === 'activate'
              ? receiver.activate()
              : boundary === 'publicKeys'
                ? receiver.publicKeys(false)
                : receiver.receive(frame),
          ).rejects.toThrow();
          expect(originalGuardRejected).toBe(true);
          expect(receiver.document).toEqual([]);
          f.auth.serializePublicKey = serialize;
          f.auth.deserializePublicKey = deserialize;
          f.auth.verify = verify;
          f.authority.role = 3;
          await expect(receiver.receive(frame)).resolves.toBe(true);
          await expect(receiver.receive(frame)).resolves.toBe(false);
          expect(receiver.document).toEqual([value]);
        } finally {
          await receiver.close();
          await sender.close();
        }
      }),
      { seed: 2011404, numRuns: 12 },
    );
  },
);

function nativeLease() {
  const memberId = new Uint8Array(32).fill(7);
  return {
    headId: new Uint8Array(32).fill(11),
    members: [{ memberId, publicKey: 'synthetic-public-key', role: 3 }],
    alive: true,
    isCurrent() {
      return this.alive;
    },
  };
}

test('required authority fields reject accessors and inherited data without invoking getters', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(
        'isCurrent',
        'members',
        'headId',
        '0',
        'memberId',
        'publicKey',
        'role',
      ),
      fc.boolean(),
      (field, inherited) => {
        const lease = nativeLease();
        const localId = documentBytesId(lease.members[0].memberId);
        const target = ['isCurrent', 'members', 'headId'].includes(field)
          ? lease
          : field === '0'
            ? lease.members
            : lease.members[0];
        const original = Object.getOwnPropertyDescriptor(target, field)!.value;
        let reads = 0;
        if (inherited) {
          const prototype = Object.create(Object.getPrototypeOf(target));
          Object.defineProperty(prototype, field, { value: original });
          Reflect.deleteProperty(target, field);
          Object.setPrototypeOf(target, prototype);
        } else {
          Object.defineProperty(target, field, {
            get: () => {
              reads++;
              throw new Error('Synthetic untrusted authority getter');
            },
          });
        }
        expect(() => captureDocumentAuthorityLease(lease, localId)).toThrow();
        expect(reads).toBe(0);
      },
    ),
    { seed: 2011405, numRuns: 100 },
  );
});

test('detached scalar roster maps agree with an independent tuple oracle', () => {
  const member = fc.record({
    identity: fc.integer({ min: 0, max: 7 }),
    idLength: fc.constantFrom(63, 64, 65),
    keyLength: fc.constantFrom(0, 1, 12, 16384, 16385),
    role: fc.constantFrom(
      Number.MIN_SAFE_INTEGER,
      0,
      1,
      2,
      3,
      4,
      Number.MAX_SAFE_INTEGER,
    ),
  });
  fc.assert(
    fc.property(
      fc.oneof(
        fc.array(member, { maxLength: 20 }),
        fc.uniqueArray(
          fc.record({
            identity: fc.integer({ min: 0, max: 7 }),
            idLength: fc.constant(64),
            keyLength: fc.constantFrom(1, 12, 16384),
            role: fc.integer({ min: 1, max: 3 }),
          }),
          { maxLength: 8, selector: (entry) => entry.identity },
        ),
      ),
      fc.integer({ min: 0, max: 8 }),
      (input, local) => {
        const entries = input.map(
          (entry): CapturedDocumentMember => ({
            id: entry.identity.toString().padStart(entry.idLength, '0'),
            publicKey: 'k'.repeat(entry.keyLength),
            role: entry.role,
          }),
        );
        const localId = local.toString().padStart(64, '0');
        const expected =
          input.length > 0 &&
          input.some(
            (entry) => entry.idLength === 64 && entry.identity === local,
          ) &&
          input.every(
            (entry) =>
              entry.idLength === 64 &&
              entry.keyLength > 0 &&
              entry.keyLength <= 16384 &&
              [1, 2, 3].includes(entry.role),
          ) &&
          input.every((entry, index) =>
            input
              .slice(0, index)
              .every((previous) => previous.identity !== entry.identity),
          );
        const first = captureDocumentRoster(entries, localId);
        const second = captureDocumentRoster(entries, localId);
        expect(first.valid).toBe(expected);
        expect(second.valid).toBe(expected);
        expect([...first.members]).toEqual(
          expected ? entries.map((entry) => [entry.id, entry]) : [],
        );
        expect(first.members).not.toBe(second.members);
        const before = [...second.members];
        first.members.clear();
        entries.reverse();
        expect([...second.members]).toEqual(before);
      },
    ),
    { seed: 2011406, numRuns: 200 },
  );
});

test('native captures own their bytes and scalar roster while retaining the original receiver-bound strict guard', () => {
  fc.assert(
    fc.property(
      fc.constantFrom<unknown>(
        true,
        false,
        1,
        'true',
        null,
        undefined,
        new Boolean(true),
      ),
      fc.integer({ min: 0, max: 255 }),
      (answer, changedByte) => {
        const lease = nativeLease();
        let calls = 0;
        lease.isCurrent = function () {
          expect(this).toBe(lease);
          calls++;
          return (this.alive ? answer : false) as boolean;
        };
        const localId = documentBytesId(lease.members[0].memberId);
        const first = captureDocumentAuthorityLease(lease, localId);
        const second = captureDocumentAuthorityLease(lease, localId);
        lease.headId.fill(changedByte);
        lease.members[0].memberId.fill(changedByte);
        lease.members[0].publicKey = 'changed';
        lease.members[0].role = 1;
        lease.members.length = 0;
        lease.isCurrent = () => true;
        expect(first.headId).toEqual(new Uint8Array(32).fill(11));
        expect([...first.members.values()]).toEqual([
          { id: localId, publicKey: 'synthetic-public-key', role: 3 },
        ]);
        expect(first.isCurrent()).toBe(answer === true);
        expect(second.isCurrent()).toBe(answer === true);
        lease.alive = false;
        expect(first.isCurrent()).toBe(false);
        expect(second.isCurrent()).toBe(false);
        expect(calls).toBe(4);
        first.headId.fill(99);
        (first.members as Map<string, CapturedDocumentMember>).clear();
        expect(second.headId).toEqual(new Uint8Array(32).fill(11));
        expect(second.members.size).toBe(1);
      },
    ),
    { seed: 2011407, numRuns: 100 },
  );
});

test('roster bounds reject before reading entries and admit exactly 256 own entries', () => {
  fc.assert(
    fc.property(
      fc.constantFrom(0, 1, 256, 257),
      fc.boolean(),
      (count, sparse) => {
        const lease = nativeLease();
        const localId = documentBytesId(lease.members[0].memberId);
        lease.members = Array.from({ length: count }, (_, index) => {
          const memberId = new Uint8Array(32).fill(7);
          memberId[31] = index;
          return { memberId, publicKey: `key-${index}`, role: 3 };
        });
        const expectedLocalId =
          count > 0 ? documentBytesId(lease.members[0].memberId) : localId;
        let reads = 0;
        if (count === 0 || count > 256) {
          Object.defineProperty(lease, 'headId', {
            get: () => {
              reads++;
              throw new Error('Synthetic premature head read');
            },
          });
        } else if (sparse) {
          Reflect.deleteProperty(lease.members, 0);
        }
        if (count === 0 || count > 256 || sparse) {
          expect(() =>
            captureDocumentAuthorityLease(lease, expectedLocalId),
          ).toThrow();
        } else {
          const captured = captureDocumentAuthorityLease(
            lease,
            expectedLocalId,
          );
          expect(captured.members.size).toBe(count);
          expect(captured.members.has(expectedLocalId)).toBe(true);
        }
        expect(reads).toBe(0);
      },
    ),
    { seed: 2011408, numRuns: 48 },
  );
});
