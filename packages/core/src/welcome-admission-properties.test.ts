import { expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import {
  PendingWelcomeBuffer,
  PENDING_WELCOME_MAX_BODY_BYTES,
  PENDING_WELCOMES_MAX_ENTRIES,
  PENDING_WELCOMES_MAX_RETAINED_BYTES,
} from './pending-welcome-buffer.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import type { SyncMessageSerializer } from './sync-message-serializer.js';
import * as byteUtilities from './utils.js';
import * as admissionPolicy from './policy/welcome-admission.js';

const welcome = (): CRDTSyncMessage<Uint8Array> => ({
  documentId: '/welcome/admission/property',
  signatureContext: 'beekem-welcome-v2',
  welcomeEpochId: new Uint8Array(32).fill(1),
  welcomeRecipient: 'synthetic-recipient',
  welcomeRecipientKemPublicKey: new Uint8Array(65).fill(4),
  eciesSealed: new Uint8Array([1, 2, 3]),
  signature: 'synthetic-signature',
});

test('unverified floods cannot evict authenticated Welcomes at the entry limit', () => {
  fc.assert(
    fc.property(
      fc.array(fc.integer({ min: 0, max: 255 }), {
        minLength: PENDING_WELCOMES_MAX_ENTRIES,
        maxLength: PENDING_WELCOMES_MAX_ENTRIES,
      }),
      fc.integer({ min: 1, max: 40 }),
      (values, flood) => {
        const buffer = new PendingWelcomeBuffer();
        values.forEach((value, index) =>
          buffer.store(
            `trusted-${index}`,
            new Uint8Array([value]),
            index,
            true,
          ),
        );
        const before = buffer.keysSnapshot();
        for (let index = 0; index < flood; index++) {
          expect(
            buffer.store(
              `hostile-${index}`,
              new Uint8Array([255]),
              100 + index,
              false,
            ),
          ).toEqual({
            stored: false,
            replaced: false,
            evictedKeys: [],
          });
        }
        expect(buffer.keysSnapshot()).toEqual(before);
        values.forEach((value, index) => {
          const retained = buffer.get(`trusted-${index}`)!;
          expect(retained.authenticated).toBe(true);
          expect(retained.body[0]).toBe(value);
          expect(retained.bufferedAtMs).toBe(index);
        });
        expect(buffer.retainedBytes).toBe(values.length);
      },
    ),
    { seed: 2011310, numRuns: 25 },
  );
});

test('unverified byte pressure cannot displace authenticated bodies', () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 255 }), (value) => {
      const buffer = new PendingWelcomeBuffer();
      const body = new Uint8Array(PENDING_WELCOME_MAX_BODY_BYTES).fill(value);
      buffer.store('trusted-a', body, 0, true);
      buffer.store('trusted-b', body, 1, true);
      expect(buffer.retainedBytes).toBe(PENDING_WELCOMES_MAX_RETAINED_BYTES);
      expect(
        buffer.store('hostile', new Uint8Array([value]), 2, false).stored,
      ).toBe(false);
      expect(buffer.keysSnapshot()).toEqual(['trusted-a', 'trusted-b']);
      expect(buffer.retainedBytes).toBe(PENDING_WELCOMES_MAX_RETAINED_BYTES);
    }),
    { seed: 2011311, numRuns: 3 },
  );
});

test('native authentication and key values are validated before admitting entries', () => {
  fc.assert(
    fc.property(
      fc.constantFrom<unknown>(
        'false',
        1,
        {},
        [],
        new Boolean(false),
        null,
        undefined,
      ),
      fc.boolean(),
      (malformed, invalidKey) => {
        const buffer = new PendingWelcomeBuffer();
        buffer.store('trusted', new Uint8Array([1]), 0, true);
        const key = invalidKey
          ? typeof malformed === 'string'
            ? new String(malformed)
            : malformed
          : 'trusted';
        const authenticated = invalidKey ? true : malformed;
        expect(() =>
          buffer.store(
            key as string,
            new Uint8Array([2]),
            1,
            authenticated as boolean,
          ),
        ).toThrow(TypeError);
        let reflections = 0;
        const message = new Proxy(welcome(), {
          ownKeys: () => {
            reflections++;
            throw new Error('Invalid admission must not inspect a message');
          },
        });
        const serializer = {} as SyncMessageSerializer<Uint8Array>;
        expect(() =>
          buffer.storeMessage(
            key as string,
            message,
            serializer,
            1,
            authenticated as boolean,
          ),
        ).toThrow(TypeError);
        expect(reflections).toBe(0);
        expect(buffer.keysSnapshot()).toEqual(['trusted']);
        expect(buffer.get('trusted')!.body[0]).toBe(1);
        expect(buffer.retainedBytes).toBe(1);
      },
    ),
    { seed: 2011312, numRuns: 30 },
  );
});

test('a preparation failure cannot commit a tentative replacement or eviction', () => {
  fc.assert(
    fc.property(
      fc.boolean(),
      fc.integer({ min: 0, max: 255 }),
      fc.constantFrom('copy', 'projection', 'insertion'),
      (replace, value, stage) => {
        const buffer = new PendingWelcomeBuffer();
        for (let index = 0; index < PENDING_WELCOMES_MAX_ENTRIES; index++)
          buffer.store(
            `trusted-${index}`,
            new Uint8Array([value]),
            index,
            true,
          );
        const before = buffer.keysSnapshot();
        const preparation =
          stage === 'copy'
            ? jest.spyOn(byteUtilities, 'copyUnsharedUint8Array')
            : stage === 'projection'
              ? jest.spyOn(admissionPolicy, 'retainPendingWelcomeValues')
              : jest.spyOn(admissionPolicy, 'insertPendingWelcomeValue');
        preparation.mockImplementation(() => {
          throw new RangeError('Synthetic preparation failure');
        });
        try {
          expect(() =>
            buffer.store(
              replace ? 'trusted-0' : 'fresh',
              new Uint8Array([2, 3]),
              100,
              true,
            ),
          ).toThrow('Synthetic preparation failure');
          expect(preparation.mock.calls.length).toBe(1);
        } finally {
          preparation.mockRestore();
        }
        expect(buffer.keysSnapshot()).toEqual(before);
        expect(buffer.retainedBytes).toBe(PENDING_WELCOMES_MAX_ENTRIES);
        for (let index = 0; index < PENDING_WELCOMES_MAX_ENTRIES; index++) {
          expect(buffer.get(`trusted-${index}`)!.body[0]).toBe(value);
          expect(buffer.get(`trusted-${index}`)!.authenticated).toBe(true);
          expect(buffer.get(`trusted-${index}`)!.bufferedAtMs).toBe(index);
        }
      },
    ),
    {
      seed: 2011315,
      numRuns: 20,
      examples: [
        [false, 1, 'copy'],
        [true, 2, 'projection'],
        [false, 3, 'insertion'],
      ],
    },
  );
});

test('admission is checked again after a serializer changes the buffer', () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 255 }), (value) => {
      const buffer = new PendingWelcomeBuffer();
      let serializations = 0;
      const serializer = {
        serializeSyncMessage: () => {
          serializations++;
          for (let index = 0; index < PENDING_WELCOMES_MAX_ENTRIES; index++)
            buffer.store(
              `trusted-${index}`,
              new Uint8Array([value]),
              index,
              true,
            );
          return new Uint8Array([value]);
        },
      } as unknown as SyncMessageSerializer<Uint8Array>;
      expect(
        buffer.storeMessage('hostile', welcome(), serializer, 100, false),
      ).toEqual({ stored: false, replaced: false, evictedKeys: [] });
      expect(serializations).toBe(1);
      expect(buffer.keysSnapshot()).toEqual(
        Array.from(
          { length: PENDING_WELCOMES_MAX_ENTRIES },
          (_, index) => `trusted-${index}`,
        ),
      );
      expect(buffer.retainedBytes).toBe(PENDING_WELCOMES_MAX_ENTRIES);
    }),
    { seed: 2011316, numRuns: 12 },
  );
});

test('rejected unverified duplicates do not copy body bytes', () => {
  fc.assert(
    fc.property(fc.integer({ min: 1, max: 4096 }), (size) => {
      const buffer = new PendingWelcomeBuffer();
      buffer.store('trusted', new Uint8Array([1]), 0, true);
      const copy = jest.spyOn(byteUtilities, 'copyUnsharedUint8Array');
      try {
        expect(
          buffer.store('trusted', new Uint8Array(size), 1, false).stored,
        ).toBe(false);
        expect(copy.mock.calls.length).toBe(0);
      } finally {
        copy.mockRestore();
      }
    }),
    { seed: 2011313, numRuns: 12 },
  );
});

test('capacity-rejected messages are dropped before snapshotting or serialization', () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 255 }), (value) => {
      const buffer = new PendingWelcomeBuffer();
      for (let index = 0; index < PENDING_WELCOMES_MAX_ENTRIES; index++)
        buffer.store(`trusted-${index}`, new Uint8Array([value]), index, true);
      let reflections = 0;
      const message = new Proxy(welcome(), {
        ownKeys: () => {
          reflections++;
          throw new Error('Discarded messages must not be inspected');
        },
      });
      let serializations = 0;
      const serializer = {
        serializeSyncMessage: () => {
          serializations++;
          return new Uint8Array([value]);
        },
      } as unknown as SyncMessageSerializer<Uint8Array>;
      expect(
        buffer.storeMessage('hostile', message, serializer, 100, false).stored,
      ).toBe(false);
      expect(reflections).toBe(0);
      expect(serializations).toBe(0);
      expect(buffer.size).toBe(PENDING_WELCOMES_MAX_ENTRIES);
      expect(buffer.retainedBytes).toBe(PENDING_WELCOMES_MAX_ENTRIES);
      expect(buffer.keysSnapshot()).toEqual(
        Array.from(
          { length: PENDING_WELCOMES_MAX_ENTRIES },
          (_, index) => `trusted-${index}`,
        ),
      );
    }),
    { seed: 2011314, numRuns: 12 },
  );
});
