import { describe, expect, jest, test } from '@jest/globals';
import fc from 'fast-check';
import { CoordinatedDocument } from './coordinated-document.js';
import {
  documentFixture,
  testCRDT,
  testChanges,
  TestDocumentAuthority,
} from './__testutils__/coordinated-document.js';
import { control } from './__testutils__/group-security-coordinator.js';

const create = (
  f: Awaited<ReturnType<typeof documentFixture>>,
  path = f.authority.documentId,
) =>
  new CoordinatedDocument(
    path,
    [],
    testCRDT,
    testChanges,
    f.auth,
    f.identity,
    f.identity,
    { coordinator: f.coordinator, authority: f.authority },
  );

describe('coordinated document runtime boundaries', () => {
  test('authenticates exact prefixes, suppresses replay, and rejects damaged or cross-document ciphertext', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.integer({ min: -10000, max: 10000 }), {
          minLength: 1,
          maxLength: 18,
        }),
        async (values) => {
          const f = await documentFixture(),
            a = create(f),
            b = create(f);
          await a.activate();
          await b.activate();
          const frames: Uint8Array[] = [];
          for (const value of values)
            frames.push(
              await a.change((doc) => {
                doc.push(value);
              }),
            );
          if (frames.length > 1)
            await expect(b.receive(frames[1])).rejects.toThrow('prefix');
          for (let index = 0; index < frames.length; index++) {
            expect(await b.receive(frames[index])).toBe(true);
            expect(await b.receive(frames[index])).toBe(false);
            const bad = frames[index].slice();
            bad[bad.length - 1] ^= 1;
            await expect(b.receive(bad)).rejects.toThrow();
            expect(b.document).toEqual(values.slice(0, index + 1));
          }
          const other = {
            authority: new TestDocumentAuthority(
              '/other-document',
              f.coordinator.documentContext,
              f.identity,
            ),
          };
          // Deliberately reuse the same exporter and signing material across documents.
          const c = new CoordinatedDocument(
            '/other-document',
            [],
            testCRDT,
            testChanges,
            f.auth,
            f.identity,
            f.identity,
            { coordinator: f.coordinator, authority: other.authority },
          );
          await expect(c.receive(frames[0])).rejects.toThrow();
          expect(c.document).toEqual([]);
          await a.close();
          await b.close();
          await c.close();
        },
      ),
      { seed: 2011131, numRuns: 35 },
    );
  });

  test('discards staged changes if authority or the authenticated epoch changes during signing', async () => {
    for (const action of ['role', 'epoch', 'signer-error'] as const) {
      const f = await documentFixture(),
        a = create(f);
      const nativeSign = f.auth.sign;
      f.auth.sign = async (bytes, key) => {
        if (action === 'role') f.authority.role = 1;
        if (action === 'epoch')
          await f.coordinator.createCommit(
            { changes: [] },
            control(2, 'update', f.identity),
          );
        if (action === 'signer-error')
          throw new Error('Injected signer failure');
        return nativeSign(bytes, key);
      };
      await expect(
        a.change((doc) => {
          doc.push(1);
        }),
      ).rejects.toThrow();
      expect(a.document).toEqual([]);
      f.auth.sign = nativeSign;
      f.authority.role = 3;
      f.authority.context = f.coordinator.documentContext;
      expect(
        await a.change((doc) => {
          doc.push(2);
        }),
      ).toBeInstanceOf(Uint8Array);
      expect(a.document).toEqual([2]);
      await a.close();
    }
  });

  test('bounds queued work before retaining input or calling a second CRDT preparation', async () => {
    const f = await documentFixture(),
      a = create(f);
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const nativeSign = f.auth.sign;
    let calls = 0;
    f.auth.sign = async (bytes, key) => {
      calls++;
      await waiting;
      return nativeSign(bytes, key);
    };
    const pending = Array.from({ length: 16 }, (_, value) =>
      a.change((doc) => {
        doc.push(value);
      }),
    );
    await expect(
      a.change((doc) => {
        doc.push(17);
      }),
    ).rejects.toMatchObject({ code: 'capacity-exceeded' });
    for (let turn = 0; !calls && turn < 100; turn++)
      await new Promise((resolve) => setImmediate(resolve));
    expect(a.document).toEqual([]);
    expect(calls).toBe(1);
    release();
    await Promise.all(pending);
    expect(a.document).toHaveLength(16);
    await a.close();
  });
});
