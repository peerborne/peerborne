import {
  afterAll,
  beforeAll,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import fc from 'fast-check';
import {
  createUCAN,
  serializeUCAN,
  deserializeUCAN,
  validateUCANChain,
  type UCAN,
} from './ucan.js';

const abilities = ['/doc/admin', '/doc/write', '/doc/read'];
let keys: CryptoKeyPair[];
const now = 1_700_000_000_000;

beforeAll(async () => {
  jest.spyOn(Date, 'now').mockReturnValue(now);
  keys = await Promise.all(
    Array.from({ length: 6 }, () =>
      crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, [
        'sign',
        'verify',
      ]),
    ),
  );
});
afterAll(() => {
  jest.restoreAllMocks();
});

function resolve(issuer: string): Promise<CryptoKey> {
  return Promise.resolve(keys[Number(issuer.slice('member'.length))].publicKey);
}

describe('generated signed UCAN delegation histories', () => {
  test('accepts attenuated chains, preserves canonical tokens, and enforces depth and signature boundaries', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.integer({ min: 0, max: 2 }), {
          minLength: 1,
          maxLength: 5,
        }),
        async (levels) => {
          const attenuation = [...levels].sort();
          let token: UCAN | undefined;
          for (let index = 0; index < attenuation.length; index++) {
            token = await createUCAN(
              keys[index].privateKey,
              'member' + index,
              'member' + (index + 1),
              [
                {
                  resource: '/documents/generated',
                  ability: abilities[attenuation[index]],
                },
              ],
              token ? [serializeUCAN(token)] : [],
            );
          }
          const encoded = serializeUCAN(token!);
          expect(serializeUCAN(deserializeUCAN(encoded)) === encoded).toBe(
            true,
          );
          expect(
            (
              await validateUCANChain(
                token!,
                keys[0].publicKey,
                resolve,
                attenuation.length,
              )
            ).valid,
          ).toBe(true);
          expect(
            (
              await validateUCANChain(
                token!,
                keys[0].publicKey,
                resolve,
                attenuation.length - 1,
              )
            ).valid,
          ).toBe(false);
          const corrupted = {
            ...token!,
            signature:
              (token!.signature[0] === 'A' ? 'B' : 'A') +
              token!.signature.slice(1),
          };
          expect(
            (await validateUCANChain(corrupted, keys[0].publicKey, resolve))
              .valid,
          ).toBe(false);
        },
      ),
      { seed: 9540, numRuns: 70 },
    );
  }, 30_000);

  test('valid signatures cannot broaden permissions, change resources, or bypass token lifetimes', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 2 }),
        fc.boolean(),
        async (parentLevel, differentResource) => {
          const parent = await createUCAN(
            keys[0].privateKey,
            'member0',
            'member1',
            [{ resource: '/documents/a', ability: abilities[parentLevel] }],
          );
          const child = await createUCAN(
            keys[1].privateKey,
            'member1',
            'member2',
            [
              {
                resource: differentResource ? '/documents/b' : '/documents/a',
                ability: differentResource
                  ? abilities[parentLevel]
                  : '/doc/admin',
              },
            ],
            [serializeUCAN(parent)],
          );
          expect(
            (await validateUCANChain(child, keys[0].publicKey, resolve)).valid,
          ).toBe(false);
          for (const options of [
            { expiration: now / 1000 - 1 },
            { notBefore: now / 1000 + 1 },
          ]) {
            const timed = await createUCAN(
              keys[0].privateKey,
              'member0',
              'member1',
              [{ resource: '/documents/a', ability: '/doc/read' }],
              [],
              options,
            );
            expect(
              (await validateUCANChain(timed, keys[0].publicKey, resolve))
                .valid,
            ).toBe(false);
          }
        },
      ),
      { seed: 9541, numRuns: 70 },
    );
  }, 30_000);
});
