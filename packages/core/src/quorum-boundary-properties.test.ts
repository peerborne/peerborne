import {
  afterEach,
  beforeEach,
  describe,
  expect,
  jest,
  test,
} from '@jest/globals';
import fc from 'fast-check';
import { decideLoadQuorum, LoadQuorumFailedError } from './load-quorum.js';
import {
  runLoadQuorum,
  type LoadQuorumProbeResult,
} from './load-quorum-orchestrator.js';

const hash = (value: number) => new Uint8Array(32).fill(value);
const hex = (value: number) => Buffer.from(hash(value)).toString('hex');

describe('generated native quorum boundaries', () => {
  beforeEach(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => jest.restoreAllMocks());

  test('counts only the first usable vote of each peer and preserves the exact digest cohort', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            peer: fc.constantFrom(
              '',
              '__proto__',
              'constructor',
              'a',
              'b',
              'c',
              '\ud800',
            ),
            digest: fc.integer({ min: 0, max: 3 }),
            usable: fc.boolean(),
          }),
          { maxLength: 80 },
        ),
        fc.integer({ min: 1, max: 20 }),
        (votes, threshold) => {
          const first = votes.filter(
            (vote, index) =>
              vote.usable &&
              !votes
                .slice(0, index)
                .some((prior) => prior.usable && prior.peer === vote.peer),
          );
          const digests = [...new Set(first.map((vote) => vote.digest))];
          const counts = digests.map(
            (digest) => first.filter((vote) => vote.digest === digest).length,
          );
          const winners = digests.filter(
            (_, index) => counts[index] >= threshold,
          );
          const decision = decideLoadQuorum(
            votes.map((vote) => ({
              peerId: vote.peer,
              hash: vote.usable ? hash(vote.digest) : null,
            })),
            threshold,
          );
          expect(decision.respondingCount).toBe(first.length);
          expect(decision.effectiveQ).toBe(threshold);
          if (winners.length === 1) {
            expect(decision).toMatchObject({
              ok: true,
              winningHashHex: hex(winners[0]),
              agreeingPeerIds: first
                .filter((vote) => vote.digest === winners[0])
                .map((vote) => vote.peer),
            });
          } else {
            expect(decision).toMatchObject({
              ok: false,
              reason:
                votes.length === 0
                  ? 'no-peers-queried'
                  : winners.length > 1
                    ? 'conflicting-quorum'
                    : first.length < threshold
                      ? 'insufficient-responses'
                      : 'no-agreement',
            });
            if (decision.ok) throw new Error('expected rejected quorum');
            expect([...decision.agreement]).toEqual(
              digests.map((digest, index) => [hex(digest), counts[index]]),
            );
          }
        },
      ),
      { seed: 9801, numRuns: 800 },
    );
  });

  test('retains the originally probed cohort when the caller replaces peers during a round', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 2, max: 8 }),
        fc.nat(),
        fc.boolean(),
        async (size, position, rename) => {
          const original = Array.from({ length: size }, (_, index) => ({
            id: `peer-${index}`,
            index,
          }));
          const peers = [...original];
          let release!: () => void;
          const gate = new Promise<void>((resolve) => {
            release = resolve;
          });
          let lookups = 0;
          const probed: typeof peers = [];
          const round = runLoadQuorum({
            peers,
            documentPath: '/synthetic/cohort',
            config: { k: size, q: size },
            peerIdOf: (peer) => {
              lookups++;
              return peer.id;
            },
            probeFn: async (peer) => {
              probed.push(peer);
              await gate;
              return {
                hash: hash(1),
                signerAuthority: `authority-${peer.index}`,
              };
            },
          });
          const slot = position % size;
          peers[slot] = { id: original[slot].id, index: 1000 };
          peers.push({ id: original[slot].id, index: 1001 });
          if (rename)
            original.forEach((peer) => {
              peer.id = `changed-${peer.index}`;
            });
          release();
          const result = await round;
          expect(probed).toEqual(original);
          if (!('ok' in result)) throw new Error('expected quorum');
          expect(result.narrowedPeers).toHaveLength(size);
          result.narrowedPeers.forEach((peer, index) =>
            expect(peer).toBe(original[index]),
          );
          expect(lookups).toBe(size);
        },
      ),
      { seed: 9802, numRuns: 100, examples: [[2, 0, false]] },
    );
  });

  test('never reads or logs rejected probe error details', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ maxLength: 50 }),
        fc.boolean(),
        async (suffix, single) => {
          const privateFixture = `synthetic-private-payload/${suffix}`;
          let reads = 0;
          const error = Object.defineProperty(
            new Error(privateFixture),
            'name',
            {
              get: () => {
                reads++;
                return privateFixture;
              },
            },
          );
          jest.mocked(console.warn).mockClear();
          const result = await runLoadQuorum({
            peers: single ? ['a'] : ['a', 'b', 'c'],
            peerIdOf: (peer) => peer,
            probeFn: async () => {
              throw error;
            },
            documentPath: '/synthetic/error',
            config: { k: single ? 1 : 3, allowSinglePeer: single },
          }).catch((failure: unknown) => failure);
          expect(result).toBeInstanceOf(LoadQuorumFailedError);
          expect((result as LoadQuorumFailedError).reason).toBe(
            'insufficient-responses',
          );
          expect(
            jest.mocked(console.warn).mock.calls.flat().map(String).join('\n'),
          ).not.toContain(privateFixture);
          expect(reads).toBe(0);
        },
      ),
      {
        seed: 9803,
        numRuns: 100,
        examples: [
          ['', false],
          ['', true],
        ],
      },
    );
  });

  test('matches an independent authority tally under reordered probes and hostile response ownership', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            kind: fc.constantFrom(
              'valid',
              'offset',
              'null',
              'throw',
              'short',
              'shared',
              'hash-getter',
              'authority-getter',
            ),
            authority: fc.integer({ min: 0, max: 6 }),
            digest: fc.integer({ min: 0, max: 3 }),
            order: fc.nat(),
          }),
          { maxLength: 14 },
        ),
        fc.integer({ min: 1, max: 16 }),
        fc.nat(),
        fc.boolean(),
        fc.boolean(),
        async (specs, configuredK, floorSeed, explicit, allowSinglePeer) => {
          const peers = specs.map((_, index) => ({ id: `p${index}`, index }));
          const k = Math.min(specs.length, configuredK);
          const configuredQ = explicit
            ? 1 + (floorSeed % configuredK)
            : undefined;
          const q = configuredQ ?? Math.floor(k / 2) + 1;
          const good = (index: number) =>
            ['valid', 'offset'].includes(specs[index].kind);
          const valid = specs
            .slice(0, k)
            .map((_, index) => index)
            .filter(good);
          const first = valid.filter(
            (index, position) =>
              !valid
                .slice(0, position)
                .some(
                  (prior) => specs[prior].authority === specs[index].authority,
                ),
          );
          const equivocating = valid.some((index) =>
            valid.some(
              (other) =>
                specs[index].authority === specs[other].authority &&
                specs[index].digest !== specs[other].digest,
            ),
          );
          const winningDigests = [
            ...new Set(first.map((index) => specs[index].digest)),
          ].filter(
            (digest) =>
              first.filter((index) => specs[index].digest === digest).length >=
              q,
          );
          let reason: string | undefined;
          if (k > 0) {
            if (configuredQ !== undefined && configuredQ > k)
              reason = 'insufficient-responses';
            else if (k === 1 && !allowSinglePeer)
              reason = 'insufficient-responses';
            else if (equivocating) reason = 'equivocating-authority';
            else if (winningDigests.length > 1) reason = 'conflicting-quorum';
            else if (winningDigests.length === 0)
              reason =
                first.length < q ? 'insufficient-responses' : 'no-agreement';
          }
          const preflightRefusal =
            k > 0 &&
            ((configuredQ !== undefined && configuredQ > k) ||
              (k === 1 && !allowSinglePeer));
          let getterReads = 0;
          const gates: Array<{
            index: number;
            resolve: (value: LoadQuorumProbeResult) => void;
            reject: (reason: unknown) => void;
          }> = [];
          const round = runLoadQuorum({
            peers,
            peerIdOf: (peer) => peer.id,
            documentPath: '/synthetic/schedules',
            config: { k: configuredK, q: configuredQ, allowSinglePeer },
            probeFn: (peer) =>
              new Promise((resolve, reject) =>
                gates.push({ index: peer.index, resolve, reject }),
              ),
          }).catch((failure: unknown) => failure);
          expect(gates.map(({ index }) => index)).toEqual(
            preflightRefusal
              ? []
              : Array.from({ length: k }, (_, index) => index),
          );
          for (const gate of gates.sort(
            (a, b) => specs[a.index].order - specs[b.index].order,
          )) {
            const spec = specs[gate.index];
            if (spec.kind === 'throw') {
              gate.reject(new Error('synthetic probe rejection'));
              continue;
            }
            const storage = new Uint8Array(40).fill(spec.digest);
            const bytes =
              spec.kind === 'offset'
                ? storage.subarray(4, 36)
                : spec.kind === 'short'
                  ? storage.subarray(0, 31)
                  : spec.kind === 'shared'
                    ? new Uint8Array(new SharedArrayBuffer(32))
                    : hash(spec.digest);
            const response: { hash: Uint8Array; signerAuthority: string } = {
              hash: bytes,
              signerAuthority: `authority-${spec.authority}`,
            };
            if (spec.kind === 'hash-getter')
              Object.defineProperty(response, 'hash', {
                get: () => {
                  getterReads++;
                  return bytes;
                },
              });
            if (spec.kind === 'authority-getter')
              Object.defineProperty(response, 'signerAuthority', {
                get: () => {
                  getterReads++;
                  return 'forged';
                },
              });
            gate.resolve(spec.kind === 'null' ? null : response);
            await Promise.resolve();
            await Promise.resolve();
            bytes.fill(0xff);
            if (good(gate.index))
              response.signerAuthority = 'changed-after-resolution';
          }
          const result = await round;
          expect(getterReads).toBe(0);
          if (k === 0) {
            expect(result).toEqual({ skipped: true });
          } else if (reason !== undefined) {
            expect(result).toBeInstanceOf(LoadQuorumFailedError);
            expect((result as LoadQuorumFailedError).reason).toBe(reason);
            const required =
              configuredQ !== undefined && configuredQ > k
                ? configuredQ
                : k === 1 && !allowSinglePeer
                  ? 2
                  : q;
            expect((result as LoadQuorumFailedError).requiredQ).toBe(required);
          } else {
            if (
              !(typeof result === 'object' && result !== null && 'ok' in result)
            )
              throw new Error('expected quorum success');
            const success = result as {
              ok: true;
              winningHashHex: string;
              narrowedPeers: typeof peers;
            };
            expect(success.winningHashHex).toBe(hex(winningDigests[0]));
            const expected = first.filter(
              (index) => specs[index].digest === winningDigests[0],
            );
            expect(success.narrowedPeers).toEqual(
              expected.map((index) => peers[index]),
            );
            success.narrowedPeers.forEach((peer, position) =>
              expect(peer).toBe(peers[expected[position]]),
            );
          }
        },
      ),
      {
        seed: 9804,
        numRuns: 300,
        examples: [
          [
            [
              { kind: 'offset', authority: 0, digest: 1, order: 3 },
              { kind: 'valid', authority: 1, digest: 1, order: 2 },
              { kind: 'throw', authority: 2, digest: 2, order: 1 },
            ],
            3,
            0,
            false,
            false,
          ],
          [
            [
              { kind: 'valid', authority: 0, digest: 1, order: 3 },
              { kind: 'valid', authority: 0, digest: 1, order: 2 },
              { kind: 'valid', authority: 1, digest: 1, order: 1 },
            ],
            3,
            1,
            true,
            false,
          ],
        ],
      },
    );
  });
});
