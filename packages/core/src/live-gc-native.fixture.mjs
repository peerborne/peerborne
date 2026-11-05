import assert from 'node:assert/strict';
import test from 'node:test';
import fc from 'fast-check';
import { createHeliaLight } from 'helia';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as raw from 'multiformats/codecs/raw';
import { PeerborneDocument } from './peerborne-document.ts';
import { InvitationMembershipQueue } from './invitation-membership.ts';

const cidFor = async (bytes) =>
  CID.createV1(raw.code, await sha256.digest(bytes));

test('real offline Helia pin and blockstore behavior agrees with live document retention', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(fc.boolean(), { minLength: 1, maxLength: 8 }),
      async (flags) => {
        const helia = createHeliaLight({ routers: [], blockBrokers: [] });
        await helia.start();
        try {
          const rootBytes = new Uint8Array([0, 255]);
          const root = await cidFor(rootBytes);
          await helia.blockstore.put(root, rootBytes);
          const ids = [];
          for (const [index, pinned] of flags.entries()) {
            const bytes = new Uint8Array([index + 1, pinned ? 1 : 0]);
            const cid = await cidFor(bytes);
            await helia.blockstore.put(cid, bytes);
            ids.push(cid);
            if (pinned)
              for await (const _ of helia.pins.add(cid)) {
                /* drain */
              }
          }
          const retained = ids.filter((_, index) => index % 3 === 1);
          const document = Object.assign(
            Object.create(PeerborneDocument.prototype),
            {
              documentPath: '/native-gc',
              _mutationQueue: new InvitationMembershipQueue(),
              _gcLifecycle: {},
              _gcCandidates: new Set(),
              _recentTips: [],
              _latestSnapshot: { lastChangeNodeCID: root.toString() },
              _lastSyncMessage: {
                changeId: root.toString(),
                changes: {
                  kind: 'document',
                  children: Object.fromEntries(
                    retained.map((cid) => [
                      cid.toString(),
                      { kind: 'document' },
                    ]),
                  ),
                },
              },
              swarm: { heliaNode: helia },
            },
          );
          await document._gcPrunedBlocks(
            new Set([root.toString(), ...ids.map((cid) => cid.toString())]),
          );
          assert.equal(await helia.blockstore.has(root), true);
          for (const [index, cid] of ids.entries()) {
            assert.equal(
              await helia.blockstore.has(cid),
              flags[index] || retained.includes(cid),
            );
            assert.equal(await helia.pins.isPinned(cid), flags[index]);
          }
        } finally {
          await helia.stop();
        }
      },
    ),
    { seed: 2012209, numRuns: 12, examples: [[[true, false, true, false]]] },
  );
});
