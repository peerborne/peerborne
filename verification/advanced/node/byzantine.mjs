import assert from 'node:assert/strict';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import {
  collectBoundedChangeTree,
  MAX_CHANGE_TREE_DEPTH,
  MAX_CHANGE_TREE_NODES,
  MAX_CHANGE_TREE_EDGES,
} from '../../../packages/core/dist/esm/src/change-tree-walk.js';
import {
  A,
  Y,
  documentFixture,
  providerFor,
  signingIdentity,
  signedMessage,
  project,
  receiveEncrypted,
  seededRandom,
} from '../../fixtures.mjs';
import { memory, measure, measuredOnly } from '../../measure.mjs';

async function envelope(
  fixture,
  change,
  signer = fixture.identity.privateKey,
  kind = 'document',
) {
  const message = {
    documentId: fixture.document.documentPath,
    signatureContext: 'ordinary-sync-v1',
    changeId: await fixture.document._putBlock(change),
    changes: { kind, change },
  };
  message.signature = fixture.document._serializeSignature(
    await fixture.auth.sign(
      fixture.serializer.serializeSyncMessage(message),
      signer,
    ),
  );
  const [epoch, key] = await fixture.document._keychain.current();
  const encrypted = await fixture.auth.encrypt(
    fixture.serializer.serializeSyncMessage(message),
    key,
  );
  const frame = new Uint8Array(
    epoch.length + encrypted.nonce.length + encrypted.data.length,
  );
  frame.set(epoch);
  frame.set(encrypted.nonce, epoch.length);
  frame.set(encrypted.data, epoch.length + encrypted.nonce.length);
  return frame;
}

export async function authorization({ full, seed }) {
  const target = await documentFixture();
  const attacker = await signingIdentity();
  const operations = full ? 512 : 32;
  const random = seededRandom(seed);
  const raw = new Y.Doc();
  raw.clientID = 9000;
  let state = Y.encodeStateVector(raw);
  let unauthorizedRejected = 0;
  try {
    const before = project(target);
    for (let i = 0; i < operations; i++) {
      const field = ['roles', 'anotherUsersProperty', 'permissions'][
        Math.floor(random() * 3)
      ];
      raw.getMap('root').set(field, `synthetic-forbidden-${i}`);
      const delta = Y.encodeStateAsUpdateV2(raw, state);
      state = Y.encodeStateVector(raw);
      assert.equal(
        await receiveEncrypted(
          target,
          await envelope(target, delta, attacker.privateKey),
        ),
        false,
        'a non-writer with an encryption key cannot authenticate raw operations',
      );
      unauthorizedRejected++;
    }
    assert.deepEqual(
      project(target),
      before,
      'invalid writers cannot alter document state',
    );
    const unauthorizedAcl = await target.document._writers.add(
      attacker.publicKey,
    );
    await target.document._writers.remove(attacker.publicKey);
    target.document._invalidateWriterKeyCache();
    assert.equal(
      await receiveEncrypted(
        target,
        await envelope(target, unauthorizedAcl, attacker.privateKey, 'writer'),
      ),
      false,
      'an incoming ACL cannot grant the signer its own authority before verification',
    );

    // Set up a real document writer. Field policies below are requested policy,
    // not a fabricated engine feature or permission-log integration.
    await target.document._runWriterMutation(() =>
      target.document._writers.add(attacker.publicKey),
    );
    const allowed = new Y.Doc();
    allowed.clientID = 9001;
    allowed.getMap('root').set('roles', { owner: 'synthetic-attacker' });
    allowed.getMap('root').set('anotherUsersProperty', 'synthetic-overwrite');
    const acceptedRestrictedOperation = await receiveEncrypted(
      target,
      await envelope(
        target,
        Y.encodeStateAsUpdateV2(allowed),
        attacker.privateKey,
      ),
    );
    assert(
      acceptedRestrictedOperation,
      'probe must reach document-writer operation ingress',
    );
    const fieldPolicyEnforced =
      target.document.document.getMap('root').get('anotherUsersProperty') !==
      'synthetic-overwrite';
    await target.document._runWriterMutation(() =>
      target.document._writers.remove(attacker.publicKey),
    );
    const afterRevocation = project(target);
    allowed.getMap('root').set('postRevocation', true);
    assert.equal(
      await receiveEncrypted(
        target,
        await envelope(
          target,
          Y.encodeStateAsUpdateV2(allowed),
          attacker.privateKey,
        ),
      ),
      false,
      'a locally revoked writer must be rejected at ingress',
    );
    assert.deepEqual(project(target), afterRevocation);
    await target.document.change((doc) =>
      doc.getMap('root').set('benignAfterAttack', true),
    );
    assert.equal(
      target.document.document.getMap('root').get('benignAfterAttack'),
      true,
    );
    allowed.destroy();
    return {
      scope:
        'Raw Yjs bytes inside real AES-GCM and signed ordinary-sync envelopes; actual current writer ACL verification. ACL membership setup is local and explicit, not a networked append-only permission log.',
      metrics: {
        unauthorizedRejected,
        unauthorizedAclSelfGrantRejected: true,
        revokedWriterRejected: true,
        documentWriterRestrictedFieldApplied: !fieldPolicyEnforced,
        benignFollowupApplied: true,
      },
      gaps: [
        ...(!fieldPolicyEnforced
          ? [
              'Current writer authorization admits arbitrary document fields, including synthetic role and another-user fields. No field-level capability policy or append-only permission-log check was observed at this ingress.',
            ]
          : []),
        'Distributed permission-log history and stale remote revocation are not established by a local ACL setup.',
      ],
    };
  } finally {
    raw.destroy();
    await target.close();
  }
}

async function graphBoundaries(full) {
  const id = await (async () =>
    CID.createV1(0x55, await sha256.digest(new Uint8Array([1]))).toString())();
  const canonicalizeNodeId = (value) => CID.parse(value).toString();
  const chain = (depth) => {
    let root = { kind: 'document' };
    for (let i = 1; i < depth; i++)
      root = { kind: 'document', children: { [id]: root } };
    return root;
  };
  for (const depth of [MAX_CHANGE_TREE_DEPTH - 1, MAX_CHANGE_TREE_DEPTH])
    assert.equal(
      collectBoundedChangeTree(id, chain(depth), { canonicalizeNodeId }).length,
      depth,
    );
  assert.throws(() =>
    collectBoundedChangeTree(id, chain(MAX_CHANGE_TREE_DEPTH + 1), {
      canonicalizeNodeId,
    }),
  );
  const cycle = { kind: 'document', children: {} };
  cycle.children[id] = cycle;
  assert.throws(() =>
    collectBoundedChangeTree(id, cycle, { canonicalizeNodeId }),
  );
  for (const node of [
    null,
    [],
    { kind: 'permission' },
    { kind: 'document', children: [] },
    { kind: 'document', children: { 'not-a-cid': { kind: 'document' } } },
  ])
    assert.throws(() =>
      collectBoundedChangeTree(id, node, { canonicalizeNodeId }),
    );
  let widthChecked = false;
  if (full) {
    const children = {};
    for (let i = 0; i < MAX_CHANGE_TREE_NODES; i++) {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, i);
      children[CID.createV1(0x55, await sha256.digest(bytes)).toString()] = {
        kind: 'document',
      };
    }
    const entries = Object.entries(children);
    const boundary = {
      kind: 'document',
      children: Object.fromEntries(entries.slice(0, MAX_CHANGE_TREE_NODES - 1)),
    };
    assert.equal(
      collectBoundedChangeTree(id, boundary, { canonicalizeNodeId }).length,
      MAX_CHANGE_TREE_NODES,
    );
    boundary.children[entries.at(-1)[0]] = entries.at(-1)[1];
    assert.throws(() =>
      collectBoundedChangeTree(id, boundary, { canonicalizeNodeId }),
    );
    widthChecked = true;
  }
  return {
    depthLimit: MAX_CHANGE_TREE_DEPTH,
    nodeLimit: MAX_CHANGE_TREE_NODES,
    edgeLimit: MAX_CHANGE_TREE_EDGES,
    exactDepthBoundaryAccepted: true,
    oversizedDepthRejected: true,
    cycleRejected: true,
    widthBoundaryChecked: widthChecked,
  };
}

export async function poisoning({ full }) {
  const target = await documentFixture();
  const count = full ? 1024 : 32;
  const sources = [];
  const before = memory();
  let acceptedOrphans = 0;
  let unresolvedParents = 0;
  try {
    const graph = await graphBoundaries(full);
    const initial = target.document.historySize();
    const timing = await measure(async () => {
      for (let i = 0; i < count; i++) {
        const p = providerFor('yjs', 10000 + i);
        let state = p.newDocument();
        let ancestor, orphan;
        [state, ancestor] = p.localChange(state, '', (doc) =>
          doc.getArray('poisoned').push([0]),
        );
        [state, orphan] = p.localChange(state, '', (doc) =>
          doc.getArray('poisoned').push([1]),
        );
        const parentId = await target.document._putBlock(ancestor);
        const orphanId = await target.document._putBlock(orphan);
        // A deferred parent references valid CID syntax but is absent from the
        // receiving engine. The inline descendant has a missing CRDT ancestor.
        const message = await signedMessage(target, {
          changeId: orphanId,
          changes: { kind: 'document', change: orphan },
        });
        if (await target.document.sync(message)) acceptedOrphans++;
        sources.push({ state, ancestor, parentId, orphanId });
      }
    });
    assert(acceptedOrphans > 0);
    const buffered =
      target.document.document.store.pendingStructs?.update.byteLength ?? 0;
    assert(buffered > 0, 'the signed flood must reach CRDT causal buffering');
    assert.equal(
      target.document.document.getArray('poisoned').length,
      0,
      'missing parents cannot be invented',
    );
    const afterFlood = memory();
    for (const source of sources)
      assert(
        await target.document.sync(
          await signedMessage(target, {
            changeId: source.parentId,
            changes: { kind: 'document', change: source.ancestor },
          }),
        ),
      );
    assert.equal(
      target.document.document.getArray('poisoned').length,
      count * 2,
      'actual missing contexts must release all buffered operations',
    );

    const bogusParent = CID.createV1(
      0x55,
      await sha256.digest(
        new TextEncoder().encode('synthetic-never-published-parent'),
      ),
    ).toString();
    const validParent = sources[0].parentId;
    assert.notEqual(bogusParent, validParent);
    const change = sources[0].ancestor;
    const poison = await signedMessage(target, {
      changeId: await target.document._putBlock(new Uint8Array([4, 2])),
      changes: {
        kind: 'document',
        change,
        children: { [bogusParent]: { kind: 'document', children: false } },
      },
    });
    let parentRejected = false;
    try {
      parentRejected = !(await target.document.sync(poison));
    } catch {
      parentRejected = true;
    }
    if (!parentRejected) unresolvedParents++;

    const clockResults = [];
    for (const adapter of ['yjs', 'automerge']) {
      const fixture = await documentFixture({ adapter, index: 12000 });
      try {
        const clocks = full
          ? [
              2 ** 31 - 1,
              2 ** 32,
              Number.MAX_SAFE_INTEGER - 1,
              Number.MAX_SAFE_INTEGER,
            ]
          : [Number.MAX_SAFE_INTEGER];
        for (const clock of clocks) {
          let payload;
          let encoded = false;
          let accepted = false;
          let bufferedBytes = 0;
          try {
            if (adapter === 'yjs') {
              const hostile = new Y.Doc();
              hostile.clientID = 13000 + clockResults.length;
              hostile.getMap('root').set('inflated', true);
              hostile.store.clients.get(hostile.clientID)[0].id.clock = clock;
              payload = Y.encodeStateAsUpdateV2(hostile);
              assert.equal(
                Y.decodeUpdateV2(payload).structs[0].id.clock,
                clock,
                'encoded wire counter must actually be inflated',
              );
              hostile.destroy();
            } else {
              const source = A.change(
                A.init({ actor: 'f'.repeat(32) }),
                (doc) => {
                  doc.inflated = true;
                },
              );
              const decoded = A.decodeChange(A.getLastLocalChange(source));
              const changed = { ...decoded, startOp: clock };
              delete changed.hash;
              payload = [A.encodeChange(changed)];
              assert.equal(A.decodeChange(payload[0]).startOp, clock);
              A.free(source);
            }
            encoded = true;
            accepted = await fixture.document.sync(
              await signedMessage(fixture, {
                changeId: await fixture.document._putBlock(payload),
                changes: { kind: 'document', change: payload },
              }),
            );
            bufferedBytes =
              adapter === 'yjs'
                ? (fixture.document.document.store.pendingStructs?.update
                    .byteLength ?? 0)
                : 0;
          } catch (error) {
            if (error.code === 'ERR_ASSERTION') throw error;
          }
          clockResults.push({
            adapter,
            clock,
            encoded,
            accepted,
            bufferedBytes,
          });
        }
        await fixture.document.change((doc) => {
          if (adapter === 'yjs')
            doc.getMap('root').set('benignAfterInflation', true);
          else doc.benignAfterInflation = true;
        });
        assert(
          adapter === 'yjs'
            ? fixture.document.document
                .getMap('root')
                .get('benignAfterInflation')
            : fixture.document.document.benignAfterInflation,
          'inflation must not stall an independent benign writer',
        );
      } finally {
        await fixture.close();
      }
    }
    await target.document.change((doc) =>
      doc.getMap('root').set('benignAfterPoison', true),
    );
    return {
      scope:
        'Real signed sync ingress and CRDT causal queues; writer-authenticated flood. Tree-budget checks invoke the production walker directly. Inflated counters are verified in actual Yjs/Automerge wire bytes, not transport sequence labels.',
      metrics: {
        count,
        acceptedOrphans,
        bufferedBytesBeforeAncestors: buffered,
        historyGrowth: target.document.historySize() - initial,
        before,
        afterFlood,
        ...measuredOnly(timing),
        releasedAfterContext: count * 2,
        missingParentRejected: parentRejected,
        unresolvedParents,
        graph,
        clockResults,
        benignFollowupApplied: true,
      },
      gaps: [
        'The authorized orphan queue has no verified aggregate byte/count/TTL bound. The workload is capped by the harness and is not memory-flood rejection evidence.',
        ...(unresolvedParents
          ? [
              'A nonexistent deferred parent was admitted; no peer quarantine or bounded aggregate parent-fetch budget was established.',
            ]
          : []),
        ...(clockResults.some(({ accepted }) => accepted)
          ? [
              'At least one huge counter was accepted or buffered. A clock-admission policy and isolation of malicious writers are not established.',
            ]
          : []),
      ],
    };
  } finally {
    for (const { state } of sources) state.destroy();
    await target.close();
  }
}
