import {
  Doc,
  applyUpdateV2,
  decodeUpdateV2,
  diffUpdateV2,
  encodeStateAsUpdateV2,
} from 'yjs';
import { YjsACL } from '@peerborne/yjs';
import { aclDependencyScenarios } from '../../../verification/acl-dependencies.mjs';

function encodeStateVectorOf(clocks) {
  const bytes = [];
  const writeVarUint = (value) => {
    while (value > 0x7f) {
      bytes.push(0x80 | (value & 0x7f));
      value = Math.floor(value / 128);
    }
    bytes.push(value);
  };
  writeVarUint(clocks.size);
  for (const [client, clock] of clocks) {
    writeVarUint(client);
    writeVarUint(clock);
  }
  return new Uint8Array(bytes);
}

// A membership write five clocks past the actor's next one, so the
// clocks in between were never sent.
async function orphan(acl, publicKey, actor) {
  const serializer = new YjsACL();
  await serializer.add(publicKey);
  const [member] = serializer._acl.getMap('users').keys();
  const author = new Doc({ gc: false });
  applyUpdateV2(author, acl.current());
  const known = new Map(
    [...author.store.clients].map(([client, structs]) => {
      const tail = structs.at(-1);
      return [client, tail.id.clock + tail.length];
    }),
  );
  const client = Number(actor);
  author.clientID = client;
  for (let index = 0; index < 6; index++) {
    author.getMap('users').set(member, true);
  }
  const update = encodeStateAsUpdateV2(author);
  const last = decodeUpdateV2(update)
    .structs.filter((struct) => struct.id.client === client)
    .at(-1);
  known.set(client, last.id.clock);
  return diffUpdateV2(update, encodeStateVectorOf(known));
}

aclDependencyScenarios({
  adapter: 'yjs',
  orphan,
  write: (key, value) => (doc) => doc.getMap('root').set(key, value),
});
