import {
  Doc,
  applyUpdateV2,
  decodeUpdateV2,
  encodeStateAsUpdateV2,
  encodeStateVector,
} from 'yjs';
import { YjsACL } from '@peerborne/yjs';
import { aclActorBindingScenarios } from '../../../verification/acl-actor-binding.mjs';

// A different membership write at the victim's client and clock.
async function squat(state, victim, publicKey) {
  const serializer = new YjsACL();
  await serializer.add(publicKey);
  const [member] = serializer._acl.getMap('users').keys();
  const [{ id }] = decodeUpdateV2(victim).structs;
  const author = new Doc({ gc: false });
  applyUpdateV2(author, state);
  const before = encodeStateVector(author);
  author.clientID = id.client;
  author.getMap('users').set(member, true);
  return encodeStateAsUpdateV2(author, before);
}

aclActorBindingScenarios({
  adapter: 'yjs',
  squat,
  write: (key, value) => (doc) => doc.getMap('root').set(key, value),
});
