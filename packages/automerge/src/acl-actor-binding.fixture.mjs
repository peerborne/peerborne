import { clone, getChanges } from '@automerge/automerge';
import { AutomergeACL } from '@peerborne/automerge';
import { aclActorBindingScenarios } from '../../../verification/acl-actor-binding.mjs';

// A different membership write under the victim's actor at its sequence.
async function squat(state, victim, publicKey) {
  const author = new AutomergeACL();
  author.merge(state);
  const before = clone(author._acl);
  const [actor] = author.actorBinding.changeActors(victim);
  author.actorBinding.setLocalActor(actor);
  await author.add(publicKey);
  return getChanges(before, author._acl);
}

aclActorBindingScenarios({
  adapter: 'automerge',
  squat,
  write: (key, value) => (doc) => {
    doc[key] = value;
  },
});
