import * as A from '@automerge/automerge';
import {
  AutomergeACLProvider,
  AutomergeJSONSerializer,
  AutomergeKeychainProvider,
  AutomergeProvider,
} from '@peerborne/automerge';
import { actorBindingScenarios } from '../../../verification/actor-binding.mjs';

actorBindingScenarios({
  name: 'automerge',
  hashDependencies: true,
  provider: () => new AutomergeProvider(),
  acl: () => new AutomergeACLProvider(),
  keychain: () => new AutomergeKeychainProvider(),
  serializer: () => new AutomergeJSONSerializer(),
  write: (key) => (doc) => {
    doc[key] = 1;
  },
  forge(document, actor, key) {
    const forged = A.change(A.clone(document, actor), (doc) => {
      doc[key] = 1;
    });
    return A.getChanges(document, forged);
  },
  json: (document) => A.toJS(document),
  actor: (document) => A.getActorId(document),
  hasActor: (document, actor) =>
    A.getChangesMetaSince(document, []).some(
      (change) => change.actor === actor,
    ),
});
