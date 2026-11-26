import {
  clone,
  decodeChange,
  encodeChange,
  getChanges,
} from '@automerge/automerge';
import { AutomergeACL } from '@peerborne/automerge';
import { aclDependencyScenarios } from '../../../verification/acl-dependencies.mjs';

// A valid membership addition whose only dependency is a hash nobody holds.
async function orphan(acl, publicKey) {
  const author = new AutomergeACL();
  author.merge(acl.current());
  const before = clone(author._acl);
  await author.add(publicKey);
  const [addition] = getChanges(before, author._acl);
  const decoded = decodeChange(addition);
  decoded.deps = ['ab'.repeat(32)];
  delete decoded.hash;
  return [encodeChange(decoded)];
}

aclDependencyScenarios({
  adapter: 'automerge',
  orphan,
  write: (key, value) => (doc) => {
    doc[key] = value;
  },
});
