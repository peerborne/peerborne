import { LoroDoc } from 'loro-crdt';
import { LoroProvider } from '@peerborne/loro';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
} from '@peerborne/yjs';
import { actorBindingScenarios } from '../../../verification/actor-binding.mjs';

actorBindingScenarios({
  name: 'loro',
  provider: () => new LoroProvider(),
  acl: () => new YjsACLProvider(),
  keychain: () => new YjsKeychainProvider(),
  serializer: () => new YjsJSONSerializer(),
  write: (key) => (doc) => doc.getMap('m').set(key, 1),
  forge(document, actor, key) {
    const forger = new LoroDoc();
    forger.import(document.export({ mode: 'snapshot' }));
    forger.setPeerId(BigInt(actor));
    const from = forger.oplogVersion();
    forger.getMap('m').set(key, 1);
    forger.commit();
    return forger.export({ mode: 'update', from });
  },
  json: (document) => document.getMap('m').toJSON(),
  actor: (document) => document.peerIdStr,
  hasActor: (document, actor) => document.oplogVersion().toJSON().has(actor),
  squat: (actor, key) => (doc) => {
    doc.setPeerId(BigInt(actor));
    doc.getMap('m').set(key, 1);
  },
});
