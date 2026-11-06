import type { CRDTProvider } from '../crdt-provider.js';
import type { ChangesSerializer } from '../changes-serializer.js';
import {
  CoordinatedDocument,
  type DocumentAuthority,
} from '../coordinated-document.js';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from '../document-authority-log.js';
import type { DocumentWritePaths } from '../document-field-authorization.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
} from '../document-replay-journal.js';
import { InMemoryDocumentJournalStore } from '../document-journal-store.js';
import { GroupSecurityCoordinator } from '../group-security-coordinator.js';
import { documentBytesId } from '../internal/document-binary.js';
import { testAuth } from './coordinated-document.js';
import {
  context,
  config,
  createGroupInput,
  protocol,
  groupId,
  id,
  control,
} from './group-security-coordinator.js';

export async function fieldDocumentFixture<Document, Changes, Change>(
  crdt: CRDTProvider<Document, Changes, Change>,
  serializer: ChangesSerializer<Changes>,
  grants: DocumentWritePaths,
) {
  const f = await context(),
    auth = testAuth(f);
  const controlAuthority = new DocumentGroupControlAuthority(
    protocol,
    groupId,
    f.identities.actorId,
  );
  const coordinator = await GroupSecurityCoordinator.bootstrap(
    { ...config(f), authorizeControl: controlAuthority.authorize },
    createGroupInput,
    { operationId: id(1), subjectId: f.identities.actorId },
  );
  const authority = await DocumentAuthorityLog.create(
    '/field-authorization',
    coordinator.documentContext,
    [
      {
        memberId: f.identities.actorId,
        publicKey: documentBytesId(f.identities.actorId),
        role: 3,
      },
    ],
    f.identities.actorId,
    auth,
    controlAuthority,
  );
  await coordinator.createCommit(
    { changes: [] },
    control(2, 'update', f.identities.actorId),
  );
  const permissionUpdate = await authority.signUpdate(
    coordinator.documentContext,
    [
      {
        memberId: f.identities.actorId,
        publicKey: documentBytesId(f.identities.actorId),
        role: 2,
        writePaths: grants,
      },
      {
        memberId: f.identities.attackerId,
        publicKey: documentBytesId(f.identities.attackerId),
        role: 3,
      },
    ],
    f.identities.actorId,
  );
  await authority.applyUpdate(coordinator, permissionUpdate);
  // A compromised member can sign/encrypt arbitrary bytes without using an honest local authority adapter.
  const dishonest: DocumentAuthority = {
    documentId: authority.documentId,
    genesisId: authority.genesisId,
    headId: authority.headId,
    extendsHead: authority.extendsHead.bind(authority),
    assertCoordinator: authority.assertCoordinator.bind(authority),
    capture: (state) => {
      const lease = authority.capture(state);
      return {
        ...lease,
        members: lease.members.map(
          ({ writePaths: _scope, ...member }) => member,
        ),
      };
    },
  };
  const store = new InMemoryDocumentJournalStore();
  const deviceKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const journal = new DocumentReplayJournal(
    authority.documentId,
    authority.genesisId,
    deviceKey,
    store,
    new InMemoryDocumentJournalRollbackAnchor(),
  );
  return {
    store,
    storageKey: documentBytesId(authority.genesisId),
    create: (initial: Document, bypass = false, persist = false) =>
      new CoordinatedDocument(
        authority.documentId,
        initial,
        crdt,
        serializer,
        auth,
        f.identities.actorId,
        f.identities.actorId,
        {
          coordinator,
          authority: bypass ? dishonest : authority,
          ...(persist ? { journal, persistPublications: true } : {}),
        },
      ),
  };
}
