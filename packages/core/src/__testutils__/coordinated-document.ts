import type { AuthProvider } from '../auth-provider.js';
import type { CRDTProvider } from '../crdt-provider.js';
import { preparedDocumentChange } from '../document-crdt-session.js';
import {
  documentBytesEqual,
  documentBytesId,
} from '../internal/document-binary.js';
import {
  bootstrap,
  context,
  type TestContext,
} from './group-security-coordinator.js';
import type {
  DocumentAuthority,
  DocumentMemberAuthority,
} from '../coordinated-document.js';
import type { GroupSecurityDocumentContext } from '../group-security-coordinator.js';
import { documentContextsMatch } from '../document-security-wire.js';

export type TestChange = (document: number[]) => void;
export const testCRDT: CRDTProvider<number[], number[], TestChange> = {
  newDocument: () => [],
  localChange: (current, _message, change) => {
    const next = [...current];
    change(next);
    return [next, next.slice(current.length)];
  },
  remoteChange: (current, changes) => [...current, ...changes],
  getHistory: (current) => [...current],
  getSnapshot: (current) => [...current],
  createDocumentSession(initial) {
    let document = [...initial],
      closed = false;
    const prepare = (next: number[], changes: number[]) => {
      const base = document;
      return preparedDocumentChange(
        changes,
        () => !closed && base === document,
        () => {
          document = next;
        },
        () => {},
        () => [...next],
      );
    };
    return {
      get document() {
        return document;
      },
      prepareLocal(message, change) {
        const [next, changes] = testCRDT.localChange(document, message, change);
        return prepare(next, changes);
      },
      prepareRemote(changes) {
        if (
          !Array.isArray(changes) ||
          changes.length > 1000 ||
          changes.some((value) => !Number.isSafeInteger(value))
        )
          throw new Error('Invalid CRDT input');
        return prepare([...document, ...changes], changes);
      },
      prepareSnapshot(changes) {
        return prepare([...changes], [...changes]);
      },
      close() {
        closed = true;
      },
    };
  },
};
export const testChanges = {
  serializeChanges: (values: number[]) =>
    new TextEncoder().encode(JSON.stringify(values)),
  deserializeChanges: (bytes: Uint8Array) =>
    JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    ) as number[],
};

export class TestDocumentAuthority implements DocumentAuthority {
  readonly genesisId = new Uint8Array(32).fill(0x61);
  version = 0;
  role: 1 | 2 | 3 = 3;
  constructor(
    readonly documentId: string,
    public context: GroupSecurityDocumentContext,
    readonly memberId: Uint8Array,
  ) {}
  get headId(): Uint8Array { return this.genesisId.slice(); }
  extendsHead(head: Uint8Array): boolean { return documentBytesEqual(head, this.genesisId); }
  capture(context: GroupSecurityDocumentContext) {
    if (!documentContextsMatch(this.context, context))
      throw new Error('Role log does not cover the group head');
    const version = this.version,
      role = this.role;
    return {
      headId: this.headId,
      members: [
        {
          memberId: this.memberId.slice(),
          role,
          publicKey: documentBytesId(this.memberId),
        },
      ] satisfies DocumentMemberAuthority[],
      isCurrent: () => version === this.version && role === this.role,
    };
  }
}

export function testAuth(
  value: TestContext,
): AuthProvider<Uint8Array, Uint8Array, string> {
  return {
    nonceBytes: 12,
    sign: (data, privateKey) => value.identities.signAs(privateKey, data),
    verify: (data, publicKey, signature) =>
      value.identities.verify(data, signature, publicKey),
    serializePublicKey: async (key) => documentBytesId(key),
    deserializePublicKey: async (key) => {
      const known = [
        value.identities.actorId,
        value.identities.attackerId,
      ].find((id) => documentBytesId(id) === key);
      if (!known) throw new Error('Unknown identity');
      return known.slice();
    },
    encrypt: async () => {
      throw new Error('Legacy encryption must not run');
    },
    decrypt: async () => {
      throw new Error('Legacy decryption must not run');
    },
  };
}

export async function documentFixture(path = '/sensitive-document') {
  const value = await context();
  const coordinator = await bootstrap(value);
  const authority = new TestDocumentAuthority(
    path,
    coordinator.documentContext,
    value.identities.actorId,
  );
  const auth = testAuth(value);
  return {
    value,
    coordinator,
    authority,
    auth,
    identity: value.identities.actorId,
  };
}
