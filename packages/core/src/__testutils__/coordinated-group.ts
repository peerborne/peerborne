import type { AuthProvider } from '../auth-provider.js';
import type { ChangesSerializer } from '../changes-serializer.js';
import type { CRDTProvider } from '../crdt-provider.js';
import type { DocumentMemberAuthority } from '../coordinated-document.js';
import {
  DocumentAuthorityLog,
  DocumentGroupControlAuthority,
} from '../document-authority-log.js';
import { InMemoryDocumentJournalStore } from '../document-journal-store.js';
import {
  DocumentReplayJournal,
  InMemoryDocumentJournalRollbackAnchor,
} from '../document-replay-journal.js';
import {
  GroupSecurityCoordinator,
  type GroupSecurityCoordinatorConfig,
  type GroupSecurityDelivery,
} from '../group-security-coordinator.js';
import { createGroupSecurityDurableAcceptance } from '../group-security-durable-acceptance.js';
import type {
  CreateGroupCommitInput,
  CreateGroupInput,
  ExportGroupSecretInput,
  GroupSecurityActiveApplyResult,
  GroupSecurityCommit,
  GroupSecurityCommitResult,
  GroupSecurityCreateResult,
  GroupSecurityPublicState,
  JoinGroupInput,
} from '../group-security-provider.js';
import { InMemoryGroupSecurityRollbackAnchor } from '../group-security-rollback-anchor.js';
import { InMemoryGroupStateStore } from '../group-state-store.js';
import { bytesToHex } from '../internal/hex.js';
import { Peerborne } from '../peerborne.js';
import type { PeerborneDocument } from '../peerborne-document.js';
import { WebCryptoGroupStateProtector } from '../webcrypto-group-state-protector.js';
import {
  ContractTestProvider,
  JsonTestCodec,
  generateHmacKey,
  groupId,
  protocol,
  storeKey,
  toHex,
  fromHex,
} from './group-security-coordinator.js';

/** HMAC signing identities for a group of test members. */
export class GroupTestIdentities {
  private readonly keys = new Map<string, CryptoKey>();

  static async create(
    members: readonly Uint8Array[],
  ): Promise<GroupTestIdentities> {
    const value = new GroupTestIdentities();
    for (const member of members)
      value.keys.set(toHex(member), await generateHmacKey());
    return value;
  }

  async signAs(actorId: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
    const key = this.keys.get(toHex(actorId));
    if (key === undefined) throw new Error('unknown test member');
    return new Uint8Array(
      await crypto.subtle.sign('HMAC', key, payload as BufferSource),
    );
  }

  readonly verify = async (
    payload: Uint8Array,
    signature: Uint8Array,
    actorId: Uint8Array,
  ): Promise<boolean> => {
    const key = this.keys.get(toHex(actorId));
    return (
      key !== undefined &&
      crypto.subtle.verify(
        'HMAC',
        key,
        signature as BufferSource,
        payload as BufferSource,
      )
    );
  };

  auth(): AuthProvider<Uint8Array, Uint8Array, string> {
    return {
      nonceBytes: 12,
      sign: (data, privateKey) => this.signAs(privateKey, data),
      verify: (data, publicKey, signature) =>
        this.verify(data, signature, publicKey),
      serializePublicKey: async (key) => bytesToHex(key),
      deserializePublicKey: async (key) => {
        if (!this.keys.has(key)) throw new Error('Unknown identity');
        return fromHex(key);
      },
      encrypt: async () => {
        throw new Error('Legacy encryption must not run');
      },
      decrypt: async () => {
        throw new Error('Legacy decryption must not run');
      },
    };
  }
}

/** Member rosters by epoch, shared by every member's provider in one group. */
type RosterHistory = Map<bigint, readonly string[]>;

/** Reports the authenticated roster it reached and exports per-epoch secrets. */
export class RosterTestProvider extends ContractTestProvider {
  private members: readonly string[] = [];

  constructor(private readonly history: RosterHistory) {
    super();
  }

  override async createGroup(
    input: CreateGroupInput,
  ): Promise<GroupSecurityCreateResult> {
    const result = await super.createGroup(input);
    this.members = [toHex(input.creatorMemberId)];
    this.history.set(result.state.epoch, this.members);
    return result;
  }

  override async joinGroup(
    input: JoinGroupInput,
  ): Promise<GroupSecurityPublicState> {
    const state = await super.joinGroup(input);
    this.members = this.history.get(state.epoch) ?? [];
    return state;
  }

  override async createCommit(
    input: CreateGroupCommitInput,
  ): Promise<GroupSecurityCommitResult> {
    const result = await super.createCommit(input);
    let members = [...this.members];
    for (const change of result.appliedMembership.changes) {
      const member = toHex(change.memberId);
      members =
        change.kind === 'remove'
          ? members.filter((value) => value !== member)
          : [...members, member];
    }
    this.members = members;
    this.history.set(result.state.epoch, members);
    return result;
  }

  override async applyCommit(
    commit: GroupSecurityCommit,
  ): Promise<GroupSecurityActiveApplyResult> {
    const result = await super.applyCommit(commit);
    if (result.status === 'applied')
      this.members = this.history.get(result.state.epoch) ?? [];
    return result;
  }

  async getAuthenticatedMemberIds(): Promise<Uint8Array[]> {
    return this.members.map(fromHex);
  }

  override async exportSecret(
    input: ExportGroupSecretInput,
  ): Promise<Uint8Array> {
    await super.exportSecret(input);
    const label = new TextEncoder().encode(input.label);
    const bytes = new Uint8Array(label.length + input.context.length);
    bytes.set(label);
    bytes.set(input.context, label.length);
    return new Uint8Array(
      await crypto.subtle.digest('SHA-256', bytes as BufferSource),
    ).slice(0, input.length);
  }
}

export interface GroupPublication {
  readonly sender: number;
  readonly topic: string;
  readonly data: Uint8Array;
}

type FakePubSub = EventTarget & {
  subscribe(topic: string): void;
  unsubscribe(topic: string): void;
  publish(topic: string, data: Uint8Array): Promise<{ recipients: string[] }>;
};

export interface CoordinatedGroupOptions {
  /** Number of possible members; member 0 is the controller. */
  readonly members: number;
  readonly journal?: boolean;
  /** Requires a CRDT session with detached snapshot merges. */
  readonly catchUp?: boolean;
  /** Give each member a libp2p PeerId, which enables redelivery requests. */
  readonly peers?: boolean;
}

/** The base58 libp2p PeerId of a fixture member. */
export const groupPeer = (index: number) =>
  `12D3KooWTestPeer${'ABCDEFGHJKMNPQRS'[index]}`;

/**
 * Members of one strict coordinated document opened through `Peerborne.doc`,
 * over a recorded pubsub whose delivery the test controls.
 */
export async function coordinatedGroupFixture<Document, Changes, Change>(
  crdt: CRDTProvider<Document, Changes, Change>,
  serializer: ChangesSerializer<Changes>,
  {
    members: size,
    journal = true,
    catchUp = false,
    peers = false,
  }: CoordinatedGroupOptions,
) {
  const path = '/coordinated-group';
  const members = Array.from({ length: size }, (_, index) => {
    const member = new Uint8Array(32);
    member[0] = 0x40 + index;
    return member;
  });
  const identities = await GroupTestIdentities.create(members);
  const auth = identities.auth();
  const history: RosterHistory = new Map();
  const providers = members.map(() => new RosterTestProvider(history));
  const controls = members.map(
    () => new DocumentGroupControlAuthority(protocol, groupId, members[0]),
  );
  const protectors = await Promise.all(
    members.map((_, index) =>
      WebCryptoGroupStateProtector.generate(`coordinated-group-${index}`),
    ),
  );
  const stores = members.map(() => new InMemoryGroupStateStore());
  const anchors = members.map(() => new InMemoryGroupSecurityRollbackAnchor());
  const configuration = (index: number): GroupSecurityCoordinatorConfig => ({
    provider: providers[index],
    store: stores[index],
    storeKey,
    rollbackAnchor: anchors[index],
    protector: protectors[index],
    actorId: members[index],
    signControlRecord: (bytes) => identities.signAs(members[index], bytes),
    verifyControlSignature: identities.verify,
    authorizeControl: controls[index].authorize,
    outboxCodec: new JsonTestCodec(),
    now: () => 1_700_000_000_000,
  });
  const collect = async (coordinator: GroupSecurityCoordinator) => {
    const values: GroupSecurityDelivery[] = [];
    await coordinator.flushOutbox(async (delivery) => {
      values.push(delivery);
      return createGroupSecurityDurableAcceptance(delivery);
    });
    return values;
  };
  let operation = 0;
  const nextId = () => {
    const value = new Uint8Array(32);
    new DataView(value.buffer).setUint32(0, ++operation);
    return value;
  };
  const coordinators: GroupSecurityCoordinator[] = [];
  coordinators[0] = await GroupSecurityCoordinator.bootstrap(
    configuration(0),
    { groupId, creatorMemberId: members[0], credential: members[0] },
    { operationId: nextId(), subjectId: members[0] },
  );
  const controlRecords = (await collect(coordinators[0])).map(
    (delivery) => delivery.controlRecord,
  );
  const roster: DocumentMemberAuthority[] = [
    { memberId: members[0], publicKey: bytesToHex(members[0]), role: 3 },
  ];
  const logs: DocumentAuthorityLog<Uint8Array, Uint8Array, string>[] = [];
  logs[0] = await DocumentAuthorityLog.create(
    path,
    coordinators[0].documentContext,
    roster,
    members[0],
    auth,
    controls[0],
  );
  const journalStores = members.map(() => new InMemoryDocumentJournalStore());
  const journalAnchors = members.map(
    () => new InMemoryDocumentJournalRollbackAnchor(),
  );
  const deviceKeys = await Promise.all(
    members.map(() =>
      crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ]),
    ),
  );

  const publications: GroupPublication[] = [];
  /** Members whose publications currently report no topic recipients. */
  const offline = new Set<number>();
  const pubsubs = members.map((_, index) => {
    const pubsub = new EventTarget() as FakePubSub;
    pubsub.subscribe = () => {};
    pubsub.unsubscribe = () => {};
    pubsub.publish = async (topic, data) => {
      publications.push({ sender: index, topic, data: data.slice() });
      return { recipients: offline.has(index) ? [] : ['test-peer'] };
    };
    return pubsub;
  });
  const legacy = { initialize: () => ({}) } as never;
  const swarms = members.map((member, index) => {
    const swarm = new Peerborne<
      Document,
      Changes,
      Change,
      Uint8Array,
      Uint8Array,
      string
    >(
      member,
      member,
      crdt,
      serializer,
      serializer as never,
      serializer as never,
      auth,
      legacy,
      legacy,
    );
    Object.assign(swarm, {
      _heliaNode: {
        libp2p: {
          services: { pubsub: pubsubs[index] },
          ...(peers ? { peerId: { toString: () => groupPeer(index) } } : {}),
        },
      },
      _config: { enableSigning: false },
    });
    return swarm;
  });
  type Doc = PeerborneDocument<
    Document,
    Changes,
    Change,
    Uint8Array,
    Uint8Array,
    string
  >;
  const docs: (Doc | undefined)[] = members.map(() => undefined);
  const makeDocument = (index: number): Doc =>
    swarms[index].doc(path, {
      security: {
        coordinator: coordinators[index],
        authority: logs[index],
        requireGroupRosterMatch: true,
        enableAuthenticatedCatchUp: catchUp,
        ...(journal
          ? {
              journal: new DocumentReplayJournal(
                path,
                logs[0].genesisId,
                deviceKeys[index],
                journalStores[index],
                journalAnchors[index],
              ),
            }
          : {}),
      },
    });
  const open = async (index: number): Promise<Doc> => {
    const document = makeDocument(index);
    if (index === 0 && docs.every((value) => value === undefined))
      await document.create();
    else await document.open();
    docs[index] = document;
    return document;
  };
  const doc = (index: number): Doc => {
    const document = docs[index];
    if (!document) throw new Error(`member ${index} has no open document`);
    return document;
  };

  const applyRole = async (record: Uint8Array, targets: readonly number[]) => {
    for (const index of targets) {
      const document = docs[index];
      if (document) await document.applySecurityAuthorityUpdate(record);
      else await logs[index].applyUpdate(coordinators[index], record);
    }
  };
  const joined = () =>
    coordinators.flatMap((coordinator, index) =>
      coordinator && index !== 0 ? [index] : [],
    );

  /** Add a writer and deliver the commit and role record to `applyTo`. */
  const addMember = async (
    index: number,
    { applyTo = joined(), role = 2 as 1 | 2 | 3 } = {},
  ) => {
    const keyPackage = await GroupSecurityCoordinator.createPendingKeyPackage(
      configuration(index),
      {
        operationId: nextId(),
        groupId,
        memberId: members[index],
        credential: members[index],
      },
    );
    await coordinators[0].createCommit(
      { changes: [{ kind: 'add', memberId: members[index], keyPackage }] },
      {
        operationId: nextId(),
        requestDigest: nextId(),
        action: 'add',
        subjectId: members[index],
      },
    );
    const [delivery] = await collect(coordinators[0]);
    controlRecords.push(delivery.controlRecord);
    for (const target of applyTo)
      await coordinators[target].applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        delivery.welcomes,
      );
    roster.push({
      memberId: members[index],
      publicKey: bytesToHex(members[index]),
      role,
    });
    const record = await logs[0].signUpdate(
      coordinators[0].documentContext,
      roster,
      members[0],
    );
    await applyRole(record, [0, ...applyTo]);
    logs[index] = await DocumentAuthorityLog.restore(
      logs[0].exportRecords(),
      logs[0].genesisId,
      auth,
      controls[index],
    );
    coordinators[index] = await GroupSecurityCoordinator.joinFromInvitation(
      configuration(index),
      {
        subjectId: members[index],
        keyPackageRef: keyPackage.reference,
        controlPrefix: [...controlRecords],
        commit: delivery.commit!,
        welcome: delivery.welcomes[0],
      },
    );
    return { delivery, record };
  };

  /** Rotate the epoch at the controller and sign the unchanged roster for it. */
  const renew = async () => {
    await coordinators[0].createCommit(
      { changes: [] },
      {
        operationId: nextId(),
        requestDigest: nextId(),
        action: 'update',
        subjectId: members[0],
      },
    );
    const [delivery] = await collect(coordinators[0]);
    controlRecords.push(delivery.controlRecord);
    const record = await logs[0].signUpdate(
      coordinators[0].documentContext,
      roster,
      members[0],
    );
    return { delivery, record };
  };

  /** Deliver a commit from `renew` to a member and apply its role record. */
  const applyRenewal = async (
    index: number,
    { delivery, record }: Awaited<ReturnType<typeof renew>>,
  ) => {
    if (index !== 0)
      await coordinators[index].applyCommit(
        delivery.commit!,
        delivery.controlRecord,
        [],
      );
    await applyRole(record, [index]);
  };

  /** Run the real pubsub handler for one publication at `recipient`. */
  const dispatch = (
    publication: GroupPublication,
    recipient: number,
    from = groupPeer(publication.sender),
  ) => {
    const event = new CustomEvent('message', {
      detail: {
        topic: publication.topic,
        data: publication.data.slice(),
        type: 'signed',
        from: { toString: () => from },
      },
    });
    pubsubs[recipient].dispatchEvent(event);
  };

  /** Await receipt at each recipient, returning per-recipient errors. */
  const deliver = async (
    publication: GroupPublication,
    recipients: readonly number[],
  ) => {
    const errors: string[] = [];
    for (const recipient of recipients) {
      if (recipient === publication.sender || !docs[recipient]) continue;
      try {
        await docs[recipient]!.receiveSecurityFrame(publication.data);
      } catch (error) {
        errors.push(`${recipient}: ${(error as Error).message}`);
      }
    }
    return errors;
  };

  /** Give a member an empty journal, store and rollback anchor for its next open. */
  const resetJournal = (index: number) => {
    journalStores[index] = new InMemoryDocumentJournalStore();
    journalAnchors[index] = new InMemoryDocumentJournalRollbackAnchor();
  };

  const take = () => publications.splice(0);
  const signRoster = () =>
    logs[0].signUpdate(coordinators[0].documentContext, roster, members[0]);

  return {
    path,
    members,
    coordinators,
    logs,
    pubsubs,
    publications,
    offline,
    open,
    doc,
    addMember,
    renew,
    applyRenewal,
    applyRole,
    dispatch,
    deliver,
    take,
    signRoster,
    nextId,
    resetJournal,
    journalStores,
    journalAnchors,
    async close() {
      await Promise.all(docs.map((document) => document?.close()));
    },
  };
}
