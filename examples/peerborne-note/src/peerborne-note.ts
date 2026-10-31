import { type Change, type Doc, splice } from '@automerge/automerge';
import {
  AutomergeACLProvider,
  AutomergeJSONSerializer,
  AutomergeKeychainProvider,
  AutomergeProvider,
} from '@peerborne/automerge';
import {
  defaultBootstrapConfig,
  defaultConfig,
  decodeInvitationOffer,
  encodeInvitationOffer,
  Peerborne,
  type PeerborneDocument,
  SubtleCrypto,
  type InvitationOfferV1,
  type InvitationRole,
} from '@peerborne/core';
import {
  assertTrustedRendezvous,
  invitationUrl,
  rendezvousForCircuitReservation,
} from './invitation-link.js';
import {
  getNoteIdentity,
  NoteStore,
  type BrowserIdentity,
} from './note-store.js';

export const MAX_NOTE_CHARACTERS = 20_000;

export interface NoteData {
  body?: string;
}

export interface NoteSnapshot {
  readonly body: string;
}

type NoteChange = (document: NoteData) => void;
type NotePeerborne = Peerborne<
  Doc<NoteData>,
  Change[],
  NoteChange,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
type NoteDocument = PeerborneDocument<
  Doc<NoteData>,
  Change[],
  NoteChange,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;

const NOTE_SUBSCRIBER_ID = 'peerborne-note-ui';
const PEER_SUBSCRIBER_ID = 'peerborne-note-network-ui';
const RESERVATION_TIMEOUT_MS = 45_000;

function snapshot(document: Doc<NoteData>): NoteSnapshot {
  return { body: typeof document.body === 'string' ? document.body : '' };
}

function applyTextEdit(document: NoteData, next: string): void {
  const previous = typeof document.body === 'string' ? document.body : '';
  if (typeof document.body !== 'string') {
    document.body = next;
    return;
  }
  let prefix = 0;
  while (
    prefix < previous.length &&
    prefix < next.length &&
    previous[prefix] === next[prefix]
  ) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < previous.length - prefix &&
    suffix < next.length - prefix &&
    previous[previous.length - 1 - suffix] === next[next.length - 1 - suffix]
  ) {
    suffix++;
  }
  splice(
    document as unknown as Doc<NoteData>,
    ['body'],
    prefix,
    previous.length - prefix - suffix,
    next.slice(prefix, next.length - suffix),
  );
}

async function waitForCircuitAddress(
  peerborne: NotePeerborne,
  relayMultiaddr: string,
): Promise<string> {
  const peerId = peerborne.peerId.toString();
  const deadline = Date.now() + RESERVATION_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const rendezvous = rendezvousForCircuitReservation(
      peerborne.libp2p.getMultiaddrs().map((address) => address.toString()),
      relayMultiaddr,
      peerId,
    );
    if (rendezvous) return rendezvous;
    await new Promise<void>((resolve) => window.setTimeout(resolve, 250));
  }
  throw new Error('The relay reservation was not observed in time');
}

export class PeerborneNoteSession {
  private readonly peerborne: NotePeerborne;
  private document?: NoteDocument;
  private documentRole?: InvitationRole;
  private founder = false;
  private founderKemKeyPair?: CryptoKeyPair;
  private recipientKemKeyPair?: CryptoKeyPair;
  private readonly noteListeners = new Set<(note: NoteSnapshot) => void>();
  private readonly networkListeners = new Set<(peerCount: number) => void>();
  private readonly storageListeners = new Set<
    (state: 'saving' | 'saved' | 'error') => void
  >();
  private readonly store: NoteStore;
  private revision = 0;
  private writes: Promise<void> = Promise.resolve();
  private pendingSaves = 0;
  private pendingChanges = 0;
  private storageFailed = false;

  private constructor(
    private readonly identity: BrowserIdentity,
    private readonly owner: string,
    private readonly relayMultiaddr?: string,
  ) {
    const serializer = new AutomergeJSONSerializer();
    this.peerborne = new Peerborne(
      identity.signing.privateKey,
      identity.signing.publicKey,
      new AutomergeProvider<NoteData>(),
      serializer,
      serializer,
      serializer,
      new SubtleCrypto(),
      new AutomergeACLProvider(),
      new AutomergeKeychainProvider(),
    );
    this.store = new NoteStore(identity, owner);
  }

  static async initialize(
    identity: CryptoKeyPair,
    relayMultiaddr?: string,
  ): Promise<PeerborneNoteSession> {
    const retainedIdentity = await getNoteIdentity(identity);
    const owner = await new SubtleCrypto().serializePublicKey(
      identity.publicKey,
    );
    const session = new PeerborneNoteSession(
      retainedIdentity,
      owner,
      relayMultiaddr,
    );
    const config = defaultConfig(defaultBootstrapConfig([]));
    config.enableTopicValidators = true;
    await session.peerborne.initialize(config);
    session.peerborne.subscribeToPeerConnect(PEER_SUBSCRIBER_ID, () => {
      session.emitNetwork();
    });
    session.peerborne.subscribeToPeerDisconnect(PEER_SUBSCRIBER_ID, () => {
      session.emitNetwork();
    });
    return session;
  }

  get role(): InvitationRole | undefined {
    return this.documentRole;
  }

  get isFounder(): boolean {
    return this.founder;
  }

  get storageStatus(): 'saving' | 'saved' | 'error' {
    return this.storageState();
  }

  get currentNote(): NoteSnapshot | undefined {
    return this.document ? snapshot(this.document.document) : undefined;
  }

  onNote(listener: (note: NoteSnapshot) => void): () => void {
    this.noteListeners.add(listener);
    const current = this.currentNote;
    if (current) listener(current);
    return () => this.noteListeners.delete(listener);
  }

  onNetwork(listener: (peerCount: number) => void): () => void {
    this.networkListeners.add(listener);
    listener(new Set(this.peerborne.peerIds).size);
    return () => this.networkListeners.delete(listener);
  }

  onStorage(
    listener: (state: 'saving' | 'saved' | 'error') => void,
  ): () => void {
    this.storageListeners.add(listener);
    listener(this.storageState());
    return () => {
      this.storageListeners.delete(listener);
    };
  }

  listSavedNotes(): Promise<string[]> {
    return this.store.listDocuments();
  }

  async openSavedNote(path: string): Promise<NoteSnapshot> {
    if (this.document) throw new Error('A note is already open');
    const saved = await this.store.load(path);
    if (!saved) throw new Error('No saved note is available in this browser');
    const document = this.peerborne.doc(path);
    try {
      await document.setKemKeyPair(this.identity.kem);
      await document.restoreCheckpoint(saved.checkpoint);
      const auth = new SubtleCrypto();
      const writerIds = await Promise.all(
        (await document.getWriters()).map((key) =>
          auth.serializePublicKey(key),
        ),
      );
      const role: InvitationRole = writerIds.includes(this.owner)
        ? 'editor'
        : 'reader';
      await document.open();
      this.revision = saved.revision;
      this.activateDocument(document, role, false);
      return snapshot(document.document);
    } catch (error) {
      await document.close().catch(() => undefined);
      throw error;
    } finally {
      saved.checkpoint.payload.fill(0);
      saved.checkpoint.signature.fill(0);
    }
  }

  async createNote(): Promise<NoteSnapshot> {
    if (this.document) throw new Error('A note is already open');
    const document = this.peerborne.doc(`/notes/${crypto.randomUUID()}`);
    await document.setKemKeyPair(this.identity.kem);
    await document.create();
    document.historyVisibility = 'full_history';
    await document.change((draft) => {
      draft.body = '';
    }, 'Create note');
    this.activateDocument(document, 'editor', true);
    await this.persistDocument();
    return snapshot(document.document);
  }

  async createInvitation(
    role: InvitationRole,
    currentHref: string,
  ): Promise<{ readonly href: string; readonly offer: InvitationOfferV1 }> {
    const document = this.requireDocument();
    if (!this.founder) {
      throw new Error('Only the founding browser can invite a collaborator');
    }
    if (!this.relayMultiaddr) {
      throw new Error('No relay is configured');
    }
    if (!this.founderKemKeyPair) {
      this.founderKemKeyPair = this.identity.kem;
      await document.setKemKeyPair(this.founderKemKeyPair);
    }
    await this.peerborne.connect([this.relayMultiaddr]);
    const rendezvous = await waitForCircuitAddress(
      this.peerborne,
      this.relayMultiaddr,
    );
    assertTrustedRendezvous([rendezvous], this.relayMultiaddr);
    const offer = await document.createInvitation({
      role,
      rendezvous: [rendezvous],
    });
    return {
      href: invitationUrl(encodeInvitationOffer(offer), currentHref),
      offer,
    };
  }

  async acceptInvitation(encodedOffer: Uint8Array): Promise<NoteSnapshot> {
    if (this.document) throw new Error('A note is already open');
    if (!this.recipientKemKeyPair) {
      this.recipientKemKeyPair = this.identity.kem;
    }
    const offer = decodeInvitationOffer(encodedOffer);
    const document = await this.peerborne.acceptInvitation(
      offer,
      this.recipientKemKeyPair,
    );
    this.activateDocument(document, offer.role, false);
    await this.persistDocument();
    return snapshot(document.document);
  }

  async updateBody(body: string): Promise<void> {
    if (body.length > MAX_NOTE_CHARACTERS) {
      throw new Error(`Note exceeds ${MAX_NOTE_CHARACTERS} characters`);
    }
    if (this.documentRole !== 'editor') {
      throw new Error('This invitation grants read-only access');
    }
    const document = this.requireDocument();
    this.pendingChanges++;
    this.emitStorage();
    try {
      await document.change((draft) => applyTextEdit(draft, body), 'Edit note');
      await this.persistDocument();
    } finally {
      this.pendingChanges--;
      this.emitStorage();
    }
  }

  async retrySave(): Promise<void> {
    await this.persistDocument();
  }

  private storageState(): 'saving' | 'saved' | 'error' {
    return this.storageFailed
      ? 'error'
      : this.pendingSaves + this.pendingChanges > 0
        ? 'saving'
        : 'saved';
  }

  private emitStorage(): void {
    for (const listener of this.storageListeners) listener(this.storageState());
  }

  private persistDocument(): Promise<void> {
    const document = this.requireDocument();
    this.pendingSaves++;
    this.emitStorage();
    const operation = this.writes
      .catch(() => undefined)
      .then(async () => {
        const checkpoint = await document.exportCheckpoint();
        try {
          this.revision = await this.store.save(
            document.documentPath,
            true,
            checkpoint,
            this.revision,
          );
        } finally {
          checkpoint.payload.fill(0);
          checkpoint.signature.fill(0);
        }
      });
    this.writes = operation;
    return operation
      .then(
        () => {
          this.storageFailed = false;
        },
        (error) => {
          this.storageFailed = true;
          throw error;
        },
      )
      .finally(() => {
        this.pendingSaves--;
        this.emitStorage();
      });
  }

  async close(): Promise<void> {
    this.peerborne.unsubscribeFromPeerConnect(PEER_SUBSCRIBER_ID);
    this.peerborne.unsubscribeFromPeerDisconnect(PEER_SUBSCRIBER_ID);
    if (this.document) {
      this.document.unsubscribe(NOTE_SUBSCRIBER_ID);
      await this.writes.catch(() => undefined);
      await this.document.close();
      this.document = undefined;
    }
    this.noteListeners.clear();
    this.networkListeners.clear();
    this.storageListeners.clear();
    await this.peerborne.heliaNode.stop().catch(() => undefined);
  }

  private requireDocument(): NoteDocument {
    if (!this.document) throw new Error('No note is open');
    return this.document;
  }

  private activateDocument(
    document: NoteDocument,
    role: InvitationRole,
    founder: boolean,
  ): void {
    this.document = document;
    this.documentRole = role;
    this.founder = founder;
    document.subscribe(
      NOTE_SUBSCRIBER_ID,
      (current) => {
        this.emitNote(snapshot(current));
        void this.persistDocument().catch(() => undefined);
      },
      'all',
    );
    this.emitNote(snapshot(document.document));
  }

  private emitNote(note: NoteSnapshot): void {
    for (const listener of this.noteListeners) listener(note);
  }

  private emitNetwork(): void {
    const count = new Set(this.peerborne.peerIds).size;
    for (const listener of this.networkListeners) listener(count);
  }
}
