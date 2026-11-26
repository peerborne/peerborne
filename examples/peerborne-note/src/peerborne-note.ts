import {
  type Change,
  type Doc,
  decodeChange,
  getHeads,
  getLastLocalChange,
  view,
} from '@automerge/automerge';
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
  type ConnectionProgress,
} from '@peerborne/core';
import {
  assertTrustedRendezvous,
  invitationUrl,
  isConfiguredRelayAddress,
  rendezvousForCircuitReservation,
} from './invitation-link.js';
import { identityFingerprint } from './identity-store.js';
import {
  getNoteIdentity,
  NoteStore,
  type BrowserIdentity,
  type SavedDocument,
} from './note-store.js';
import {
  applyTextEdit,
  noteBody,
  noteVersion,
  rebaseText,
  sameHeads,
  type NoteData,
  type NoteVersion,
  type RebasedText,
  type TextSelection,
} from './note-text.js';
import { NoteSharingError } from './sharing-error.js';

export type { NoteVersion, TextSelection } from './note-text.js';

export const MAX_NOTE_CHARACTERS = 20_000;

export interface NoteCollaborator {
  readonly fingerprint: string;
  readonly role: InvitationRole;
}

export interface NoteMembership {
  readonly founder: boolean;
  readonly canShare: boolean;
  readonly collaborator?: NoteCollaborator;
}

export interface NoteSyncStatus {
  readonly sharing: boolean;
  readonly relayConnected: boolean;
  readonly peers: number;
  readonly undelivered: boolean;
}

export type StorageStatus = 'saving' | 'saved' | 'error' | 'evicted';

export type BodyUpdate =
  | { readonly kind: 'stale' }
  | { readonly kind: 'saved'; readonly version: NoteVersion }
  | { readonly kind: 'failed'; readonly version?: NoteVersion };

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

class StaleNoteBase extends Error {}

function lastLocalChange(document: Doc<NoteData>) {
  const change = getLastLocalChange(document);
  return change && decodeChange(change);
}

function sameMembership(a: NoteMembership, b: NoteMembership): boolean {
  return (
    a.founder === b.founder &&
    a.canShare === b.canShare &&
    a.collaborator?.fingerprint === b.collaborator?.fingerprint &&
    a.collaborator?.role === b.collaborator?.role
  );
}

async function waitForCircuitAddress(
  peerborne: NotePeerborne,
  relayMultiaddr: string,
  signal: AbortSignal,
): Promise<string> {
  const peerId = peerborne.peerId.toString();
  while (true) {
    signal.throwIfAborted();
    const rendezvous = rendezvousForCircuitReservation(
      peerborne.libp2p.getMultiaddrs().map((address) => address.toString()),
      relayMultiaddr,
      peerId,
    );
    if (rendezvous) return rendezvous;
    await new Promise<void>((resolve, reject) => {
      const abort = () => {
        clearTimeout(timer);
        reject(signal.reason);
      };
      const timer = setTimeout(() => {
        signal.removeEventListener('abort', abort);
        resolve();
      }, 250);
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) abort();
    });
  }
}

export class PeerborneNoteSession {
  private readonly peerborne: NotePeerborne;
  private document?: NoteDocument;
  private documentRole?: InvitationRole;
  private membership: NoteMembership = { founder: false, canShare: false };
  private membershipRefresh?: Promise<void>;
  private membershipOutdated = false;
  private founderKemKeyPair?: CryptoKeyPair;
  private recipientKemKeyPair?: CryptoKeyPair;
  private readonly noteListeners = new Set<(note: NoteVersion) => void>();
  private readonly networkListeners = new Set<
    (status: NoteSyncStatus) => void
  >();
  private readonly membershipListeners = new Set<
    (membership: NoteMembership) => void
  >();
  private readonly storageListeners = new Set<(state: StorageStatus) => void>();
  private readonly store: NoteStore;
  private readonly relayPeerId?: string;
  private revision = 0;
  private writes: Promise<void> = Promise.resolve();
  private pendingSaves = 0;
  private pendingChanges = 0;
  private storageFailed = false;
  private storageEvicted = false;
  private deliveryFailures = 0;
  private undelivered = false;
  private sharingActive = false;
  private sharingTimer?: ReturnType<typeof setTimeout>;
  private sharingTask?: Promise<void>;
  private sharingController?: AbortController;
  private sharingFailed = false;

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
    this.relayPeerId = relayMultiaddr?.slice(
      relayMultiaddr.lastIndexOf('/p2p/') + 5,
    );
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
    const libp2p = config.helia?.libp2p;
    config.helia = {
      ...config.helia,
      libp2p: {
        ...libp2p,
        connectionGater: {
          ...libp2p?.connectionGater,
          denyDialMultiaddr: async (address) =>
            !isConfiguredRelayAddress(address.toString(), relayMultiaddr),
        },
      },
    };
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

  get storageStatus(): StorageStatus {
    return this.storageState();
  }

  get currentNote(): NoteVersion | undefined {
    return this.document ? noteVersion(this.document.document) : undefined;
  }

  onNote(listener: (note: NoteVersion) => void): () => void {
    this.noteListeners.add(listener);
    const current = this.currentNote;
    if (current) listener(current);
    return () => this.noteListeners.delete(listener);
  }

  onNetwork(listener: (status: NoteSyncStatus) => void): () => void {
    this.networkListeners.add(listener);
    listener(this.syncStatus());
    return () => this.networkListeners.delete(listener);
  }

  onMembership(listener: (membership: NoteMembership) => void): () => void {
    this.membershipListeners.add(listener);
    listener(this.membership);
    return () => this.membershipListeners.delete(listener);
  }

  onStorage(listener: (state: StorageStatus) => void): () => void {
    this.storageListeners.add(listener);
    listener(this.storageState());
    return () => {
      this.storageListeners.delete(listener);
    };
  }

  listSavedNotes(): Promise<SavedDocument[]> {
    return this.store.listDocuments();
  }

  async openSavedNote(path: string): Promise<NoteVersion> {
    if (this.document) throw new Error('A note is already open');
    const saved = await this.store.load(path);
    if (!saved) throw new Error('No saved note is available in this browser');
    const document = this.peerborne.doc(path);
    try {
      await document.setKemKeyPair(this.identity.kem);
      await document.restorePlaintextCheckpoint(saved.checkpoint);
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
      this.activateDocument(document, role);
      await this.refreshMembership();
      if (this.membership.collaborator) this.startSharing();
      return noteVersion(document.document);
    } catch (error) {
      await document.close().catch(() => undefined);
      throw error;
    } finally {
      saved.checkpoint.payload.fill(0);
      saved.checkpoint.signature.fill(0);
    }
  }

  async createNote(): Promise<NoteVersion> {
    if (this.document) throw new Error('A note is already open');
    const document = this.peerborne.doc(`/notes/${crypto.randomUUID()}`);
    await document.setKemKeyPair(this.identity.kem);
    await document.create();
    document.historyVisibility = 'full_history';
    await document.change((draft) => {
      draft.body = '';
    }, 'Create note');
    this.activateDocument(document, 'editor');
    try {
      await this.persistDocument();
    } finally {
      await this.refreshMembership().catch(() => undefined);
    }
    return noteVersion(document.document);
  }

  async createInvitation(
    role: InvitationRole,
    currentHref: string,
    onProgress?: (event: ConnectionProgress) => void | Promise<void>,
  ): Promise<{ readonly href: string; readonly offer: InvitationOfferV1 }> {
    const document = this.requireDocument();
    if (!this.membership.canShare) {
      throw new Error('Only the founding browser can invite a collaborator');
    }
    if (!this.relayMultiaddr) {
      throw new Error('No relay is configured');
    }
    if (!this.founderKemKeyPair) {
      this.founderKemKeyPair = this.identity.kem;
      await document.setKemKeyPair(this.founderKemKeyPair);
    }
    const started = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(
      () =>
        controller.abort(
          new DOMException('Relay readiness deadline exceeded', 'TimeoutError'),
        ),
      RESERVATION_TIMEOUT_MS,
    );
    let lastProgress: ConnectionProgress | undefined;
    let rendezvous: string;
    try {
      try {
        await this.peerborne.connect([this.relayMultiaddr], {
          signal: controller.signal,
          maxAttempts: 3,
          retryDelayMs: 5000,
          onProgress: (event) => {
            lastProgress = event;
            return onProgress?.(event);
          },
        });
      } catch (error) {
        throw new NoteSharingError(
          'relay-connection',
          error,
          lastProgress?.errorType ?? 'OtherError',
          lastProgress?.attempt ?? 0,
          Math.round(performance.now() - started),
        );
      }
      try {
        rendezvous = await waitForCircuitAddress(
          this.peerborne,
          this.relayMultiaddr,
          controller.signal,
        );
      } catch (error) {
        throw new NoteSharingError(
          'relay-reservation',
          error,
          controller.signal.aborted ? 'TimeoutError' : 'OtherError',
          lastProgress?.attempt ?? 0,
          Math.round(performance.now() - started),
        );
      }
    } finally {
      clearTimeout(timeout);
    }
    assertTrustedRendezvous([rendezvous], this.relayMultiaddr);
    this.startSharing();
    let offer: InvitationOfferV1;
    try {
      offer = await document.createInvitation({
        role,
        rendezvous: [rendezvous],
        beforeAcceptance: async () => {
          await this.persistDocument();
          void this.refreshMembership().catch(() => undefined);
        },
      });
    } catch (error) {
      throw new NoteSharingError(
        'invitation',
        error,
        'OtherError',
        lastProgress?.attempt ?? 0,
        Math.round(performance.now() - started),
      );
    }
    return {
      href: invitationUrl(encodeInvitationOffer(offer), currentHref),
      offer,
    };
  }

  async acceptInvitation(encodedOffer: Uint8Array): Promise<NoteVersion> {
    if (this.document) throw new Error('A note is already open');
    if (!this.recipientKemKeyPair) {
      this.recipientKemKeyPair = this.identity.kem;
    }
    const offer = decodeInvitationOffer(encodedOffer);
    const document = await this.peerborne.acceptInvitation(
      offer,
      this.recipientKemKeyPair,
    );
    this.activateDocument(document, offer.role);
    this.startSharing();
    try {
      await this.persistDocument();
    } finally {
      await this.refreshMembership().catch(() => undefined);
    }
    return noteVersion(document.document);
  }

  async removeCollaborator(): Promise<void> {
    const document = this.requireDocument();
    const { founder, collaborators } = await this.readMembers(document);
    if (!founder) {
      throw new Error('Only the founding browser can remove a collaborator');
    }
    try {
      for (const collaborator of collaborators) {
        if (collaborator.writer)
          await document.removeWriter(collaborator.key, {
            requireRemainingWriter: true,
          });
        await document.removeReader(collaborator.key);
      }
    } finally {
      await this.persistDocument().catch(() => undefined);
      await this.refreshMembership();
    }
  }

  refreshMembership(): Promise<void> {
    if (this.membershipRefresh) {
      this.membershipOutdated = true;
      return this.membershipRefresh;
    }
    const refresh = (async () => {
      do {
        this.membershipOutdated = false;
        const next = await this.readMembership();
        if (!sameMembership(next, this.membership)) {
          this.membership = next;
          for (const listener of this.membershipListeners) listener(next);
        }
      } while (this.membershipOutdated);
    })().finally(() => {
      this.membershipRefresh = undefined;
    });
    this.membershipRefresh = refresh;
    return refresh;
  }

  rebase(
    base: NoteVersion,
    text: string,
    selection?: TextSelection,
  ): RebasedText {
    return rebaseText(this.requireDocument().document, base, text, selection);
  }

  async updateBody(base: NoteVersion, body: string): Promise<BodyUpdate> {
    if (body.length > MAX_NOTE_CHARACTERS) {
      throw new Error(`Note exceeds ${MAX_NOTE_CHARACTERS} characters`);
    }
    if (this.documentRole !== 'editor') {
      throw new Error('This invitation grants read-only access');
    }
    const document = this.requireDocument();
    if (body === base.body) return { kind: 'saved', version: base };
    this.pendingChanges++;
    this.emitStorage();
    try {
      const previous = lastLocalChange(document.document)?.hash;
      const failures = this.deliveryFailures;
      let failure: { error: unknown } | undefined;
      try {
        await document.change((draft) => {
          if (!sameHeads(getHeads(document.document), base.heads))
            throw new StaleNoteBase();
          applyTextEdit(draft, base.body, body);
        }, 'Edit note');
      } catch (error) {
        if (error instanceof StaleNoteBase) return { kind: 'stale' };
        failure = { error };
      }
      const latest = lastLocalChange(document.document);
      const version =
        latest &&
        latest.hash !== previous &&
        noteBody(view(document.document, [latest.hash])) === body
          ? { body, heads: [latest.hash] }
          : undefined;
      if (failure || !version) {
        await this.detectEviction();
        return { kind: 'failed', version };
      }
      if (this.undelivered && this.deliveryFailures === failures) {
        this.undelivered = false;
        this.emitNetwork();
      }
      await this.persistDocument().catch(() => undefined);
      return { kind: 'saved', version };
    } finally {
      this.pendingChanges--;
      this.emitStorage();
    }
  }

  async retrySave(): Promise<void> {
    await this.persistDocument();
  }

  private storageState(): StorageStatus {
    return this.storageEvicted
      ? 'evicted'
      : this.storageFailed
        ? 'error'
        : this.pendingSaves + this.pendingChanges > 0
          ? 'saving'
          : 'saved';
  }

  /**
   * A saved note whose record is gone was removed by the browser, as when it
   * evicts or clears site data, which also removes the browser identity.
   */
  private async detectEviction(): Promise<void> {
    const document = this.document;
    if (!document || this.revision < 1 || this.storageEvicted) return;
    let stored: boolean;
    try {
      stored = await this.store.has(document.documentPath);
    } catch {
      return;
    }
    if (stored) return;
    this.storageEvicted = true;
    this.emitStorage();
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
        const checkpoint = await document.exportPlaintextCheckpoint();
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
        async (error) => {
          this.storageFailed = true;
          await this.detectEviction();
          throw error;
        },
      )
      .finally(() => {
        this.pendingSaves--;
        this.emitStorage();
      });
  }

  async close(): Promise<void> {
    this.sharingActive = false;
    clearTimeout(this.sharingTimer);
    this.sharingController?.abort();
    await this.sharingTask?.catch(() => undefined);
    this.peerborne.unsubscribeFromPeerConnect(PEER_SUBSCRIBER_ID);
    this.peerborne.unsubscribeFromPeerDisconnect(PEER_SUBSCRIBER_ID);
    if (this.document) {
      this.document.unsubscribe(NOTE_SUBSCRIBER_ID);
      this.document.unsubscribeDeliveryFailures(NOTE_SUBSCRIBER_ID);
      await this.writes.catch(() => undefined);
      await this.document.close();
      this.document = undefined;
    }
    this.noteListeners.clear();
    this.networkListeners.clear();
    this.membershipListeners.clear();
    this.storageListeners.clear();
    await this.peerborne.heliaNode.stop().catch(() => undefined);
  }

  private startSharing(): void {
    if (this.sharingActive || !this.relayMultiaddr) return;
    this.sharingActive = true;
    this.emitNetwork();
    const maintain = (): void => {
      if (!this.sharingActive) return;
      this.sharingTask = this.reconnectSharing().finally(() => {
        if (!this.sharingActive) return;
        void this.refreshMembership().catch(() => undefined);
        this.sharingTimer = setTimeout(
          maintain,
          this.sharingFailed ? 30_000 : 5000,
        );
      });
    };
    maintain();
  }

  private async reconnectSharing(): Promise<void> {
    const controller = new AbortController();
    this.sharingController = controller;
    const timeout = setTimeout(
      () => controller.abort(),
      RESERVATION_TIMEOUT_MS,
    );
    let errorType: ConnectionProgress['errorType'];
    try {
      const connected = this.peerborne.libp2p
        .getConnections()
        .some(
          (connection) =>
            connection.remotePeer.toString() === this.relayPeerId &&
            connection.status === 'open',
        );
      if (!connected)
        await this.peerborne.connect([this.relayMultiaddr!], {
          signal: controller.signal,
          maxAttempts: 3,
          retryDelayMs: 5000,
          onProgress: (event) => {
            errorType = event.errorType;
          },
        });
      if (!this.sharingActive) return;
      // Reconnecting is enough: Peerborne's automatic catch-up asks for
      // missed updates when the relay re-announces the note's topic.
      this.sharingFailed = false;
    } catch {
      if (this.sharingActive && !this.sharingFailed) {
        console.warn('Peerborne Note sharing reconnect failed', {
          errorType: errorType ?? 'OtherError',
        });
        this.sharingFailed = true;
      }
    } finally {
      clearTimeout(timeout);
      if (this.sharingController === controller)
        this.sharingController = undefined;
    }
  }

  private requireDocument(): NoteDocument {
    if (!this.document) throw new Error('No note is open');
    return this.document;
  }

  private async readMembers(document: NoteDocument): Promise<{
    founder: boolean;
    collaborators: { key: CryptoKey; writer: boolean }[];
  }> {
    const auth = new SubtleCrypto();
    const [writers, readers] = await Promise.all([
      document.getWriters(),
      document.getReaders(),
    ]);
    const writerIds = new Set(
      await Promise.all(writers.map((key) => auth.serializePublicKey(key))),
    );
    const others = new Map<string, CryptoKey>();
    for (const key of [...readers, ...writers]) {
      const id = await auth.serializePublicKey(key);
      if (id !== this.owner && !others.has(id)) others.set(id, key);
    }
    return {
      founder:
        writerIds.has(this.owner) && document.invitationEpoch === undefined,
      collaborators: [...others].map(([id, key]) => ({
        key,
        writer: writerIds.has(id),
      })),
    };
  }

  private async readMembership(): Promise<NoteMembership> {
    const document = this.document;
    if (!document) return { founder: false, canShare: false };
    const { founder, collaborators } = await this.readMembers(document);
    let canShare = false;
    if (founder && collaborators.length === 0) {
      try {
        await document.assertCanCreateInitialInvitation();
        canShare = true;
      } catch {}
    }
    const [collaborator] = collaborators;
    return {
      founder,
      canShare,
      collaborator: collaborator && {
        fingerprint: await identityFingerprint(collaborator.key),
        role: collaborator.writer ? 'editor' : 'reader',
      },
    };
  }

  private activateDocument(document: NoteDocument, role: InvitationRole): void {
    this.document = document;
    this.documentRole = role;
    document.subscribe(
      NOTE_SUBSCRIBER_ID,
      (current) => {
        this.emitNote(noteVersion(current));
        void this.persistDocument().catch(() => undefined);
      },
      'all',
    );
    document.subscribeDeliveryFailures(NOTE_SUBSCRIBER_ID, () => {
      this.deliveryFailures++;
      this.undelivered = true;
      this.emitNetwork();
    });
    this.emitNote(noteVersion(document.document));
  }

  private emitNote(note: NoteVersion): void {
    for (const listener of this.noteListeners) listener(note);
  }

  private syncStatus(): NoteSyncStatus {
    const peers = new Set(this.peerborne.peerIds);
    const relayConnected =
      this.relayPeerId !== undefined && peers.has(this.relayPeerId);
    return {
      sharing: this.sharingActive,
      relayConnected,
      peers: peers.size - (relayConnected ? 1 : 0),
      undelivered: this.undelivered,
    };
  }

  private emitNetwork(): void {
    const status = this.syncStatus();
    for (const listener of this.networkListeners) listener(status);
  }
}
