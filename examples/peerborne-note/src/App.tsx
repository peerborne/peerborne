import {
  assertInvitationOfferUsable,
  decodeInvitationOffer,
  SubtleCrypto,
  type InvitationOfferV1,
  type InvitationRole,
} from '@peerborne/core';
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';
import { getOrCreateIdentity, identityFingerprint } from './identity-store.js';
import {
  assertRelayMultiaddrForOrigin,
  assertTrustedRendezvous,
  type ConsumedInvitationFragment,
} from './invitation-link.js';
import {
  MAX_NOTE_CHARACTERS,
  PeerborneNoteSession,
  type NoteMembership,
  type NoteSyncStatus,
  type NoteVersion,
  type TextSelection,
} from './peerborne-note.js';
import type { SavedDocument } from './note-store.js';
import { acquireSingleTabLease, type SingleTabLease } from './single-tab.js';
import { NoteSharingError } from './sharing-error.js';

type Screen = 'booting' | 'blocked' | 'ready' | 'review' | 'note' | 'fatal';
type StorageState = 'saving' | 'saved' | 'error';

interface EditorSelection extends TextSelection {
  readonly direction: 'forward' | 'backward' | 'none';
}

interface PendingInvitation {
  readonly bytes: Uint8Array;
  readonly offer: InvitationOfferV1;
  readonly issuerFingerprint: string;
}

interface AppProps {
  readonly initialFragment: ConsumedInvitationFragment;
}

const relayMultiaddr = import.meta.env.VITE_PEERBORNE_RELAY_MULTIADDR?.trim();
const INTERRUPTED_ACCEPTANCE_KEY = 'peerborne-note-interrupted-acceptance';
const INTERRUPTED_ACCEPTANCE_NOTICE =
  'An invitation accepted in this browser was interrupted before its note was saved here. Ask the person who shared it to remove the collaborator from their note, then send you a new link.';
const INTERRUPTED_ACCEPTANCE_ERROR =
  'This browser already accepted this invitation, but the note was not saved here before the tab closed. Ask the person who shared it to remove the collaborator from their note, then send you a new link.';

function interruptedAcceptance(): string | undefined {
  try {
    return localStorage.getItem(INTERRUPTED_ACCEPTANCE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

function rememberAcceptance(documentId: string): void {
  try {
    localStorage.setItem(INTERRUPTED_ACCEPTANCE_KEY, documentId);
  } catch {}
}

function forgetAcceptance(): void {
  try {
    localStorage.removeItem(INTERRUPTED_ACCEPTANCE_KEY);
  } catch {}
}

function syncLabel(status: NoteSyncStatus): string {
  if (!status.sharing) return 'Only in this browser';
  if (status.undelivered) return 'Some edits have not reached a peer yet';
  if (!status.relayConnected) return 'Offline · reconnecting';
  return status.peers > 0
    ? `Connected · ${status.peers} ${status.peers === 1 ? 'peer' : 'peers'} online`
    : 'Connected · no peers online';
}

function secondsRemaining(expiresAtMs: number, nowMs: number): number {
  return Math.max(0, Math.ceil((expiresAtMs - nowMs) / 1000));
}

function formatRemaining(seconds: number): string {
  if (seconds <= 0) return 'expired';
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}:${remainder.toString().padStart(2, '0')}`;
}

function PageHeader({ fingerprint }: { readonly fingerprint?: string }) {
  return (
    <header className="site-header">
      <a className="brand" href="/" aria-label="Peerborne Note home">
        <span className="brand-mark" aria-hidden="true">
          <span />
          <span />
          <span />
        </span>
        <span>
          <strong>Peerborne</strong>
          <small>Note</small>
        </span>
      </a>
      {fingerprint ? (
        <div className="identity-chip" title="This browser's signing identity">
          <span className="status-dot" />
          <span>
            Browser identity
            <code>{fingerprint}</code>
          </span>
        </div>
      ) : null}
    </header>
  );
}

function Footer() {
  return (
    <footer>
      <span>Alpha · Encrypted notes, carried by peers.</span>
      <nav aria-label="Project links">
        <a href="https://peerborne.io/concepts/limitations/">About this demo</a>
        <a href="https://peerborne.io/cookbook/invitations/">
          How invitations work
        </a>
        <a href="https://github.com/Peerborne/peerborne">Source</a>
      </nav>
    </footer>
  );
}

export default function App({ initialFragment }: AppProps) {
  const [screen, setScreen] = useState<Screen>('booting');
  const [bootMessage, setBootMessage] = useState(
    'Preparing a browser identity…',
  );
  const [errorMessage, setErrorMessage] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [identityId, setIdentityId] = useState<string>();
  const [session, setSession] = useState<PeerborneNoteSession>();
  const [savedNotes, setSavedNotes] = useState<SavedDocument[]>([]);
  const [storageError, setStorageError] = useState(false);
  const [pendingInvitation, setPendingInvitation] =
    useState<PendingInvitation>();
  const pendingBytesRef = useRef<Uint8Array | undefined>(undefined);
  const leaseRef = useRef<SingleTabLease | undefined>(undefined);

  const [body, setBody] = useState('');
  const bodyRef = useRef('');
  const baseRef = useRef<NoteVersion | undefined>(undefined);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const pendingSelectionRef = useRef<EditorSelection | undefined>(undefined);
  const [localPending, setLocalPending] = useState(false);
  const [editFailed, setEditFailed] = useState(false);
  const [storageState, setStorageState] = useState<StorageState>('saved');
  const saveTimerRef = useRef<number | undefined>(undefined);
  const committingRef = useRef(false);
  const commitAgainRef = useRef(false);
  const staleRetriesRef = useRef(0);
  const commitRef = useRef<() => Promise<void>>(async () => undefined);
  const [membership, setMembership] = useState<NoteMembership>({
    founder: false,
    canShare: false,
  });
  const [syncStatus, setSyncStatus] = useState<NoteSyncStatus>({
    sharing: false,
    relayConnected: false,
    peers: 0,
    undelivered: false,
  });
  const [confirmRemoval, setConfirmRemoval] = useState(false);

  const [busy, setBusy] = useState(false);
  const [shareRole, setShareRole] = useState<InvitationRole>('editor');
  const [sharedRole, setSharedRole] = useState<InvitationRole>();
  const [shareHref, setShareHref] = useState<string>();
  const shareInputRef = useRef<HTMLInputElement>(null);
  const [shareExpiresAtMs, setShareExpiresAtMs] = useState<number>();
  const [nowMs, setNowMs] = useState(Date.now());

  useEffect(() => {
    let cancelled = false;
    let createdSession: PeerborneNoteSession | undefined;

    void (async () => {
      let unclaimedInvitationBytes: Uint8Array | undefined;
      try {
        if (
          !window.isSecureContext ||
          !window.crypto?.subtle ||
          !window.indexedDB
        ) {
          throw new Error(
            'Peerborne Note requires HTTPS or localhost with Web Crypto and IndexedDB',
          );
        }
        const lease = await acquireSingleTabLease();
        if (cancelled) {
          lease.release();
          return;
        }
        leaseRef.current = lease;
        if (!lease.acquired) {
          setScreen('blocked');
          return;
        }
        if (!lease.supported) {
          setNotice(
            'This browser cannot enforce the single-tab safety check. Keep only one Peerborne Note tab open.',
          );
        }

        setBootMessage('Restoring this browser’s signing identity…');
        const identity = await getOrCreateIdentity();
        const auth = new SubtleCrypto();
        const [fingerprint, serializedIdentity] = await Promise.all([
          identityFingerprint(identity.publicKey),
          auth.serializePublicKey(identity.publicKey),
        ]);
        if (cancelled) return;
        setIdentityId(fingerprint);

        setBootMessage('Starting encrypted local storage and peer networking…');
        createdSession = await PeerborneNoteSession.initialize(
          identity,
          relayMultiaddr,
        );
        if (cancelled) {
          await createdSession.close();
          return;
        }
        setSession(createdSession);
        const saved = await createdSession.listSavedNotes();
        setSavedNotes(saved);
        const interrupted = interruptedAcceptance();
        if (
          interrupted !== undefined &&
          saved.some((note) => note.path === interrupted)
        )
          forgetAcceptance();
        else if (interrupted !== undefined && initialFragment.kind === 'none')
          setNotice(INTERRUPTED_ACCEPTANCE_NOTICE);

        if (initialFragment.kind === 'invalid') {
          setErrorMessage(
            'This invitation link is malformed. No network connection was attempted.',
          );
          setScreen('ready');
          return;
        }
        if (initialFragment.kind === 'none') {
          setScreen('ready');
          return;
        }

        assertRelayMultiaddrForOrigin(
          relayMultiaddr,
          window.location.protocol === 'https:',
        );
        const bytes = initialFragment.bytes;
        unclaimedInvitationBytes = bytes;
        const offer = decodeInvitationOffer(bytes);
        assertInvitationOfferUsable(offer);
        assertTrustedRendezvous(offer.rendezvous, relayMultiaddr);
        if (offer.issuer === serializedIdentity) {
          bytes.fill(0);
          unclaimedInvitationBytes = undefined;
          setErrorMessage(
            'This link was created by the same browser identity. Open it on another device, browser, or browser profile.',
          );
          setScreen('ready');
          return;
        }
        const issuerPublicKey = await auth.deserializePublicKey(offer.issuer);
        pendingBytesRef.current = bytes;
        unclaimedInvitationBytes = undefined;
        setPendingInvitation({
          bytes,
          offer,
          issuerFingerprint: await identityFingerprint(issuerPublicKey),
        });
        setScreen('review');
      } catch {
        unclaimedInvitationBytes?.fill(0);
        if (cancelled) return;
        if (initialFragment.kind === 'invite') {
          setErrorMessage(
            'This invitation is invalid, expired, or uses an untrusted rendezvous. No invitation was accepted.',
          );
          setScreen(createdSession ? 'ready' : 'fatal');
        } else {
          setErrorMessage(
            'Peerborne Note could not initialize secure browser storage. Existing identity data was left unchanged.',
          );
          setScreen('fatal');
        }
      }
    })();

    return () => {
      cancelled = true;
      pendingBytesRef.current?.fill(0);
      leaseRef.current?.release();
      if (createdSession) void createdSession.close();
    };
  }, [initialFragment]);

  const updatePending = useCallback(() => {
    setLocalPending(
      committingRef.current ||
        (baseRef.current !== undefined &&
          bodyRef.current !== baseRef.current.body),
    );
  }, []);

  const showNote = (note: NoteVersion) => {
    baseRef.current = note;
    bodyRef.current = note.body;
    setBody(note.body);
    setEditFailed(false);
    setConfirmRemoval(false);
    updatePending();
  };

  const reconcile = useCallback(() => {
    const base = baseRef.current;
    if (!session || !base || committingRef.current) return;
    const element = textareaRef.current;
    const selection: EditorSelection | undefined =
      element && element === document.activeElement
        ? {
            start: element.selectionStart,
            end: element.selectionEnd,
            direction: element.selectionDirection,
          }
        : undefined;
    let rebased;
    try {
      rebased = session.rebase(base, bodyRef.current, selection);
    } catch {
      return;
    }
    baseRef.current = rebased.note;
    if (rebased.body !== bodyRef.current) {
      bodyRef.current = rebased.body;
      pendingSelectionRef.current =
        selection && rebased.selection
          ? { ...rebased.selection, direction: selection.direction }
          : undefined;
      setBody(rebased.body);
    }
    updatePending();
  }, [session, updatePending]);

  const scheduleCommit = useCallback(() => {
    if (saveTimerRef.current !== undefined) {
      window.clearTimeout(saveTimerRef.current);
    }
    saveTimerRef.current = window.setTimeout(() => {
      saveTimerRef.current = undefined;
      void commitRef.current();
    }, 350);
  }, []);

  const commit = useCallback(async () => {
    if (saveTimerRef.current !== undefined) {
      window.clearTimeout(saveTimerRef.current);
      saveTimerRef.current = undefined;
    }
    const base = baseRef.current;
    if (!session || !base) return;
    if (committingRef.current) {
      commitAgainRef.current = true;
      return;
    }
    const target = bodyRef.current;
    if (target === base.body) return;
    committingRef.current = true;
    commitAgainRef.current = false;
    updatePending();
    let retry: 'now' | 'later' | undefined;
    try {
      const update = await session.updateBody(base, target);
      if (update.kind === 'stale') {
        staleRetriesRef.current++;
        retry = staleRetriesRef.current <= 3 ? 'now' : 'later';
      } else {
        staleRetriesRef.current = 0;
        if (update.version) baseRef.current = update.version;
        setEditFailed(update.kind === 'failed');
        if (update.kind === 'failed')
          setErrorMessage(
            'The latest edit could not be saved. Keep this tab open and try again.',
          );
      }
    } catch {
      setEditFailed(true);
      setErrorMessage(
        'The latest edit could not be saved. Keep this tab open and try again.',
      );
    } finally {
      committingRef.current = false;
      reconcile();
      updatePending();
      if (retry === 'later') scheduleCommit();
      else if (retry === 'now' || commitAgainRef.current)
        void commitRef.current();
    }
  }, [reconcile, scheduleCommit, session, updatePending]);
  commitRef.current = commit;

  useEffect(() => {
    if (!session) return;
    return session.onStorage((state) => {
      setStorageState(state);
      setStorageError(state === 'error');
    });
  }, [session]);

  useEffect(() => {
    if (!session) return;
    return session.onMembership(setMembership);
  }, [session]);

  useEffect(() => {
    if (!session) return;
    return session.onNetwork(setSyncStatus);
  }, [session]);

  useEffect(() => {
    if (!session || screen !== 'note') return;
    return session.onNote(() => reconcile());
  }, [reconcile, screen, session]);

  useLayoutEffect(() => {
    const selection = pendingSelectionRef.current;
    pendingSelectionRef.current = undefined;
    const element = textareaRef.current;
    if (selection && element && element === document.activeElement)
      element.setSelectionRange(
        selection.start,
        selection.end,
        selection.direction,
      );
  }, [body]);

  useEffect(() => {
    if (screen !== 'note') return;
    const unsaved = () =>
      committingRef.current ||
      bodyRef.current !== baseRef.current?.body ||
      session?.storageStatus !== 'saved';
    const flush = () => {
      if (bodyRef.current !== baseRef.current?.body) void commitRef.current();
    };
    const beforeUnload = (event: BeforeUnloadEvent) => {
      flush();
      if (!unsaved()) return;
      event.preventDefault();
      event.returnValue = '';
    };
    const visibilityChange = () => {
      if (document.visibilityState === 'hidden') flush();
    };
    window.addEventListener('beforeunload', beforeUnload);
    document.addEventListener('visibilitychange', visibilityChange);
    return () => {
      window.removeEventListener('beforeunload', beforeUnload);
      document.removeEventListener('visibilitychange', visibilityChange);
    };
  }, [screen, session]);

  useEffect(() => {
    if (membership.collaborator && shareHref) {
      setShareHref(undefined);
      setShareExpiresAtMs(undefined);
      setSharedRole(undefined);
      setNotice('Your collaborator accepted the invitation.');
    }
  }, [membership, shareHref]);

  useEffect(() => {
    if (!shareExpiresAtMs && !pendingInvitation) return;
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [pendingInvitation, shareExpiresAtMs]);

  useEffect(() => {
    if (
      pendingInvitation &&
      secondsRemaining(pendingInvitation.offer.expiresAtMs, nowMs) === 0
    ) {
      pendingInvitation.bytes.fill(0);
      pendingBytesRef.current = undefined;
      setPendingInvitation(undefined);
      setErrorMessage('This invitation has expired and was discarded.');
      setScreen('ready');
    }
    if (
      shareHref &&
      shareExpiresAtMs !== undefined &&
      secondsRemaining(shareExpiresAtMs, nowMs) === 0
    ) {
      setShareHref(undefined);
      setShareExpiresAtMs(undefined);
      setSharedRole(undefined);
      setNotice(
        'The invitation expired. Create a new link if you still want to share.',
      );
      void session?.refreshMembership().catch(() => undefined);
    }
  }, [nowMs, pendingInvitation, session, shareExpiresAtMs, shareHref]);

  useEffect(
    () => () => {
      if (saveTimerRef.current !== undefined) {
        window.clearTimeout(saveTimerRef.current);
      }
    },
    [],
  );

  const changeBody = (nextBody: string) => {
    bodyRef.current = nextBody;
    setBody(nextBody);
    setErrorMessage(undefined);
    updatePending();
    scheduleCommit();
  };

  const flushBodyUpdate = () => {
    if (
      saveTimerRef.current !== undefined ||
      bodyRef.current !== baseRef.current?.body
    )
      void commit();
  };

  const createNote = async () => {
    if (!session) return;
    setBusy(true);
    setErrorMessage(undefined);
    try {
      showNote(await session.createNote());
      setScreen('note');
    } catch {
      if (session.currentNote) {
        showNote(session.currentNote);
        setScreen('note');
      } else setErrorMessage('A new local note could not be created.');
    } finally {
      setBusy(false);
    }
  };

  const openSavedNote = async (path: string) => {
    if (!session) return;
    setBusy(true);
    setErrorMessage(undefined);
    try {
      showNote(await session.openSavedNote(path));
      setScreen('note');
    } catch {
      setErrorMessage(
        'This saved note could not be opened. Its stored data was left unchanged.',
      );
    } finally {
      setBusy(false);
    }
  };

  const acceptInvitation = async () => {
    if (!session || !pendingInvitation) return;
    setBusy(true);
    setErrorMessage(undefined);
    const documentId = pendingInvitation.offer.documentId;
    const interrupted = interruptedAcceptance() === documentId;
    rememberAcceptance(documentId);
    try {
      const note = await session.acceptInvitation(pendingInvitation.bytes);
      forgetAcceptance();
      pendingInvitation.bytes.fill(0);
      pendingBytesRef.current = undefined;
      setPendingInvitation(undefined);
      setNotice(undefined);
      showNote(note);
      setScreen('note');
    } catch {
      if (session.currentNote) {
        pendingInvitation.bytes.fill(0);
        pendingBytesRef.current = undefined;
        setPendingInvitation(undefined);
        showNote(session.currentNote);
        setScreen('note');
      } else {
        if (!interrupted) forgetAcceptance();
        setErrorMessage(
          interrupted
            ? INTERRUPTED_ACCEPTANCE_ERROR
            : 'The invitation could not be accepted. It may be expired or claimed, or the founding browser may be offline.',
        );
      }
    } finally {
      setBusy(false);
    }
  };

  const dismissInvitation = () => {
    pendingInvitation?.bytes.fill(0);
    pendingBytesRef.current = undefined;
    setPendingInvitation(undefined);
    setErrorMessage(undefined);
    setScreen('ready');
  };

  const createShareLink = async () => {
    if (!session) return;
    setBusy(true);
    setErrorMessage(undefined);
    setNotice(
      'Connecting to the coordination relay and waiting for a reservation…',
    );
    try {
      assertRelayMultiaddrForOrigin(
        relayMultiaddr,
        window.location.protocol === 'https:',
      );
      const invitation = await session.createInvitation(
        shareRole,
        window.location.href,
        (event) => {
          if (event.type === 'retrying') {
            setNotice('The relay connection was interrupted. Retrying…');
            console.info('Peerborne Note relay retry', event);
          } else if (event.type === 'connected') {
            setNotice('Waiting for a relay reservation…');
          }
        },
      );
      setShareHref(invitation.href);
      setShareExpiresAtMs(invitation.offer.expiresAtMs);
      setSharedRole(invitation.offer.role);
      setNotice(
        'Invitation ready. Keep this tab open until the other browser accepts it.',
      );
    } catch (error) {
      setNotice(undefined);
      console.warn(
        'Peerborne Note sharing failed',
        error instanceof NoteSharingError
          ? error.diagnostic
          : { stage: 'preparation', errorType: 'OtherError' },
      );
      setErrorMessage(
        error instanceof NoteSharingError
          ? error.message
          : 'A share link could not be created. Check the relay configuration and connection, then try again.',
      );
    } finally {
      setBusy(false);
    }
  };

  const removeCollaborator = async () => {
    if (!session) return;
    setBusy(true);
    setErrorMessage(undefined);
    try {
      await session.removeCollaborator();
      setNotice(
        'The collaborator was removed. Create a new link to share this note again.',
      );
    } catch {
      setErrorMessage(
        'The collaborator could not be removed. Check the connection and try again.',
      );
    } finally {
      setConfirmRemoval(false);
      setBusy(false);
    }
  };

  const copyShareLink = async () => {
    if (!shareHref) return;
    let copied = false;
    try {
      await navigator.clipboard.writeText(shareHref);
      copied = true;
    } catch {
      shareInputRef.current?.select();
      copied = document.execCommand('copy');
    }
    setNotice(
      copied
        ? 'Invitation copied. Send it through a channel you trust.'
        : 'Select and copy the invitation manually.',
    );
  };

  const invitationSeconds = pendingInvitation
    ? secondsRemaining(pendingInvitation.offer.expiresAtMs, nowMs)
    : 0;
  const shareSeconds = shareExpiresAtMs
    ? secondsRemaining(shareExpiresAtMs, nowMs)
    : 0;
  const role = session?.role;
  const saveLabel =
    editFailed || storageState === 'error'
      ? 'Unsaved changes'
      : localPending || storageState === 'saving'
        ? 'Saving…'
        : 'Saved in this browser';

  return (
    <div className="page-shell">
      <PageHeader fingerprint={identityId} />
      <main>
        {errorMessage ? (
          <div className="message error" role="alert">
            {errorMessage}
          </div>
        ) : null}
        {storageError ? (
          <div className="message error" role="alert">
            This note could not be saved. Keep this tab open.{' '}
            <button
              onClick={() => {
                if (bodyRef.current !== baseRef.current?.body) void commit();
                else void session?.retrySave().catch(() => undefined);
              }}
            >
              Retry saving
            </button>
          </div>
        ) : null}
        {notice ? (
          <div className="message notice" role="status" aria-live="polite">
            {notice}
          </div>
        ) : null}

        {screen === 'booting' ? (
          <section className="panel centered" aria-live="polite">
            <div className="loader" aria-hidden="true" />
            <p className="eyebrow">Starting locally</p>
            <h1>Your browser is becoming a peer.</h1>
            <p>{bootMessage}</p>
          </section>
        ) : null}

        {screen === 'blocked' ? (
          <section className="panel centered">
            <p className="eyebrow">Another tab is active</p>
            <h1>Use the existing Peerborne Note tab.</h1>
            <p>
              One active tab per browser profile protects the local identity and
              saved notes from concurrent access. A collaborator needs a
              different browser profile or device.
            </p>
          </section>
        ) : null}

        {screen === 'fatal' ? (
          <section className="panel centered">
            <p className="eyebrow">Initialization stopped safely</p>
            <h1>Your existing browser identity was not replaced.</h1>
            <p>
              Check that site storage is allowed and that this page is running
              on HTTPS or localhost, then reload.
            </p>
          </section>
        ) : null}

        {screen === 'ready' ? (
          <section className="hero-grid">
            <div className="hero-copy">
              <p className="eyebrow">No account. No install.</p>
              <h1>A shared note without a plaintext database.</h1>
              <p className="lede">
                Peerborne applies edits locally, encrypts document updates in
                this browser, and shares them directly with your collaborators.
              </p>
              <button
                className="primary large"
                disabled={busy}
                onClick={() => void createNote()}
              >
                {busy ? 'Creating locally…' : 'Create a note'}
              </button>
            </div>
            <div className="boundary-card">
              <h2>Your notes</h2>
              {savedNotes.length > 0 ? (
                <ul>
                  {savedNotes.map((note) => (
                    <li key={note.path}>
                      <button
                        disabled={busy}
                        onClick={() => void openSavedNote(note.path)}
                      >
                        {note.createdAtMs === undefined
                          ? 'Open saved note'
                          : `Open note added ${new Date(
                              note.createdAtMs,
                            ).toLocaleString(undefined, {
                              dateStyle: 'medium',
                              timeStyle: 'medium',
                            })}`}
                      </button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p>
                  Create a note to start writing. Your notes will be saved in
                  this browser.
                </p>
              )}
            </div>
          </section>
        ) : null}

        {screen === 'review' && pendingInvitation ? (
          <section className="panel invitation-review">
            <p className="eyebrow">Invitation received</p>
            <h1>Review before this browser claims access.</h1>
            <div className="invitation-facts">
              <div>
                <span>Access</span>
                <strong>
                  {pendingInvitation.offer.role === 'editor'
                    ? 'Can edit'
                    : 'Read only'}
                </strong>
              </div>
              <div>
                <span>Expires in</span>
                <strong>{formatRemaining(invitationSeconds)}</strong>
              </div>
              <div>
                <span>Claimed issuer fingerprint</span>
                <code>{pendingInvitation.issuerFingerprint}</code>
              </div>
            </div>
            <div className="warning-box">
              <strong>Only continue if you trust who sent this link.</strong>
              <p>
                The first valid claimant receives the selected role and retained
                note history. The issuer signature is verified during
                acceptance.
              </p>
            </div>
            <div className="button-row">
              <button
                className="primary"
                disabled={busy || invitationSeconds === 0}
                onClick={() => void acceptInvitation()}
              >
                {busy ? 'Accepting securely…' : 'Accept invitation'}
              </button>
              <button
                className="secondary"
                disabled={busy}
                onClick={dismissInvitation}
              >
                Decline
              </button>
            </div>
          </section>
        ) : null}

        {screen === 'note' && session ? (
          <section className="workspace">
            <div className="editor-panel">
              <div className="editor-heading">
                <div>
                  <p className="eyebrow">Encrypted note</p>
                  <h1>
                    {role === 'reader' ? 'Shared with you' : 'Write locally'}
                  </h1>
                </div>
                <div className="editor-status" aria-live="polite">
                  <span>{role === 'reader' ? 'Read only' : 'Editor'}</span>
                  <span>{syncLabel(syncStatus)}</span>
                  <span>{saveLabel}</span>
                </div>
              </div>
              <label htmlFor="note-body" className="visually-hidden">
                Note text
              </label>
              <textarea
                ref={textareaRef}
                id="note-body"
                value={body}
                maxLength={MAX_NOTE_CHARACTERS}
                readOnly={role === 'reader'}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                placeholder={
                  role === 'reader'
                    ? 'Waiting for note content…'
                    : 'Start with what matters…'
                }
                onChange={(event) => changeBody(event.currentTarget.value)}
                onBlur={flushBodyUpdate}
              />
              <div className="editor-meta">
                <span>
                  {body.length.toLocaleString()} /{' '}
                  {MAX_NOTE_CHARACTERS.toLocaleString()} characters
                </span>
              </div>
            </div>

            {membership.founder && membership.collaborator ? (
              <aside className="share-panel">
                <p className="eyebrow">Shared note</p>
                <h2>One collaborator has access.</h2>
                <div className="collaborator">
                  <span>
                    {membership.collaborator.role === 'editor'
                      ? 'Can edit'
                      : 'Read only'}
                  </span>
                  <code>{membership.collaborator.fingerprint}</code>
                </div>
                <p className="collaborator-help">
                  If they never finished joining, for example because their tab
                  closed while accepting, remove them and send a new link.
                  Removal changes the note key: they keep what they already
                  received but cannot read later edits.
                </p>
                {confirmRemoval ? (
                  <div className="button-row">
                    <button
                      className="primary"
                      disabled={busy}
                      onClick={() => void removeCollaborator()}
                    >
                      {busy ? 'Removing…' : 'Confirm removal'}
                    </button>
                    <button
                      className="secondary"
                      disabled={busy}
                      onClick={() => setConfirmRemoval(false)}
                    >
                      Keep collaborator
                    </button>
                  </div>
                ) : (
                  <button
                    className="secondary full"
                    disabled={busy}
                    onClick={() => setConfirmRemoval(true)}
                  >
                    Remove collaborator
                  </button>
                )}
              </aside>
            ) : membership.canShare || shareHref ? (
              <aside className="share-panel">
                <p className="eyebrow">Share this note</p>
                <h2>Share while this tab stays open.</h2>
                {!shareHref ? (
                  <>
                    <fieldset>
                      <legend>Choose the least access they need</legend>
                      <label
                        className={
                          shareRole === 'editor'
                            ? 'role-option selected'
                            : 'role-option'
                        }
                      >
                        <input
                          type="radio"
                          name="share-role"
                          value="editor"
                          checked={shareRole === 'editor'}
                          disabled={busy}
                          onChange={() => setShareRole('editor')}
                        />
                        <span>
                          <strong>Editor</strong>
                          <small>Can read and publish changes</small>
                        </span>
                      </label>
                      <label
                        className={
                          shareRole === 'reader'
                            ? 'role-option selected'
                            : 'role-option'
                        }
                      >
                        <input
                          type="radio"
                          name="share-role"
                          value="reader"
                          checked={shareRole === 'reader'}
                          disabled={busy}
                          onChange={() => setShareRole('reader')}
                        />
                        <span>
                          <strong>Reader</strong>
                          <small>Can read but cannot publish changes</small>
                        </span>
                      </label>
                    </fieldset>
                    <button
                      className="primary full"
                      disabled={busy}
                      onClick={() => void createShareLink()}
                    >
                      {busy ? 'Preparing invitation…' : 'Create 15-minute link'}
                    </button>
                  </>
                ) : (
                  <div className="share-link">
                    <label htmlFor="share-link">Invitation link</label>
                    <p>
                      Grants {sharedRole === 'reader' ? 'read-only' : 'editing'}{' '}
                      access.
                    </p>
                    <input
                      ref={shareInputRef}
                      id="share-link"
                      value={shareHref}
                      readOnly
                      aria-describedby="share-expiry"
                    />
                    <button
                      className="primary full"
                      onClick={() => void copyShareLink()}
                    >
                      Copy invitation
                    </button>
                    <p id="share-expiry">
                      {shareSeconds > 0
                        ? `Expires in ${formatRemaining(shareSeconds)}. First valid claimant wins.`
                        : 'This invitation has expired.'}
                    </p>
                  </div>
                )}
                <div className="privacy-note">
                  <span>
                    Anyone with this link can claim the selected access until it
                    expires.
                  </span>
                </div>
              </aside>
            ) : (
              <aside className="share-panel boundary-only">
                <p className="eyebrow">Saved note</p>
                <h2>
                  {role === 'reader'
                    ? 'You can read this note.'
                    : 'You can edit this note.'}
                </h2>
                <p>
                  This note is saved in this browser. Return here to open it
                  again.
                </p>
              </aside>
            )}
          </section>
        ) : null}
      </main>
      <Footer />
    </div>
  );
}
