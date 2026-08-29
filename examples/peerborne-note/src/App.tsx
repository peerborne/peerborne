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
} from './peerborne-note.js';
import { acquireSingleTabLease, type SingleTabLease } from './single-tab.js';

type Screen = 'booting' | 'blocked' | 'ready' | 'review' | 'note' | 'fatal';
type SaveState = 'idle' | 'pending' | 'saved';

interface PendingInvitation {
  readonly bytes: Uint8Array;
  readonly offer: InvitationOfferV1;
  readonly issuerFingerprint: string;
}

interface AppProps {
  readonly initialFragment: ConsumedInvitationFragment;
}

const relayMultiaddr = import.meta.env.VITE_PEERBORNE_RELAY_MULTIADDR?.trim();

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

function SafetyNotice() {
  return (
    <aside className="safety-notice" aria-label="Initial release limitations">
      <strong>Initial release demo</strong>
      <span>
        Early-stage and not production-ready. Do not use it for sensitive or
        durable information.
      </span>
    </aside>
  );
}

function Footer() {
  return (
    <footer>
      <span>Encrypted local-first state, carried by peers.</span>
      <nav aria-label="Project links">
        <a href="https://peerborne.io/concepts/limitations/">Limitations</a>
        <a href="https://peerborne.io/cookbook/invitations/">How invitations work</a>
        <a href="https://github.com/Peerborne/peerborne">Source</a>
      </nav>
    </footer>
  );
}

export default function App({ initialFragment }: AppProps) {
  const [screen, setScreen] = useState<Screen>('booting');
  const [bootMessage, setBootMessage] = useState('Preparing a browser identity…');
  const [errorMessage, setErrorMessage] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [identityId, setIdentityId] = useState<string>();
  const [session, setSession] = useState<PeerborneNoteSession>();
  const [pendingInvitation, setPendingInvitation] = useState<PendingInvitation>();
  const pendingBytesRef = useRef<Uint8Array | undefined>(undefined);
  const leaseRef = useRef<SingleTabLease | undefined>(undefined);

  const [body, setBody] = useState('');
  const bodyRef = useRef('');
  const [peerCount, setPeerCount] = useState(0);
  const [saveState, setSaveState] = useState<SaveState>('idle');
  const saveTimerRef = useRef<number | undefined>(undefined);
  const editVersionRef = useRef(0);
  const editingRef = useRef(false);

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
        if (!window.isSecureContext || !window.crypto?.subtle || !window.indexedDB) {
          throw new Error('Peerborne Note requires HTTPS or localhost with Web Crypto and IndexedDB');
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
          setNotice('This browser cannot enforce the single-tab safety check. Keep only one Peerborne Note tab open.');
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

        if (initialFragment.kind === 'invalid') {
          setErrorMessage('This invitation link is malformed. No network connection was attempted.');
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

  useEffect(() => {
    if (!session) return;
    return session.onNetwork(setPeerCount);
  }, [session]);

  useEffect(() => {
    if (!session || screen !== 'note') return;
    return session.onNote((note) => {
      if (editingRef.current) return;
      bodyRef.current = note.body;
      setBody(note.body);
    });
  }, [screen, session]);

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
    }
  }, [nowMs, pendingInvitation, shareExpiresAtMs, shareHref]);

  useEffect(() => () => {
    if (saveTimerRef.current !== undefined) {
      window.clearTimeout(saveTimerRef.current);
    }
  }, []);

  const persistBody = useCallback(async (
    nextBody: string,
    version: number,
  ) => {
    if (!session) return;
    try {
      await session.updateBody(nextBody);
      if (editVersionRef.current === version) {
        editingRef.current = false;
        const current = session.currentNote?.body ?? nextBody;
        bodyRef.current = current;
        setBody(current);
        setSaveState('saved');
      }
    } catch {
      if (editVersionRef.current === version) {
        editingRef.current = false;
        setSaveState('idle');
        setErrorMessage('The latest edit could not be applied locally.');
      }
    }
  }, [session]);

  const scheduleBodyUpdate = (nextBody: string) => {
    bodyRef.current = nextBody;
    setBody(nextBody);
    setErrorMessage(undefined);
    setSaveState('pending');
    editingRef.current = true;
    const version = ++editVersionRef.current;
    if (saveTimerRef.current !== undefined) {
      window.clearTimeout(saveTimerRef.current);
    }
    saveTimerRef.current = window.setTimeout(() => {
      saveTimerRef.current = undefined;
      void persistBody(nextBody, version);
    }, 350);
  };

  const flushBodyUpdate = () => {
    if (saveTimerRef.current === undefined) return;
    window.clearTimeout(saveTimerRef.current);
    saveTimerRef.current = undefined;
    void persistBody(bodyRef.current, editVersionRef.current);
  };

  const createNote = async () => {
    if (!session) return;
    setBusy(true);
    setErrorMessage(undefined);
    try {
      const note = await session.createNote();
      bodyRef.current = note.body;
      setBody(note.body);
      setSaveState('saved');
      setScreen('note');
    } catch {
      setErrorMessage('A new local note could not be created.');
    } finally {
      setBusy(false);
    }
  };

  const acceptInvitation = async () => {
    if (!session || !pendingInvitation) return;
    setBusy(true);
    setErrorMessage(undefined);
    try {
      const note = await session.acceptInvitation(pendingInvitation.bytes);
      pendingInvitation.bytes.fill(0);
      pendingBytesRef.current = undefined;
      setPendingInvitation(undefined);
      bodyRef.current = note.body;
      setBody(note.body);
      setSaveState('saved');
      setScreen('note');
    } catch {
      setErrorMessage(
        'The invitation could not be accepted. It may be expired or claimed, or the founding browser may be offline.',
      );
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
    setNotice('Connecting to the coordination relay and waiting for a reservation…');
    try {
      assertRelayMultiaddrForOrigin(
        relayMultiaddr,
        window.location.protocol === 'https:',
      );
      const invitation = await session.createInvitation(
        shareRole,
        window.location.href,
      );
      setShareHref(invitation.href);
      setShareExpiresAtMs(invitation.offer.expiresAtMs);
      setSharedRole(invitation.offer.role);
      setNotice(
        'Invitation ready. Keep this tab open until the other browser accepts it.',
      );
    } catch {
      setNotice(undefined);
      setErrorMessage(
        'A share link could not be created. Check the relay configuration and connection, then try again.',
      );
    } finally {
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

  return (
    <div className="page-shell">
      <PageHeader fingerprint={identityId} />
      <main>
        <SafetyNotice />

        {errorMessage ? <div className="message error" role="alert">{errorMessage}</div> : null}
        {notice ? <div className="message notice" role="status" aria-live="polite">{notice}</div> : null}

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
              Peerborne datastore from concurrent access. A collaborator needs a
              different browser profile or device.
            </p>
          </section>
        ) : null}

        {screen === 'fatal' ? (
          <section className="panel centered">
            <p className="eyebrow">Initialization stopped safely</p>
            <h1>Your existing browser identity was not replaced.</h1>
            <p>
              Check that site storage is allowed and that this page is running on
              HTTPS or localhost, then reload.
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
                this browser, and lets two browser identities meet through a
                coordination relay.
              </p>
              <button className="primary large" disabled={busy} onClick={() => void createNote()}>
                {busy ? 'Creating locally…' : 'Create a note'}
              </button>
            </div>
            <div className="boundary-card">
              <h2>Know the boundary</h2>
              <ul>
                <li>One founder and one active collaborator.</li>
                <li>Both browsers must remain open and online.</li>
                <li>Invitation links are one-person bearer links.</li>
                <li>The collaborator receives retained note history.</li>
                <li>The relay sees network metadata and can deny service.</li>
                <li>Refresh and browser-restart recovery are not verified.</li>
              </ul>
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
                <strong>{pendingInvitation.offer.role === 'editor' ? 'Can edit' : 'Read only'}</strong>
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
                note history. The issuer signature is verified during acceptance.
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
              <button className="secondary" disabled={busy} onClick={dismissInvitation}>
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
                  <h1>{role === 'reader' ? 'Shared with you' : 'Write locally'}</h1>
                </div>
                <div className="editor-status" aria-live="polite">
                  <span>{peerCount} network peer{peerCount === 1 ? '' : 's'}</span>
                  <span>
                    {role === 'reader'
                      ? 'Read only'
                      : saveState === 'pending'
                        ? 'Applying locally…'
                        : saveState === 'saved'
                          ? 'Applied locally'
                          : 'Ready'}
                  </span>
                </div>
              </div>
              <label htmlFor="note-body" className="visually-hidden">Note text</label>
              <textarea
                id="note-body"
                value={body}
                maxLength={MAX_NOTE_CHARACTERS}
                readOnly={role === 'reader'}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                placeholder={role === 'reader' ? 'Waiting for note content…' : 'Start with what matters…'}
                onChange={(event) => scheduleBodyUpdate(event.currentTarget.value)}
                onBlur={flushBodyUpdate}
              />
              <div className="editor-meta">
                <span>{body.length.toLocaleString()} / {MAX_NOTE_CHARACTERS.toLocaleString()} characters</span>
                <span>No delivery acknowledgement or restart guarantee</span>
              </div>
            </div>

            {session.isFounder ? (
              <aside className="share-panel">
                <p className="eyebrow">Invite one collaborator</p>
                <h2>Share while this tab stays open.</h2>
                {!shareHref ? (
                  <>
                    <fieldset>
                      <legend>Choose the least access they need</legend>
                      <label className={shareRole === 'editor' ? 'role-option selected' : 'role-option'}>
                        <input
                          type="radio"
                          name="share-role"
                          value="editor"
                          checked={shareRole === 'editor'}
                          disabled={busy}
                          onChange={() => setShareRole('editor')}
                        />
                        <span><strong>Editor</strong><small>Can read and publish changes</small></span>
                      </label>
                      <label className={shareRole === 'reader' ? 'role-option selected' : 'role-option'}>
                        <input
                          type="radio"
                          name="share-role"
                          value="reader"
                          checked={shareRole === 'reader'}
                          disabled={busy}
                          onChange={() => setShareRole('reader')}
                        />
                        <span><strong>Reader</strong><small>Can read but cannot publish changes</small></span>
                      </label>
                    </fieldset>
                    <button className="primary full" disabled={busy} onClick={() => void createShareLink()}>
                      {busy ? 'Preparing invitation…' : 'Create 15-minute link'}
                    </button>
                  </>
                ) : (
                  <div className="share-link">
                    <label htmlFor="share-link">One-person bearer link</label>
                    <p>
                      Grants {sharedRole === 'reader' ? 'read-only' : 'editing'} access.
                    </p>
                    <input
                      ref={shareInputRef}
                      id="share-link"
                      value={shareHref}
                      readOnly
                      aria-describedby="share-expiry"
                    />
                    <button className="primary full" onClick={() => void copyShareLink()}>
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
                  <strong>Send it through a channel you trust.</strong>
                  <span>
                    The fragment is not sent in the page request, but browser
                    history, extensions, screenshots, and recipients can expose it.
                  </span>
                </div>
              </aside>
            ) : (
              <aside className="share-panel boundary-only">
                <p className="eyebrow">Session boundary</p>
                <h2>{role === 'reader' ? 'You can read this note.' : 'You can edit this note.'}</h2>
                <p>
                  Keep this browser open. Peerborne has no delivery acknowledgement,
                  automatic reconnect guarantee, or verified restart recovery in
                  this initial release.
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
