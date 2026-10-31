'use client';

import { useEffect, useRef, useState } from 'react';
import { usePeerborneStore } from '@peerborne/react/store';
import type { BrowserSession } from './browser-session';

export function DocumentWorkspace({ session }: { session: BrowserSession }) {
  const snapshot = usePeerborneStore(session.store);
  const [title, setTitle] = useState('');
  const [failed, setFailed] = useState(false);
  async function save() {
    try {
      await session.store.change((doc) => {
        doc.getMap('data').set('title', title);
      });
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }
  return (
    <section>
      <p role="status" aria-label="Document status">
        {snapshot.status}
      </p>
      <output data-testid="document-title">
        {String(snapshot.data?.getMap('data').get('title') ?? 'Untitled')}
      </output>
      <label>
        Title{' '}
        <input
          value={title}
          onChange={(event) => setTitle(event.target.value)}
        />
      </label>
      <button
        disabled={snapshot.status !== 'ready'}
        onClick={() => {
          void save();
        }}
      >
        Save title
      </button>
      {(failed || snapshot.error !== undefined) && (
        <p role="alert">The document operation failed.</p>
      )}
    </section>
  );
}

/** The initial server render imports only React and the small store binding. */
export function BrowserWorkspace() {
  const [session, setSession] = useState<BrowserSession>();
  const [starting, setStarting] = useState(false);
  const [failed, setFailed] = useState(false);
  const active = useRef(false);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  useEffect(
    () => () => {
      if (session) void session.dispose().catch(() => {});
    },
    [session],
  );

  async function start() {
    setStarting(true);
    try {
      const { createBrowserSession } = await import('./browser-session');
      const created = await createBrowserSession();
      if (active.current) setSession(created);
      else await created.dispose();
    } catch {
      if (active.current) setFailed(true);
    } finally {
      if (active.current) setStarting(false);
    }
  }
  return session ? (
    <DocumentWorkspace session={session} />
  ) : (
    <section>
      <p>
        Create a local document in this browser. This exercise creates a new
        identity on reload.
      </p>
      <button
        disabled={starting}
        onClick={() => {
          void start();
        }}
      >
        {starting ? 'Starting…' : 'Start local document'}
      </button>
      {failed && <p role="alert">Unable to start the local document.</p>}
    </section>
  );
}
