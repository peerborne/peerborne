import React from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  Link,
} from 'react-router-dom';
import { Alert, Button, Container, Nav } from 'react-bootstrap';
import {
  Peerborne,
  defaultConfig,
  defaultBootstrapConfig,
  SubtleCrypto,
} from '@peerborne/core';
import {
  YjsProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsACLProvider,
  serializeKey,
} from '@peerborne/yjs';
import { Login } from './Login';
import { PasswordVault } from './PasswordList';
import { Settings } from './Settings';
import { VaultSession, useVaultSession } from './vault-session';
import { VaultStore, type BrowserIdentity } from './vault-store';
import './App.css';
import 'bootstrap/dist/css/bootstrap.min.css';

function SignedIn({ session }: { session: VaultSession }) {
  useVaultSession(session);
  return (
    <>
      <p role="status" className="mt-3">
        {session.error
          ? 'Vault changes have not been saved.'
          : session.saving
            ? 'Saving…'
            : 'Saved in this browser.'}
      </p>
      {session.error && (
        <Alert variant="danger">
          {session.error.message}{' '}
          <Button
            size="sm"
            onClick={() => {
              void session.retry().catch(() => undefined);
            }}
          >
            Retry saving
          </Button>
        </Alert>
      )}
      <PasswordVault
        userId={session.storeOwner}
        peerborne={session.peerborne}
        kemKeyPair={session.identity.kem}
        session={session}
      />
    </>
  );
}

function App() {
  const [session, setSession] = React.useState<VaultSession>();
  const login = async (identity: BrowserIdentity, peers: string[]) => {
    const locks = navigator.locks;
    if (!locks)
      throw new Error('This browser does not support exclusive vault sessions');
    let release!: () => void;
    const acquired = await new Promise<boolean>((resolve) => {
      void locks
        .request(
          'peerborne-password-manager-active-tab',
          { ifAvailable: true },
          async (lock) => {
            if (!lock) {
              resolve(false);
              return;
            }
            resolve(true);
            await new Promise<void>((done) => {
              release = done;
            });
          },
        )
        .catch(() => resolve(false));
    });
    if (!acquired)
      throw new Error('The password manager is open in another tab');
    const provider = new YjsProvider();
    const serializer = new YjsJSONSerializer();
    const peerborne = new Peerborne(
      identity.signing.privateKey,
      identity.signing.publicKey,
      provider,
      serializer,
      serializer,
      serializer,
      new SubtleCrypto(),
      new YjsACLProvider(),
      new YjsKeychainProvider(),
    );
    try {
      const relay = import.meta.env.VITE_RELAY_MULTIADDR;
      const config = defaultConfig(
        defaultBootstrapConfig(relay ? [relay] : []),
      );
      await peerborne.initialize(config);
      if (peers.length > 0) await peerborne.connect(peers);
      const owner = await serializeKey(identity.signing.publicKey);
      const next = new VaultSession(
        peerborne,
        identity,
        new VaultStore(identity, owner),
      );
      await next.initialize();
      setSession(next);
    } catch (error) {
      release();
      try {
        await peerborne.heliaNode.stop();
      } catch {}
      throw error;
    }
  };
  return (
    <Router>
      <Container>
        <Nav variant="tabs">
          <Nav.Item>
            <Nav.Link as={Link} to="/login">
              Login
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link as={Link} to="/secrets">
              Secrets
            </Nav.Link>
          </Nav.Item>
          <Nav.Item>
            <Nav.Link as={Link} to="/settings">
              Settings
            </Nav.Link>
          </Nav.Item>
        </Nav>
        {session && <SignedIn session={session} />}
        <Routes>
          <Route
            path="/login"
            element={
              session ? (
                <Navigate to="/secrets" replace />
              ) : (
                <Login onLogin={login} />
              )
            }
          />
          <Route
            path="/secrets"
            element={session ? null : <Navigate to="/login" replace />}
          />
          <Route
            path="/settings"
            element={
              session ? (
                <Settings
                  peerborne={session.peerborne}
                  publicKey={session.identity.signing.publicKey}
                  kemKeyPair={session.identity.kem}
                />
              ) : (
                <Navigate to="/login" replace />
              )
            }
          />
          <Route
            path="/"
            element={<Navigate to={session ? '/secrets' : '/login'} replace />}
          />
        </Routes>
      </Container>
    </Router>
  );
}
export default App;
