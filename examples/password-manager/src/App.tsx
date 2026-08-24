import React, { useEffect } from 'react';
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Redirect,
  Link,
} from 'react-router-dom';
import { Container, Nav } from 'react-bootstrap';
import './App.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import {
  PeerborneDocument,
  defaultConfig,
  defaultBootstrapConfig,
  SubtleCrypto,
} from '@peerborne/core';
import {
  PeerborneContext,
  usePeerborne,
} from '@peerborne/react';
import {
  YjsProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsACLProvider,
} from '@peerborne/yjs';
import { Login } from './Login';
import { PasswordList } from './PasswordList';
import { Settings } from './Settings';

const crdt = new YjsProvider();
const serializer = new YjsJSONSerializer();
const auth = new SubtleCrypto();
const acl = new YjsACLProvider();
const keychain = new YjsKeychainProvider();

function App() {
  const [privateKey, setPrivateKey] = React.useState<CryptoKey | undefined>();
  const [publicKey, setPublicKey] = React.useState<CryptoKey | undefined>();
  const [userId, setUserId] = React.useState<string | undefined>();
  const [bootstrapPeers, setBootstrapPeers] = React.useState<
    string[] | undefined
  >();
  const [docCache, setDocCache] = React.useState<{
    [docPath: string]: PeerborneDocument<any, any, any, any, any, any>;
  }>({});
  const [docDataCache, setDocDataCache] = React.useState<{
    [docPath: string]: any;
  }>({});
  const [docReadersCache, setDocReadersCache] = React.useState<{
    [docPath: string]: any[];
  }>({});
  const [docWritersCache, setDocWritersCache] = React.useState<{
    [docPath: string]: any[];
  }>({});
  // Get relay/bootstrap address from env. The relay multiaddr
  // (e.g. /ip4/.../tcp/9001/ws/p2p/...) is used as a bootstrap peer
  // for libp2p peer discovery — NOT as a listen address.
  const relayAddr = import.meta.env.VITE_RELAY_MULTIADDR;
  const relayPeers = relayAddr ? [relayAddr] : [];
  const config = defaultConfig(defaultBootstrapConfig(relayPeers));
  const peerborne = usePeerborne(
    privateKey,
    publicKey,
    crdt,
    serializer,
    serializer,
    serializer,
    auth,
    acl,
    keychain,
    config,
  );
  // Calls connect whenever bootstrap peers changes.
  useEffect(() => {
    if (peerborne && bootstrapPeers) {
      console.log(`Connecting to peers: ${bootstrapPeers}`);
      peerborne.connect(bootstrapPeers);
    } else {
      console.warn(`Skipping peerborne.connect(${bootstrapPeers})`);
    }
  }, [bootstrapPeers, peerborne]);

  const loggedIn = (privateKey && publicKey) !== undefined;

  return (
    <PeerborneContext.Provider
      value={{
        docCache,
        docDataCache,
        docReadersCache,
        docWritersCache,
        setDocCache,
        setDocDataCache,
        setDocReadersCache,
        setDocWritersCache,
      }}
    >
      <Router>
        <Container>
          <Nav variant="tabs" defaultActiveKey="/login">
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

          <Switch>
            <Route path="/login">
              <Login
                privateKey={privateKey}
                setPrivateKey={setPrivateKey}
                publicKey={publicKey}
                setPublicKey={setPublicKey}
                userId={userId}
                setUserId={setUserId}
                bootstrapPeers={bootstrapPeers}
                setBootstrapPeers={setBootstrapPeers}
              />
            </Route>
            <Route path="/secrets">
              {loggedIn ? (
                peerborne && userId ? (
                  <PasswordList userId={userId} peerborne={peerborne} />
                ) : (
                  <i>Loading peerborne...</i>
                )
              ) : (
                <Redirect to="/login" />
              )}
            </Route>
            <Route path="/settings">
              {loggedIn ? (
                peerborne ? (
                  <Settings
                    peerborne={peerborne}
                    publicKey={publicKey}
                  />
                ) : (
                  <i>Loading peerborne...</i>
                )
              ) : (
                <Redirect to="/login" />
              )}
            </Route>
            <Route exact path="/">
              {loggedIn ? <Redirect to="/secrets" /> : <Redirect to="/login" />}
            </Route>
          </Switch>
        </Container>
      </Router>
    </PeerborneContext.Provider>
  );
}

export default App;
