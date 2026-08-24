import React from 'react';
import './App.css';
import {
  connectAsync,
  openDocumentAsync,
  closeDocumentAsync,
  changeDocumentAsync,
  initializeAsync,
} from '@peerborne/redux';
import { connect } from 'react-redux';
import { ThunkDispatch } from 'redux-thunk';
import { JsonEditor } from 'jsoneditor-react';
import * as jsondiffpatch from 'jsondiffpatch';
import { AutomergeSwarmActions, AutomergeSwarmState } from './utils';
import {
  Peerborne,
  PeerborneConfig,
  PeerborneDocument,
  defaultConfig,
  defaultBootstrapConfig,
} from '@peerborne/core';
import { Doc, Change } from '@automerge/automerge';

export type AutomergeSwarm<T = any> = Peerborne<
  Doc<T>,
  Change[],
  (doc: T) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;
export type AutomergeSwarmDocument<T = any> = PeerborneDocument<
  Doc<T>,
  Change[],
  (doc: T) => void,
  CryptoKey,
  CryptoKey,
  CryptoKey
>;

const jdp = jsondiffpatch.create();

interface AppProps {
  state: AutomergeSwarmState;
  onInitialize: (config: PeerborneConfig) => Promise<AutomergeSwarm>;
  onConnect: (addresses: string[]) => any;
  onDocumentOpen: (documentId: string) => any;
  onDocumentClose: (documentId: string) => any;
  onDocumentChange: (
    documentId: string,
    changeFn: (current: any) => void,
    message?: string,
  ) => any;
}

interface AppState {
  connectionAddress: string;
  documentId: string;
  aclReaders: { [docPath: string]: string[] };
  aclWriters: { [docPath: string]: string[] };
}

class App extends React.Component<
  AppProps,
  AppState,
  AutomergeSwarmState<any>
> {
  // Per-document monotonically increasing counters used to detect stale
  // refreshACL calls. Each call captures the current value for its document;
  // if it changes before setState, a newer refresh has been initiated and
  // the stale one is discarded.
  private _refreshCounters: Record<string, number> = {};

  constructor(public props: AppProps) {
    super(props);

    this.state = {
      connectionAddress: '',
      documentId: '',
      aclReaders: {},
      aclWriters: {},
    };
  }

  // Demo-only helper: fetches and displays the current ACL for a document.
  async refreshACL(documentPath: string) {
    const docState = this.props.state.documents[documentPath];
    if (!docState?.documentRef) return;

    this._refreshCounters[documentPath] = (this._refreshCounters[documentPath] ?? 0) + 1;
    const thisRefresh = this._refreshCounters[documentPath];

    try {
      const [readers, writers] = await Promise.all([
        docState.documentRef.getReaders(),
        docState.documentRef.getWriters(),
      ]);

      // Bail out if a newer refreshACL call has been initiated.
      if (this._refreshCounters[documentPath] !== thisRefresh) return;

      // Serialize each CryptoKey to { fullHex, displayHex }.
      // fullHex is the complete SHA-256 hash used for de-duplication;
      // displayHex is the truncated 8-byte prefix shown in the UI.
      // Promise.allSettled is ES2020. The tsconfig targets ES5 but includes
      // "esnext" in `lib`, and CRA's default browserslist polyfills it for
      // older browsers, so this is safe at runtime.
      const serializeKeys = async (keys: CryptoKey[], fallbackPrefix: string) => {
        const results = await Promise.allSettled(
          keys.map(async (k) => {
            const raw = await crypto.subtle.exportKey('raw', k);
            const hash = await crypto.subtle.digest('SHA-256', raw);
            const bytes = Array.from(new Uint8Array(hash));
            const fullHex = bytes
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');
            const displayHex = bytes
              .slice(0, 8)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');
            return { fullHex, displayHex };
          }),
        );
        // Unexportable keys get a fallback string. React key collisions are
        // avoided because the key prop includes the array index (e.g. `reader-${id}-${i}`).
        return results.map((r, index) =>
          r.status === 'fulfilled'
            ? r.value
            : { fullHex: `<unexportable-${fallbackPrefix}-${index}>`, displayHex: '<unexportable>' },
        );
      };
      const writerEntries = await serializeKeys(writers, 'writer');
      const allReaderEntries = await serializeKeys(readers, 'reader');

      // Final guard: a newer refresh may have started during serializeKeys.
      if (this._refreshCounters[documentPath] !== thisRefresh) return;

      // getReaders() returns both readers and writers; filter out writers
      // using the full hash to avoid incorrect matches from truncation collisions.
      const writerFullSet = new Set(writerEntries.map((e) => e.fullHex));
      const readerEntries = allReaderEntries.filter(
        (e) => !writerFullSet.has(e.fullHex),
      );

      this.setState((prev) => ({
        aclReaders: {
          ...prev.aclReaders,
          [documentPath]: readerEntries.map((e) => e.displayHex),
        },
        aclWriters: {
          ...prev.aclWriters,
          [documentPath]: writerEntries.map((e) => e.displayHex),
        },
      }));
    } catch (err) {
      console.warn('Failed to refresh ACL:', err);
    }
  }

  componentDidMount() {
    if (this.props.onInitialize) {
      // Get relay/bootstrap address from env. The relay multiaddr
      // (e.g. /ip4/.../tcp/9001/ws/p2p/...) is used as a bootstrap peer
      // for libp2p peer discovery — NOT as a listen address.
      const relayAddr = import.meta.env.VITE_RELAY_MULTIADDR;
      const bootstrapPeers = relayAddr ? [relayAddr] : [];
      const config = defaultConfig(defaultBootstrapConfig(bootstrapPeers));
      if (import.meta.env.VITE_CROSS_NAT_TEST === '1') {
        config.loadQuorumEnabled = false;
        config.compaction = { enabled: false };
        const libp2p = config.helia!.libp2p as any;
        // This suite proves the circuit-relay path specifically. Remove
        // peer-discovery and direct/hole-punch transports that can race the
        // explicit circuit dial or accidentally make the test pass via a
        // different data plane.
        libp2p.addresses.listen = ['/p2p-circuit'];
        libp2p.transports = libp2p.transports.slice(0, 2);
        libp2p.peerDiscovery = libp2p.peerDiscovery.slice(0, 1);
        delete libp2p.services.dcutr;
        delete libp2p.services.autoNAT;
      }
      this.props.onInitialize(config);
    }
  }

  render() {
    const nodeAddresses = (() => {
      try {
        return this.props.state.node ? this.props.state.node.libp2p.getMultiaddrs() : null;
      } catch (ex) {
        // No-op.
        console.warn('Failed to read node addresses:', ex);
      }
      return null;
    })();

    return (
      <div>
        <div id="info">
          <div>
            <strong>Node Addresses:</strong>
          </div>
          <ul>
            {nodeAddresses &&
              nodeAddresses.map((address: any, i: number) => (
                <li key={i}>
                  <pre>{address.toString()}</pre>
                </li>
              ))}
          </ul>
          <div>
            <strong>Connected Peers:</strong>
          </div>
          <ul>
            {this.props.state.peers.map((address: string, i: number) => (
              <li key={i}>
                <pre>{address}</pre>
              </li>
            ))}
          </ul>
        </div>
        <div id="connect">
          <input
            type="text"
            defaultValue={this.state.connectionAddress}
            onChange={(e) =>
              this.setState({ connectionAddress: e.currentTarget.value })
            }
          />
          <button
            onClick={() => this.props.onConnect([this.state.connectionAddress])}
          >
            Connect
          </button>
        </div>
        <div id="open">
          <input
            type="text"
            value={this.state.documentId}
            onChange={(e) =>
              this.setState({ documentId: e.currentTarget.value })
            }
          />
          <button
            onClick={() => this.props.onDocumentOpen(this.state.documentId)}
          >
            Open
          </button>
        </div>
        {/* {Object.entries(this.props.state.documents).map(([documentPath, documentState]: [string, any]) => <React.Fragment key={documentPath}> */}
        {Object.entries(this.props.state.documents).map(
          ([documentPath, documentState]: [string, any]) => (
            <React.Fragment key={JSON.stringify(documentState.document)}>
              <h3>{documentPath}</h3>
              <JsonEditor
                value={JSON.parse(JSON.stringify(documentState.document))}
                onChange={(currentDoc: any) => {
                  try {
                    const delta = jdp.diff(documentState.document, currentDoc);
                    if (delta) {
                      console.log(
                        `Applying json patch to '${documentPath}':`,
                        delta,
                      );
                      this.props.onDocumentChange(documentPath, (doc) => {
                        try {
                          jdp.patch(doc, delta);
                        } catch (ex) {
                          console.warn(ex);
                        }
                      });
                    }
                  } catch (ex) {
                    console.warn(ex);
                    return;
                  }
                }}
              />
              <div style={{ marginTop: '8px' }}>
                <strong>ACL:</strong>{' '}
                <button onClick={() => this.refreshACL(documentPath)}>
                  Refresh ACL
                </button>
                {this.state.aclReaders[documentPath] && (
                  <div>
                    <em>Readers ({this.state.aclReaders[documentPath].length}):</em>{' '}
                    {this.state.aclReaders[documentPath].map((id, i) => (
                      <code key={`reader-${id}-${i}`} style={{ marginRight: '4px' }}>{id}…</code>
                    ))}
                  </div>
                )}
                {this.state.aclWriters[documentPath] && (
                  <div>
                    <em>Writers ({this.state.aclWriters[documentPath].length}):</em>{' '}
                    {this.state.aclWriters[documentPath].map((id, i) => (
                      <code key={`writer-${id}-${i}`} style={{ marginRight: '4px' }}>{id}…</code>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <button
                  onClick={() => {
                    this.props.onDocumentClose(documentPath);
                    // Invalidate any in-flight refreshACL calls for this document,
                    // then clean up the counter to avoid leaking entries.
                    this._refreshCounters[documentPath] = (this._refreshCounters[documentPath] ?? 0) + 1;
                    delete this._refreshCounters[documentPath];
                    this.setState((prev) => {
                      const { [documentPath]: _r, ...remainingReaders } = prev.aclReaders;
                      const { [documentPath]: _w, ...remainingWriters } = prev.aclWriters;
                      return { aclReaders: remainingReaders, aclWriters: remainingWriters };
                    });
                  }}
                >
                  Close Document
                </button>
              </div>
            </React.Fragment>
          ),
        )}
      </div>
    );
  }
}

function mapStateToProps(state: AutomergeSwarmState<any>) {
  return { state };
}

function mapDispatchToProps(
  dispatch: ThunkDispatch<
    AutomergeSwarmState<any>,
    unknown,
    AutomergeSwarmActions
  >,
) {
  return {
    onInitialize: (config: PeerborneConfig) =>
      dispatch(
        initializeAsync<
          Doc<any>,
          Change[],
          (doc: any) => void,
          CryptoKey,
          CryptoKey,
          CryptoKey
        >(config),
      ),
    onConnect: (addresses: string[]) =>
      dispatch(
        connectAsync<
          Doc<any>,
          Change[],
          (doc: any) => void,
          CryptoKey,
          CryptoKey,
          CryptoKey
        >(addresses),
      ),
    onDocumentOpen: (documentId: string) =>
      dispatch(
        openDocumentAsync<
          Doc<any>,
          Change[],
          (doc: any) => void,
          CryptoKey,
          CryptoKey,
          CryptoKey
        >(documentId),
      ),
    onDocumentClose: (documentId: string) =>
      dispatch(
        closeDocumentAsync<
          Doc<any>,
          Change[],
          (doc: any) => void,
          CryptoKey,
          CryptoKey,
          CryptoKey
        >(documentId),
      ),
    onDocumentChange: (
      documentId: string,
      changeFn: (current: any) => void,
      message?: string,
    ) =>
      dispatch(
        changeDocumentAsync<
          Doc<any>,
          Change[],
          (doc: any) => void,
          CryptoKey,
          CryptoKey,
          CryptoKey
        >(documentId, changeFn, message),
      ),
  };
}

export default connect(mapStateToProps, mapDispatchToProps)(App);
