import React from 'react';
import { connect } from 'react-redux';
import { ThunkDispatch } from 'redux-thunk';
import { Doc } from '@automerge/automerge';
import type { PeerborneConfig } from '@peerborne/core';
import {
  defaultConfig,
  defaultBootstrapConfig,
} from '@peerborne/core';
import {
  changeDocumentAsync,
  openDocumentAsync,
  closeDocumentAsync,
  initializeAsync,
} from '@peerborne/redux';
import { WikiSwarmArticle } from '../models';
import { RootState, selectAutomergeSwarmState } from '../reducers';
import dayjs from 'dayjs';
import Spinner from 'react-bootstrap/Spinner';
import { SlateInput } from '../components/SlateInput';
import { initialValue } from '../components/Slate';
import {
  AutomergeSwarm,
  AutomergeSwarmActions,
  AutomergeSwarmDocument,
} from '../utils';

/**
 * Set `updatedOn` to now and back-fill `createdOn` / `createdBy` if they
 * were never recorded. Called from every `onChange` handler so the two
 * paths (title edits and content edits) can't drift out of sync.
 */
function stampTimestamps(doc: WikiSwarmArticle) {
  doc.updatedOn = dayjs().format();
  if (!doc.createdOn && doc.updatedOn) {
    doc.createdOn = doc.updatedOn;
  }
  if (!doc.createdBy && doc.updatedBy) {
    doc.createdBy = doc.updatedBy;
  }
}

interface WikiArticleOwnProps {
  documentId: string;
  create?: boolean;
  /** Called after `create` founds the article so the URL stops re-creating it. */
  onCreated?: () => void;
}

interface WikiArticleProps extends WikiArticleOwnProps {
  document: WikiSwarmArticle | null;
  documentRef: AutomergeSwarmDocument<WikiSwarmArticle> | null;

  onInitialize: (config: PeerborneConfig) => Promise<AutomergeSwarm>;
  onDocumentOpen: (
    documentPath: string,
    initialization?: 'open' | 'create',
  ) => Promise<AutomergeSwarmDocument<WikiSwarmArticle> | null>;
  onDocumentClose: (documentPath: string) => Promise<void>;
  onDocumentChange: (
    documentPath: string,
    changeFn: (current: WikiSwarmArticle) => void,
    message?: string,
  ) => Promise<Doc<WikiSwarmArticle>>;
}

interface WikiArticleState {
  loadError?: string;
  aclReaders: string[];
  aclWriters: string[];
}

class WikiArticle extends React.Component<
  WikiArticleProps,
  WikiArticleState,
  RootState
> {
  private _mounted = false;
  private _refreshCounter = 0;

  constructor(public props: WikiArticleProps) {
    super(props);
    this.state = { aclReaders: [], aclWriters: [] };
  }

  async refreshACL() {
    const docRef = this.props.documentRef;
    if (!docRef) return;
    const thisRefresh = ++this._refreshCounter;
    try {
      const readers = await docRef.getReaders();
      const writers = await docRef.getWriters();
      const serializeKey = async (k: CryptoKey): Promise<string> => {
        const raw = await crypto.subtle.exportKey('raw', k);
        const hash = await crypto.subtle.digest('SHA-256', raw);
        return Array.from(new Uint8Array(hash).slice(0, 8))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      };
      const serializeKeys = async (keys: CryptoKey[]) => {
        const results = await Promise.allSettled(keys.map(serializeKey));
        return results.map((r) =>
          r.status === 'fulfilled' ? r.value : '<unexportable>',
        );
      };
      const aclWriters = await serializeKeys(writers);
      const writerSet = new Set(aclWriters);
      const allReaders = await serializeKeys(readers);
      const aclReaders = allReaders.filter((id) => !writerSet.has(id));
      // Re-check mounted and that no newer refresh has started
      if (!this._mounted || thisRefresh !== this._refreshCounter) return;
      this.setState({ aclReaders, aclWriters });
    } catch (err) {
      console.warn('Failed to refresh ACL:', err);
    }
  }

  componentDidMount() {
    this._mounted = true;
    // Load this article upon component mount.
    if (this.props.onDocumentOpen && this.props.documentId) {
      console.log('Loading article at:', this.props.documentId);
      // Get relay/bootstrap address from env. The relay multiaddr
      // (e.g. /ip4/.../tcp/9001/ws/p2p/...) is used as a bootstrap peer
      // for libp2p peer discovery — NOT as a listen address.
      const relayAddr = import.meta.env.VITE_RELAY_MULTIADDR;
      const bootstrapPeers = relayAddr ? [relayAddr] : [];
      const config = defaultConfig(defaultBootstrapConfig(bootstrapPeers));
      this.props
        .onInitialize(config)
        .then(() =>
          this.props.onDocumentOpen(this.props.documentId, this.props.create ? 'create' : 'open'),
        )
        .then(() => {
          if (this._mounted && this.props.create) this.props.onCreated?.();
        })
        .catch(() => { if (this._mounted) this.setState({ loadError: 'Unable to open this article. Check its invitation and connection.' }); });
    }
  }

  componentWillUnmount() {
    this._mounted = false;
    // Close this article upon component unmount.
    if (this.props.onDocumentClose && this.props.documentId) {
      console.log('Closing article at:', this.props.documentId);
      this.props.onDocumentClose(this.props.documentId);
    }
  }

  // https://caffeinecoding.com/react-redux-draftjs/
  render() {
    if (this.state.loadError) return <p role="alert">{this.state.loadError}</p>;
    if (this.props.document) {
      if (!this.props.document.content) {
        console.warn(
          'this.props.document.content is empty!',
          this.props.document,
        );
      }
      // A newly created article has no title until its first edit.
      const currentTitle = this.props.document.title?.toString() ?? '';
      return (
        <div className="m-3">
          <label htmlFor="wiki-article-title" className="visually-hidden">
            Article title
          </label>
          <input
            id="wiki-article-title"
            type="text"
            className="form-control form-control-lg mb-2"
            placeholder="Article title"
            value={currentTitle}
            onChange={(e) => {
              const newTitle = e.target.value;
              this.props.onDocumentChange(
                this.props.documentId,
                (currentDocument) => {
                  // Automerge 3 models collaborative text with native strings.
                  // This whole-value assignment matches the previous example's
                  // replacement semantics; richer editors should use splice().
                  currentDocument.title = newTitle;
                  stampTimestamps(currentDocument);
                },
              );
            }}
          />
          <div>
            <SlateInput
              value={this.props.document.content || initialValue}
              placeholder="Enter run notes here..."
              onChange={(content) => {
                // Your Redux action
                this.props.onDocumentChange(
                  this.props.documentId,
                  (currentDocument) => {
                    stampTimestamps(currentDocument);
                    currentDocument.content = content;
                  },
                );
              }}
            />
          </div>
          <div className="mt-3 p-2 border rounded">
            <strong>ACL</strong>{' '}
            <button className="btn btn-sm btn-outline-secondary ms-2" onClick={() => this.refreshACL()}>
              Refresh
            </button>
            {this.state.aclReaders.length > 0 && (
              <div className="mt-1">
                <em>Readers ({this.state.aclReaders.length}):</em>{' '}
                {this.state.aclReaders.map((id, i) => (
                  <code key={`${id}-${i}`} className="me-1">{id}…</code>
                ))}
              </div>
            )}
            {this.state.aclWriters.length > 0 && (
              <div className="mt-1">
                <em>Writers ({this.state.aclWriters.length}):</em>{' '}
                {this.state.aclWriters.map((id, i) => (
                  <code key={`${id}-${i}`} className="me-1">{id}…</code>
                ))}
              </div>
            )}
          </div>
        </div>
      );
    } else {
      return (
        <div>
          <Spinner
            animation="grow"
            variant="info"
            className="mx-auto"
          ></Spinner>
        </div>
      );
    }
  }
}

function mapStateToProps(state: RootState, ownProps: WikiArticleOwnProps) {
  const documentState =
    state.automergeSwarm.documents[ownProps.documentId];
  return {
    document: documentState ? documentState.document : null,
    documentRef: documentState ? documentState.documentRef : null,
  };
}

function mapDispatchToProps(
  dispatch: ThunkDispatch<
    RootState,
    unknown,
    AutomergeSwarmActions<WikiSwarmArticle>
  >,
) {
  return {
    onInitialize: (config: PeerborneConfig) =>
      dispatch(initializeAsync(config, selectAutomergeSwarmState)),
    onDocumentOpen: (documentId: string, initialization: 'open' | 'create' = 'open') =>
      dispatch(openDocumentAsync(documentId, selectAutomergeSwarmState, initialization)),
    onDocumentClose: (documentId: string) =>
      dispatch(closeDocumentAsync(documentId, selectAutomergeSwarmState)),
    onDocumentChange: (
      documentId: string,
      changeFn: (current: any) => void,
      message?: string,
    ) =>
      dispatch(
        changeDocumentAsync(
          documentId,
          changeFn,
          message,
          selectAutomergeSwarmState,
        ),
      ),
  };
}

export default connect(mapStateToProps, mapDispatchToProps)(WikiArticle);
