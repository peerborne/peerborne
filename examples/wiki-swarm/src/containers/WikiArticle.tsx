import React from 'react';
import { connect } from 'react-redux';
import { Doc, splice } from '@automerge/automerge';
import { WikiSwarmArticle } from '../models';
import { RootState } from '../reducers';
import type { ArticleSaveStatus } from '../actions';
import {
  ArticleExistsError,
  changeArticle,
  openArticle,
  retryArticleSave,
  type WikiDispatch,
} from '../articles';
import dayjs from 'dayjs';
import Spinner from 'react-bootstrap/Spinner';
import { SlateInput } from '../components/SlateInput';
import { initialValue } from '../components/Slate';
import { AutomergeSwarmDocument } from '../utils';

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

/** The single splice that turns `before` into `after`. */
function textEdit(before: string, after: string) {
  let prefix = 0;
  while (
    prefix < before.length &&
    prefix < after.length &&
    before[prefix] === after[prefix]
  ) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < before.length - prefix &&
    suffix < after.length - prefix &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  ) {
    suffix++;
  }
  return {
    index: prefix,
    remove: before.length - prefix - suffix,
    insert: after.slice(prefix, after.length - suffix),
  };
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
  saveStatus?: ArticleSaveStatus;

  onDocumentOpen: (
    documentPath: string,
    initialization: 'open' | 'create',
  ) => Promise<void>;
  onDocumentChange: (
    documentPath: string,
    changeFn: (current: WikiSwarmArticle) => void,
  ) => Promise<void>;
  onSaveRetry: (documentPath: string) => Promise<void>;
}

interface WikiArticleState {
  loadError?: string;
  editFailed?: boolean;
  /** The title as typed, kept while its edits are still being applied. */
  titleDraft?: string;
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
  private _titleEdits = 0;
  private _titleDraft?: string;

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
    if (this.props.documentId) {
      this._activate();
    }
  }

  // The router keeps this instance when the URL switches between /document/
  // and /create/ for the same ID, so a failed load retries in the new mode.
  componentDidUpdate(prevProps: WikiArticleProps) {
    if (
      Boolean(prevProps.create) !== Boolean(this.props.create) &&
      this.state.loadError
    ) {
      this.setState({ loadError: undefined });
      this._activate();
    }
  }

  private _activate() {
    const create = Boolean(this.props.create);
    this.props
      .onDocumentOpen(this.props.documentId, create ? 'create' : 'open')
      .then(() => {
        if (this._mounted && this.props.create) this.props.onCreated?.();
      })
      .catch((error) => {
        if (!this._mounted) return;
        if (Boolean(this.props.create) !== create) {
          this._activate();
          return;
        }
        this.setState({
          loadError:
            error instanceof ArticleExistsError
              ? 'An article with this ID already exists in this browser. Use Search to open it.'
              : 'Unable to open this article. Check its invitation and connection.',
        });
      });
  }

  componentWillUnmount() {
    // The article stays open for this tab so it can be reopened here.
    this._mounted = false;
  }

  private _change(changeFn: (current: WikiSwarmArticle) => void) {
    return this.props
      .onDocumentChange(this.props.documentId, changeFn)
      .catch(() => {
        if (this._mounted) this.setState({ editFailed: true });
      });
  }

  private _editTitle(title: string) {
    const edit = textEdit(
      this._titleDraft ?? this.props.document?.title ?? '',
      title,
    );
    this._titleDraft = title;
    this._titleEdits++;
    this.setState({ titleDraft: title, editFailed: false });
    void this._change((current) => {
      if (typeof current.title !== 'string') current.title = '';
      const index = Math.min(edit.index, current.title.length);
      splice(
        current as Doc<WikiSwarmArticle>,
        ['title'],
        index,
        Math.min(edit.remove, current.title.length - index),
        edit.insert,
      );
      stampTimestamps(current);
    }).finally(() => {
      if (--this._titleEdits > 0) return;
      this._titleDraft = undefined;
      if (this._mounted) this.setState({ titleDraft: undefined });
    });
  }

  // https://caffeinecoding.com/react-redux-draftjs/
  render() {
    if (this.state.loadError) return <p role="alert">{this.state.loadError}</p>;
    if (this.props.document) {
      // A newly created article has no title until its first edit.
      const currentTitle =
        this.state.titleDraft ?? this.props.document.title?.toString() ?? '';
      return (
        <div className="m-3">
          {this.props.saveStatus === 'failed' ? (
            <div role="alert" className="alert alert-danger">
              This article could not be saved in this browser. Keep this tab
              open and retry.{' '}
              <button
                className="btn btn-sm btn-outline-danger"
                onClick={() => {
                  void this.props
                    .onSaveRetry(this.props.documentId)
                    .catch(() => undefined);
                }}
              >
                Retry saving
              </button>
            </div>
          ) : (
            <p role="status" className="small text-muted mb-2">
              {this.props.saveStatus === 'saving'
                ? 'Saving…'
                : 'Saved in this browser.'}
            </p>
          )}
          {this.state.editFailed && (
            <p role="alert" className="text-danger">
              An edit could not be applied. Check the article and try again.
            </p>
          )}
          <label htmlFor="wiki-article-title" className="visually-hidden">
            Article title
          </label>
          <input
            id="wiki-article-title"
            type="text"
            className="form-control form-control-lg mb-2"
            placeholder="Article title"
            value={currentTitle}
            onChange={(e) => this._editTitle(e.target.value)}
          />
          <div>
            <SlateInput
              value={this.props.document.content || initialValue}
              placeholder="Enter run notes here..."
              onChange={(content) => {
                this.setState({ editFailed: false });
                void this._change((currentDocument) => {
                  stampTimestamps(currentDocument);
                  currentDocument.content = content;
                });
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
    saveStatus: state.wikiApp.saves[ownProps.documentId],
  };
}

function mapDispatchToProps(dispatch: WikiDispatch) {
  return {
    onDocumentOpen: (documentId: string, initialization: 'open' | 'create') =>
      dispatch(openArticle(documentId, initialization)),
    onDocumentChange: (
      documentId: string,
      changeFn: (current: WikiSwarmArticle) => void,
    ) => dispatch(changeArticle(documentId, changeFn)),
    onSaveRetry: (documentId: string) =>
      dispatch(retryArticleSave(documentId)),
  };
}

export default connect(mapStateToProps, mapDispatchToProps)(WikiArticle);
