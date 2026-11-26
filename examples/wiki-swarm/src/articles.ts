import type { ThunkAction, ThunkDispatch } from 'redux-thunk';
import { defaultBootstrapConfig, defaultConfig } from '@peerborne/core';
import {
  changeDocument,
  initializeAsync,
  openDocument,
  syncDocument,
} from '@peerborne/redux';
import { articleSave, type WikiSwarmActions } from './actions';
import type { ArticleStore, BrowserIdentity } from './article-store';
import type { WikiSwarmArticle } from './models';
import { selectAutomergeSwarmState, type RootState } from './reducers';
import type { AutomergeSwarmDocument } from './utils';

type ArticleDocument = AutomergeSwarmDocument<WikiSwarmArticle>;
export type WikiDispatch = ThunkDispatch<
  RootState,
  ArticleSession,
  WikiSwarmActions
>;
type WikiThunk<T> = ThunkAction<
  Promise<T>,
  RootState,
  ArticleSession,
  WikiSwarmActions
>;

const REDUX_SUBSCRIBER = 'wiki-redux';
const CHECKPOINT_SUBSCRIBER = 'wiki-checkpoint';

export class ArticleExistsError extends Error {
  constructor() {
    super('An article with this ID already exists in this browser');
    this.name = 'ArticleExistsError';
  }
}

interface Article {
  readonly doc: ArticleDocument;
  revision: number;
  writes: Promise<void>;
  pending: number;
  failed: boolean;
}

/** Keeps articles open for the tab and saves an encrypted checkpoint after each change. */
export class ArticleSession {
  private initialization?: Promise<unknown>;
  private readonly tasks = new Map<string, Promise<Article>>();
  private readonly articles = new Map<string, Article>();

  constructor(
    private readonly identity: BrowserIdentity,
    private readonly store: ArticleStore,
  ) {}

  private initialize(dispatch: WikiDispatch): Promise<unknown> {
    if (!this.initialization) {
      const relay = import.meta.env.VITE_RELAY_MULTIADDR;
      const task = dispatch(
        initializeAsync(
          defaultConfig(defaultBootstrapConfig(relay ? [relay] : [])),
          selectAutomergeSwarmState,
        ),
      );
      this.initialization = task;
      task.catch(() => {
        if (this.initialization === task) this.initialization = undefined;
      });
    }
    return this.initialization;
  }

  async exists(path: string): Promise<boolean> {
    return this.articles.has(path) || (await this.store.has(path));
  }

  open(
    path: string,
    mode: 'open' | 'create',
    dispatch: WikiDispatch,
    getState: () => RootState,
  ): Promise<Article> {
    const existing = this.tasks.get(path);
    if (existing) return existing;
    const task = this.activate(path, mode, dispatch, getState);
    this.tasks.set(path, task);
    task.catch(() => {
      if (this.tasks.get(path) === task) this.tasks.delete(path);
    });
    return task;
  }

  private async activate(
    path: string,
    mode: 'open' | 'create',
    dispatch: WikiDispatch,
    getState: () => RootState,
  ): Promise<Article> {
    await this.initialize(dispatch);
    const doc: ArticleDocument =
      selectAutomergeSwarmState(getState()).node.doc(path);
    try {
      await doc.setKemKeyPair(this.identity.kem);
      const saved = await this.store.load(path);
      if (saved) {
        if (mode === 'create') throw new ArticleExistsError();
        try {
          await doc.restoreCheckpoint(saved.checkpoint);
        } finally {
          saved.checkpoint.payload.fill(0);
          saved.checkpoint.signature.fill(0);
        }
        await doc.open();
      } else {
        await doc[mode]();
      }
      const article: Article = {
        doc,
        revision: saved?.revision ?? 0,
        writes: Promise.resolve(),
        pending: 0,
        failed: false,
      };
      doc.subscribe(
        REDUX_SUBSCRIBER,
        (document) => {
          dispatch(syncDocument(path, document));
        },
        'remote',
      );
      doc.subscribe(CHECKPOINT_SUBSCRIBER, () => {
        void this.save(path, article, dispatch).catch(() => undefined);
      });
      this.articles.set(path, article);
      dispatch(openDocument(path, doc));
      if (!saved)
        await this.save(path, article, dispatch).catch(() => undefined);
      return article;
    } catch (error) {
      doc.unsubscribe(REDUX_SUBSCRIBER);
      doc.unsubscribe(CHECKPOINT_SUBSCRIBER);
      await doc.close().catch(() => undefined);
      throw error;
    }
  }

  private save(
    path: string,
    article: Article,
    dispatch: WikiDispatch,
  ): Promise<void> {
    article.pending++;
    dispatch(articleSave(path, article.failed ? 'failed' : 'saving'));
    const operation = article.writes
      .catch(() => undefined)
      .then(async () => {
        const checkpoint = await article.doc.exportCheckpoint();
        try {
          article.revision = await this.store.save(
            path,
            false,
            checkpoint,
            article.revision,
          );
        } finally {
          checkpoint.payload.fill(0);
          checkpoint.signature.fill(0);
        }
      });
    article.writes = operation;
    return operation
      .then(
        () => {
          article.failed = false;
        },
        (error) => {
          article.failed = true;
          throw error;
        },
      )
      .finally(() => {
        article.pending--;
        dispatch(
          articleSave(
            path,
            article.failed
              ? 'failed'
              : article.pending > 0
                ? 'saving'
                : 'saved',
          ),
        );
      });
  }

  retry(path: string, dispatch: WikiDispatch): Promise<void> {
    const article = this.articles.get(path);
    if (!article) return Promise.reject(new Error('The article is not open'));
    return this.save(path, article, dispatch);
  }
}

export function openArticle(
  path: string,
  mode: 'open' | 'create',
): WikiThunk<void> {
  return async (dispatch, getState, session) => {
    await session.open(path, mode, dispatch, getState);
  };
}

export function articleExists(path: string): WikiThunk<boolean> {
  return (_dispatch, _getState, session) => session.exists(path);
}

export function retryArticleSave(path: string): WikiThunk<void> {
  return (dispatch, _getState, session) => session.retry(path, dispatch);
}

/** Apply a local edit, then publish the changed document to Redux. */
export function changeArticle(
  path: string,
  changeFn: (article: WikiSwarmArticle) => void,
): WikiThunk<void> {
  return async (dispatch, getState) => {
    const doc =
      selectAutomergeSwarmState(getState()).documents[path]?.documentRef;
    if (!doc) throw new Error('The article is not open');
    await doc.change(changeFn);
    dispatch(changeDocument(path, doc.document));
  };
}
