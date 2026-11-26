import { createBrowserCheckpointStorage } from '../../shared/browser-checkpoint-store.js';
export type { BrowserIdentity } from '../../shared/browser-checkpoint-store.js';

export const WIKI_DATABASE = 'peerborne-wiki-swarm';
const storage = createBrowserCheckpointStorage(
  WIKI_DATABASE,
  'peerborne/wiki-swarm/checkpoint/1',
);
export const getWikiIdentity = () => storage.getIdentity();
export class ArticleStore extends storage.Store {}
