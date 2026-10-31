import { createBrowserCheckpointStorage } from '../../shared/browser-checkpoint-store.js';
export type { BrowserIdentity } from '../../shared/browser-checkpoint-store.js';

export const NOTE_DATABASE = 'peerborne-note-documents';
const storage = createBrowserCheckpointStorage(
  NOTE_DATABASE,
  'peerborne/note/checkpoint/1',
);
export const getNoteIdentity = (signing: CryptoKeyPair) =>
  storage.getIdentity(signing);
export class NoteStore extends storage.Store {}
