import { createBrowserCheckpointStorage } from '../../shared/browser-checkpoint-store.js';
export {
  validateBrowserIdentity,
  type BrowserIdentity,
} from '../../shared/browser-checkpoint-store.js';

export const VAULT_DATABASE = 'peerborne-password-manager';
const storage = createBrowserCheckpointStorage(
  VAULT_DATABASE,
  'peerborne/password-manager/checkpoint/1',
);
export const getBrowserIdentity = () => storage.getIdentity();
export class VaultStore extends storage.Store {
  listVaults(): Promise<string[]> {
    return this.listDocuments();
  }
}
