import { MemoryBlockstore } from 'blockstore-core/memory';
import { MemoryDatastore } from 'datastore-core/memory';

export function createNodeHeliaStores() {
  return {
    blockstore: new MemoryBlockstore(),
    datastore: new MemoryDatastore(),
  };
}
