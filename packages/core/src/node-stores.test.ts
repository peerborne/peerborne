const mockMemoryBlockstore = jest.fn();
const mockMemoryDatastore = jest.fn();

jest.mock(
  'blockstore-core/memory',
  () => ({ MemoryBlockstore: mockMemoryBlockstore }),
  { virtual: true },
);
jest.mock(
  'datastore-core/memory',
  () => ({ MemoryDatastore: mockMemoryDatastore }),
  { virtual: true },
);

import { createNodeHeliaStores } from './node-stores.js';

describe('createNodeHeliaStores', () => {
  test('returns fresh in-memory stores for each Node config', () => {
    const first = createNodeHeliaStores();
    const second = createNodeHeliaStores();

    expect(mockMemoryBlockstore).toHaveBeenCalledTimes(2);
    expect(mockMemoryDatastore).toHaveBeenCalledTimes(2);
    expect(second.blockstore).not.toBe(first.blockstore);
    expect(second.datastore).not.toBe(first.datastore);
  });
});
