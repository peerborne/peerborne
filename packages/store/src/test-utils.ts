import type { DocumentDeliveryFailure, DocumentHandle } from './index.js';

export type TestData = { title: string };
export type TestChange = (data: TestData) => void;

export class TestDocument
  implements DocumentHandle<TestData, TestChange, string>
{
  document = { title: 'Initial' };
  readers = ['reader'];
  writers = ['writer'];
  openCount = 0;
  closeCount = 0;
  writeCount = 0;
  openGate?: Promise<unknown>;
  readGate?: Promise<unknown>;
  writeGate?: Promise<unknown>;
  openError?: Error;
  writeError?: Error;
  reopenable = true;
  retired = false;
  retireOnWriteError = false;
  deliveryFailure?: DocumentDeliveryFailure;
  handlers = new Map<
    string,
    (
      data: TestData,
      readers: string[],
      writers: string[],
      hashes: string[],
    ) => void
  >();
  filters = new Map<string, 'all' | 'local' | 'remote'>();

  async open() {
    this.openCount++;
    if (!this.reopenable && this.closeCount > 0)
      throw new Error('Durable BeeKEM fork guard blocks document access');
    await this.openGate;
    if (this.openError) throw this.openError;
  }
  async close() {
    this.closeCount++;
  }
  async getReaders() {
    await this.readGate;
    return [...this.readers];
  }
  async getWriters() {
    await this.readGate;
    return [...this.writers];
  }
  async change(change: TestChange) {
    this.writeCount++;
    await this.writeGate;
    if (this.retired) throw new Error('Document was retired');
    if (this.writeError) {
      if (this.retireOnWriteError) {
        change(this.document);
        this.retired = true;
      }
      throw this.writeError;
    }
    change(this.document);
    const changeId = `cid-${this.writeCount}`;
    this.setDeliveryFailure(
      this.undeliveredError === undefined
        ? undefined
        : { documentPath: '/test', changeId, error: this.undeliveredError },
    );
    this.emit('local', [changeId]);
  }
  setDeliveryFailure(failure: DocumentDeliveryFailure | undefined) {
    if (this.deliveryFailure === failure) return;
    this.deliveryFailure = failure;
    for (const handler of this.deliveryHandlers.values()) handler(failure);
  }
  subscribe(
    id: string,
    handler: (
      data: TestData,
      readers: string[],
      writers: string[],
      hashes: string[],
    ) => void,
    originFilter: 'all' | 'local' | 'remote' = 'all',
  ) {
    this.handlers.set(id, handler);
    this.filters.set(id, originFilter);
  }
  unsubscribe(id: string) {
    this.handlers.delete(id);
    this.filters.delete(id);
  }
  deliveryHandlers = new Map<
    string,
    (failure: DocumentDeliveryFailure | undefined) => void
  >();
  undeliveredError?: Error;
  subscribeDeliveryState(
    id: string,
    handler: (failure: DocumentDeliveryFailure | undefined) => void,
  ) {
    this.deliveryHandlers.set(id, handler);
  }
  unsubscribeDeliveryState(id: string) {
    this.deliveryHandlers.delete(id);
  }
  emit(origin: 'local' | 'remote' = 'remote', hashes: string[] = []) {
    for (const [id, handler] of this.handlers) {
      const filter = this.filters.get(id);
      if (filter !== 'all' && filter !== origin) continue;
      handler(this.document, [...this.readers], [...this.writers], hashes);
    }
  }
}

export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
