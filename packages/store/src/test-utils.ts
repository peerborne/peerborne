import type { DocumentHandle } from './index.js';

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
  handlers = new Map<
    string,
    (
      data: TestData,
      readers: string[],
      writers: string[],
      hashes: string[],
    ) => void
  >();

  async open() {
    this.openCount++;
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
    if (this.writeError) throw this.writeError;
    change(this.document);
    this.emit();
  }
  subscribe(
    id: string,
    handler: (
      data: TestData,
      readers: string[],
      writers: string[],
      hashes: string[],
    ) => void,
  ) {
    this.handlers.set(id, handler);
  }
  unsubscribe(id: string) {
    this.handlers.delete(id);
  }
  emit() {
    for (const handler of this.handlers.values()) {
      handler(this.document, [...this.readers], [...this.writers], []);
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
