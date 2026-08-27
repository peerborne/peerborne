import { describe, expect, test } from '@jest/globals';
import {
  AuthorizedDocumentResolver,
  CandidateSearchResult,
  CandidateSearchRequest,
  QueryCandidateSource,
} from './candidate-source.js';
import { FederatedSearchCoordinator } from './federated-search.js';
import { IndexManager } from './index-manager.js';
import { MemoryIndexStorage } from './memory-index-storage.js';
import { IndexDefinition, QueryAst } from './types.js';

const definition: IndexDefinition = {
  version: 2,
  name: 'federated-articles',
  collectionPrefix: '/articles/',
  fields: [
    { path: 'status', type: 'string', required: true },
    { path: 'title', type: 'string', required: true },
  ],
  indexes: [
    { name: 'status_title', fields: ['status', 'title'] },
  ],
};

class StaticSource implements QueryCandidateSource {
  constructor(
    readonly id: string,
    private readonly _candidates: Array<{ documentPath: string; revision?: string }>,
    private readonly _exhausted = true,
  ) {}

  async search(_request: CandidateSearchRequest) {
    return { candidates: this._candidates, exhausted: this._exhausted };
  }
}

describe('FederatedSearchCoordinator', () => {
  test('treats remote rows as hints and locally verifies authorization and predicates', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    await manager.updateIndex('/articles/local', { status: 'published', title: 'Local' });

    const snapshots = new Map<string, Record<string, unknown>>([
      ['/articles/good', { status: 'published', title: 'Good', private: 'not-indexed' }],
      ['/articles/lie', { status: 'draft', title: 'Liar' }],
      ['/elsewhere/outside', { status: 'published', title: 'Outside' }],
    ]);
    const resolver: AuthorizedDocumentResolver = {
      async resolveAuthorized(documentPath, revision) {
        const snapshot = snapshots.get(documentPath);
        return snapshot ? { documentPath, revision, snapshot } : undefined;
      },
    };
    const sources: QueryCandidateSource[] = [new StaticSource('source-one', [
      { documentPath: '/articles/good', revision: 'r1' },
      { documentPath: '/articles/lie' },
      { documentPath: '/elsewhere/outside' },
      { documentPath: '/articles/local' },
      { documentPath: '/articles/unauthorized' },
    ])];
    const coordinator = new FederatedSearchCoordinator(manager, resolver);
    const result = await coordinator.search(query(), sources);
    expect(result.documents.map((entry) => entry.documentPath)).toEqual([
      '/articles/good', '/articles/local',
    ]);
    expect(result.documents[0].snapshot).not.toHaveProperty('private');
    expect(result.count).toEqual({ kind: 'verified-lower-bound', value: 2 });
    expect(result.coverage).toMatchObject({
      partial: true,
      reasons: ['byzantine-omission-possible'],
    });
    expect(result.sources[0].candidatesAccepted).toBe(1);
  });

  test('snapshots each untrusted candidate property once before verification', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    let documentPathReads = 0;
    const candidate = new Proxy<Record<string, unknown>>({}, {
      getOwnPropertyDescriptor(_target, property) {
        if (property !== 'documentPath') return undefined;
        documentPathReads++;
        return {
          configurable: true,
          enumerable: true,
          writable: true,
          value: documentPathReads === 1 ? '/articles/good' : '/elsewhere/secret',
        };
      },
    }) as { documentPath: string };
    const resolvedPaths: string[] = [];
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized(documentPath) {
        resolvedPaths.push(documentPath);
        return { documentPath, snapshot: { status: 'published', title: 'Good' } };
      },
    });

    const result = await coordinator.search(query(), [
      new StaticSource('stateful-candidate', [candidate]),
    ]);

    expect(documentPathReads).toBe(1);
    expect(resolvedPaths).toEqual(['/articles/good']);
    expect(result.documents.map((entry) => entry.documentPath)).toEqual(['/articles/good']);
  });

  test('drops accessor-backed candidate properties without invoking them', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    let getterCalls = 0;
    const candidate = {} as { documentPath: string };
    Object.defineProperty(candidate, 'documentPath', {
      enumerable: true,
      get() {
        getterCalls++;
        throw new Error('hostile getter');
      },
    });
    const resolvedPaths: string[] = [];
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized(documentPath) {
        resolvedPaths.push(documentPath);
        return undefined;
      },
    });

    const result = await coordinator.search(query(), [
      new StaticSource('accessor-candidate', [candidate]),
    ]);

    expect(getterCalls).toBe(0);
    expect(resolvedPaths).toEqual([]);
    expect(result.documents).toEqual([]);
    expect(result.sources[0]).toMatchObject({ status: 'complete', candidatesReceived: 1 });
  });

  test('contains accessor-backed source results within the source error boundary', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    let getterCalls = 0;
    const source: QueryCandidateSource = {
      id: 'accessor-result',
      async search() {
        const result = { exhausted: true };
        Object.defineProperty(result, 'candidates', {
          enumerable: true,
          get() {
            getterCalls++;
            throw new Error('hostile result getter');
          },
        });
        return result as CandidateSearchResult;
      },
    };
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized() { return undefined; },
    });

    const result = await coordinator.search(query(), [source]);

    expect(getterCalls).toBe(0);
    expect(result.sources[0].status).toBe('error');
    expect(result.coverage.reasons).toContain('source-error');
  });

  test('applies stable pagination after deterministic local/remote merge', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    await manager.updateIndex('/articles/local', { status: 'published', title: 'Local' });
    const resolver: AuthorizedDocumentResolver = {
      async resolveAuthorized(documentPath) {
        return { documentPath, snapshot: { status: 'published', title: 'Good' } };
      },
    };
    const source = new StaticSource('source-one', [{ documentPath: '/articles/good' }]);
    const coordinator = new FederatedSearchCoordinator(manager, resolver);
    const first = await coordinator.search({ ...query(), first: 1 }, [source]);
    expect(first.documents.map((entry) => entry.documentPath)).toEqual(['/articles/good']);
    expect(first.pageInfo.hasMore).toBe(true);
    const second = await coordinator.search({
      ...query(),
      first: 1,
      after: first.pageInfo.cursor,
    }, [source]);
    expect(second.documents.map((entry) => entry.documentPath)).toEqual(['/articles/local']);
  });

  test('bounds source latency and reports timeout coverage', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    const resolver: AuthorizedDocumentResolver = {
      async resolveAuthorized() { return undefined; },
    };
    let aborted = false;
    const hanging: QueryCandidateSource = {
      id: 'hanging',
      async search(request) {
        request.signal.addEventListener('abort', () => { aborted = true; });
        return new Promise(() => undefined);
      },
    };
    const coordinator = new FederatedSearchCoordinator(manager, resolver, { sourceTimeoutMs: 5 });
    const result = await coordinator.search(query(), [hanging]);
    expect(result.sources[0].status).toBe('timeout');
    expect(result.coverage.reasons).toContain('source-timeout');
    expect(aborted).toBe(true);
  });

  test('rejects duplicate source identities before network work', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized() { return undefined; },
    });
    const source = new StaticSource('duplicate', []);
    await expect(coordinator.search(query(), [source, source])).rejects.toThrow('duplicate source');
  });

  test('rejects a distributed source bound to a different schema generation', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized() { return undefined; },
    });
    let searched = false;
    const source: QueryCandidateSource = {
      id: 'wrong-schema',
      binding: {
        indexName: definition.name,
        schemaHash: 'f'.repeat(64),
        generation: 'default',
      },
      async search() {
        searched = true;
        return { candidates: [], exhausted: true };
      },
    };
    await expect(coordinator.search(query(), [source])).rejects.toThrow('generation');
    expect(searched).toBe(false);
  });

  test('deduplicates resolution work without falsely exhausting an exact candidate budget', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    let resolutions = 0;
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized(documentPath) {
        resolutions++;
        return { documentPath, snapshot: { status: 'published', title: 'Remote' } };
      },
    }, {
      maxCandidatesPerSource: 2,
      maxTotalCandidates: 2,
      resolveConcurrency: 2,
    });
    const source = new StaticSource('duplicates', [
      { documentPath: '/articles/remote' },
      { documentPath: '/articles/remote' },
    ]);
    const result = await coordinator.search(query(), [source]);
    expect(resolutions).toBe(1);
    expect(result.sources[0].candidatesAccepted).toBe(1);
    expect(result.coverage.reasons).not.toContain('candidate-budget-exhausted');
  });

  test('tries a distinct revision after a stale revision cannot be resolved', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    const revisions: Array<string | undefined> = [];
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized(documentPath, revision) {
        revisions.push(revision);
        if (revision === 'stale') return undefined;
        return {
          documentPath,
          revision,
          snapshot: { status: 'published', title: 'Current' },
        };
      },
    }, { resolveConcurrency: 1 });
    const result = await coordinator.search(query(), [new StaticSource('revisions', [
      { documentPath: '/articles/remote', revision: 'stale' },
      { documentPath: '/articles/remote', revision: 'current' },
    ])]);
    expect(revisions).toEqual(['stale', 'current']);
    expect(result.documents.map((entry) => entry.documentPath)).toEqual(['/articles/remote']);
  });

  test('bounds authorized resolution and exposes an abort signal', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    let aborted = false;
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized(_documentPath, _revision, options) {
        options?.signal.addEventListener('abort', () => { aborted = true; });
        return new Promise(() => undefined);
      },
    }, { resolveTimeoutMs: 5 });
    const result = await coordinator.search(query(), [
      new StaticSource('unresponsive-document', [{ documentPath: '/articles/hanging' }]),
    ]);
    expect(aborted).toBe(true);
    expect(result.coverage.reasons).toContain('candidate-resolution-timeout');
  });

  test('bounds the complete candidate-resolution phase', async () => {
    const manager = new IndexManager<Record<string, unknown>>(new MemoryIndexStorage(), (value) => value);
    await manager.defineIndex(definition);
    const coordinator = new FederatedSearchCoordinator(manager, {
      async resolveAuthorized() { return new Promise(() => undefined); },
    }, {
      maxCandidatesPerSource: 2,
      resolveBudgetMs: 5,
      resolveTimeoutMs: 1000,
      resolveConcurrency: 1,
    });
    const result = await coordinator.search(query(), [new StaticSource('slow-documents', [
      { documentPath: '/articles/slow-one' },
      { documentPath: '/articles/slow-two' },
    ])]);
    expect(result.coverage.reasons).toContain('candidate-resolution-budget-exhausted');
    expect(result.coverage.reasons).toContain('candidate-resolution-timeout');
  });
});

function query(): QueryAst {
  return {
    version: 2,
    indexName: definition.name,
    where: { kind: 'field', path: 'status', operator: 'eq', value: 'published' },
    orderBy: [{ path: 'title', direction: 'asc' }],
    count: 'exact',
  };
}
