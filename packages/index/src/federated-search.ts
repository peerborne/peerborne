import {
  AuthorizedDocumentResolver,
  QueryCandidateReference,
  QueryCandidateSource,
} from './candidate-source.js';
import { IndexManager } from './index-manager.js';
import {
  IndexDefinition,
  QueryAst,
  QueryExecutionInfo,
  QueryPageInfo,
  QueryResultEntry,
} from './types.js';
import {
  evaluateQueryExpression,
  hashQuery,
  invalidIndexedValueReason,
  projectFields,
  resolvedGeneration,
  validateQueryAst,
} from './query-ast.js';
import { compareEntriesForQuery, createQueryCursor, isAfterQueryCursor, parseQueryCursor } from './query-cursor.js';
import { extractField } from './field-extractor.js';

export type FederatedCoverageReason =
  | 'byzantine-omission-possible'
  | 'source-error'
  | 'source-timeout'
  | 'source-truncated'
  | 'candidate-budget-exhausted';

export interface FederatedQueryCoverage {
  partial: boolean;
  reasons: FederatedCoverageReason[];
  sourcesAttempted: number;
  sourcesCompleted: number;
}

export type FederatedQueryCount =
  | { kind: 'verified'; value: number }
  | { kind: 'verified-lower-bound'; value: number }
  | { kind: 'none' };

export interface FederatedSourceExecution {
  sourceId: string;
  status: 'complete' | 'timeout' | 'error';
  candidatesReceived: number;
  candidatesAccepted: number;
}

export interface FederatedQueryResult {
  documents: QueryResultEntry<Record<string, unknown>>[];
  count: FederatedQueryCount;
  pageInfo: QueryPageInfo;
  coverage: FederatedQueryCoverage;
  localExecution: QueryExecutionInfo;
  sources: FederatedSourceExecution[];
}

export interface FederatedSearchConfig {
  maxSources?: number;
  maxCandidatesPerSource?: number;
  maxTotalCandidates?: number;
  resolveConcurrency?: number;
  sourceTimeoutMs?: number;
}

/** Federates untrusted candidate hints and verifies every result through local authority. */
export class FederatedSearchCoordinator<DocType> {
  private readonly _maxSources: number;
  private readonly _maxCandidatesPerSource: number;
  private readonly _maxTotalCandidates: number;
  private readonly _resolveConcurrency: number;
  private readonly _sourceTimeoutMs: number;

  constructor(
    private readonly _manager: IndexManager<DocType>,
    private readonly _resolver: AuthorizedDocumentResolver,
    config: FederatedSearchConfig = {},
  ) {
    this._maxSources = config.maxSources ?? 8;
    this._maxCandidatesPerSource = config.maxCandidatesPerSource ?? 256;
    this._maxTotalCandidates = config.maxTotalCandidates ?? 1024;
    this._resolveConcurrency = config.resolveConcurrency ?? 4;
    this._sourceTimeoutMs = config.sourceTimeoutMs ?? 3000;
    for (const [name, value, maximum] of [
      ['maxSources', this._maxSources, 256],
      ['maxCandidatesPerSource', this._maxCandidatesPerSource, 4096],
      ['maxTotalCandidates', this._maxTotalCandidates, 65_536],
      ['resolveConcurrency', this._resolveConcurrency, 256],
      ['sourceTimeoutMs', this._sourceTimeoutMs, 60_000],
    ] as const) {
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
        throw new RangeError(`${name} must be an integer from 1-${maximum}`);
      }
    }
  }

  async search(queryInput: QueryAst, sources: QueryCandidateSource[]): Promise<FederatedQueryResult> {
    if (sources.length > this._maxSources) throw new RangeError('too many federated sources');
    const sourceIds = new Set<string>();
    for (const source of sources) {
      validateSourceId(source.id);
      if (sourceIds.has(source.id)) throw new TypeError(`duplicate source id: ${source.id}`);
      sourceIds.add(source.id);
    }
    const definition = resolveDefinition(this._manager, queryInput);
    const query = validateQueryAst(queryInput, definition);
    const local = await this._manager.query({
      ...query,
      first: undefined,
      after: undefined,
      select: undefined,
      count: 'exact',
    });
    for (const source of sources) {
      if (source.binding && (
        source.binding.indexName !== definition.name ||
        source.binding.schemaHash !== local.execution.schemaHash ||
        source.binding.generation !== local.execution.generation
      )) throw new TypeError(`candidate source ${source.id} does not match the local index generation`);
    }

    const deadline = Date.now() + this._sourceTimeoutMs;
    const sourceExecutions: FederatedSourceExecution[] = sources.map((source) => ({
      sourceId: source.id,
      status: 'error',
      candidatesReceived: 0,
      candidatesAccepted: 0,
    }));
    const sourceResults = await Promise.all(sources.map(async (source, index) => {
      try {
        const result = await withTimeout(source.search({
          query,
          candidateLimit: this._maxCandidatesPerSource,
          deadline,
        }), this._sourceTimeoutMs);
        if (!Array.isArray(result.candidates) || result.candidates.length > this._maxCandidatesPerSource ||
            typeof result.exhausted !== 'boolean') throw new TypeError('invalid candidate result');
        sourceExecutions[index].status = 'complete';
        sourceExecutions[index].candidatesReceived = result.candidates.length;
        return result;
      } catch (error) {
        sourceExecutions[index].status = error instanceof SourceTimeoutError ? 'timeout' : 'error';
        return undefined;
      }
    }));

    const interleaved: Array<{ sourceIndex: number; candidate: QueryCandidateReference }> = [];
    let offset = 0;
    while (interleaved.length < this._maxTotalCandidates) {
      let added = false;
      for (let sourceIndex = 0; sourceIndex < sourceResults.length; sourceIndex++) {
        const candidate = sourceResults[sourceIndex]?.candidates[offset];
        if (candidate) {
          interleaved.push({ sourceIndex, candidate });
          added = true;
          if (interleaved.length === this._maxTotalCandidates) break;
        }
      }
      if (!added) break;
      offset++;
    }

    const verified = new Map<string, { documentPath: string; fields: Record<string, unknown> }>();
    const claimed = new Set<string>();
    for (const document of local.documents) {
      verified.set(document.documentPath, { documentPath: document.documentPath, fields: document.snapshot });
    }
    let cursor = 0;
    const workers = Array.from({ length: Math.min(this._resolveConcurrency, interleaved.length) }, async () => {
      while (true) {
        const position = cursor++;
        const item = interleaved[position];
        if (!item) return;
        const { candidate, sourceIndex } = item;
        if (!validCandidate(candidate) || !candidate.documentPath.startsWith(definition.collectionPrefix) ||
            verified.has(candidate.documentPath) || claimed.has(candidate.documentPath)) continue;
        claimed.add(candidate.documentPath);
        try {
          const resolved = await this._resolver.resolveAuthorized(candidate.documentPath, candidate.revision);
          if (!resolved || resolved.documentPath !== candidate.documentPath ||
              (candidate.revision !== undefined && resolved.revision !== candidate.revision)) continue;
          const fields = materializeIndexedFields(resolved.snapshot, definition);
          if (!fields || !evaluateQueryExpression(fields, query.where, definition)) continue;
          verified.set(candidate.documentPath, { documentPath: candidate.documentPath, fields });
          sourceExecutions[sourceIndex].candidatesAccepted++;
        } catch {
          // Authorization, retrieval, and decryption failures are fail-closed candidate misses.
        }
      }
    });
    await Promise.all(workers);

    let merged = Array.from(verified.values());
    merged.sort((left, right) => compareEntriesForQuery(
      left,
      right,
      query.orderBy ?? [],
      definition,
    ));
    const verifiedCount = merged.length;
    const queryHash = await hashQuery(query);
    if (query.after) {
      const after = parseQueryCursor(
        query.after,
        queryHash,
        local.execution.schemaHash,
        resolvedGeneration(definition),
        (query.orderBy ?? []).length,
        (query.orderBy ?? []).map((clause) =>
          definition.fields.find((field) => field.path === clause.path)!.type),
      );
      merged = merged.filter((entry) =>
        isAfterQueryCursor(entry, after, query.orderBy ?? [], definition));
    }
    const total = merged.length;
    const first = query.first ?? total;
    const page = merged.slice(0, first);
    const last = page.at(-1);
    const reasons = new Set<FederatedCoverageReason>();
    if (sources.length) reasons.add('byzantine-omission-possible');
    if (sourceExecutions.some((execution) => execution.status === 'timeout')) reasons.add('source-timeout');
    if (sourceExecutions.some((execution) => execution.status === 'error')) reasons.add('source-error');
    if (sourceResults.some((result) => result && !result.exhausted)) reasons.add('source-truncated');
    const candidatesReceived = sourceResults.reduce(
      (total, result) => total + (result?.candidates.length ?? 0),
      0,
    );
    if (candidatesReceived > interleaved.length) {
      reasons.add('candidate-budget-exhausted');
    }
    return {
      documents: page.map((entry) => ({
        documentPath: entry.documentPath,
        snapshot: projectFields(entry.fields, query.select),
      })),
      count: query.count === 'exact'
        ? sources.length
          ? { kind: 'verified-lower-bound', value: verifiedCount }
          : { kind: 'verified', value: verifiedCount }
        : { kind: 'none' },
      pageInfo: {
        hasMore: total > first,
        ...(last ? {
          cursor: createQueryCursor(
            queryHash,
            local.execution.schemaHash,
            resolvedGeneration(definition),
            last.documentPath,
            last.fields,
            query,
            definition,
          ),
        } : {}),
      },
      coverage: {
        partial: reasons.size > 0,
        reasons: Array.from(reasons),
        sourcesAttempted: sources.length,
        sourcesCompleted: sourceExecutions.filter((execution) => execution.status === 'complete').length,
      },
      localExecution: local.execution,
      sources: sourceExecutions,
    };
  }
}

function resolveDefinition<DocType>(manager: IndexManager<DocType>, query: QueryAst): IndexDefinition {
  const definitions = manager.getDefinitions();
  const definition = query.indexName
    ? definitions.find((candidate) => candidate.name === query.indexName)
    : query.collectionPrefix
      ? definitions.find((candidate) => candidate.collectionPrefix === query.collectionPrefix)
      : definitions[0];
  if (!definition) throw new Error('federated query does not resolve to a defined index');
  return definition;
}

function materializeIndexedFields(
  snapshot: Record<string, unknown>,
  definition: IndexDefinition,
): Record<string, unknown> | undefined {
  const fields: Record<string, unknown> = {};
  for (const field of definition.fields) {
    const value = extractField(snapshot, field.path);
    if (invalidIndexedValueReason(value, field)) return undefined;
    setNestedField(fields, field.path, value);
  }
  return fields;
}

function setNestedField(target: Record<string, unknown>, path: string, value: unknown): void {
  const segments = path.split('.');
  let cursor = target;
  for (let i = 0; i < segments.length - 1; i++) {
    const existing = cursor[segments[i]];
    if (existing !== null && typeof existing === 'object' && !Array.isArray(existing)) {
      cursor = existing as Record<string, unknown>;
    } else {
      const nested: Record<string, unknown> = {};
      cursor[segments[i]] = nested;
      cursor = nested;
    }
  }
  cursor[segments.at(-1)!] = value;
}

function validCandidate(candidate: QueryCandidateReference): boolean {
  return candidate !== null && typeof candidate === 'object' &&
    typeof candidate.documentPath === 'string' && candidate.documentPath.length > 0 &&
    candidate.documentPath.length <= 4096 && !/[\u0000-\u001f]/.test(candidate.documentPath) &&
    (candidate.revision === undefined ||
      (typeof candidate.revision === 'string' && candidate.revision.length > 0 &&
       candidate.revision.length <= 512 && !/[\u0000-\u001f]/.test(candidate.revision)));
}

function validateSourceId(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError('candidate source id is invalid');
  }
}

class SourceTimeoutError extends Error {}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new SourceTimeoutError()), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
