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
  | 'candidate-budget-exhausted'
  | 'candidate-resolution-error'
  | 'candidate-resolution-budget-exhausted'
  | 'candidate-resolution-timeout';

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
  resolveBudgetMs?: number;
  resolveTimeoutMs?: number;
  sourceTimeoutMs?: number;
}

/** Federates untrusted candidate hints and verifies every result through local authority. */
export class FederatedSearchCoordinator<DocType> {
  private readonly _maxSources: number;
  private readonly _maxCandidatesPerSource: number;
  private readonly _maxTotalCandidates: number;
  private readonly _resolveConcurrency: number;
  private readonly _resolveBudgetMs: number;
  private readonly _resolveTimeoutMs: number;
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
    this._resolveBudgetMs = config.resolveBudgetMs ?? 10_000;
    this._resolveTimeoutMs = config.resolveTimeoutMs ?? 3000;
    this._sourceTimeoutMs = config.sourceTimeoutMs ?? 3000;
    for (const [name, value, maximum] of [
      ['maxSources', this._maxSources, 256],
      ['maxCandidatesPerSource', this._maxCandidatesPerSource, 4096],
      ['maxTotalCandidates', this._maxTotalCandidates, 65_536],
      ['resolveConcurrency', this._resolveConcurrency, 256],
      ['resolveBudgetMs', this._resolveBudgetMs, 60_000],
      ['resolveTimeoutMs', this._resolveTimeoutMs, 60_000],
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
        const abortController = new AbortController();
        const result = await withTimeout(
          source.search({
            query,
            candidateLimit: this._maxCandidatesPerSource,
            deadline,
            signal: abortController.signal,
          }),
          this._sourceTimeoutMs,
          () => abortController.abort(),
        );
        const snapshot = snapshotCandidateResult(result, this._maxCandidatesPerSource);
        sourceExecutions[index].status = 'complete';
        sourceExecutions[index].candidatesReceived = snapshot.candidates.length;
        return snapshot;
      } catch (error) {
        sourceExecutions[index].status = error instanceof SourceTimeoutError ? 'timeout' : 'error';
        return undefined;
      }
    }));

    const interleaved: Array<{ sourceIndex: number; candidate: QueryCandidateReference }> = [];
    let offset = 0;
    while (interleaved.length < this._maxTotalCandidates) {
      let sourceHasPosition = false;
      for (let sourceIndex = 0; sourceIndex < sourceResults.length; sourceIndex++) {
        const sourceResult = sourceResults[sourceIndex];
        if (!sourceResult || offset >= sourceResult.candidates.length) continue;
        sourceHasPosition = true;
        const candidate = sourceResult.candidates[offset];
        if (candidate) {
          interleaved.push({ sourceIndex, candidate });
          if (interleaved.length === this._maxTotalCandidates) break;
        }
      }
      if (!sourceHasPosition) break;
      offset++;
    }

    const verified = new Map<string, { documentPath: string; fields: Record<string, unknown> }>();
    const claimedReferences = new Set<string>();
    let resolutionError = false;
    let resolutionTimeout = false;
    let resolutionBudgetExhausted = false;
    for (const document of local.documents) {
      verified.set(document.documentPath, { documentPath: document.documentPath, fields: document.snapshot });
    }
    let cursor = 0;
    const resolutionDeadline = Date.now() + this._resolveBudgetMs;
    const workers = Array.from({ length: Math.min(this._resolveConcurrency, interleaved.length) }, async () => {
      while (true) {
        const position = cursor++;
        const item = interleaved[position];
        if (!item) return;
        const remainingResolveTime = resolutionDeadline - Date.now();
        if (remainingResolveTime <= 0) {
          resolutionBudgetExhausted = true;
          return;
        }
        const { candidate, sourceIndex } = item;
        if (!candidate.documentPath.startsWith(definition.collectionPrefix) ||
            verified.has(candidate.documentPath)) continue;
        const referenceKey = candidateReferenceKey(candidate);
        if (claimedReferences.has(referenceKey)) continue;
        claimedReferences.add(referenceKey);
        try {
          const abortController = new AbortController();
          const timeoutMs = Math.min(this._resolveTimeoutMs, remainingResolveTime);
          const resolveDeadline = Date.now() + timeoutMs;
          const resolved = await withTimeout(
            this._resolver.resolveAuthorized(candidate.documentPath, candidate.revision, {
              deadline: resolveDeadline,
              signal: abortController.signal,
            }),
            timeoutMs,
            () => abortController.abort(),
          );
          if (!resolved || resolved.documentPath !== candidate.documentPath ||
              (candidate.revision !== undefined && resolved.revision !== candidate.revision)) continue;
          const fields = materializeIndexedFields(resolved.snapshot, definition);
          if (!fields || !evaluateQueryExpression(fields, query.where, definition)) continue;
          if (verified.has(candidate.documentPath)) continue;
          verified.set(candidate.documentPath, { documentPath: candidate.documentPath, fields });
          sourceExecutions[sourceIndex].candidatesAccepted++;
        } catch (error) {
          if (error instanceof SourceTimeoutError) resolutionTimeout = true;
          else resolutionError = true;
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
    const candidatesAvailable = sourceResults.reduce(
      (total, result) => total + (result?.candidateCount ?? 0),
      0,
    );
    if (candidatesAvailable > interleaved.length) {
      reasons.add('candidate-budget-exhausted');
    }
    if (resolutionTimeout) reasons.add('candidate-resolution-timeout');
    if (resolutionError) reasons.add('candidate-resolution-error');
    if (resolutionBudgetExhausted) reasons.add('candidate-resolution-budget-exhausted');
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

interface SnapshottedCandidateResult {
  candidates: Array<QueryCandidateReference | undefined>;
  candidateCount: number;
  exhausted: boolean;
}

function snapshotCandidateResult(
  result: unknown,
  maxCandidates: number,
): SnapshottedCandidateResult {
  if (result === null || typeof result !== 'object' || Array.isArray(result)) {
    throw new TypeError('invalid candidate result');
  }
  const rawCandidates = requireOwnDataProperty(result, 'candidates');
  const exhausted = requireOwnDataProperty(result, 'exhausted');
  if (!Array.isArray(rawCandidates) || typeof exhausted !== 'boolean') {
    throw new TypeError('invalid candidate result');
  }
  const candidateLength = requireOwnDataProperty(rawCandidates, 'length');
  if (typeof candidateLength !== 'number' || !Number.isSafeInteger(candidateLength) ||
      candidateLength < 0 || candidateLength > maxCandidates) {
    throw new TypeError('invalid candidate result');
  }
  const candidates = Array.from(
    { length: candidateLength },
    (_, index) => snapshotCandidateAt(rawCandidates, index),
  );
  return {
    candidates,
    candidateCount: candidates.reduce((count, candidate) => count + (candidate ? 1 : 0), 0),
    exhausted,
  };
}

function snapshotCandidateAt(
  candidates: unknown[],
  index: number,
): QueryCandidateReference | undefined {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(candidates, index);
    if (!descriptor || !('value' in descriptor)) return undefined;
    return snapshotCandidate(descriptor.value);
  } catch {
    return undefined;
  }
}

function snapshotCandidate(candidate: unknown): QueryCandidateReference | undefined {
  try {
    if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) return undefined;
    const documentPathDescriptor = Object.getOwnPropertyDescriptor(candidate, 'documentPath');
    const revisionDescriptor = Object.getOwnPropertyDescriptor(candidate, 'revision');
    if (!documentPathDescriptor || !('value' in documentPathDescriptor) ||
        (revisionDescriptor && !('value' in revisionDescriptor))) return undefined;
    const documentPath = documentPathDescriptor.value;
    const revision = revisionDescriptor?.value;
    if (!validCandidateValues(documentPath, revision)) return undefined;
    return Object.freeze({
      documentPath,
      ...(revision !== undefined ? { revision } : {}),
    });
  } catch {
    return undefined;
  }
}

function requireOwnDataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !('value' in descriptor)) throw new TypeError('invalid candidate result');
  return descriptor.value;
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

function validCandidateValues(
  documentPath: unknown,
  revision: unknown,
): documentPath is string {
  return typeof documentPath === 'string' && documentPath.length > 0 &&
    documentPath.length <= 4096 && !/[\u0000-\u001f]/.test(documentPath) &&
    (revision === undefined ||
      (typeof revision === 'string' && revision.length > 0 &&
       revision.length <= 512 && !/[\u0000-\u001f]/.test(revision)));
}

function candidateReferenceKey(candidate: QueryCandidateReference): string {
  return `${candidate.documentPath}\u0000${candidate.revision ?? ''}`;
}

function validateSourceId(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError('candidate source id is invalid');
  }
}

class SourceTimeoutError extends Error {}

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout?: () => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout?.();
      reject(new SourceTimeoutError());
    }, timeoutMs);
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
