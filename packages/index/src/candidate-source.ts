import { QueryAst } from './types.js';

/** Untrusted hint returned by a local or remote candidate source. */
export interface QueryCandidateReference {
  documentPath: string;
  revision?: string;
}

export interface CandidateSearchRequest {
  query: QueryAst;
  candidateLimit: number;
  deadline: number;
  signal: AbortSignal;
}

export interface CandidateSearchResult {
  candidates: QueryCandidateReference[];
  exhausted: boolean;
}

export interface QueryCandidateSource {
  readonly id: string;
  readonly binding?: {
    indexName: string;
    schemaHash: string;
    generation: string;
  };
  search(request: CandidateSearchRequest): Promise<CandidateSearchResult>;
}

export interface AuthorizedDocumentSnapshot {
  documentPath: string;
  revision?: string;
  snapshot: Record<string, unknown>;
}

export interface AuthorizedDocumentResolveOptions {
  deadline: number;
  signal: AbortSignal;
}

/**
 * Security boundary for candidate materialization. Implementations must authenticate the
 * caller, enforce current ACL/history policy, retrieve authenticated state, and decrypt it.
 * Candidate sources are never permitted to supply result snapshots directly.
 */
export interface AuthorizedDocumentResolver {
  resolveAuthorized(
    documentPath: string,
    revision?: string,
    options?: AuthorizedDocumentResolveOptions,
  ): Promise<AuthorizedDocumentSnapshot | undefined>;
}
