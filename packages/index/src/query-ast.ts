import {
  FieldFilter,
  FilterOperator,
  IndexDefinition,
  IndexFieldDefinition,
  IndexKeyDefinition,
  IndexScalar,
  InvalidIndexedValueReason,
  QueryAst,
  QueryExpression,
  QueryFieldExpression,
  QueryOptions,
} from './types.js';
import { extractField } from './field-extractor.js';

const MAX_FIELD_PATH_LENGTH = 512;
const MAX_COLLECTION_PREFIX_LENGTH = 4096;
const MAX_STRING_LENGTH = 16_384;
const MAX_QUERY_DEPTH = 16;
const MAX_QUERY_NODES = 128;
const MAX_IN_VALUES = 256;
const MAX_FIRST = 10_000;
const MAX_SORT_FIELDS = 8;
const MAX_SELECT_FIELDS = 64;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const FORBIDDEN_PATH_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor']);

export class InvalidIndexSchemaError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidIndexSchemaError';
  }
}

export class InvalidQueryError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidQueryError';
  }
}

export function validateIndexDefinition(definition: IndexDefinition): IndexDefinition {
  if (!isRecord(definition)) throw new InvalidIndexSchemaError('index definition must be an object');
  const version = definition.version ?? 1;
  if (version !== 1 && version !== 2) throw new InvalidIndexSchemaError('index version must be 1 or 2');
  if (version === 1) return structuredClone(definition);
  requireOwnKeys(
    definition,
    ['version', 'name', 'collectionPrefix', 'fields'],
    'index definition',
    InvalidIndexSchemaError,
  );
  rejectUnknownSchemaKeys(definition, new Set([
    'version', 'name', 'collectionPrefix', 'fields', 'indexes', 'generation',
    'storageMode', 'invalidValuePolicy',
  ]), 'index definition');
  validateName(definition.name, 'index name');
  if (definition.name.startsWith('__peerborne_internal_')) {
    throw new InvalidIndexSchemaError('index name uses a reserved prefix');
  }
  validateCollectionPrefix(definition.collectionPrefix);
  if (!Array.isArray(definition.fields) || definition.fields.length === 0 || definition.fields.length > 64) {
    throw new InvalidIndexSchemaError('fields must contain 1-64 definitions');
  }

  const fieldPaths = new Set<string>();
  const fields = definition.fields.map((field) => {
    if (!isRecord(field)) throw new InvalidIndexSchemaError('field definitions must be objects');
    requireOwnKeys(field, ['path', 'type'], 'field definition', InvalidIndexSchemaError);
    rejectUnknownSchemaKeys(
      field,
      new Set(['path', 'type', 'required', 'maxStringLength']),
      'field definition',
    );
    validateFieldPath(field.path, 'field path', InvalidIndexSchemaError);
    if (fieldPaths.has(field.path)) throw new InvalidIndexSchemaError(`duplicate field path: ${field.path}`);
    fieldPaths.add(field.path);
    if (!['string', 'number', 'date', 'boolean'].includes(field.type)) {
      throw new InvalidIndexSchemaError(`unsupported type for ${field.path}`);
    }
    if (field.required !== undefined && typeof field.required !== 'boolean') {
      throw new InvalidIndexSchemaError(`required must be boolean for ${field.path}`);
    }
    if (field.maxStringLength !== undefined &&
        (!Number.isSafeInteger(field.maxStringLength) || field.maxStringLength < 1 ||
         field.maxStringLength > 1_000_000 || field.type !== 'string')) {
      throw new InvalidIndexSchemaError(`invalid maxStringLength for ${field.path}`);
    }
    return { ...field };
  });
  for (const path of fieldPaths) {
    for (const otherPath of fieldPaths) {
      if (otherPath.startsWith(`${path}.`)) {
        throw new InvalidIndexSchemaError(
          `field paths must not overlap: ${path} and ${otherPath}`,
        );
      }
    }
  }

  let indexes: IndexKeyDefinition[] | undefined;
  if (definition.indexes !== undefined) {
    if (!Array.isArray(definition.indexes) || definition.indexes.length === 0 || definition.indexes.length > 64) {
      throw new InvalidIndexSchemaError('indexes must contain 1-64 definitions');
    }
    const names = new Set<string>();
    indexes = definition.indexes.map((index) => {
      if (!isRecord(index)) throw new InvalidIndexSchemaError('physical index definitions must be objects');
      requireOwnKeys(index, ['name', 'fields'], 'physical index definition', InvalidIndexSchemaError);
      rejectUnknownSchemaKeys(index, new Set(['name', 'fields']), 'physical index definition');
      validateName(index.name, 'physical index name');
      if (names.has(index.name)) throw new InvalidIndexSchemaError(`duplicate physical index: ${index.name}`);
      names.add(index.name);
      if (!Array.isArray(index.fields) || index.fields.length === 0 || index.fields.length > 8) {
        throw new InvalidIndexSchemaError(`physical index ${index.name} must contain 1-8 fields`);
      }
      const seen = new Set<string>();
      for (const path of index.fields) {
        validateFieldPath(path, 'physical index field', InvalidIndexSchemaError);
        if (!fieldPaths.has(path)) throw new InvalidIndexSchemaError(`unknown field ${path} in ${index.name}`);
        if (!fields.find((field) => field.path === path)!.required) {
          throw new InvalidIndexSchemaError(
            `physical index ${index.name} requires field ${path} to be required`,
          );
        }
        if (seen.has(path)) throw new InvalidIndexSchemaError(`duplicate field ${path} in ${index.name}`);
        seen.add(path);
      }
      return { name: index.name, fields: [...index.fields] };
    });
  }

  if (definition.generation !== undefined) validateName(definition.generation, 'generation');
  if (definition.storageMode !== undefined &&
      definition.storageMode !== 'memory' && definition.storageMode !== 'cleartext-local') {
    throw new InvalidIndexSchemaError('storageMode must be memory or cleartext-local');
  }
  if (definition.invalidValuePolicy !== undefined &&
      definition.invalidValuePolicy !== 'skip-document' && definition.invalidValuePolicy !== 'reject') {
    throw new InvalidIndexSchemaError('invalidValuePolicy must be skip-document or reject');
  }

  return {
    ...definition,
    ...(definition.version !== undefined ? { version } : {}),
    fields,
    ...(indexes ? { indexes } : {}),
  };
}

export function validateQueryAst(query: QueryAst, definition: IndexDefinition): QueryAst {
  if (!isRecord(query) || query.version !== 2) throw new InvalidQueryError('query version must be 2');
  requireOwnKeys(query, ['version'], 'query', InvalidQueryError);
  const allowed = new Set([
    'version', 'indexName', 'collectionPrefix', 'where', 'orderBy', 'first', 'after',
    'select', 'count', 'allowScan', 'consistency',
  ]);
  rejectUnknownKeys(query, allowed, 'query');
  if (query.indexName !== undefined && query.indexName !== definition.name) {
    throw new InvalidQueryError(`query targets unknown index: ${query.indexName}`);
  }
  if (query.collectionPrefix !== undefined && query.collectionPrefix !== definition.collectionPrefix) {
    throw new InvalidQueryError('query collectionPrefix does not match the index');
  }
  const fields = new Map(definition.fields.map((field) => [field.path, field]));
  const counter = { value: 0 };
  const where = query.where === undefined ? undefined : validateExpression(query.where, fields, 1, counter);
  const orderBy = query.orderBy?.map((clause) => {
    if (!isRecord(clause)) throw new InvalidQueryError('sort clauses must be objects');
    requireOwnKeys(clause, ['path', 'direction'], 'sort clause', InvalidQueryError);
    rejectUnknownKeys(clause, new Set(['path', 'direction']), 'sort clause');
    validateFieldPath(clause.path, 'sort path', InvalidQueryError);
    if (!fields.has(clause.path)) throw new InvalidQueryError(`sort field is not indexed: ${clause.path}`);
    if (clause.direction !== 'asc' && clause.direction !== 'desc') {
      throw new InvalidQueryError('sort direction must be asc or desc');
    }
    return { path: clause.path, direction: clause.direction };
  });
  if (orderBy && orderBy.length > MAX_SORT_FIELDS) throw new InvalidQueryError('too many sort fields');
  if (query.first !== undefined &&
      (!Number.isSafeInteger(query.first) || query.first < 0 || query.first > MAX_FIRST)) {
    throw new InvalidQueryError(`first must be an integer from 0-${MAX_FIRST}`);
  }
  if (query.after !== undefined &&
      (typeof query.after !== 'string' || query.after.length === 0 || query.after.length > 32_768)) {
    throw new InvalidQueryError('after must be a bounded cursor string');
  }
  let select: string[] | undefined;
  if (query.select !== undefined) {
    if (!Array.isArray(query.select) || query.select.length > MAX_SELECT_FIELDS) {
      throw new InvalidQueryError('select must contain at most 64 fields');
    }
    const seen = new Set<string>();
    select = query.select.map((path) => {
      validateFieldPath(path, 'select path', InvalidQueryError);
      if (!fields.has(path)) throw new InvalidQueryError(`selected field is not indexed: ${path}`);
      if (seen.has(path)) throw new InvalidQueryError(`duplicate selected field: ${path}`);
      seen.add(path);
      return path;
    });
  }
  if (query.count !== undefined && query.count !== 'exact' && query.count !== 'none') {
    throw new InvalidQueryError('count must be exact or none');
  }
  if (query.allowScan !== undefined && typeof query.allowScan !== 'boolean') {
    throw new InvalidQueryError('allowScan must be boolean');
  }
  if (query.consistency !== undefined && query.consistency !== 'eventual' && query.consistency !== 'indexed') {
    throw new InvalidQueryError('consistency must be eventual or indexed');
  }
  return {
    ...query,
    ...(where ? { where } : {}),
    ...(orderBy ? { orderBy } : {}),
    ...(select ? { select } : {}),
  };
}

export function legacyQueryToAst(options: QueryOptions): QueryAst {
  const expressions: QueryFieldExpression[] = options.filters.map((filter) => ({
    kind: 'field',
    path: filter.path,
    operator: filter.operator,
    value: filter.value,
  }));
  return {
    version: 2,
    ...(options.indexName ? { indexName: options.indexName } : {}),
    ...(options.collectionPrefix ? { collectionPrefix: options.collectionPrefix } : {}),
    ...(expressions.length === 1 ? { where: expressions[0] } :
      expressions.length > 1 ? { where: { kind: 'and', expressions } } : {}),
    ...(options.sort ? { orderBy: options.sort } : {}),
    ...(options.limit !== undefined ? { first: options.limit } : {}),
    count: 'exact',
    allowScan: true,
  };
}

export function physicalIndexesFor(definition: IndexDefinition): IndexKeyDefinition[] {
  if (definition.indexes?.length) return definition.indexes.map((index) => ({
    name: index.name,
    fields: [...index.fields],
  }));
  return definition.fields
    .filter((field) => field.required)
    .map((field) => ({ name: `by_${field.path}`, fields: [field.path] }));
}

export function resolvedStorageMode(definition: IndexDefinition): 'memory' | 'cleartext-local' {
  return definition.storageMode ?? 'memory';
}

export function resolvedInvalidValuePolicy(definition: IndexDefinition): 'skip-document' | 'reject' {
  return definition.invalidValuePolicy ?? 'skip-document';
}

export function resolvedGeneration(definition: IndexDefinition): string {
  return definition.generation ?? 'default';
}

export function invalidIndexedValueReason(
  value: unknown,
  field: IndexFieldDefinition,
): InvalidIndexedValueReason | undefined {
  if (value === undefined || value === null) return field.required ? 'missing-required' : undefined;
  if (normalizeIndexScalar(value, field) === undefined) return 'wrong-type';
  if (field.type === 'string' &&
      (value as string).length > (field.maxStringLength ?? MAX_STRING_LENGTH)) {
    return 'value-too-large';
  }
  return undefined;
}

export function normalizeIndexScalar(
  value: unknown,
  field: IndexFieldDefinition,
): IndexScalar | undefined {
  switch (field.type) {
    case 'string':
      return typeof value === 'string' ? value : undefined;
    case 'number':
      return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
    case 'boolean':
      return typeof value === 'boolean' ? value : undefined;
    case 'date': {
      if (value instanceof Date) {
        const time = value.getTime();
        return Number.isFinite(time) ? time : undefined;
      }
      if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}/.test(value)) {
        const time = Date.parse(value);
        return Number.isFinite(time) ? time : undefined;
      }
      return undefined;
    }
  }
}

export function evaluateQueryExpression(
  fields: Record<string, unknown>,
  expression: QueryExpression | undefined,
  definition: IndexDefinition,
): boolean {
  if (!expression) return true;
  if (expression.kind === 'and') {
    return expression.expressions.every((child) => evaluateQueryExpression(fields, child, definition));
  }
  if (expression.kind === 'or') {
    return expression.expressions.some((child) => evaluateQueryExpression(fields, child, definition));
  }
  const field = definition.fields.find((candidate) => candidate.path === expression.path)!;
  const raw = extractField(fields, expression.path);
  const value = normalizeIndexScalar(raw, field);
  if (expression.operator === 'contains') {
    return typeof raw === 'string' && typeof expression.value === 'string' && raw.includes(expression.value);
  }
  if (expression.operator === 'prefix') {
    return typeof raw === 'string' && typeof expression.value === 'string' && raw.startsWith(expression.value);
  }
  if (expression.operator === 'in') {
    return Array.isArray(expression.value) && expression.value.some((candidate) =>
      compareIndexScalars(value, normalizeIndexScalar(candidate, field)) === 0);
  }
  const expected = normalizeIndexScalar(expression.value, field);
  if (expression.operator === 'neq') return compareIndexScalars(value, expected) !== 0;
  if (value === undefined || expected === undefined) return false;
  const comparison = compareIndexScalars(value, expected);
  switch (expression.operator) {
    case 'eq': return comparison === 0;
    case 'gt': return comparison > 0;
    case 'gte': return comparison >= 0;
    case 'lt': return comparison < 0;
    case 'lte': return comparison <= 0;
    default: return false;
  }
}

export function compareIndexScalars(a: IndexScalar | undefined, b: IndexScalar | undefined): number {
  if (a === b) return 0;
  if (a === undefined) return -1;
  if (b === undefined) return 1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return Number(a) - Number(b);
  return compareCodeUnits(String(a), String(b));
}

export function compareCodeUnits(left: string, right: string): number {
  return left === right ? 0 : left < right ? -1 : 1;
}

export function projectFields(fields: Record<string, unknown>, select?: string[]): Record<string, unknown> {
  if (!select) return structuredClone(fields);
  const projected: Record<string, unknown> = {};
  for (const path of select) setNestedField(projected, path, extractField(fields, path));
  return projected;
}

export function canonicalJsonString(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function canonicalIndexDefinitionString(definition: IndexDefinition): string {
  return canonicalJsonString({
    version: definition.version ?? 1,
    name: definition.name,
    collectionPrefix: definition.collectionPrefix,
    fields: definition.fields.map((field) => ({
      path: field.path,
      type: field.type,
      required: field.required ?? false,
      ...(field.type === 'string' ? { maxStringLength: field.maxStringLength ?? MAX_STRING_LENGTH } : {}),
    })),
    indexes: physicalIndexesFor(definition),
    generation: resolvedGeneration(definition),
    invalidValuePolicy: resolvedInvalidValuePolicy(definition),
  });
}

export function canonicalQueryString(query: QueryAst): string {
  return canonicalJsonString({ ...query, after: undefined });
}

export async function hashIndexDefinition(definition: IndexDefinition): Promise<string> {
  return sha256(canonicalIndexDefinitionString(definition));
}

export async function hashQuery(query: QueryAst): Promise<string> {
  return sha256(canonicalQueryString(query));
}

function validateExpression(
  expression: QueryExpression,
  fields: Map<string, IndexFieldDefinition>,
  depth: number,
  counter: { value: number },
): QueryExpression {
  if (!isRecord(expression)) throw new InvalidQueryError('query expressions must be objects');
  if (depth > MAX_QUERY_DEPTH || ++counter.value > MAX_QUERY_NODES) {
    throw new InvalidQueryError('query expression exceeds complexity limits');
  }
  if (expression.kind === 'and' || expression.kind === 'or') {
    requireOwnKeys(
      expression,
      ['kind', 'expressions'],
      `${expression.kind} expression`,
      InvalidQueryError,
    );
    rejectUnknownKeys(expression, new Set(['kind', 'expressions']), `${expression.kind} expression`);
    if (!Array.isArray(expression.expressions) || expression.expressions.length === 0) {
      throw new InvalidQueryError(`${expression.kind} expressions cannot be empty`);
    }
    return {
      kind: expression.kind,
      expressions: expression.expressions.map((child) => validateExpression(child, fields, depth + 1, counter)),
    };
  }
  if (expression.kind !== 'field') throw new InvalidQueryError('unknown query expression kind');
  requireOwnKeys(
    expression,
    ['kind', 'path', 'operator', 'value'],
    'field expression',
    InvalidQueryError,
  );
  rejectUnknownKeys(expression, new Set(['kind', 'path', 'operator', 'value']), 'field expression');
  validateFieldPath(expression.path, 'query field path', InvalidQueryError);
  const field = fields.get(expression.path);
  if (!field) throw new InvalidQueryError(`query field is not indexed: ${expression.path}`);
  const operators: FilterOperator[] = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'prefix', 'in', 'contains'];
  if (!operators.includes(expression.operator)) throw new InvalidQueryError('unknown filter operator');
  if ((expression.operator === 'prefix' || expression.operator === 'contains') && field.type !== 'string') {
    throw new InvalidQueryError(`${expression.operator} requires a string field`);
  }
  if (expression.operator === 'in') {
    if (!Array.isArray(expression.value) || expression.value.length === 0 ||
        expression.value.length > MAX_IN_VALUES) {
      throw new InvalidQueryError(`in requires 1-${MAX_IN_VALUES} values`);
    }
    for (const value of expression.value) validateFilterValue(value, field);
  } else {
    validateFilterValue(expression.value, field);
  }
  return {
    ...expression,
    value: expression.operator === 'in'
      ? (expression.value as unknown[]).map((value) => normalizeQueryValue(value, field))
      : normalizeQueryValue(expression.value, field),
  };
}

function validateFilterValue(value: unknown, field: IndexFieldDefinition): void {
  const reason = invalidIndexedValueReason(value, { ...field, required: true });
  if (reason) throw new InvalidQueryError(`invalid ${field.type} value for ${field.path}`);
}

function normalizeQueryValue(value: unknown, field: IndexFieldDefinition): unknown {
  if (field.type !== 'date') return value;
  const timestamp = normalizeIndexScalar(value, field);
  return new Date(timestamp as number).toISOString();
}

function validateName(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !NAME_PATTERN.test(value)) {
    throw new InvalidIndexSchemaError(`${label} must match ${NAME_PATTERN}`);
  }
}

function validateCollectionPrefix(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 ||
      value.length > MAX_COLLECTION_PREFIX_LENGTH || /[\u0000-\u001f]/.test(value)) {
    throw new InvalidIndexSchemaError(
      `collectionPrefix must contain 1-${MAX_COLLECTION_PREFIX_LENGTH} non-control characters`,
    );
  }
}

function validateFieldPath(
  value: unknown,
  label: string,
  ErrorType: typeof InvalidIndexSchemaError | typeof InvalidQueryError,
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_FIELD_PATH_LENGTH ||
      value.startsWith('.') || value.endsWith('.') || value.includes('..') ||
      value.startsWith('__peerborne_internal_') ||
      /[\u0000-\u001f]/.test(value) ||
      value.split('.').some((segment) => !segment || FORBIDDEN_PATH_SEGMENTS.has(segment))) {
    throw new ErrorType(`${label} is invalid`);
  }
}

function rejectUnknownKeys(value: object, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new InvalidQueryError(`unknown ${label} property: ${key}`);
  }
}

function rejectUnknownSchemaKeys(value: object, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new InvalidIndexSchemaError(`unknown ${label} property: ${key}`);
  }
}

function requireOwnKeys(
  value: object,
  required: string[],
  label: string,
  ErrorType: typeof InvalidIndexSchemaError | typeof InvalidQueryError,
): void {
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new ErrorType(`missing ${label} property: ${key}`);
    }
  }
}

function setNestedField(target: Record<string, unknown>, path: string, value: unknown): void {
  const segments = path.split('.');
  let cursor = target;
  for (let i = 0; i < segments.length - 1; i++) {
    const existing = cursor[segments[i]];
    if (existing !== null && typeof existing === 'object' && !Array.isArray(existing)) {
      cursor = existing as Record<string, unknown>;
    } else {
      const next: Record<string, unknown> = {};
      cursor[segments[i]] = next;
      cursor = next;
    }
  }
  cursor[segments[segments.length - 1]] = value;
}

function canonicalize(value: unknown): unknown {
  if (value === undefined) return null;
  if (value instanceof Date) return { $date: value.toISOString() };
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isRecord(value)) {
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) result[key] = canonicalize(value[key]);
    }
    return result;
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function sha256(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
