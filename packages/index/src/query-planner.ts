import {
  IndexDefinition,
  IndexScalar,
  QueryAst,
  QueryExpression,
  QueryFieldExpression,
  QueryScanKind,
} from './types.js';
import { normalizeIndexScalar, physicalIndexesFor } from './query-ast.js';

export interface QueryRangeConstraint {
  position: number;
  lower?: IndexScalar;
  lowerInclusive?: boolean;
  upper?: IndexScalar;
  upperInclusive?: boolean;
  prefix?: string;
}

export interface QueryIndexLookup {
  equals: IndexScalar[];
  range?: QueryRangeConstraint;
}

export interface PhysicalQueryPlan {
  kind: 'physical';
  indexName: string;
  fields: string[];
  lookups: QueryIndexLookup[];
  residualPredicate: boolean;
  sortCovered: boolean;
}

export interface FullScanQueryPlan {
  kind: 'full';
  residualPredicate: boolean;
  sortCovered: false;
}

export interface UnionQueryPlan {
  kind: 'union';
  plans: PhysicalQueryPlan[];
  residualPredicate: boolean;
  sortCovered: false;
}

export type QueryPlan = PhysicalQueryPlan | FullScanQueryPlan | UnionQueryPlan;

export function planQuery(definition: IndexDefinition, query: QueryAst): QueryPlan {
  if (query.where?.kind === 'or') {
    const plans = query.where.expressions.map((where) => planConjunction(definition, { ...query, where }));
    if (plans.some((plan) => plan.kind === 'full')) {
      return { kind: 'full', residualPredicate: true, sortCovered: false };
    }
    const physical = plans.flatMap((plan) => plan.kind === 'union' ? plan.plans : [plan]);
    return {
      kind: 'union',
      plans: physical as PhysicalQueryPlan[],
      residualPredicate: true,
      sortCovered: false,
    };
  }
  return planConjunction(definition, query);
}

export function planScanKind(plan: QueryPlan): QueryScanKind {
  if (plan.kind === 'full') return 'full';
  if (plan.kind === 'physical' && plan.lookups.every((lookup) =>
    lookup.equals.length === 0 && lookup.range === undefined)) return 'full';
  return 'bounded';
}

export function planPhysicalIndexNames(plan: QueryPlan): string[] {
  if (plan.kind === 'full') return [];
  if (plan.kind === 'physical') return [plan.indexName];
  return Array.from(new Set(plan.plans.map((child) => child.indexName)));
}

function planConjunction(definition: IndexDefinition, query: QueryAst): QueryPlan {
  const leaves = flattenAnd(query.where);
  let best: { plan: PhysicalQueryPlan; score: number } | undefined;
  for (const index of physicalIndexesFor(definition)) {
    let combinations: IndexScalar[][] = [[]];
    let unusable = false;
    let used = 0;
    let range: QueryRangeConstraint | undefined;
    for (let position = 0; position < index.fields.length; position++) {
      const path = index.fields[position];
      const field = definition.fields.find((candidate) => candidate.path === path)!;
      const equality = leaves.find((leaf) =>
        leaf.path === path && (leaf.operator === 'eq' || leaf.operator === 'in'));
      if (equality) {
        const values = equality.operator === 'in'
          ? (equality.value as unknown[]).map((value) => normalizeIndexScalar(value, field)!)
          : [normalizeIndexScalar(equality.value, field)!];
        if (combinations.length * values.length > 1024) {
          unusable = true;
          break;
        }
        combinations = combinations.flatMap((prefix) => values.map((value) => [...prefix, value]));
        used++;
        continue;
      }
      const candidates = leaves.filter((leaf) => leaf.path === path);
      const prefix = candidates.find((leaf) => leaf.operator === 'prefix');
      const lower = candidates.find((leaf) => leaf.operator === 'gt' || leaf.operator === 'gte');
      const upper = candidates.find((leaf) => leaf.operator === 'lt' || leaf.operator === 'lte');
      if (prefix || lower || upper) {
        range = {
          position,
          ...(prefix ? { prefix: prefix.value as string } : {}),
          ...(lower ? {
            lower: normalizeIndexScalar(lower.value, field)!,
            lowerInclusive: lower.operator === 'gte',
          } : {}),
          ...(upper ? {
            upper: normalizeIndexScalar(upper.value, field)!,
            upperInclusive: upper.operator === 'lte',
          } : {}),
        };
        used += Number(Boolean(prefix)) + Number(Boolean(lower)) + Number(Boolean(upper));
      }
      break;
    }

    if (unusable) continue;

    const equalityCount = combinations[0]?.length ?? 0;
    const orderBy = query.orderBy ?? [];
    const sortOffset = equalityCount;
    const sortCovered = combinations.length === 1 && orderBy.length > 0 &&
      sortOffset + orderBy.length === index.fields.length &&
      orderBy.every((clause, offset) =>
        clause.direction === 'asc' && index.fields[sortOffset + offset] === clause.path);
    const leafCount = countLeaves(query.where);
    if (used === 0 && leafCount > 0) continue;
    if (equalityCount === 0 && !range && !sortCovered) continue;
    const residualPredicate = used < leafCount || hasNestedOr(query.where);
    const plan: PhysicalQueryPlan = {
      kind: 'physical',
      indexName: index.name,
      fields: [...index.fields],
      lookups: combinations.map((equals) => ({ equals, ...(range ? { range } : {}) })),
      residualPredicate,
      sortCovered,
    };
    const score = equalityCount * 100 + Number(Boolean(range)) * 10 + Number(sortCovered) * 5 - combinations.length;
    if (!best || score > best.score) best = { plan, score };
  }
  return best?.plan ?? { kind: 'full', residualPredicate: Boolean(query.where), sortCovered: false };
}

function flattenAnd(expression: QueryExpression | undefined): QueryFieldExpression[] {
  if (!expression) return [];
  if (expression.kind === 'field') return [expression];
  if (expression.kind === 'and') return expression.expressions.flatMap(flattenAnd);
  return [];
}

function countLeaves(expression: QueryExpression | undefined): number {
  if (!expression) return 0;
  if (expression.kind === 'field') return 1;
  return expression.expressions.reduce((count, child) => count + countLeaves(child), 0);
}

function hasNestedOr(expression: QueryExpression | undefined, root = true): boolean {
  if (!expression || expression.kind === 'field') return false;
  if (expression.kind === 'or') return !root || expression.expressions.some((child) => hasNestedOr(child, false));
  return expression.expressions.some((child) => hasNestedOr(child, false));
}
