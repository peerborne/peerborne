import {
  mkdtempSync,
  cpSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  projectRoot,
  manifest,
  lsc,
  dafny,
  proofPaths,
  requireTools,
  proverEnvironment,
  typescript,
} from './support.mjs';

requireTools();
const ts = typescript();
const staging = mkdtempSync(join(tmpdir(), 'peerborne-formal-controls-'));
const results = [];
function copyProject(label) {
  const root = join(staging, label);
  mkdirSync(root, { recursive: true });
  cpSync(join(projectRoot, 'lemmascript.json'), join(root, 'lemmascript.json'));
  for (const entry of manifest.sources) {
    const source = join(root, entry.path);
    mkdirSync(dirname(source), { recursive: true });
    cpSync(join(projectRoot, entry.path), source);
    const from = proofPaths(entry.path);
    const to = proofPaths(entry.path, root);
    mkdirSync(dirname(to.proof), { recursive: true });
    cpSync(from.proof, to.proof);
    cpSync(from.generated, to.generated);
  }
  return root;
}
function verify(root, source, regenerate = false, targetFunction) {
  const result = spawnSync(
    process.execPath,
    [
      lsc,
      regenerate ? 'regen' : 'check',
      '--backend=dafny',
      '--time-limit=15',
      ...(targetFunction
        ? [`--extra-flags=--filter-symbol=${targetFunction}`]
        : []),
      source,
    ],
    {
      cwd: root,
      env: proverEnvironment(),
      encoding: 'utf8',
      timeout: 120000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  const path = join(root, '.lemmascript/runs.jsonl');
  let records = [];
  try {
    records = readFileSync(path, 'utf8')
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line));
  } catch {}
  return {
    ...result,
    record: records.findLast((record) => record.file === source),
  };
}
function requireResult(condition, name, result) {
  if (!condition)
    throw new Error(
      `Verifier control ${name} did not behave as required:\n${result?.stdout ?? ''}${result?.stderr ?? ''}`,
    );
  results.push({
    name,
    passed: true,
    failedMembers: result?.record?.failed ?? [],
    verificationScope: result?.record
      ? result.record.stage === 'diff'
        ? 'source-drift'
        : result.record.partial
          ? 'counterexample-function'
          : 'full-unit'
      : 'assumption-audit',
  });
  console.log(`${name}: passed`);
}
try {
  const positive = copyProject('positive');
  for (const entry of manifest.sources) {
    const result = verify(positive, entry.path);
    requireResult(
      result.status === 0 &&
        result.record?.stage === 'ok' &&
        !result.record.partial &&
        result.record.passed.includes(entry.witness),
      `positive/${entry.path}`,
      result,
    );
  }
  const mutations = [
    [
      'unpaired-surrogate',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (!isPairedUtf16Unit(value, index)) return false;',
      'if (false) return false;',
    ],
    [
      'empty-bootstrap-list',
      'packages/core/src/bootstrap-config.ts',
      'return config.list.length > 0;',
      'return config.list.length >= 0;',
    ],
    [
      'document-cache-collision',
      'packages/react/src/hooks-cache.ts',
      'return `${caches.contextKeyPrefix}${documentPath}`;',
      'return `${caches.contextKeyPrefix}`;',
    ],

    [
      'resource-confusion',
      'packages/core/src/capabilities.ts',
      'candidate.resource === resource &&',
      '',
    ],
    [
      'duplicate-identity',
      'string-collections.ts',
      'if (seen.has(values[index])) return index;',
      'if (false) return index;',
    ],
    [
      'editor-attenuation',
      'string-collections.ts',
      'const expectedWriters = editor ? [issuer, recipient] : [issuer];',
      'const expectedWriters = [issuer];',
    ],
    [
      'keychain-rewrite',
      'keychain-order.ts',
      'if (!sameKeychainEntry(before[index], after[index])) return index;',
      'if (false) return index;',
    ],
    ['overlapping-compaction', 'maintenance.ts', '!inProgress &&', 'true &&'],
    [
      'unauthenticated-replacement',
      'maintenance.ts',
      'return !existing || authenticated;',
      'return true;',
    ],
    [
      'replay-capacity',
      'replay-admission.ts',
      "if (size >= capacity) return 'capacity-exceeded';",
      "if (size > capacity) return 'capacity-exceeded';",
    ],
    [
      'expiry-boundary',
      'invitation-time.ts',
      'return expiresAt <= now;',
      'return expiresAt < now;',
    ],
    [
      'terminal-anchor-poison',
      'anchor-advance.ts',
      "if (previous.poisoned) return 'terminalPoison';",
      "if (false) return 'terminalPoison';",
    ],
    [
      'protected-gc-cid',
      'retention.ts',
      'if (!retained.has(cid) && !protectedCids.has(cid)) result.add(cid);',
      'if (!retained.has(cid)) result.add(cid);',
    ],
    [
      'encoded-underestimate',
      'encoded-size.ts',
      'return 4 * Math.ceil(rawBytes / 3);',
      'return 4 * Math.floor(rawBytes / 3);',
    ],
    [
      'query-expansion-limit',
      'packages/index/src/query-budget.ts',
      'return count > limit ? -1 : count;',
      'return count;',
    ],
    [
      'budget-overrun',
      'work-budget.ts',
      'if (amount > limit - used) return -1;',
      'if (false) return -1;',
    ],
    [
      'epoch-gap',
      'beekem-transition.ts',
      "if (incoming === current + 1) return 'next';",
      "if (incoming === current + 2) return 'next';",
    ],
    [
      'conflicting-quorum',
      'quorum.ts',
      'if (winner !== -1) return -2;',
      'if (false) return -2;',
    ],
    [
      'authority-equivocation',
      'authority-votes.ts',
      "if (disposition === 'equivocation') equivocating = true;",
      "if (disposition === 'equivocation') equivocating = false;",
    ],
    [
      'pending-reference-confusion',
      'package-partition.ts',
      'result.set(reference, value);',
      'result.set("different", value);',
    ],
    [
      'consumption-history-loss',
      'package-partition.ts',
      'const result = new Map(consumed);',
      'const result = new Map<string, Marker>();',
    ],
    [
      'pending-map-truncation',
      'package-partition.ts',
      'const result = new Map(pending); result.delete(reference);',
      'const result = new Map<string, Pending>(); result.delete(reference);',
    ],
    [
      'operation-binding-rewrite',
      'package-partition.ts',
      'result.set(operation, record);',
      'result.set(operation, "different");',
    ],
    [
      'committed-byte-overflow',
      'store-budget.ts',
      'return next < minimum || next > maximum ? -1 : next;',
      'return next < minimum ? -1 : next;',
    ],
    [
      'revision-overflow',
      'store-budget.ts',
      'return revision === 9007199254740991 ? -1 : revision + 1;',
      'return revision > 9007199254740991 ? -1 : revision + 1;',
    ],
    [
      'store-epoch-rollback',
      'store-budget.ts',
      "return hadEpoch && (!hasEpoch || nextEpoch < baseEpoch) ? 'rollback' : 'ready';",
      "return hadEpoch && !hasEpoch ? 'rollback' : 'ready';",
    ],
    [
      'stale-prepared-claim',
      'commit-lifecycle.ts',
      "if (!baseCurrent) return 'stale';",
      "if (false) return 'stale';",
    ],
    [
      'hydrating-prepared-claim',
      'commit-lifecycle.ts',
      "if (hydrating) return 'hydrating';",
      "if (false) return 'hydrating';",
    ],
    [
      'uncommitted-finalization',
      'commit-lifecycle.ts',
      "return 'committed';",
      'return phase;',
    ],
    [
      'poisoned-coordinator-admission',
      'commit-lifecycle.ts',
      "if (poisoned) return 'poisoned';",
      "if (false) return 'poisoned';",
    ],
    [
      'ambiguous-recovery-poison',
      'commit-lifecycle.ts',
      "return ambiguousStoreFailure ? 'propagate' : 'poison';",
      "return 'poison';",
    ],
    [
      'replay-authorization-anchor-loss',
      'replay-window.ts',
      'return floor === 0n ? 0n : floor - 1n;',
      'return floor;',
    ],
    [
      'pending-delivery-pruning',
      'replay-window.ts',
      'epoch < authorizationAnchorFloor(currentEpoch, window) && !pendingDelivery',
      'epoch < authorizationAnchorFloor(currentEpoch, window)',
    ],
    [
      'missing-retained-epoch',
      'replay-window.ts',
      'if (!byEpoch.has(epoch)) return epoch;',
      'if (false) return epoch;',
    ],
    [
      'reachable-edge-loss',
      'graph-reachability.ts',
      'children.push(edge.to);',
      'children.push(edge.from);',
    ],
    [
      'duplicate-edge-flood',
      'graph-reachability.ts',
      'children.push(edge.to);',
      'children.push(edge.to); children.push(edge.to);',
    ],
    [
      'acl-boundary-pruning',
      'graph-reachability.ts',
      'return !isAcl && documentNodesVisited >= keepCount;',
      'return documentNodesVisited >= keepCount;',
    ],
    [
      'wrong-tree-power',
      'tree-index.ts',
      'return POWERS_OF_TWO[exponent];',
      'return POWERS_OF_TWO[0];',
      'powerOfTwo',
    ],
    [
      'wrong-tree-parent-direction',
      'tree-index.ts',
      'return higherBit === 0 ? index + step : index - step;',
      'return higherBit === 0 ? index - step : index + step;',
      'parentStep',
    ],
    [
      'ragged-child-width-overflow',
      'tree-index.ts',
      'index < width ? index : clampRightChild(leftChild(index), width)',
      'index < width ? index : clampRightChild(leftChild(index), width + 1)',
      'clampRightChild',
    ],
    [
      'missing-path-parent',
      'tree-index.ts',
      'return [parent, ...treeDirectPath(parent, leaves)];',
      'return treeDirectPath(parent, leaves);',
      'treeDirectPath',
    ],
    [
      'query-descending-direction',
      'packages/index/src/query-order.ts',
      "directions[index].direction === 'desc' ? -compared : compared",
      'compared',
    ],
    [
      'query-path-tie-loss',
      'packages/index/src/query-order.ts',
      'return compareCodeUnits(leftPath, rightPath);',
      'return 0;',
    ],
    [
      'finite-numeric-reversal',
      'packages/index/src/query-order.ts',
      'return left < right ? -1 : 1;',
      'return left > right ? -1 : 1;',
    ],
    [
      'query-page-overrun',
      'packages/index/src/query-order.ts',
      'return entries.slice(0, first);',
      'return entries.slice(0, first + 1);',
    ],
    [
      'vacuous-precondition',
      'work-budget.ts',
      '//@ verify',
      '//@ verify\n  //@ requires false',
    ],
  ];
  for (const [name, file, before, after, targetFunction] of mutations) {
    const root = copyProject(name);
    const source = file.startsWith('packages/')
      ? file
      : `packages/core/src/policy/${file}`;
    const path = join(root, source);
    const text = readFileSync(path, 'utf8');
    const tokens = (value) => {
      const ast = ts.createSourceFile(
        'mutation.ts',
        value,
        ts.ScriptTarget.Latest,
        true,
      );
      const result = [];
      const collect = (node) => {
        if (
          node.kind >= ts.SyntaxKind.FirstJSDocNode &&
          node.kind <= ts.SyntaxKind.LastJSDocNode
        )
          return;
        const children = node.getChildren(ast);
        if (children.length) children.forEach(collect);
        else if (
          node.kind !== ts.SyntaxKind.EndOfFileToken &&
          node.kind !== ts.SyntaxKind.SyntaxList &&
          node.getWidth(ast) > 0
        ) {
          result.push({
            text: node.getText(ast),
            start: node.getStart(ast),
            end: node.end,
          });
        }
      };
      collect(ast);
      return result;
    };
    const target = tokens(before);
    if (target.length === 0 || before.includes('`')) {
      if (text.split(before).length !== 2)
        throw new Error(`Mutation target drifted: ${name}`);
      writeFileSync(path, text.replace(before, after));
    } else {
      const sourceTokens = tokens(text);
      const matches = sourceTokens.flatMap((_, index) =>
        target.every(
          (token, offset) => sourceTokens[index + offset]?.text === token.text,
        )
          ? [index]
          : [],
      );
      if (matches.length !== 1)
        throw new Error(`Mutation target drifted: ${name}`);
      const begin = sourceTokens[matches[0]].start;
      const end = sourceTokens[matches[0] + target.length - 1].end;
      writeFileSync(path, text.slice(0, begin) + after + text.slice(end));
    }
    const result = verify(root, source, true, targetFunction);
    requireResult(
      result.status !== 0 &&
        result.record?.stage === 'verify' &&
        result.record.failed.length > 0 &&
        (targetFunction
          ? result.record.partial &&
            result.record.failed.includes(targetFunction)
          : !result.record.partial) &&
        /Dafny program verifier finished with \d+ verified, [1-9]\d* errors?/.test(
          result.stdout ?? '',
        ),
      name,
      result,
    );
  }
  const drift = copyProject('source-drift');
  const driftSource = 'packages/core/src/policy/work-budget.ts';
  const driftPath = join(drift, driftSource);
  writeFileSync(
    driftPath,
    readFileSync(driftPath, 'utf8').replace(
      'return used + amount;',
      'return used + amount + 1;',
    ),
  );
  const driftResult = verify(drift, driftSource);
  requireResult(
    driftResult.status !== 0 && driftResult.record?.stage === 'diff',
    'stale-generated-code',
    driftResult,
  );
  for (const [name, addition] of [
    ['assume-false', '\nlemma Escape() ensures false { assume false; }\n'],
    ['bodyless-lemma', '\nlemma Escape() ensures false\n'],
    [
      'unproved-import',
      '\nfunction {:axiom} Escape(x: int): int ensures Escape(x) == x\n',
    ],
  ]) {
    const root = copyProject(name);
    const path = proofPaths(
      'packages/core/src/policy/work-budget.ts',
      root,
    ).proof;
    writeFileSync(path, readFileSync(path, 'utf8') + addition);
    const result = spawnSync(
      dafny,
      [
        'audit',
        path,
        '--unicode-char:false',
        '--allow-deprecation',
        '--report-format',
        'md',
        '--report-file',
        join(root, 'audit.md'),
      ],
      { encoding: 'utf8', timeout: 30000 },
    );
    requireResult(
      !/Dafny auditor completed with 0 findings/.test(result.stdout ?? '') &&
        /Dafny auditor completed with [1-9]/.test(result.stdout ?? ''),
      name,
      result,
    );
  }
  const directory = join(projectRoot, 'verification/results/formal');
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    join(directory, 'controls.json'),
    `${JSON.stringify({ results }, null, 2)}\n`,
  );
} finally {
  rmSync(staging, { recursive: true, force: true });
}
