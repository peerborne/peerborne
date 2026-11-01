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
  const calibration = copyProject('map-operand-calibration');
  const calibrationSource = 'map-operand-calibration.ts';
  writeFileSync(
    join(calibration, calibrationSource),
    String.raw`
export function mapOperandCalibration(value: number, values: Map<string, number>, key: string, operator: number): boolean {
  //@ verify
  //@ requires -9007199254740991 <= value && value <= 9007199254740991
  //@ requires values.has(key) && values.get(key) === value
  //@ requires 0 <= operator && operator <= 3
  //@ ensures operator === 0 ==> (\result <==> values[key] >= 1)
  //@ ensures operator === 1 ==> (\result <==> values[key] > 1)
  //@ ensures operator === 2 ==> (\result <==> values[key] <= 1)
  //@ ensures operator === 3 ==> (\result <==> values[key] < 1)
  if (operator === 0) return value >= 1;
  if (operator === 1) return value > 1;
  if (operator === 2) return value <= 1;
  return value < 1;
}
`,
  );
  const generated = spawnSync(
    process.execPath,
    [lsc, 'regen', '--backend=dafny', '--no-verify', calibrationSource],
    {
      cwd: calibration,
      env: proverEnvironment(),
      encoding: 'utf8',
      timeout: 120000,
    },
  );
  if (generated.status !== 0)
    throw new Error(
      `Map calibration generation failed: ${generated.stdout}${generated.stderr}`,
    );
  const calibrationProof = proofPaths(calibrationSource, calibration).proof;
  writeFileSync(
    calibrationProof,
    readFileSync(calibrationProof, 'utf8') +
      `
method mapOperand_domain()
{
  assert !mapOperandCalibration(0, map["k" := 0], "k", 0);
  assert mapOperandCalibration(1, map["k" := 1], "k", 0);
  assert !mapOperandCalibration(1, map["k" := 1], "k", 1);
  assert mapOperandCalibration(2, map["k" := 2], "k", 1);
  assert mapOperandCalibration(1, map["k" := 1], "k", 2);
  assert !mapOperandCalibration(2, map["k" := 2], "k", 2);
  assert mapOperandCalibration(0, map["k" := 0], "k", 3);
  assert !mapOperandCalibration(1, map["k" := 1], "k", 3);
}
`,
  );
  const calibrated = verify(calibration, calibrationSource);
  const calibrationAudit = spawnSync(
    dafny,
    [
      'audit',
      calibrationProof,
      '--unicode-char:false',
      '--allow-deprecation',
      '--report-format',
      'md',
      '--report-file',
      join(calibration, 'map-operands.audit.md'),
    ],
    { cwd: calibration, encoding: 'utf8', timeout: 120000 },
  );
  requireResult(
    calibrated.status === 0 &&
      calibrated.record?.stage === 'ok' &&
      !calibrated.record.partial &&
      calibrated.record.passed.includes('mapOperand_domain') &&
      calibrationAudit.status === 0 &&
      /Dafny auditor completed with 0 findings/.test(calibrationAudit.stdout),
    'positive/map-operand-calibration',
    calibrated,
  );
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
      'authentication-attempt-overrun',
      'authentication-budget.ts',
      'attempts === attemptLimit ||',
      'false ||',
    ],
    [
      'authentication-partial-refusal',
      'authentication-budget.ts',
      'return { accepted: false, attempts, bytes };',
      'return { accepted: false, attempts: attempts + 1, bytes };',
    ],
    [
      'control-create-after-genesis',
      'control-chain.ts',
      'return hasPrevious !== creating;',
      'return true;',
    ],
    [
      'control-epoch-skip',
      'control-chain.ts',
      'incomingEpoch === previousEpoch + 1n',
      'incomingEpoch === previousEpoch + 2n',
    ],
    [
      'control-parent-confusion',
      'control-chain.ts',
      'hasPrevious ? !hasParent || !parentMatches : hasParent',
      'hasPrevious ? !hasParent : hasParent',
    ],
    [
      'control-operation-rebinding',
      'control-chain.ts',
      "if (operationKnown) return 'operation-id-conflict';",
      "if (false) return 'operation-id-conflict';",
    ],
    [
      'frame-trailer-overlap',
      'frame-layout.ts',
      'length > total - offset - trailer',
      'length > total - offset',
    ],
    [
      'frame-chunk-overread',
      'frame-layout.ts',
      'return remaining < available ? remaining : available;',
      'return available;',
    ],
    [
      'duplicate-eligible-peer',
      'quorum.ts',
      'eligible[index] && !seen.has(peerIds[index])',
      'eligible[index]',
    ],
    [
      'ineligible-peer-credit',
      'quorum.ts',
      'eligible[index] && !seen.has(peerIds[index])',
      '!seen.has(peerIds[index])',
    ],
    [
      'peer-identity-confusion',
      'quorum.ts',
      'seen.add(peerIds[index]);',
      'seen.add("different");',
    ],
    [
      'digest-repeat-count-loss',
      'quorum.ts',
      'const count = previous === undefined ? 0 : previous;',
      'const count = 0;',
    ],
    [
      'digest-count-inflation',
      'quorum.ts',
      'const count = previous === undefined ? 0 : previous;',
      'const count = previous === undefined ? 1 : previous;',
    ],
    [
      'nonagreeing-cohort-inclusion',
      'quorum.ts',
      'if (agreeing.has(peerIds[index])) selected.push(index);',
      'if (!agreeing.has(peerIds[index])) selected.push(index);',
    ],
    [
      'quorum-conflict-reason-loss',
      'quorum.ts',
      "if (conflicting) return 'conflicting-quorum';",
      "if (false) return 'conflicting-quorum';",
    ],
    [
      'quorum-response-boundary',
      'quorum.ts',
      'responding < threshold',
      'responding <= threshold',
    ],
    [
      'vacuous-precondition',
      'work-budget.ts',
      '//@ verify',
      '//@ verify\n  //@ requires false',
    ],
    [
      'prepared-change-early-success',
      'document-admission.ts',
      "if (event === 'begin') return 'applying';",
      "if (event === 'begin') return 'committed';",
    ],
    [
      'prepared-change-failed-retry',
      'document-admission.ts',
      "if (event === 'fail') return 'failed';",
      "if (event === 'fail') return 'prepared';",
    ],
    [
      'prepared-change-failure-success',
      'document-admission.ts',
      "if (event === 'fail') return 'failed';",
      "if (event === 'fail') return 'committed';",
    ],
    [
      'prepared-change-cancel-application',
      'document-admission.ts',
      "if (event === 'succeed') return 'committed';",
      "if (event === 'cancel') return 'cancelled'; if (event === 'succeed') return 'committed';",
    ],
    [
      'document-operation-count-overflow',
      'document-admission.ts',
      'return count < countLimit &&',
      'return count <= countLimit &&',
    ],
    [
      'document-operation-byte-overflow',
      'document-admission.ts',
      'return count < countLimit && incomingBytes <= byteLimit - bytes;',
      'return count < countLimit && incomingBytes <= byteLimit;',
    ],
    [
      'document-operation-release-inflation',
      'document-admission.ts',
      'return bytes - releasedBytes;',
      'return bytes + releasedBytes;',
    ],
    [
      'document-operation-cancel-resurrection',
      'document-admission.ts',
      "if (event === 'cancel') return 'cancelled';",
      "if (event === 'cancel') return 'prepared';",
      'advanceDocumentOperation',
    ],
    [
      'document-operation-stale-commit',
      'document-admission.ts',
      "return contextMatches && authorizationMatches ? 'committed' : phase;",
      "return authorizationMatches ? 'committed' : phase;",
    ],
    [
      'document-operation-authorization-bypass',
      'document-admission.ts',
      "return contextMatches && authorizationMatches ? 'committed' : phase;",
      "return contextMatches ? 'committed' : phase;",
    ],
    [
      'document-operation-commit-resurrection',
      'document-admission.ts',
      "if (phase === 'committed' || phase === 'cancelled') return phase;",
      "if (phase === 'committed') return 'preparing'; if (phase === 'cancelled') return phase;",
    ],
    [
      'document-sequence-replay',
      'document-content.ts',
      "if (sequence <= accepted) return 'replay';",
      "if (sequence < accepted) return 'replay';",
    ],
    [
      'document-sequence-gap',
      'document-content.ts',
      "if (sequence - accepted !== 1) return 'gap';",
      "if (sequence - accepted > 2) return 'gap';",
    ],
    [
      'document-parent-binding',
      'document-content.ts',
      "return parentMatches ? 'apply' : 'parent-mismatch';",
      "return true ? 'apply' : 'parent-mismatch';",
    ],
    [
      'document-reader-writes',
      'document-content.ts',
      'return role === 3 || (!snapshot && role === 2);',
      'return role >= 1;',
    ],
    [
      'document-journal-same-revision-substitution',
      'document-journal.ts',
      "if (stored === anchored && commitmentMatches) return 'current';",
      "if (stored === anchored) return 'current';",
    ],
    [
      'document-journal-skipped-anchor',
      'document-journal.ts',
      'stored - anchored === 1',
      'stored - anchored >= 1',
    ],
    [
      'document-journal-parent-binding',
      'document-journal.ts',
      "if (stored > anchored && stored - anchored === 1 && parentMatches) return 'finish-anchor';",
      "if (stored > anchored && stored - anchored === 1) return 'finish-anchor';",
    ],
    [
      'document-authority-epoch-rollback',
      'document-journal.ts',
      'return next > previous && sameGroup && headChanged;',
      'return next >= previous && sameGroup && headChanged;',
    ],
    [
      'document-authority-group-binding',
      'document-journal.ts',
      'return next > previous && sameGroup && headChanged;',
      'return next > previous && headChanged;',
    ],
    [
      'document-journal-uncommitted-promotion',
      'document-journal.ts',
      "if (!markerAuthenticated) return 'reject';",
      "if (false) return 'reject';",
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
