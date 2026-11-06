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
import { pathToFileURL } from 'node:url';
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
  const aliasRoot = copyProject('map-alias-calibration');
  const aliasSource = 'packages/core/src/policy/document-journal.ts';
  const aliasPath = join(aliasRoot, aliasSource);
  const aliasOriginal = readFileSync(aliasPath, 'utf8');
  const aliasNeedle = 'const result = new Map(ledger);';
  if (aliasOriginal.split(aliasNeedle).length !== 2)
    throw new Error('Map alias calibration target drifted');
  const aliasText = aliasOriginal.replace(
    aliasNeedle,
    'const result = ledger;',
  );
  writeFileSync(aliasPath, aliasText);
  const aliasVerified = verify(aliasRoot, aliasSource, true);
  const aliasJavaScript = ts.transpileModule(aliasText, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
    },
  }).outputText;
  const aliasRuntime = join(aliasRoot, 'map-alias.runtime.cjs');
  writeFileSync(aliasRuntime, aliasJavaScript);
  const nativeModule = (await import(pathToFileURL(aliasRuntime).href)).default;
  const nativeParent = new Map();
  const nativeCandidate = nativeModule.recordDocumentPublicationBinding(
    nativeParent,
    'candidate',
    1,
    144,
  );
  requireResult(
    aliasVerified.status === 0 &&
      aliasVerified.record?.stage === 'ok' &&
      !aliasVerified.record.partial &&
      nativeCandidate === nativeParent &&
      nativeParent.has('candidate'),
    'model-calibration/native-map-alias',
    aliasVerified,
  );
  results.at(-1).verificationScope = 'model-calibration';
  results.at(-1).nativeCounterexample = 'candidate-mutated-parent';
  const mutations = [
    [
      'field-parent-path-bypass',
      'field-authorization.ts',
      'if (grant.length > target.length) return false;',
      'if (false) return false;',
      'isFieldPathPrefix',
    ],
    [
      'field-segment-mismatch-bypass',
      'field-authorization.ts',
      'if (grant[index] !== target[index]) return false;',
      'if (false) return false;',
      'isFieldPathPrefix',
    ],
    [
      'field-ungranted-sibling',
      'field-authorization.ts',
      'if (isFieldPathPrefix(grants[index], target)) return true;',
      'if (isFieldPathPrefix(grants[index], target) || index >= 0) return true;',
      'grantsFieldPath',
    ],
    [
      'field-first-operation-omission',
      'field-authorization.ts',
      'for (let index = 0; index < targets.length; index++)',
      'for (let index = 1; index < targets.length; index++)',
      'firstUnauthorizedFieldPath',
    ],
    [
      'field-grant-direction',
      'field-authorization.ts',
      'if (isFieldPathPrefix(grants[index], target)) return true;',
      'if (isFieldPathPrefix(target, grants[index])) return true;',
      'grantsFieldPath',
    ],
    [
      'field-inspection-work-overflow',
      'field-authorization.ts',
      'additional <= 131072 - scanned',
      'additional <= 131073 - scanned',
      'canAdmitFieldInspection_ensures',
    ],
    [
      'field-inspection-target-overflow',
      'field-authorization.ts',
      'known || distinct < 4096',
      'known || distinct <= 4096',
      'canAdmitFieldInspection_ensures',
    ],
    [
      'field-inspection-units-overflow',
      'field-authorization.ts',
      'addedUnits <= 1048576 - units',
      'addedUnits <= 1048577 - units',
      'canAdmitFieldInspection_ensures',
    ],
    [
      'journal-store-duplicate-publication',
      'journal-store.ts',
      "return { decision: 'duplicate', publications: [], retained: [], bytes: 0, };",
      "return { decision: 'accept', publications: [], retained: [], bytes: 0, };",
    ],
    [
      'journal-store-byte-accounting',
      'journal-store.ts',
      'total += publication.bytes;',
      'total += 0;',
    ],
    [
      'journal-store-publication-count-overflow',
      'journal-store.ts',
      'publications.length >= 16',
      'publications.length > 16',
    ],
    [
      'journal-store-publication-byte-overflow',
      'journal-store.ts',
      'bytes > 16777216 - total',
      'bytes > 16777216 - total + 1',
    ],
    [
      'journal-store-acknowledges-other-id',
      'journal-store.ts',
      'if (append || publication.id !== id)',
      'if (append || publication.id === id)',
    ],
    [
      'journal-store-retained-index-substitution',
      'journal-store.ts',
      'retained.push(index);',
      'retained.push(0);',
    ],
    [
      'journal-store-pending-reservation-overwrite',
      'journal-store.ts',
      'if (revision !== expected || revision === 9007199254740991 || hasPending)',
      'if (revision !== expected || revision === 9007199254740991 || false)',
    ],
    [
      'journal-store-checkpoint-budget-inversion',
      'journal-store.ts',
      '(!checkpoint && (entries >= 128 || entryBytes + 32 > 134217728 - retainedBytes))',
      '(checkpoint && (entries >= 128 || entryBytes + 32 > 134217728 - retainedBytes))',
    ],
    [
      'journal-store-revision-overflow',
      'journal-store.ts',
      'revision === expected && revision < 9007199254740991 && hasPending && sameToken && sameCheckpoint',
      'revision === expected && true && hasPending && sameToken && sameCheckpoint',
    ],
    [
      'journal-store-checkpoint-substitution',
      'journal-store.ts',
      'revision === expected && revision < 9007199254740991 && hasPending && sameToken && sameCheckpoint',
      'revision === expected && revision < 9007199254740991 && hasPending && sameToken && true',
    ],
    [
      'journal-store-token-substitution',
      'journal-store.ts',
      'revision === expected && revision < 9007199254740991 && hasPending && sameToken && sameCheckpoint',
      'revision === expected && revision < 9007199254740991 && hasPending && true && sameCheckpoint',
    ],
    [
      'journal-store-missing-acceptance-overhead',
      'journal-store.ts',
      'entryBytes + 32 > 134217728 - retainedBytes',
      'entryBytes > 134217728 - retainedBytes',
    ],
    [
      'keychain-history-empty-id',
      'keychain-order.ts',
      "id === '' || seen.has(id) || byParent.has(parent)",
      'false || seen.has(id) || byParent.has(parent)',
    ],
    [
      'keychain-history-duplicate-id',
      'keychain-order.ts',
      "id === '' || seen.has(id) || byParent.has(parent)",
      "id === '' || false || byParent.has(parent)",
    ],
    [
      'keychain-history-fork-admission',
      'keychain-order.ts',
      "id === '' || seen.has(id) || byParent.has(parent)",
      "id === '' || seen.has(id) || false",
    ],
    [
      'keychain-history-index-binding',
      'keychain-order.ts',
      'byParent.set(parent, index);',
      'byParent.set(id, index);',
    ],
    [
      'keychain-history-root',
      'keychain-order.ts',
      "let cursor = '';",
      "let cursor = 'missing';",
    ],
    [
      'keychain-history-nonconsuming-walk',
      'keychain-order.ts',
      'byParent.delete(cursor);',
      'byParent.delete(cursor); byParent.set(cursor, next);',
    ],
    [
      'keychain-history-successor',
      'keychain-order.ts',
      'cursor = ids[next];',
      'cursor = parents[next];',
    ],
    [
      'keychain-history-work-accounting',
      'keychain-order.ts',
      'probes++;',
      'probes += 2;',
    ],
    [
      'keychain-history-orphan-admission',
      'keychain-order.ts',
      'return { valid: order.length === ids.length, order, probes };',
      'return { valid: true, order, probes };',
    ],
    [
      'keychain-history-clock-off-by-one',
      'keychain-order.ts',
      'offset > 9007199254740991 - clock',
      'offset >= 9007199254740991 - clock',
    ],
    [
      'utf8-oversized-preflight-admission',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (value.length > maximum) return -1;',
      'if (value.length > maximum) return 0;',
    ],
    [
      'utf8-unpaired-surrogate-admission',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (!isPairedUtf16Unit(value, index)) return -2;',
      'if (isPairedUtf16Unit(value, index)) return -2;',
    ],
    [
      'utf8-byte-limit-off-by-one',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (width > maximum - bytes) return -1;',
      'if (width > maximum - bytes + 1) return -1;',
    ],
    [
      'utf8-weight-accounting-loss',
      'packages/core/src/internal/canonical-encoding.ts',
      'bytes += width;',
      'bytes += 1;',
    ],
    [
      'utf8-ascii-overcount',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (code < 0x80) return 1;',
      'if (code < 0x80) return 2;',
    ],
    [
      'utf8-two-byte-undercount',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (code < 0x800) return 2;',
      'if (code < 0x800) return 1;',
    ],
    [
      'utf8-surrogate-overcount',
      'packages/core/src/internal/canonical-encoding.ts',
      'if (code >= 0xd800 && code <= 0xdfff) return 2;',
      'if (code >= 0xd800 && code <= 0xdfff) return 3;',
    ],
    [
      'utf8-three-byte-undercount',
      'packages/core/src/internal/canonical-encoding.ts',
      'return 3;',
      'return 2;',
    ],
    [
      'document-write-missing-prefix-reservation',
      'frame-layout.ts',
      '    maximum,\n    prefix,',
      '    maximum,\n    0,',
    ],
    [
      'document-write-missing-field-bound',
      'frame-layout.ts',
      '    maximum,\n    prefix,',
      '    4294967295,\n    prefix,',
    ],
    [
      'document-write-rejection-consumes-space',
      'frame-layout.ts',
      'end: valid ? payloadEnd + prefix : used,',
      'end: valid ? payloadEnd + prefix : used + 1,',
    ],
    [
      'document-write-double-payload-copy',
      'frame-layout.ts',
      'copyBytes: valid ? length : 0,',
      'copyBytes: valid ? 2 * length : 0,',
    ],
    [
      'document-write-empty-part-retention',
      'frame-layout.ts',
      'parts: valid ? (framed ? 1 : 0) + (length > 0 ? 1 : 0) : 0,',
      'parts: valid ? (framed ? 1 : 0) + 1 : 0,',
    ],
    [
      'document-write-missing-payload-copy',
      'frame-layout.ts',
      'copyBytes: valid ? length : 0,',
      'copyBytes: 0,',
    ],
    [
      'document-write-missing-prefix-size',
      'frame-layout.ts',
      'end: valid ? payloadEnd + prefix : used,',
      'end: valid ? payloadEnd : used,',
    ],
    [
      'document-write-zero-boundary-rejection',
      'frame-layout.ts',
      'const valid = payloadEnd >= 0;',
      'const valid = payloadEnd > 0;',
    ],
    [
      'recovery-io-eager-publications',
      'document-journal.ts',
      'const publicationReads = recovery ? 0 : publications;',
      'const publicationReads = publications;',
    ],
    [
      'recovery-io-eager-pending-body',
      'document-journal.ts',
      'const pending = hasPending && !recovery;',
      'const pending = hasPending;',
    ],
    [
      'recovery-io-lost-pending-token',
      'document-journal.ts',
      'pendingToken: hasPending && recovery,',
      'pendingToken: false,',
    ],
    [
      'recovery-io-dropped-accepted-entries',
      'document-journal.ts',
      'entries,',
      'entries: 0,',
    ],
    [
      'recovery-io-undercounted-rows',
      'document-journal.ts',
      'rowReads: 1 + entries + publicationReads + (pending ? 1 : 0),',
      'rowReads: 1 + entries,',
    ],
    [
      'recovery-io-inverted-publication-mode',
      'document-journal.ts',
      'const publicationReads = recovery ? 0 : publications;',
      'const publicationReads = recovery ? publications : 0;',
    ],
    [
      'journal-index-gapped-suffix',
      'journal-index.ts',
      '(index > 0 && current - previous !== 1)',
      'false',
    ],
    [
      'journal-index-missing-head',
      'journal-index.ts',
      'return previous === revision;',
      'return true;',
    ],
    [
      'journal-index-capacity-overflow',
      'journal-index.ts',
      'revisions.length > 128',
      'revisions.length > 129',
    ],
    [
      'journal-index-orphan-bytes',
      'journal-index.ts',
      'return revision === 0 && bytes === 0;',
      'return revision === 0;',
    ],
    [
      'journal-index-undercounted-bytes',
      'journal-index.ts',
      'bytes < revisions.length',
      'false',
    ],
    [
      'journal-read-offset-overflow',
      'frame-layout.ts',
      'length > total - offset - trailer',
      'length > total - trailer',
    ],
    [
      'journal-read-exact-size-bypass',
      'frame-layout.ts',
      'length < minimum || length > maximum',
      'length > maximum',
    ],
    [
      'authority-capture-duplicate-binding',
      'authority-capture.ts',
      'count < 256 && !duplicate && idLength === 64',
      'count < 256 && idLength === 64',
    ],
    [
      'authority-capture-invalid-role',
      'authority-capture.ts',
      '(role === 1 || role === 2 || role === 3)',
      'true',
    ],
    [
      'authority-capture-capacity-overflow',
      'authority-capture.ts',
      'count < 256 && !duplicate',
      'count <= 256 && !duplicate',
    ],
    [
      'authority-capture-key-substitution',
      'authority-capture.ts',
      'members.set(entry.id, entry);',
      'members.set(localId, entry);',
    ],
    [
      'authority-capture-value-substitution',
      'authority-capture.ts',
      'members.set(entry.id, entry);',
      'members.set(entry.id, entries[0]);',
    ],
    [
      'authority-capture-missing-local-member',
      'authority-capture.ts',
      'if (!members.has(localId)) return { valid: false, members: new Map() };',
      'if (false) return { valid: false, members: new Map() };',
    ],
    [
      'sync-clock-rollback',
      'sync-request.ts',
      'return previous > observed ? previous : observed;',
      'return observed;',
    ],
    [
      'sync-live-nonce-retirement',
      'sync-request.ts',
      'return now - issuedAt > 60000;',
      'return now - issuedAt >= 60000;',
    ],
    [
      'sync-prune-live-retention',
      'sync-request.ts',
      'if (!syncRequestReplayExpired(ledger.get(key)!, now))',
      'if (false)',
    ],
    [
      'sync-prune-inverted-lifetime',
      'sync-request.ts',
      'if (!syncRequestReplayExpired(ledger.get(key)!, now))',
      'if (syncRequestReplayExpired(ledger.get(key)!, now))',
    ],
    [
      'sync-prune-wrong-identity',
      'sync-request.ts',
      'result.set(key, ledger.get(key)!);',
      'result.set("different", ledger.get(key)!);',
    ],
    [
      'sync-replay-bypass',
      'sync-request.ts',
      "if (known) return 'replay';",
      "if (false) return 'replay';",
    ],
    [
      'sync-stale-admission',
      'sync-request.ts',
      "if (!syncRequestTimeAllowed(issuedAt, now)) return 'stale';",
      "if (false) return 'stale';",
    ],
    [
      'sync-replay-capacity-overflow',
      'sync-request.ts',
      "return size < capacity ? 'fresh' : 'capacity';",
      "return size <= capacity ? 'fresh' : 'capacity';",
    ],
    [
      'sync-replay-history-loss',
      'sync-request.ts',
      'const result = new Map(ledger);',
      'const result = new Map<string, number>();',
    ],
    [
      'sync-replay-timestamp-rewrite',
      'sync-request.ts',
      'result.set(key, issuedAt);',
      'result.set(key, issuedAt + 1);',
    ],
    [
      'sync-response-cooldown',
      'sync-request.ts',
      'now - lastResponse >= 2000',
      'now - lastResponse >= 1999',
    ],
    [
      'sync-response-known-state',
      'sync-request.ts',
      '(!changeKnown || (hasSnapshot && !snapshotKnown))',
      'true',
    ],
    [
      'sync-response-known-snapshot',
      'sync-request.ts',
      'hasSnapshot && !snapshotKnown',
      'hasSnapshot && snapshotKnown',
    ],
    [
      'sync-response-without-change',
      'sync-request.ts',
      '    hasChange &&',
      '    true &&',
    ],
    [
      'authority-role-range',
      'document-authority.ts',
      'if (role !== 1 && role !== 2 && role !== 3) return -1;',
      'if (false) return -1;',
    ],
    [
      'authority-two-controllers',
      'document-authority.ts',
      'if (controller !== -1) return -1;',
      'if (false) return -1;',
    ],
    [
      'authority-missing-controller',
      'document-authority.ts',
      'return controller;',
      'return controller === -1 ? 0 : controller;',
    ],
    [
      'authority-duplicate-member',
      'document-authority.ts',
      'if (!validDocumentAuthorityFields(memberIds, 64, 64)) return false;',
      'if (false) return false;',
    ],
    [
      'authority-duplicate-key',
      'document-authority.ts',
      'if (!validDocumentAuthorityFields(publicKeys, 1, 4096)) return false;',
      'if (false) return false;',
    ],
    [
      'authority-roster-bound',
      'document-authority.ts',
      'roles.length > 256',
      'roles.length > 257',
    ],
    [
      'authority-empty-key',
      'document-authority.ts',
      'validDocumentAuthorityFields(publicKeys, 1, 4096)',
      'validDocumentAuthorityFields(publicKeys, 0, 4096)',
    ],
    [
      'authority-controller-capacity',
      'document-authority.ts',
      'return controllers.size < limit && !controllers.has(head);',
      'return controllers.size <= limit && !controllers.has(head);',
    ],
    [
      'authority-controller-rebinding',
      'document-authority.ts',
      'return controllers.size < limit && !controllers.has(head);',
      'return controllers.size < limit;',
    ],
    [
      'authority-controller-history-loss',
      'document-authority.ts',
      'const result = new Map(controllers);',
      'const result = new Map<string, Controller>();',
    ],
    [
      'authority-wrong-control-head',
      'document-authority.ts',
      'result.set(head, controller);',
      'result.set("unexpected", controller);',
    ],
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
      'packages/react/src/document-cache-key.ts',
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
    [
      'welcome-duplicate-authentication-bypass',
      'welcome-admission.ts',
      '(!existing || authenticated) &&',
      'true &&',
      'canAdmitPendingWelcome_ensures',
    ],
    [
      'welcome-protected-budget-bypass',
      'welcome-admission.ts',
      'protectedCount < maximumEntries && protectedBytes <= maximumBytes - incomingBytes',
      'true',
      'canAdmitPendingWelcome_ensures',
    ],
    [
      'welcome-protected-budget-inversion',
      'welcome-admission.ts',
      'if (entry.authenticated) { protectedBytes += entry.bytes; protectedCount++; }',
      'if (!entry.authenticated) { protectedBytes += entry.bytes; protectedCount++; }',
      'pendingWelcomeBudget',
    ],
    [
      'welcome-byte-accounting-substitution',
      'welcome-admission.ts',
      'total += entry.bytes;',
      'total += 1;',
      'pendingWelcomeBudget',
    ],
    [
      'welcome-pressure-count-boundary',
      'welcome-admission.ts',
      'remainingCount >= maximumEntries',
      'remainingCount > maximumEntries',
      'trimPendingWelcomes',
    ],
    [
      'welcome-pressure-extra-eviction',
      'welcome-admission.ts',
      'remainingBytes > maximumBytes - incomingBytes',
      'remainingBytes >= maximumBytes - incomingBytes',
      'trimPendingWelcomes',
    ],
    [
      'welcome-pressure-authentication-bypass',
      'welcome-admission.ts',
      'allowAuthenticated || !entry.authenticated',
      'true',
      'trimPendingWelcomes',
    ],
    [
      'welcome-removal-wrong-key',
      'welcome-admission.ts',
      'if (entry.key === key) { removed = true; }',
      'if (entry.key !== key) { removed = true; }',
      'planPendingWelcomeRemoval',
    ],
    [
      'welcome-retained-value-substitution',
      'welcome-admission.ts',
      'result.set(key, values.get(key)!);',
      'result.set(key, values.get(kept[0].key)!);',
      'retainPendingWelcomeValues',
    ],
    [
      'welcome-missing-insertion',
      'welcome-admission.ts',
      'const result = new Map(values); result.set(key, value);',
      'const result = new Map(values); result.delete(key);',
      'insertPendingWelcomeValue',
    ],
    [
      'welcome-first-pass-evicts-authenticated',
      'welcome-admission.ts',
      'const unverified = trimPendingWelcomes(removal.kept, incomingBytes, false, maximumEntries, maximumBytes,);',
      'const unverified = trimPendingWelcomes(removal.kept, incomingBytes, true, maximumEntries, maximumBytes,);',
      'planPendingWelcomeAdmission',
    ],
    [
      'welcome-clock-rollback',
      'welcome-admission.ts',
      'return previous >= now ? previous : now;',
      'return now;',
      'advancePendingWelcomeClock_ensures',
    ],
    [
      'welcome-clock-freeze',
      'welcome-admission.ts',
      'return previous >= now ? previous : now;',
      'return previous;',
      'advancePendingWelcomeClock_ensures',
    ],
    [
      'welcome-expiry-boundary',
      'welcome-admission.ts',
      'return now - bufferedAtMs > ttl;',
      'return now - bufferedAtMs >= ttl;',
      'isPendingWelcomeExpired_ensures',
    ],
    [
      'welcome-expiry-clock-substitution',
      'welcome-admission.ts',
      'isPendingWelcomeExpired(bufferedAtMs[index], now, ttl)',
      'isPendingWelcomeExpired(now, now, ttl)',
      'planPendingWelcomeExpiry',
    ],
    [
      'welcome-expiry-inversion',
      'welcome-admission.ts',
      'if (isPendingWelcomeExpired(bufferedAtMs[index], now, ttl))',
      'if (!isPendingWelcomeExpired(bufferedAtMs[index], now, ttl))',
      'planPendingWelcomeExpiry',
    ],
    [
      'welcome-expiry-initial-byte-leak',
      'welcome-admission.ts',
      'const expiredKeys: string[] = []; let retainedBytes = 0;',
      'const expiredKeys: string[] = []; let retainedBytes = 1;',
      'planPendingWelcomeExpiry',
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
      'decideJoinReplay_ensures',
    ],
    [
      'invitation-clock-rollback',
      'replay-admission.ts',
      'return previous > observed ? previous : observed;',
      'return observed;',
      'advanceInvitationReplayClock_ensures',
    ],
    [
      'invitation-expiry-frontier-direction',
      'replay-admission.ts',
      'return previous < added ? previous : added;',
      'return previous > added ? previous : added;',
      'nextInvitationReplayExpiry_ensures',
    ],
    [
      'invitation-sweep-deadline',
      'replay-admission.ts',
      'return now >= earliest;',
      'return now > earliest;',
      'shouldSweepInvitationReplays_ensures',
    ],
    [
      'invitation-expired-projection-boundary',
      'replay-admission.ts',
      'if (expiry <= now)',
      'if (expiry < now)',
      'collectExpiredInvitationClaims',
    ],
    [
      'invitation-expired-projection-key',
      'replay-admission.ts',
      'expired.push(key);',
      "expired.push('');",
      'collectExpiredInvitationClaims',
    ],
    [
      'invitation-expired-projection-frontier',
      'replay-admission.ts',
      'nextExpiry = nextInvitationReplayExpiry(nextExpiry, expiry);',
      'nextExpiry = 9007199254740991;',
      'collectExpiredInvitationClaims',
    ],
    [
      'invitation-join-offer-index',
      'replay-admission.ts',
      'offers.set(invitationId, offerDigest);',
      'offers.delete(invitationId);',
      'recordInvitationReplayJoin',
    ],
    [
      'invitation-join-request-binding',
      'replay-admission.ts',
      'requests.set(requestId, { offerDigest, envelopeDigest: requestDigest });',
      'requests.set(requestId, { offerDigest, envelopeDigest: offerDigest });',
      'recordInvitationReplayJoin',
    ],
    [
      'invitation-acceptance-join-rewrite',
      'replay-admission.ts',
      'requestDigest: claim.requestDigest,',
      'requestDigest: acceptanceDigest,',
      'recordInvitationReplayAcceptance',
    ],
    [
      'invitation-acceptance-not-consumed',
      'replay-admission.ts',
      'accepted: true,',
      'accepted: false,',
      'recordInvitationReplayAcceptance',
    ],
    [
      'invitation-retire-unrelated-offer-index',
      'replay-admission.ts',
      'offers.has(claim.invitationId) && offers.get(claim.invitationId) === offerDigest',
      'offers.has(claim.invitationId)',
      'retireInvitationReplayClaim',
    ],
    [
      'invitation-retire-unrelated-request-index',
      'replay-admission.ts',
      'requests.has(claim.requestId) && requests.get(claim.requestId)!.offerDigest === offerDigest',
      'requests.has(claim.requestId)',
      'retireInvitationReplayClaim',
    ],
    [
      'invitation-retire-unconsumed-acceptance-index',
      'replay-admission.ts',
      'claim.accepted && acceptances.has(claim.acceptanceId) && acceptances.get(claim.acceptanceId)!.offerDigest === offerDigest',
      'acceptances.has(claim.acceptanceId) && acceptances.get(claim.acceptanceId)!.offerDigest === offerDigest',
      'retireInvitationReplayClaim',
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
      'retained-gc-cid',
      'retention.ts',
      'if (!retained.has(cid) && !protectedCids.has(cid)) result.add(cid);',
      'if (!protectedCids.has(cid)) result.add(cid);',
    ],
    [
      'gc-noncandidate-substitution',
      'retention.ts',
      'const cid = candidates[index];',
      'const cid = "injected-not-candidate";',
    ],
    [
      'gc-safe-candidate-omission',
      'retention.ts',
      'if (!retained.has(cid) && !protectedCids.has(cid)) result.add(cid);',
      'if (false) result.add(cid);',
    ],
    [
      'gc-stale-tree-lease',
      'retention.ts',
      'return sameTree && sameSnapshot && sameTips && active;',
      'return sameSnapshot && sameTips && active;',
    ],
    [
      'gc-stale-snapshot-lease',
      'retention.ts',
      'return sameTree && sameSnapshot && sameTips && active;',
      'return sameTree && sameTips && active;',
    ],
    [
      'gc-stale-tips-lease',
      'retention.ts',
      'return sameTree && sameSnapshot && sameTips && active;',
      'return sameTree && sameSnapshot && active;',
    ],
    [
      'gc-closed-lifecycle-lease',
      'retention.ts',
      'return sameTree && sameSnapshot && sameTips && active;',
      'return sameTree && sameSnapshot && sameTips;',
    ],
    [
      'gc-pinned-delete-entry',
      'retention.ts',
      "if (phase === 'checking' && action === 'delete' && leaseCurrent && unpinned) return 'deleting';",
      "if (phase === 'checking' && action === 'delete' && leaseCurrent) return 'deleting';",
    ],
    [
      'gc-stale-delete-entry',
      'retention.ts',
      "if (phase === 'checking' && action === 'delete' && leaseCurrent && unpinned) return 'deleting';",
      "if (phase === 'checking' && action === 'delete' && unpinned) return 'deleting';",
    ],
    [
      'gc-terminal-restart',
      'retention.ts',
      "return 'aborted';",
      "return 'ready';",
    ],
    [
      'gc-candidate-count-overflow',
      'retention.ts',
      'return length >= 1 && length <= 512 && (known || count < 32768);',
      'return length >= 1 && length <= 512 && (known || count <= 32768);',
    ],
    [
      'gc-candidate-length-overflow',
      'retention.ts',
      'return length >= 1 && length <= 512 && (known || count < 32768);',
      'return length >= 1 && length <= 513 && (known || count < 32768);',
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
      'return leaves === 2 && index === 0 ? [] : [parent, ...treeDirectPath(parent, leaves)];',
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
      "if (phase === 'committed' || phase === 'cancelled') return phase; if (event === 'cancel') return 'cancelled';",
      "if (phase === 'committed' || phase === 'cancelled') return phase; if (event === 'cancel') return 'prepared';",
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
      'publication-ledger-rebind',
      'document-journal.ts',
      '!ledger.has(token) && ledger.size < limit',
      'ledger.size < limit',
    ],
    [
      'publication-ledger-overflow',
      'document-journal.ts',
      'ledger.size < limit &&',
      'ledger.size <= limit &&',
    ],
    [
      'publication-ledger-old-delta-revision',
      'document-journal.ts',
      'checkpoint || bindingRevision === entryRevision',
      'checkpoint || bindingRevision <= entryRevision',
    ],
    [
      'publication-ledger-revision-rewrite',
      'document-journal.ts',
      'result.set(token, revision);',
      'result.set(token, revision + 1);',
    ],
    [
      'publication-ledger-history-loss',
      'document-journal.ts',
      'const result = new Map(ledger);',
      'const result = new Map<string, number>();',
    ],
    [
      'publication-ledger-compaction-resurrection',
      'document-journal.ts',
      'const result = new Map<string, number>();',
      'const result = new Map(ledger);',
    ],
    [
      'publication-ledger-dangling-retention',
      'document-journal.ts',
      'if (!ledger.has(pending[index]) || seen.has(pending[index])) return false;',
      'if (seen.has(pending[index])) return false;',
    ],
    [
      'publication-ledger-duplicate-retention',
      'document-journal.ts',
      'if (!ledger.has(pending[index]) || seen.has(pending[index])) return false;',
      'if (!ledger.has(pending[index])) return false;',
    ],
    [
      'publication-ledger-aborted-install',
      'document-journal.ts',
      'return anchored ? candidate : before;',
      'return candidate;',
    ],
    [
      'publication-ledger-wrong-token-revision',
      'document-journal.ts',
      'isAcceptedDocumentPublication(revision, currentRevision, ledger.get(token)!)',
      'isAcceptedDocumentPublication(revision, currentRevision, revision)',
    ],
    [
      'document-publication-revision-only',
      'document-journal.ts',
      'return (1 <= revision && revision <= currentRevision && bindingRevision === revision);',
      'return 1 <= revision && revision <= currentRevision;',
    ],
    [
      'document-publication-future-binding',
      'document-journal.ts',
      'return (1 <= revision && revision <= currentRevision && bindingRevision === revision);',
      'return 1 <= revision && bindingRevision === revision;',
    ],
    [
      'document-publication-zero-binding',
      'document-journal.ts',
      'return (1 <= revision && revision <= currentRevision && bindingRevision === revision);',
      'return revision <= currentRevision && bindingRevision === revision;',
    ],
    [
      'document-journal-uncommitted-promotion',
      'document-journal.ts',
      "if (!markerAuthenticated) return 'reject';",
      "if (false) return 'reject';",
    ],
  ];
  mutations.push([
    'connection-retry-after-cancellation',
    'connection-retry.ts',
    'return retryable && !aborted && attempt < maximum;',
    'return retryable && attempt < maximum;',
  ]);
  mutations.push([
    'expired-sync-request-admission',
    'sync-request.ts',
    'return issuedAt - now >= -60000 && issuedAt - now <= 30000;',
    'return issuedAt - now >= -60001 && issuedAt - now <= 30000;',
  ]);
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
