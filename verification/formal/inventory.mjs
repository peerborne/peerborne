import {
  readdirSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
} from 'node:fs';
import { join, relative } from 'node:path';
import { projectRoot, manifest, typescript } from './support.mjs';

const ts = typescript();
const files = [];
function visit(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!/^(__|node_modules|dist)/.test(entry.name)) visit(path);
    } else if (
      entry.name.endsWith('.ts') &&
      !/\.(test|spec|benchmark|d)\.ts$/.test(entry.name) &&
      entry.name !== 'test-utils.ts'
    ) {
      const source = readFileSync(path, 'utf8');
      const syntax = ts.createSourceFile(
        path,
        source,
        ts.ScriptTarget.Latest,
        true,
      );
      const selectedNames = [];
      const topLevelFunctions = [];
      let functions = 0,
        asynchronous = 0,
        methods = 0,
        awaits = 0;
      const scan = (node) => {
        if (ts.isFunctionLike(node) && node.body) {
          functions++;
          if (
            ts.isFunctionDeclaration(node) &&
            node.parent === syntax &&
            node.name
          )
            topLevelFunctions.push(node.name.text);
          if (ts.isBlock(node.body)) {
            const comments =
              ts.getLeadingCommentRanges(source, node.body.statements.pos) ??
              [];
            if (
              comments.some((range) =>
                /^\/\/@\s*verify\s*$/.test(source.slice(range.pos, range.end)),
              )
            ) {
              selectedNames.push(node.name?.getText(syntax) ?? '<anonymous>');
            }
          }
          if (
            node.modifiers?.some(
              (modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword,
            )
          )
            asynchronous++;
          if (
            ts.isMethodDeclaration(node) ||
            ts.isConstructorDeclaration(node) ||
            ts.isGetAccessor(node) ||
            ts.isSetAccessor(node)
          )
            methods++;
        }
        if (ts.isAwaitExpression(node)) awaits++;
        ts.forEachChild(node, scan);
      };
      scan(syntax);
      const pathName = relative(projectRoot, path);
      const declared =
        manifest.sources.find((entry) => entry.path === pathName)?.functions ??
        [];
      if (
        JSON.stringify([...selectedNames].sort()) !==
        JSON.stringify([...declared].sort())
      ) {
        throw new Error(`Unregistered or stale formal selection: ${pathName}`);
      }
      files.push({
        path: relative(projectRoot, path),
        physicalLines: source.split(/\r?\n/).length,
        functions,
        selectedFunctions: declared,
        remainingTopLevelFunctions: topLevelFunctions.filter(
          (name) => !declared.includes(name),
        ),
        asynchronous,
        methods,
        awaits,
        proofFunctions:
          manifest.sources.find(
            (entry) => entry.path === relative(projectRoot, path),
          )?.functions.length ?? 0,
      });
    }
  }
}
for (const name of readdirSync(join(projectRoot, 'packages'))) {
  const directory = join(projectRoot, 'packages', name, 'src');
  try {
    visit(directory);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}
const totals = files.reduce(
  (sum, file) => {
    for (const key of [
      'physicalLines',
      'functions',
      'asynchronous',
      'methods',
      'awaits',
      'proofFunctions',
    ])
      sum[key] += file[key];
    return sum;
  },
  {
    files: files.length,
    physicalLines: 0,
    functions: 0,
    asynchronous: 0,
    methods: 0,
    awaits: 0,
    proofFunctions: 0,
  },
);
const strategy = JSON.parse(
  readFileSync(join(projectRoot, 'verification/strategy.json'), 'utf8'),
);
if (
  JSON.stringify(strategy.priority) !==
  JSON.stringify(['formal', 'property', 'regression-integration'])
) {
  throw new Error(
    'Verification strategy must preserve the requested fallback order',
  );
}
const assertions = [];
function declaredNumbers(node) {
  if (ts.isNumericLiteral(node)) return [Number(node.text.replaceAll('_', ''))];
  if (
    ts.isPrefixUnaryExpression(node) &&
    node.operator === ts.SyntaxKind.MinusToken &&
    ts.isNumericLiteral(node.operand)
  )
    return [-Number(node.operand.text)];
  if (ts.isConditionalExpression(node))
    return [
      ...declaredNumbers(node.whenTrue),
      ...declaredNumbers(node.whenFalse),
    ];
  throw new Error(
    'Property seeds and run counts must be declared numeric constants or explicit fixed alternatives',
  );
}
function auditTests(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (
        !['node_modules', 'dist', '__mocks__', '__benchmarks__'].includes(
          entry.name,
        )
      )
        auditTests(join(directory, entry.name));
      continue;
    }
    if (!/\.(?:test\.[cm]?[jt]sx?|fixture\.mjs)$/.test(entry.name)) continue;
    const path = join(directory, entry.name),
      name = relative(projectRoot, path);
    const source = readFileSync(path, 'utf8');
    const syntax = ts.createSourceFile(
      path,
      source,
      ts.ScriptTarget.Latest,
      true,
    );
    const fcImports = syntax.statements
      .filter(ts.isImportDeclaration)
      .filter(
        (node) =>
          ts.isStringLiteral(node.moduleSpecifier) &&
          node.moduleSpecifier.text === 'fast-check',
      );
    if (!fcImports.length) continue;
    const aliases = fcImports
      .flatMap((node) => {
        const bindings = node.importClause?.namedBindings;
        return [
          node.importClause?.name?.text,
          bindings && ts.isNamespaceImport(bindings)
            ? bindings.name.text
            : undefined,
        ];
      })
      .filter(Boolean);
    const cases = [];
    const scan = (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'assert' &&
        ts.isIdentifier(node.expression.expression) &&
        aliases.includes(node.expression.expression.text)
      ) {
        const config = node.arguments[1];
        if (!config || !ts.isObjectLiteralExpression(config))
          throw new Error(`Property assertion lacks explicit options: ${name}`);
        const option = (key) =>
          config.properties.find(
            (property) =>
              ts.isPropertyAssignment(property) &&
              property.name.getText(syntax) === key,
          )?.initializer;
        const seed = option('seed'),
          runs = option('numRuns');
        if (!seed || !runs)
          throw new Error(
            `Property assertion needs an explicit seed and numRuns: ${name}`,
          );
        const seeds = declaredNumbers(seed),
          runCounts = declaredNumbers(runs);
        if (
          seeds.some(
            (value) =>
              !Number.isInteger(value) ||
              value < -2147483648 ||
              value > 2147483647,
          ) ||
          runCounts.some((value) => !Number.isSafeInteger(value) || value < 1)
        )
          throw new Error(`Invalid property workload: ${name}`);
        cases.push({
          line:
            syntax.getLineAndCharacterOfPosition(node.getStart(syntax)).line +
            1,
          seeds,
          declaredRunsPerInvocation: runCounts,
        });
      }
      ts.forEachChild(node, scan);
    };
    scan(syntax);
    if (!cases.length)
      throw new Error(`No auditable assertions in property suite: ${name}`);
    assertions.push({ path: name, assertions: cases });
  }
}
for (const packageName of readdirSync(join(projectRoot, 'packages'))) {
  const source = join(projectRoot, 'packages', packageName, 'src');
  if (existsSync(source)) auditTests(source);
}
for (const group of strategy.propertyGroups) {
  if (!group.formalBoundary?.trim())
    throw new Error(`Missing formal-boundary explanation: ${group.id}`);
  for (const path of [...group.evidence, ...group.sources]) {
    if (!existsSync(join(projectRoot, path)))
      throw new Error(`Missing strategy evidence: ${path}`);
  }
  if (
    group.evidence.some(
      (path) => !assertions.some((file) => file.path === path),
    )
  )
    throw new Error(
      `Strategy group references a non-property suite: ${group.id}`,
    );
}
for (const file of assertions) {
  if (
    !strategy.propertyGroups.some((group) => group.evidence.includes(file.path))
  )
    throw new Error(
      `Property suite needs a formal-boundary explanation in verification/strategy.json: ${file.path}`,
    );
}
for (const boundary of strategy.integrationBoundaries) {
  for (const path of boundary.evidence)
    if (!existsSync(join(projectRoot, path)))
      throw new Error(`Missing integration evidence: ${path}`);
}
const report = {
  scope:
    'First-party library TypeScript, excluding tests, mocks, benchmarks and declarations. Function counts, selections and property declarations are inventory metadata, not semantic correctness or security coverage.',
  totals: {
    ...totals,
    propertyFiles: assertions.length,
    propertyAssertions: assertions.reduce(
      (sum, file) => sum + file.assertions.length,
      0,
    ),
  },
  files: files.sort((a, b) => a.path.localeCompare(b.path)),
  propertySuites: assertions.sort((a, b) => a.path.localeCompare(b.path)),
  strategy,
};
const directory = join(projectRoot, 'verification/results/formal');
mkdirSync(directory, { recursive: true });
writeFileSync(
  join(directory, 'inventory.json'),
  `${JSON.stringify(report, null, 2)}\n`,
);
console.log(JSON.stringify(report.totals, null, 2));
