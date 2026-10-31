import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
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
      !/\.(test|spec|benchmark|d)\.ts$/.test(entry.name)
    ) {
      const source = readFileSync(path, 'utf8');
      const syntax = ts.createSourceFile(
        path,
        source,
        ts.ScriptTarget.Latest,
        true,
      );
      let functions = 0,
        asynchronous = 0,
        methods = 0,
        awaits = 0;
      const scan = (node) => {
        if (ts.isFunctionLike(node) && node.body) {
          functions++;
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
      files.push({
        path: relative(projectRoot, path),
        physicalLines: source.split(/\r?\n/).length,
        functions,
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
const report = {
  scope:
    'First-party library TypeScript, excluding tests, mocks, benchmarks and declaration files. Counts are structural inventory, not semantic purity or security coverage.',
  totals,
  files: files.sort((a, b) => a.path.localeCompare(b.path)),
};
const directory = join(projectRoot, 'verification/results/formal');
mkdirSync(directory, { recursive: true });
writeFileSync(
  join(directory, 'inventory.json'),
  `${JSON.stringify(report, null, 2)}\n`,
);
console.log(JSON.stringify(totals, null, 2));
