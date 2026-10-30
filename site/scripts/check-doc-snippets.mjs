import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const rootNames = ['peerborne.tsx', 'Workspace.tsx', 'main.tsx'].map((name) =>
  fileURLToPath(new URL(`../src/snippets/${name}`, import.meta.url)),
);
rootNames.push(fileURLToPath(new URL('../src/lib/sync-story-controller.ts', import.meta.url)));
const component = readFileSync(new URL('../src/snippets/Workspace.tsx', import.meta.url), 'utf8').trimEnd();
const readme = readFileSync(new URL('../../README.md', import.meta.url), 'utf8');
if (!readme.includes(`\`\`\`tsx\n${component}\n\`\`\``)) {
  throw new Error('The README React snippet must match the checked component source.');
}
const program = ts.createProgram(rootNames, {
  noEmit: true,
  strict: true,
  skipLibCheck: true,
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  jsx: ts.JsxEmit.ReactJSX,
  esModuleInterop: true,
  types: ['react', 'react-dom'],
});
const diagnostics = ts.getPreEmitDiagnostics(program);
if (diagnostics.length) {
  process.stderr.write(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (file) => file,
    getCurrentDirectory: ts.sys.getCurrentDirectory,
    getNewLine: () => '\n',
  }));
  process.exitCode = 1;
} else {
  console.log('React snippets and sync-story controller typecheck; README snippet matches.');
}
