import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

export const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
export const configuration = JSON.parse(
  readFileSync(new URL('./toolchain.json', import.meta.url), 'utf8'),
);
export const manifest = JSON.parse(
  readFileSync(new URL('./manifest.json', import.meta.url), 'utf8'),
);
export const toolsRoot = resolve(
  process.env.PEERBORNE_FORMAL_TOOLS ??
    join(projectRoot, 'verification/formal/.tools'),
);
export const lemmaRoot = join(toolsRoot, 'lemmascript');
export const lsc = join(lemmaRoot, 'tools/dist/lsc.js');
export const dafny = join(toolsRoot, 'dafny/dafny');
export const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');
export const digestFile = (path) => sha256(readFileSync(path));
export function execute(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: projectRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 300000,
    ...options,
  });
  if (result.error || result.status !== 0) {
    const error = new Error(
      `${program} failed (${result.status ?? result.error?.code}):\n${result.stdout ?? ''}${result.stderr ?? ''}`,
    );
    error.result = result;
    throw error;
  }
  return result.stdout;
}
export function proofPaths(source, root = projectRoot) {
  const base = join(
    root,
    'verification/formal/proofs',
    source.replace(/\.ts$/, ''),
  );
  return { generated: `${base}.dfy.gen`, proof: `${base}.dfy` };
}
export function requireTools({ requireInstallStamp = true } = {}) {
  if (!existsSync(lsc) || !existsSync(dafny))
    throw new Error(
      'Formal tools are missing. Run node verification/formal/setup.mjs first.',
    );
  const revision = execute('git', ['rev-parse', 'HEAD'], {
    cwd: lemmaRoot,
  }).trim();
  if (revision !== configuration.lemmaScript.revision)
    throw new Error('LemmaScript revision does not match toolchain.json');
  execute('git', ['diff', '--exit-code', 'HEAD', '--'], { cwd: lemmaRoot });
  const version = execute(dafny, ['--version']).trim();
  if (
    !version.startsWith(`${configuration.dafny.version}+`) &&
    version !== configuration.dafny.version
  )
    throw new Error('Dafny version does not match toolchain.json');
  const compiler = JSON.parse(
    readFileSync(join(lemmaRoot, 'package.json'), 'utf8'),
  );
  if (compiler.version !== configuration.lemmaScript.version)
    throw new Error(
      'LemmaScript package version does not match toolchain.json',
    );
  const versions = {
    lemmaScriptRevision: revision,
    lemmaScriptVersion: compiler.version,
    dafnyVersion: version,
  };
  if (requireInstallStamp) {
    const stampPath = join(toolsRoot, 'installed.json');
    if (!existsSync(stampPath))
      throw new Error(
        'Formal setup did not complete; rerun node verification/formal/setup.mjs',
      );
    const stamp = JSON.parse(readFileSync(stampPath, 'utf8'));
    if (Object.entries(versions).some(([key, value]) => stamp[key] !== value))
      throw new Error(
        'Formal installation stamp does not match the active tools',
      );
  }
  return versions;
}
export const proverEnvironment = () => ({
  ...process.env,
  PATH: `${dirname(dafny)}:${process.env.PATH ?? ''}`,
  LSC_RUN_LOG: 'true',
});
export function typescript() {
  return createRequire(join(lemmaRoot, 'package.json'))('typescript');
}
