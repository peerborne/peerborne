import {
  mkdirSync,
  existsSync,
  writeFileSync,
  mkdtempSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  configuration,
  toolsRoot,
  lemmaRoot,
  lsc,
  dafny,
  execute,
  sha256,
  requireTools,
} from './support.mjs';

const archive =
  configuration.dafny.archives[`${process.platform}-${process.arch}`];
if (!archive)
  throw new Error('Formal setup supports Linux x64 and macOS arm64/x64.');
mkdirSync(toolsRoot, { recursive: true });
if (!existsSync(lemmaRoot)) {
  execute(
    'git',
    [
      'clone',
      '--no-checkout',
      '--filter=blob:none',
      configuration.lemmaScript.repository,
      lemmaRoot,
    ],
    { stdio: 'inherit' },
  );
  execute('git', ['checkout', '--detach', configuration.lemmaScript.revision], {
    cwd: lemmaRoot,
    stdio: 'inherit',
  });
}
if (
  execute('git', ['rev-parse', 'HEAD'], { cwd: lemmaRoot }).trim() !==
  configuration.lemmaScript.revision
)
  throw new Error(
    'Existing tool checkout has another revision. Choose an empty PEERBORNE_FORMAL_TOOLS directory.',
  );
execute('git', ['diff', '--exit-code', 'HEAD', '--'], { cwd: lemmaRoot });
execute('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], {
  cwd: lemmaRoot,
  stdio: 'inherit',
});
execute('npm', ['run', 'build', '--', '--types', 'node'], {
  cwd: lemmaRoot,
  stdio: 'inherit',
});
if (!existsSync(lsc))
  throw new Error('LemmaScript build did not produce the verifier CLI');
if (!existsSync(dafny)) {
  const staging = mkdtempSync(join(toolsRoot, 'dafny-setup-'));
  try {
    const url = `https://github.com/dafny-lang/dafny/releases/download/v${configuration.dafny.version}/${archive.name}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
    if (!response.ok)
      throw new Error(`Dafny download returned HTTP ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (sha256(bytes) !== archive.sha256)
      throw new Error('Dafny archive checksum mismatch');
    const zip = join(staging, 'dafny.zip');
    writeFileSync(zip, bytes);
    execute('unzip', ['-q', zip, '-d', staging]);
    renameSync(join(staging, 'dafny'), join(toolsRoot, 'dafny'));
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
const installed = requireTools({ requireInstallStamp: false });
writeFileSync(
  join(toolsRoot, 'installed.json'),
  `${JSON.stringify({ ...installed, dafnyArchiveSha256: archive.sha256 }, null, 2)}\n`,
);
console.log(
  `Formal tools ready: LemmaScript ${installed.lemmaScriptVersion}, Dafny ${installed.dafnyVersion}`,
);
