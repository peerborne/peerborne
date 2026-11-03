import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertInstalledArtifacts } from './consumer.mjs';
import { auditConsumer } from './audit.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const consumer = resolve(process.argv[2] ?? '');
if (!process.argv[2])
  throw new Error(
    'Usage: node verification/release/run.mjs <installed-consumer>',
  );
const { artifacts } = JSON.parse(
  await readFile(join(consumer, 'release-artifacts.json'), 'utf8'),
);
await assertInstalledArtifacts(consumer, artifacts);
const profile =
  process.env.PEERBORNE_RELEASE_PROFILE ??
  (process.env.PEERBORNE_RELEASE_BROWSERS ?? 'chromium').split(',').join('-');
if (!/^[a-z0-9-]{1,64}$/u.test(profile))
  throw new Error('Invalid release evidence profile');
const temporary = await mkdtemp(join(tmpdir(), 'peerborne-release-browser-'));
const names = [
  'note',
  'integrations',
  'nextjs',
  'tanstack',
  'control',
  'relayReadiness',
  'relayWebSocket',
  'relayTcp',
];
const servers = names.map(() => createServer());
await Promise.all(
  servers.map(
    (server) =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
      }),
  ),
);
const ports = Object.fromEntries(
  servers.map((server, index) => [names[index], server.address().port]),
);
await Promise.all(
  servers.map((server) => new Promise((resolve) => server.close(resolve))),
);
const configuration = join(temporary, 'configuration.json');
const reportDirectory = join(root, 'verification/results/release', profile);
await mkdir(reportDirectory, { recursive: true });
await writeFile(configuration, JSON.stringify({ consumer, ports, temporary }));
const env = {
  ...process.env,
  NODE_AUTH_TOKEN: undefined,
  NPM_TOKEN: undefined,
  PEERBORNE_RELEASE_CONFIGURATION: configuration,
  PEERBORNE_RELEASE_REPORT_DIRECTORY: reportDirectory,
  PEERBORNE_NOTE_LIVE_URL: `http://127.0.0.1:${ports.note}/`,
  PEERBORNE_NOTE_RELAY_CONNECT_SOURCE:
    process.env.PEERBORNE_RELEASE_RELAY_ORIGIN ??
    `ws://127.0.0.1:${ports.relayWebSocket}`,
  PEERBORNE_NOTE_PUBLIC_RELAY: process.env.PEERBORNE_RELEASE_RELAY_MULTIADDR
    ? '1'
    : undefined,
  PEERBORNE_NOTE_LIVE_COOLDOWN_FILE: process.env
    .PEERBORNE_RELEASE_RELAY_MULTIADDR
    ? join(temporary, 'public-session-finished-at')
    : undefined,
  PEERBORNE_NOTE_LIVE_FAULTS: process.env.PEERBORNE_RELEASE_RELAY_MULTIADDR
    ? process.env.PEERBORNE_NOTE_LIVE_FAULTS
    : '1',
  PEERBORNE_SSR_ORIGINS: JSON.stringify({
    'Next.js': `http://127.0.0.1:${ports.nextjs}/`,
    'TanStack Start': `http://127.0.0.1:${ports.tanstack}/`,
  }),
};
const started = Date.now();
try {
  const child = spawn(
    process.execPath,
    [
      join(root, 'node_modules/@playwright/test/cli.js'),
      'test',
      '--config=verification/release/playwright.config.mjs',
      ...process.argv.slice(3),
    ],
    { cwd: root, env, stdio: 'inherit' },
  );
  const [code] = await once(child, 'exit');
  await assertInstalledArtifacts(consumer, artifacts);
  await auditConsumer(consumer, 'final-application-audit', false);
  await writeFile(
    join(reportDirectory, 'run.json'),
    `${JSON.stringify(
      {
        status: code === 0 ? 'passed' : 'failed',
        node: process.version,
        durationMs: Date.now() - started,
        browsers: (env.PEERBORNE_RELEASE_BROWSERS ?? 'chromium').split(','),
        selection: process.argv.slice(3),
        packageLockSha256: createHash('sha256')
          .update(await readFile(join(consumer, 'package-lock.json')))
          .digest('hex'),
        relay: env.PEERBORNE_RELEASE_RELAY_MULTIADDR
          ? 'configured external relay'
          : 'local relay',
        profile:
          'installed tarballs, separate browser processes and persistent profiles',
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = code ?? 1;
} finally {
  await rm(temporary, { recursive: true, force: true });
}
