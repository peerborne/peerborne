import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const temporary = await mkdtemp(join(tmpdir(), 'peerborne-note-relay-'));
const children = new Set();
let stopping = false;

function start(command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: root,
    env: process.env,
    stdio: 'inherit',
    detached: process.platform !== 'win32',
    ...options,
  });
  children.add(child);
  child.once('error', () => {
    void stop(1);
  });
  return child;
}

function signal(child, name) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === 'win32') child.kill(name);
    else process.kill(-child.pid, name);
  } catch {}
}

async function stop(code) {
  if (stopping) return;
  stopping = true;
  const exits = [...children]
    .filter((child) => child.exitCode === null && child.signalCode === null)
    .map((child) => once(child, 'exit').catch(() => undefined));
  for (const child of children) signal(child, 'SIGTERM');
  const force = setTimeout(() => {
    for (const child of children) signal(child, 'SIGKILL');
  }, 2000);
  await Promise.allSettled(exits);
  clearTimeout(force);
  await rm(temporary, { recursive: true, force: true });
  process.exit(code);
}

process.once('SIGINT', () => {
  void stop(0);
});
process.once('SIGTERM', () => {
  void stop(0);
});

try {
  const relay = start(
    process.execPath,
    [join(root, 'relay-server/dist/index.js')],
    {
      cwd: temporary,
      env: {
        ...process.env,
        WS_LISTEN: '/ip4/127.0.0.1/tcp/0/ws',
        TCP_LISTEN: '/ip4/127.0.0.1/tcp/0',
        READINESS_PORT: '19200',
        RELAY_IDENTITY_KEY_PATH: join(temporary, 'identity.key'),
      },
    },
  );
  relay.once('exit', () => {
    if (!stopping) void stop(1);
  });
  let address;
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch('http://127.0.0.1:19200/readyz', {
        signal: AbortSignal.timeout(1000),
      });
      if (response.ok) {
        const info = JSON.parse(
          await readFile(join(temporary, 'relay-info.json'), 'utf8'),
        );
        if (
          typeof info.wsMultiaddr === 'string' &&
          /\/tcp\/[1-9]\d*\/ws\/p2p\//u.test(info.wsMultiaddr)
        ) {
          address = info.wsMultiaddr;
          break;
        }
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  if (!address) throw new Error('Local Note relay did not become ready');
  const env = { ...process.env, VITE_PEERBORNE_RELAY_MULTIADDR: address };
  const build = start(
    'yarn',
    ['workspace', '@peerborne/peerborne-note', 'build'],
    { env },
  );
  const [code] = await once(build, 'exit');
  if (code !== 0) throw new Error('Local Note build failed');
  const preview = start(
    'yarn',
    [
      'workspace',
      '@peerborne/peerborne-note',
      'vite',
      'preview',
      '--host',
      '127.0.0.1',
      '--port',
      '4179',
      '--strictPort',
    ],
    { env },
  );
  preview.once('exit', () => {
    if (!stopping) void stop(1);
  });
} catch {
  console.error('Local Note relay setup failed');
  await stop(1);
}
