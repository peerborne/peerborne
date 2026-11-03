import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const { consumer, ports, temporary } = JSON.parse(
  await readFile(process.env.PEERBORNE_RELEASE_CONFIGURATION, 'utf8'),
);
const children = new Set();
let relay;
let stopping = false;
let ready = false;
let commands = Promise.resolve();
const defaultReservationLimit = process.env.RELAY_MAX_RESERVATIONS ?? '128';
let reservationLimit = defaultReservationLimit;
function start(command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: consumer,
    env: process.env,
    stdio: 'inherit',
    detached: process.platform !== 'win32',
    ...options,
  });
  children.add(child);
  child.once('error', () => {
    void stop(1);
  });
  child.once('exit', () => children.delete(child));
  return child;
}
function signal(child, name) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    if (process.platform === 'win32') child.kill(name);
    else process.kill(-child.pid, name);
  } catch {}
}
async function stopChild(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null)
    return;
  const exited = once(child, 'exit').catch(() => undefined);
  signal(child, 'SIGTERM');
  const force = setTimeout(() => signal(child, 'SIGKILL'), 3000);
  await exited;
  clearTimeout(force);
}
async function stop(code) {
  if (stopping) return;
  stopping = true;
  await Promise.allSettled([...children].map(stopChild));
  process.exit(code);
}
process.once('SIGINT', () => {
  void stop(0);
});
process.once('SIGTERM', () => {
  void stop(0);
});

async function startRelay() {
  if (relay && relay.exitCode === null && relay.signalCode === null) return;
  relay = start(process.execPath, [join(root, 'relay-server/dist/index.js')], {
    cwd: temporary,
    env: {
      ...process.env,
      WS_LISTEN: `/ip4/127.0.0.1/tcp/${ports.relayWebSocket}/ws`,
      TCP_LISTEN: `/ip4/127.0.0.1/tcp/${ports.relayTcp}`,
      READINESS_PORT: String(ports.relayReadiness),
      RELAY_IDENTITY_KEY_PATH: join(temporary, 'relay-identity.key'),
      RELAY_MAX_RESERVATIONS: reservationLimit,
    },
  });
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (relay.exitCode !== null || relay.signalCode !== null)
      throw new Error('Release relay exited before readiness');
    try {
      const response = await fetch(
        `http://127.0.0.1:${ports.relayReadiness}/readyz`,
        { signal: AbortSignal.timeout(1000) },
      );
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Release relay did not become ready');
}
async function run(command, args, options) {
  const child = start(command, args, options);
  const [code] = await once(child, 'exit');
  if (code !== 0) throw new Error('Release consumer build failed');
}

try {
  await startRelay();
  const { wsMultiaddr } = JSON.parse(
    await readFile(join(temporary, 'relay-info.json'), 'utf8'),
  );
  if (typeof wsMultiaddr !== 'string')
    throw new Error('Release relay address is unavailable');
  const note = join(consumer, 'applications/peerborne-note');
  const integrations = join(consumer, 'applications/integrations');
  const nextjs = join(consumer, 'applications/nextjs');
  const tanstack = join(consumer, 'applications/tanstack-start');
  const vite = join(consumer, 'node_modules/vite/bin/vite.js');
  const next = join(consumer, 'node_modules/next/dist/bin/next');
  const tsc = join(consumer, 'node_modules/typescript/bin/tsc');
  const noteEnv = {
    ...process.env,
    VITE_PEERBORNE_RELAY_MULTIADDR:
      process.env.PEERBORNE_RELEASE_RELAY_MULTIADDR ?? wsMultiaddr,
  };
  await run(process.execPath, [tsc, '--noEmit'], { cwd: note, env: noteEnv });
  await run(process.execPath, [vite, 'build'], { cwd: note, env: noteEnv });
  await run(process.execPath, [tsc, '--noEmit'], { cwd: integrations });
  await run(process.execPath, [vite, 'build'], { cwd: integrations });
  await run(process.execPath, [next, 'build', '--webpack'], { cwd: nextjs });
  await run(process.execPath, [vite, 'build'], { cwd: tanstack });
  await run(process.execPath, [tsc, '--noEmit'], { cwd: tanstack });
  start(
    process.execPath,
    [
      vite,
      'preview',
      '--host',
      '127.0.0.1',
      '--strictPort',
      '--port',
      String(ports.note),
    ],
    { cwd: note, env: noteEnv },
  );
  start(
    process.execPath,
    [
      vite,
      'preview',
      '--host',
      '127.0.0.1',
      '--strictPort',
      '--port',
      String(ports.integrations),
    ],
    { cwd: integrations },
  );
  start(
    process.execPath,
    [next, 'start', '--hostname', '127.0.0.1', '--port', String(ports.nextjs)],
    { cwd: nextjs },
  );
  start(process.execPath, [join(tanstack, 'serve.mjs')], {
    cwd: tanstack,
    env: { ...process.env, PORT: String(ports.tanstack) },
  });
  for (const port of [
    ports.note,
    ports.integrations,
    ports.nextjs,
    ports.tanstack,
  ]) {
    const deadline = Date.now() + 30_000;
    let available = false;
    while (Date.now() < deadline) {
      try {
        if (
          (
            await fetch(`http://127.0.0.1:${port}/`, {
              signal: AbortSignal.timeout(1000),
            })
          ).ok
        ) {
          available = true;
          break;
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (!available)
      throw new Error('Installed release application did not become ready');
  }
  ready = true;
  createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/ready') {
      response.writeHead(ready ? 200 : 503).end();
      return;
    }
    const action = request.method === 'POST' && request.url;
    if (
      ![
        '/relay/stop',
        '/relay/start',
        '/relay/reservations/one',
        '/relay/reservations/reset',
      ].includes(action)
    ) {
      response.writeHead(404).end();
      return;
    }
    commands = commands.then(async () => {
      try {
        if (action === '/relay/stop') await stopChild(relay);
        else if (action === '/relay/start') await startRelay();
        else {
          reservationLimit =
            action === '/relay/reservations/one'
              ? '1'
              : defaultReservationLimit;
          await stopChild(relay);
          await startRelay();
        }
        response.writeHead(200).end();
      } catch {
        response.writeHead(500).end();
      }
    });
  }).listen(ports.control, '127.0.0.1');
} catch {
  console.error('Installed release browser setup failed');
  await stop(1);
}
