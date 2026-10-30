import {
  chromium,
  expect,
  test,
  type Page,
  type TestInfo,
} from '@playwright/test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

const profileName = process.env.PEERBORNE_VERIFY_PROFILE ?? 'smoke';
if (!['smoke', 'full'].includes(profileName))
  throw new Error('PEERBORNE_VERIFY_PROFILE must be smoke or full');
const full = profileName === 'full';
const strict = process.env.PEERBORNE_VERIFY_STRICT === '1';
const seed = Number(process.env.PEERBORNE_VERIFY_SEED ?? 186);
if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff)
  throw new Error('PEERBORNE_VERIFY_SEED must be a uint32');
const topology = process.env.PEERBORNE_VERIFY_TOPOLOGY ?? 'mesh';
if (!['mesh', 'ring'].includes(topology))
  throw new Error('PEERBORNE_VERIFY_TOPOLOGY must be mesh or ring');
const reported = new Set<string>();
const reportPath = (info: TestInfo, id: string) =>
  resolve(
    info.config.rootDir,
    '../results/reports',
    profileName,
    topology,
    `${id}-report.json`,
  );

test.afterEach(async ({}, info) => {
  if (info.status === info.expectedStatus || reported.has(info.testId)) return;
  const id = info.title.startsWith('cold')
    ? 'cold'
    : info.title.startsWith('IndexedDB')
      ? 'idb'
      : 'webrtc';
  const file = reportPath(info, id);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(
    file,
    JSON.stringify(
      {
        id,
        status: 'failed',
        profile: profileName,
        seed,
        error: 'Playwright workload did not complete; see runner failure.',
      },
      null,
      2,
    ),
  );
});

async function ready(page: Page) {
  let errors = 0;
  page.on('pageerror', () => {
    errors++;
  });
  await page.goto('/');
  await page.waitForFunction(() => Boolean((window as any).technical));
  expect(errors, 'browser startup errors').toBe(0);
  return () => errors;
}

async function report(info: TestInfo, id: string, result: any) {
  const status = result.gaps.length ? 'gap' : 'passed';
  const file = reportPath(info, id);
  await mkdir(dirname(file), { recursive: true });
  await writeFile(
    file,
    JSON.stringify(
      { id, status, profile: profileName, seed, ...result },
      null,
      2,
    ),
  );
  await info.attach(`${id}-report.json`, {
    path: file,
    contentType: 'application/json',
  });
  reported.add(info.testId);
  for (const gap of result.gaps)
    info.annotations.push({ type: 'capability-gap', description: gap });
  if (strict)
    expect(result.gaps, 'strict acceptance forbids unmet guarantees').toEqual(
      [],
    );
}

test('IndexedDB paste and explicit transactional batching', async ({
  page,
}, info) => {
  const errorCount = await ready(page);
  const result = await page.evaluate(
    (options) => (window as any).technical.batching(options),
    { full },
  );
  expect(errorCount(), 'runtime errors').toBe(0);
  await report(info, 'idb', result);
});

test('webrtc concurrent encrypted document convergence', async ({
  page,
}, info) => {
  const errorCount = await ready(page);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Performance.enable');
  const before = await cdp.send('Performance.getMetrics');
  let result;
  try {
    result = await page.evaluate(
      (options) => (window as any).technical.topology(options),
      { full, topology },
    );
  } catch (error) {
    const file = reportPath(info, 'webrtc');
    await mkdir(dirname(file), { recursive: true });
    await writeFile(
      file,
      JSON.stringify(
        {
          id: 'webrtc',
          status: 'failed',
          profile: profileName,
          seed,
          metrics: await page.evaluate(() => (window as any).technicalProgress),
          error: 'RTC workload did not complete; see Playwright failure.',
        },
        null,
        2,
      ),
    );
    await info.attach('webrtc-report.json', {
      path: file,
      contentType: 'application/json',
    });
    reported.add(info.testId);
    throw error;
  }
  const after = await cdp.send('Performance.getMetrics');
  const value = (metrics: typeof after.metrics, name: string) =>
    metrics.find((metric) => metric.name === name)?.value;
  const beforeThread = value(before.metrics, 'ThreadTime');
  const afterThread = value(after.metrics, 'ThreadTime');
  result.metrics.browserMainThreadCPUms =
    beforeThread !== undefined && afterThread !== undefined
      ? (afterThread - beforeThread) * 1000
      : null;
  result.metrics.browserTaskDurationMs =
    ((value(after.metrics, 'TaskDuration') ?? 0) -
      (value(before.metrics, 'TaskDuration') ?? 0)) *
    1000;
  result.metrics.jsHeapUsedBytes = value(after.metrics, 'JSHeapUsedSize');
  expect(errorCount(), 'runtime errors').toBe(0);
  await report(info, 'webrtc', result);
});

test('cold browser process reads large encrypted IndexedDB history and measures document TTI', async ({
  baseURL,
}, info) => {
  const profile = await mkdtemp(join(tmpdir(), 'peerborne-cold-'));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      baseURL,
      headless: true,
    });
    const seedPage = await context.newPage();
    await ready(seedPage);
    const fixture = await seedPage.evaluate(
      (options) => (window as any).technical.seedCold(options),
      { full, seed },
    );
    await context.close();
    context = undefined;

    context = await chromium.launchPersistentContext(profile, {
      baseURL,
      headless: true,
    });
    const page = await context.newPage();
    const errors = await ready(page);
    const result = await page.evaluate(() =>
      (window as any).technical.loadCold(),
    );
    result.metrics.fixture = fixture;
    expect(result.metrics.encodedHistoryBytes).toBeGreaterThanOrEqual(
      (full ? 50 : 1) * 1024 * 1024,
    );
    await page.getByRole('button', { name: 'Input probe' }).click();
    await expect(page.locator('#probe')).toHaveText('2');
    expect(errors(), 'cold process runtime errors').toBe(0);
    await report(info, 'cold', result);
  } finally {
    await context?.close();
    await rm(profile, { recursive: true, force: true });
  }
});
