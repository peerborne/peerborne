import { expect, test, type TestInfo } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { catalog, options } from '../catalog.mjs';

const settings = options();
const definitions = (await catalog()).filter(
  ({ runtime, driver }) => runtime === 'browser' && !driver,
);
const reported = new Set<string>();
const pathFor = (info: TestInfo, id: string) =>
  resolve(
    info.config.rootDir,
    '../../results/advanced',
    settings.profile,
    `${id}-report.json`,
  );
async function save(info: TestInfo, result: any) {
  const path = pathFor(info, result.id);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(result, null, 2));
  await info.attach(`${result.id}-report.json`, {
    path,
    contentType: 'application/json',
  });
  reported.add(info.testId);
}
test.afterEach(async ({}, info) => {
  if (info.status === info.expectedStatus || reported.has(info.testId)) return;
  const definition = definitions.find(({ id }) => info.title.startsWith(id));
  if (definition)
    await save(info, {
      ...definition,
      ...settings,
      status: 'failed',
      error: 'Browser workload did not complete; see Playwright failure.',
    });
});
for (const definition of definitions) {
  test(`${definition.id}: ${definition.name}`, async ({ page }, info) => {
    let runtimeErrors = 0;
    page.on('pageerror', () => {
      runtimeErrors++;
    });
    await page.addInitScript(() => {
      (window as any).advancedWorkerConstructions = 0;
      const Original = window.Worker;
      window.Worker = class extends Original {
        constructor(scriptURL: string | URL, options?: WorkerOptions) {
          super(scriptURL, options);
          (window as any).advancedWorkerConstructions++;
        }
      };
    });
    await page.goto('/');
    await page.waitForFunction(() => Boolean((window as any).advanced));
    const observation = await page.evaluate(
      ([id, configuration]) => (window as any).advanced.run(id, configuration),
      [definition.id, settings] as const,
    );
    expect(runtimeErrors, 'unexpected browser runtime errors').toBe(0);
    const result = {
      ...definition,
      ...settings,
      ...observation,
      status: observation.gaps.length ? 'gap' : 'passed',
    };
    await save(info, result);
    for (const description of observation.gaps)
      info.annotations.push({ type: 'capability-gap', description });
    if (settings.strict)
      expect(
        observation.gaps,
        'strict acceptance rejects missing guarantees',
      ).toEqual([]);
  });
}
