import { expect, test, type Page } from '@playwright/test';
import cases from './integration-cases.json';

function captureErrors(page: Page) {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  return errors;
}

for (const view of cases.documents) {
  test(`${view} commits a real local Peerborne document mutation`, async ({
    page,
  }) => {
    const errors = captureErrors(page);
    await page.goto(`/?view=${view}`);
    await page.getByRole('button', { name: 'Start local document' }).click();
    await expect(
      page.getByRole('status', { name: 'Document status' }),
    ).toHaveText('ready', { timeout: 25_000 });
    await page
      .getByRole('textbox', { name: 'Title' })
      .fill(`Saved using ${view}`);
    await page.getByRole('button', { name: 'Save title' }).click();
    await expect(page.getByTestId('document-title')).toHaveText(
      `Saved using ${view}`,
    );
    await expect(page.locator('p[role="alert"]')).not.toBeVisible();
    expect(errors).toEqual([]);
  });
}

for (const view of cases.editors) {
  test(`${view} sends typed editor changes through Peerborne`, async ({
    page,
  }) => {
    const errors = captureErrors(page);
    await page.goto(`/?view=${view}`);
    await page.getByRole('button', { name: 'Start local document' }).click();
    await expect(
      page.getByRole('status', { name: 'Document status' }),
    ).toHaveText('ready', { timeout: 25_000 });
    const editor = page.locator(
      view === 'codemirror'
        ? '.cm-content'
        : view === 'tiptap'
          ? '.tiptap'
          : '.monaco-editor',
    );
    await editor.click();
    await page.keyboard.type(`Typed using ${view}`);
    await page.getByRole('button', { name: 'Flush editor changes' }).click();
    await expect(page.getByTestId('document-title')).toContainText(
      `Typed using ${view}`,
    );
    await expect(page.locator('p[role="alert"]')).not.toBeVisible();
    expect(errors).toEqual([]);
  });
}

for (const { framework, port } of cases.ssr) {
  test(`${framework} renders without browser APIs and starts a local document after hydration`, async ({
    page,
    request,
  }) => {
    const url = `http://127.0.0.1:${port}/`;
    const response = await request.get(url);
    expect(response.ok()).toBe(true);
    expect(await response.text()).toContain('Start local document');
    const errors = captureErrors(page);
    await page.goto(url);
    await page.getByRole('button', { name: 'Start local document' }).click();
    await expect(
      page.getByRole('status', { name: 'Document status' }),
    ).toHaveText('ready', { timeout: 25_000 });
    await page
      .getByRole('textbox', { name: 'Title' })
      .fill(`Saved using ${framework}`);
    await page.getByRole('button', { name: 'Save title' }).click();
    await expect(page.getByTestId('document-title')).toHaveText(
      `Saved using ${framework}`,
    );
    expect(errors).toEqual([]);
  });
}
