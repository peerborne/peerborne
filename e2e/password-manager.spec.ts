import { expect, test } from '@playwright/test';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

test('password-manager loads the packaged Peerborne stack without runtime errors', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.push(`console: ${message.text()}`);
    }
  });

  await page.goto('/');
  await expect(page).toHaveTitle('Peerborne Password Manager');
  await page.waitForTimeout(1_000);
  await expect(page.locator('#root')).not.toBeEmpty();
  await expect(page.getByRole('button', { name: 'Login' })).toBeVisible();
  expect(errors, 'application startup errors').toEqual([]);
});

test('redirects anonymous visits to protected routes back to login', async ({ page }) => {
  for (const path of ['/', '/secrets', '/settings']) {
    await page.goto(path);
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole('button', { name: 'Login' })).toBeVisible();
  }
});

test('keeps the last editor of a secret from being demoted or removed', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  const dialogs: string[] = [];
  page.on('dialog', (dialog) => {
    dialogs.push(dialog.message());
    void dialog.accept();
  });

  await page.goto('/login');
  await expect(page.getByLabel('Public Key', { exact: true })).not.toHaveValue(
    '',
  );
  await page.getByRole('button', { name: 'Login' }).click();
  await expect(page).toHaveURL(/\/secrets$/);

  await page.getByRole('button', { name: 'New Secret' }).click();
  await page.getByText(/^Unnamed Secret/).click();

  const editorRow = page
    .getByRole('row')
    .filter({ has: page.getByRole('cell', { name: 'Editor', exact: true }) });
  await expect(editorRow).toHaveCount(1, { timeout: 30_000 });
  const founderKey = await editorRow.getByRole('cell').first().innerText();
  expect(founderKey).not.toEqual('');

  await page.getByPlaceholder('Public Key to add').fill(founderKey);
  await page.getByRole('combobox').selectOption('r');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs)
    .toEqual([
      'The last editor cannot be demoted or removed. Add another editor first.',
    ]);

  await editorRow.getByRole('button', { name: 'Remove' }).click();
  await expect.poll(() => dialogs.length).toBe(2);
  expect(dialogs[1]).toEqual(dialogs[0]);

  await expect(editorRow).toHaveCount(1);
  await expect(
    page
      .getByRole('row')
      .filter({ has: page.getByRole('button', { name: 'Remove' }) }),
  ).toHaveCount(1);
  expect(errors, 'permission update errors').toEqual([]);
});
