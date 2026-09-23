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


test('creates a vault and preserves a secret across selection and navigation', async ({ page }) => {
  await page.goto('/login');
  await expect(page.getByPlaceholder('Enter private key')).not.toHaveValue('');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Create a vault', exact: true }).click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  const name = page.getByPlaceholder('Enter a name here...').filter({ visible: true });
  await expect(name).toBeVisible();
  await name.fill('Smoke secret');
  await expect(page.getByText('Smoke secret', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await page.getByText('Smoke secret', { exact: true }).click();
  await expect(name).toHaveValue('Smoke secret');
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('link', { name: 'Secrets', exact: true }).click();
  await expect(name).toHaveValue('Smoke secret');
});
