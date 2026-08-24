import { expect, test } from '@playwright/test';

test('browser-test loads Automerge and initializes without runtime errors', async ({
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
  await expect(page).toHaveTitle('Peerborne Browser Test');
  await page.waitForTimeout(2_000);
  await expect(page.getByText('Node Addresses:', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Connect' })).toBeVisible();

  // Opening a document is the first point where the example exercises the
  // configured user keys, serializers, crypto, ACL, and keychain providers.
  await page.locator('#open input').fill('/smoke/document');
  await page.locator('#open button').click();
  await expect(page.getByRole('heading', { name: '/smoke/document' })).toBeVisible({
    timeout: 15_000,
  });

  expect(errors, 'application startup/document errors').toEqual([]);
});
