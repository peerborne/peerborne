import { expect, test } from '@playwright/test';

test('wiki-swarm loads Automerge WASM and renders without runtime errors', async ({
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
  await expect(page).toHaveTitle('Peerborne Wiki');
  await page.waitForTimeout(1_000);
  await expect(page.locator('#root')).not.toBeEmpty();
  await expect(page.getByRole('textbox', { name: 'Document ID' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Search' })).toHaveAttribute(
    'href',
    '/document/',
  );
  expect(errors, 'application startup errors').toEqual([]);
});
