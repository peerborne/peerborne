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

test('wiki-swarm Search routes an encoded article ID to the article view', async ({
  page,
}) => {
  const documentId = `e2e/${Date.now()}?draft#1`;
  const encodedId = encodeURIComponent(documentId);
  const searchLink = page.getByRole('link', { name: 'Search' });
  const createLink = page.getByRole('link', { name: 'Create article' });

  await page.goto('/');
  await page.getByRole('textbox', { name: 'Document ID' }).fill(documentId);
  await expect(createLink).toHaveAttribute('href', `/create/${encodedId}`);
  await expect(searchLink).toHaveAttribute('href', `/document/${encodedId}`);

  await searchLink.click();
  await expect(page).toHaveURL(`/document/${encodedId}`);
  await expect(page.getByText('Welcome to WikiSwarm!')).toBeHidden();
  await expect(page.getByRole('alert')).toContainText(
    'Unable to open this article',
    { timeout: 30_000 },
  );
});
