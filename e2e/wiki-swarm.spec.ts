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

test('wiki-swarm creates an article after Search fails to open it', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  const documentId = `e2e-create-${Date.now()}`;
  const encodedId = encodeURIComponent(documentId);

  await page.goto('/');
  await page.getByRole('textbox', { name: 'Document ID' }).fill(documentId);
  await page.getByRole('link', { name: 'Search' }).click();
  await expect(page.getByRole('alert')).toContainText(
    'Unable to open this article',
    { timeout: 30_000 },
  );

  await page.getByRole('link', { name: 'Create article' }).click();
  await expect(
    page.getByRole('textbox', { name: 'Article title' }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(page).toHaveURL(`/document/${encodedId}`);
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(errors, 'article creation errors').toEqual([]);
});

test('wiki-swarm keeps every title keystroke and reloads the saved article', async ({
  page,
}) => {
  const errors: string[] = [];
  const logs: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => logs.push(message.text()));
  const documentId = `e2e-title-${Date.now()}`;
  const title = page.getByRole('textbox', { name: 'Article title' });
  const body = page.locator('[contenteditable="true"]');

  await page.goto(`/create/${documentId}`);
  await expect(title).toBeVisible({ timeout: 30_000 });
  await expect(page).toHaveURL(`/document/${documentId}`);
  await title.click();
  await title.pressSequentially('Hello wiki', { delay: 80 });
  await title.press('Home');
  await title.pressSequentially('Say ', { delay: 20 });
  await body.click();
  await page.keyboard.type('Body ZQXJ marker', { delay: 20 });
  await expect(title).toHaveValue('Say Hello wiki');
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');

  await page.reload();
  await expect(title).toHaveValue('Say Hello wiki', { timeout: 30_000 });
  await expect(body).toContainText('Body ZQXJ marker');
  expect(
    logs.filter((text) => text.includes('Hello wiki') || text.includes('ZQXJ')),
    'article text in the console',
  ).toEqual([]);
  expect(errors, 'article errors').toEqual([]);
});

test('wiki-swarm reopens an article in the same tab and refuses to create it again', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  const documentId = `e2e-reopen-${Date.now()}`;
  const field = page.getByRole('textbox', { name: 'Document ID' });
  const title = page.getByRole('textbox', { name: 'Article title' });
  const exists = `An article with the ID “${documentId}” already exists in this browser. Use Search to open it instead of creating it again.`;
  const writers = async () => {
    await page.getByRole('button', { name: 'Refresh' }).click();
    const acl = page.locator('.border.rounded');
    await expect(acl).toContainText('Writers (1)');
    return acl.innerText();
  };

  await page.goto('/');
  await field.fill(documentId);
  await page.getByRole('link', { name: 'Create article' }).click();
  await expect(title).toBeVisible({ timeout: 30_000 });
  await title.fill('Original title');
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  const founder = await writers();

  await field.fill(`${documentId}-missing`);
  await page.getByRole('link', { name: 'Search' }).click();
  await expect(page.getByRole('alert')).toContainText(
    'Unable to open this article',
    { timeout: 30_000 },
  );
  await field.fill(documentId);
  await page.getByRole('link', { name: 'Search' }).click();
  await expect(title).toHaveValue('Original title');
  await expect(page.getByRole('alert')).toHaveCount(0);

  await page.getByRole('link', { name: 'Create article' }).click();
  await expect(page.getByRole('alert')).toHaveText(exists);
  await expect(page).toHaveURL(`/document/${documentId}`);
  await expect(title).toHaveValue('Original title');

  await page.reload();
  await expect(title).toHaveValue('Original title', { timeout: 30_000 });
  expect(await writers()).toBe(founder);
  await field.fill(documentId);
  await page.getByRole('link', { name: 'Create article' }).click();
  await expect(page.getByRole('alert')).toHaveText(exists);

  await page.goto(`/create/${documentId}`);
  await expect(page.getByRole('alert')).toHaveText(
    'An article with this ID already exists in this browser. Use Search to open it.',
    { timeout: 30_000 },
  );
  const signingKeyExtractable = await page.evaluate(async () => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('peerborne-wiki-swarm', 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      const identity = await new Promise<{ signing: CryptoKeyPair }>(
        (resolve, reject) => {
          const request = database
            .transaction('identity', 'readonly')
            .objectStore('identity')
            .get('current');
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        },
      );
      return identity.signing.privateKey.extractable;
    } finally {
      database.close();
    }
  });
  expect(signingKeyExtractable).toBe(false);
  expect(errors, 'article errors').toEqual([]);
});
