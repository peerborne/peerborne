import { expect, test, type Page } from '@playwright/test';

async function storedIdentityProfile(page: Page) {
  return page.evaluate(async () => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('peerborne-note-identity', 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      const record = await new Promise<{
        privateKey: CryptoKey;
        publicKey: CryptoKey;
      }>((resolve, reject) => {
        const request = database
          .transaction('identities', 'readonly')
          .objectStore('identities')
          .get('current');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const publicBytes = await crypto.subtle.exportKey('raw', record.publicKey);
      const digest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', publicBytes),
      );
      let privateExportRejected = false;
      try {
        await crypto.subtle.exportKey('jwk', record.privateKey);
      } catch {
        privateExportRejected = true;
      }
      return {
        fingerprint: Array.from(digest, (byte) =>
          byte.toString(16).padStart(2, '0'),
        ).join(''),
        privateExtractable: record.privateKey.extractable,
        privateUsages: [...record.privateKey.usages],
        privateExportRejected,
        publicExtractable: record.publicKey.extractable,
        publicUsages: [...record.publicKey.usages],
      };
    } finally {
      database.close();
    }
  });
}

function failOnRuntimeErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.push(`console: ${message.text()}`);
    }
  });
  return errors;
}

test('creates a local note and restores a non-extractable signing identity', async ({
  page,
}) => {
  const errors = failOnRuntimeErrors(page);

  const response = await page.goto('/');
  expect(response).not.toBeNull();
  const headers = response!.headers();
  expect(headers['content-security-policy']).toContain(
    "connect-src 'self' wss://relay.peerborne.io",
  );
  expect(headers['referrer-policy']).toBe('no-referrer');
  expect(headers['x-content-type-options']).toBe('nosniff');
  await expect(page).toHaveTitle('Peerborne Note');
  await expect(page.getByText('Initial release demo', { exact: true })).toBeVisible();
  await expect(page.getByText(/not production-ready/i)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create a note' })).toBeEnabled({
    timeout: 30_000,
  });

  const firstIdentity = await storedIdentityProfile(page);
  expect(firstIdentity).toMatchObject({
    privateExtractable: false,
    privateUsages: ['sign'],
    privateExportRejected: true,
    publicExtractable: true,
    publicUsages: ['verify'],
  });

  await page.getByRole('button', { name: 'Create a note' }).click();
  const editor = page.getByRole('textbox', { name: 'Note text' });
  await expect(editor).toBeEditable({ timeout: 30_000 });
  await editor.fill('Created locally without waiting for a relay.');
  await expect(page.getByText('Applied locally', { exact: true })).toBeVisible();

  await page.reload();
  await expect(page.getByRole('button', { name: 'Create a note' })).toBeEnabled({
    timeout: 30_000,
  });
  const restoredIdentity = await storedIdentityProfile(page);
  expect(restoredIdentity.fingerprint).toBe(firstIdentity.fingerprint);
  expect(restoredIdentity.privateExtractable).toBe(false);
  expect(restoredIdentity.privateExportRejected).toBe(true);
  expect(errors, 'application runtime errors').toEqual([]);
});

test('scrubs an invalid invitation fragment without opening a WebSocket', async ({
  page,
}) => {
  const errors = failOnRuntimeErrors(page);
  const webSockets: string[] = [];
  page.on('websocket', (socket) => webSockets.push(socket.url()));

  await page.goto('/#not-an-invitation');
  await expect.poll(() => new URL(page.url()).hash).toBe('');
  await expect(page.getByRole('alert')).toContainText(
    'This invitation link is malformed',
    { timeout: 30_000 },
  );
  expect(webSockets).toEqual([]);
  expect(errors, 'application runtime errors').toEqual([]);
});

test('blocks a second tab in the same browser profile', async ({ context, page }) => {
  const errors = failOnRuntimeErrors(page);
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Create a note' })).toBeEnabled({
    timeout: 30_000,
  });

  const secondPage = await context.newPage();
  const secondErrors = failOnRuntimeErrors(secondPage);
  await secondPage.goto('/');
  await expect(
    secondPage.getByRole('heading', {
      name: 'Use the existing Peerborne Note tab.',
    }),
  ).toBeVisible({ timeout: 30_000 });

  expect(errors, 'first-tab runtime errors').toEqual([]);
  expect(secondErrors, 'second-tab runtime errors').toEqual([]);
});
