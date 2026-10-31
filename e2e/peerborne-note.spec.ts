import { chromium, expect, test, type Page } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

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
      const publicBytes = await crypto.subtle.exportKey(
        'raw',
        record.publicKey,
      );
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

test('preserves note text and the signing identity across reloads', async ({
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
  await expect(
    page.getByRole('link', { name: 'About this demo' }),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create a note' })).toBeEnabled(
    {
      timeout: 30_000,
    },
  );

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
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();

  await page.reload();
  await expect(
    page.getByRole('button', { name: 'Open saved note 1', exact: true }),
  ).toBeEnabled({
    timeout: 30_000,
  });
  const restoredIdentity = await storedIdentityProfile(page);
  expect(restoredIdentity.fingerprint).toBe(firstIdentity.fingerprint);
  expect(restoredIdentity.privateExtractable).toBe(false);
  expect(restoredIdentity.privateExportRejected).toBe(true);
  await page
    .getByRole('button', { name: 'Open saved note 1', exact: true })
    .click();
  await expect(editor).toHaveValue(
    'Created locally without waiting for a relay.',
  );
  await editor.fill('Edited after reopening.');
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
  await page.reload();
  await page
    .getByRole('button', { name: 'Open saved note 1', exact: true })
    .click();
  await expect(editor).toHaveValue('Edited after reopening.');
  expect(errors, 'application runtime errors').toEqual([]);
});

test('restores note text after Chromium closes and relaunches with the same profile', async ({
  baseURL,
}) => {
  const profile = await mkdtemp(join(tmpdir(), 'peerborne-note-restart-'));
  let context = await chromium.launchPersistentContext(profile, { baseURL });
  try {
    let page = await context.newPage();
    await page.goto('/');
    await page
      .getByRole('button', { name: 'Create a note', exact: true })
      .click();
    await page
      .getByRole('textbox', { name: 'Note text' })
      .fill('Browser restart fixture');
    await expect(
      page.getByText('Saved in this browser', { exact: true }),
    ).toBeVisible();
    const originalIdentity = await storedIdentityProfile(page);
    await context.close();
    context = await chromium.launchPersistentContext(profile, { baseURL });
    page = await context.newPage();
    await page.goto('/');
    await page
      .getByRole('button', { name: 'Open saved note 1', exact: true })
      .click();
    await expect(page.getByRole('textbox', { name: 'Note text' })).toHaveValue(
      'Browser restart fixture',
    );
    expect((await storedIdentityProfile(page)).fingerprint).toBe(
      originalIdentity.fingerprint,
    );
  } finally {
    await context.close();
    await rm(profile, { recursive: true, force: true });
  }
});

test('retains a damaged saved note and reports that it cannot be opened', async ({
  page,
}) => {
  await page.goto('/');
  await page
    .getByRole('button', { name: 'Create a note', exact: true })
    .click();
  await page
    .getByRole('textbox', { name: 'Note text' })
    .fill('Damaged storage fixture');
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
  await page.evaluate(async () => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('peerborne-note-documents', 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = database.transaction('documents', 'readwrite');
        const request = tx.objectStore('documents').openCursor();
        request.onsuccess = () => {
          const cursor = request.result;
          if (!cursor) return;
          const record = cursor.value;
          new Uint8Array(record.ciphertext)[0] ^= 1;
          cursor.update(record);
        };
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      database.close();
    }
  });
  await page.reload();
  await page
    .getByRole('button', { name: 'Open saved note 1', exact: true })
    .click();
  await expect(page.getByRole('alert')).toHaveText(
    'This saved note could not be opened. Its stored data was left unchanged.',
  );
  await expect(page.getByRole('textbox', { name: 'Note text' })).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Open saved note 1', exact: true }),
  ).toBeVisible();
});

test('reports a failed note write and saves it after retry', async ({
  page,
}) => {
  await page.addInitScript(() => {
    const original = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (
      ...args: Parameters<IDBObjectStore['put']>
    ) {
      if (
        this.name === 'documents' &&
        (window as unknown as { failNoteWrites?: boolean }).failNoteWrites
      ) {
        this.transaction.abort();
        throw new DOMException(
          'Injected note write failure',
          'QuotaExceededError',
        );
      }
      return Reflect.apply(original, this, args);
    };
  });
  await page.goto('/');
  await page
    .getByRole('button', { name: 'Create a note', exact: true })
    .click();
  const editor = page.getByRole('textbox', { name: 'Note text' });
  await expect(editor).toBeVisible();
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
  await page.evaluate(() => {
    (window as unknown as { failNoteWrites?: boolean }).failNoteWrites = true;
  });
  await editor.fill('Retry storage fixture');
  await expect(
    page.getByText('Unsaved changes', { exact: true }),
  ).toBeVisible();
  const retry = page.getByRole('button', { name: 'Retry saving', exact: true });
  await retry.evaluate((button) => {
    button.addEventListener(
      'click',
      () => {
        (window as unknown as { failNoteWrites?: boolean }).failNoteWrites =
          false;
      },
      { capture: true, once: true },
    );
  });
  await retry.click();
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
  await page.reload();
  await page
    .getByRole('button', { name: 'Open saved note 1', exact: true })
    .click();
  await expect(editor).toHaveValue('Retry storage fixture');
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

test('blocks a second tab in the same browser profile', async ({
  context,
  page,
}) => {
  const errors = failOnRuntimeErrors(page);
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Create a note' })).toBeEnabled(
    {
      timeout: 30_000,
    },
  );

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
