import { chromium, expect, test } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

test('another tab cannot write until the active vault tab closes', async ({
  page,
  context,
}) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await expect(
    page.getByRole('button', { name: 'New Secret', exact: true }),
  ).toBeEnabled();
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  const other = await context.newPage();
  await other.goto('/login');
  await other.getByRole('button', { name: 'Login', exact: true }).click();
  await expect(other.getByRole('alert')).toHaveText(
    'The password manager is open in another tab',
  );
  await expect(
    other.getByRole('button', { name: 'Create a vault', exact: true }),
  ).toHaveCount(0);
  await page.close();
  await other.getByRole('button', { name: 'Login', exact: true }).click();
  await other
    .getByRole('button', { name: 'Open vault 1', exact: true })
    .click();
  await expect(
    other.getByRole('button', { name: 'New Secret', exact: true }),
  ).toBeEnabled();
});

test('reopens a saved vault after closing and relaunching Chromium', async ({
  baseURL,
}) => {
  const profile = await mkdtemp(join(tmpdir(), 'peerborne-vault-test-'));
  let context = await chromium.launchPersistentContext(profile, { baseURL });
  try {
    let page = await context.newPage();
    await page.goto('/login');
    await expect(
      page.getByRole('button', { name: 'Login', exact: true }),
    ).toBeEnabled();
    const originalIdentity = await page
      .getByLabel('Public Key', { exact: true })
      .inputValue();
    await page.getByRole('button', { name: 'Login', exact: true }).click();
    await page
      .getByRole('button', { name: 'Create a vault', exact: true })
      .click();
    await page.getByRole('button', { name: 'New Secret', exact: true }).click();
    await page.getByPlaceholder('Enter a name here...').fill('Restart fixture');
    await page
      .getByPlaceholder('Enter a secret here...')
      .fill('persistent fixture value');
    await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
    await context.close();
    context = await chromium.launchPersistentContext(profile, { baseURL });
    page = await context.newPage();
    await page.goto('/login');
    await expect(page.getByLabel('Public Key', { exact: true })).toHaveValue(
      originalIdentity,
    );
    await page.getByRole('button', { name: 'Login', exact: true }).click();
    await page
      .getByRole('button', { name: 'Open vault 1', exact: true })
      .click();
    await page.getByText('Restart fixture', { exact: true }).click();
    await expect(page.getByPlaceholder('Enter a secret here...')).toHaveValue(
      'persistent fixture value',
    );
  } finally {
    await context.close();
    await rm(profile, { recursive: true, force: true });
  }
});

test('rejects a damaged saved vault without replacing it', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await expect(
    page.getByRole('button', { name: 'New Secret', exact: true }),
  ).toBeEnabled();
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  await page.evaluate(async () => {
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('peerborne-password-manager', 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = database.transaction('documents', 'readwrite');
        const objects = tx.objectStore('documents');
        const request = objects.openCursor();
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
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText(
    'Could not open this vault. Your saved data was left unchanged.',
  );
  await expect(
    page.getByRole('button', { name: 'New Secret', exact: true }),
  ).toHaveCount(0);
  await page
    .getByRole('button', { name: 'Choose another vault', exact: true })
    .click();
  await expect(
    page.getByRole('button', { name: 'Open vault 1', exact: true }),
  ).toBeVisible();
});

test('reports failed writes and saves the current edits after retry', async ({
  page,
}) => {
  await page.addInitScript(() => {
    const original = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (
      ...args: Parameters<IDBObjectStore['put']>
    ) {
      if (
        this.name === 'documents' &&
        (window as unknown as { failVaultWrites?: boolean }).failVaultWrites
      ) {
        this.transaction.abort();
        throw new DOMException('Injected write failure', 'QuotaExceededError');
      }
      return Reflect.apply(original, this, args);
    };
  });
  await page.goto('/login');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await page.getByPlaceholder('Enter a name here...').fill('Write fixture');
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  await page.evaluate(() => {
    (window as unknown as { failVaultWrites?: boolean }).failVaultWrites = true;
  });
  await page
    .getByPlaceholder('Enter a secret here...')
    .fill('retry fixture value');
  await expect(page.getByRole('status')).toHaveText(
    'Vault changes have not been saved.',
  );
  await expect(page.getByRole('alert')).toContainText(
    'Keep this tab open and retry.',
  );
  await page.evaluate(() => {
    (window as unknown as { failVaultWrites?: boolean }).failVaultWrites =
      false;
  });
  await page.getByRole('button', { name: 'Retry saving', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  await page.reload();
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await page.getByText('Write fixture', { exact: true }).click();
  await expect(page.getByPlaceholder('Enter a secret here...')).toHaveValue(
    'retry fixture value',
  );
});

test('restores the same vault and keys after reload, including another saved edit', async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/login');
  const identity = page.getByLabel('Public Key', { exact: true });
  await expect(identity).not.toHaveValue('');
  const originalIdentity = await identity.inputValue();
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  const name = page
    .getByPlaceholder('Enter a name here...')
    .filter({ visible: true });
  const value = page
    .getByPlaceholder('Enter a secret here...')
    .filter({ visible: true });
  await name.fill('Reload fixture');
  await value.fill('saved fixture value');
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  await page.reload();
  await expect(identity).toHaveValue(originalIdentity);
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await page.getByText('Reload fixture', { exact: true }).click();
  await expect(value).toHaveValue('saved fixture value');
  await value.fill('edited after reload');
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  await page.reload();
  await expect(identity).toHaveValue(originalIdentity);
  await context.setOffline(true);
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await page.getByText('Reload fixture', { exact: true }).click();
  await expect(value).toHaveValue('edited after reload');
  expect(errors, 'reload errors').toEqual([]);
});

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

test('redirects anonymous visits to protected routes back to login', async ({
  page,
}) => {
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
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();

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

test('sets a new member as a reader and then promotes them to editor', async ({
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
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();

  await page.getByRole('button', { name: 'New Secret' }).click();
  await page.getByText(/^Unnamed Secret/).click();
  await expect(
    page
      .getByRole('row')
      .filter({ has: page.getByRole('cell', { name: 'Editor', exact: true }) }),
  ).toHaveCount(1, { timeout: 30_000 });

  const { memberKey, memberKemKey } = await page.evaluate(async () => {
    const exportRaw = async (publicKey: CryptoKey) => {
      const raw = new Uint8Array(
        await crypto.subtle.exportKey('raw', publicKey),
      );
      return btoa(String.fromCharCode(...raw));
    };
    const signing = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    );
    const kem = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    return {
      memberKey: await exportRaw(signing.publicKey),
      memberKemKey: await exportRaw(kem.publicKey),
    };
  });
  const memberRows = page
    .getByRole('row')
    .filter({ has: page.getByRole('button', { name: 'Remove' }) });
  const memberRow = memberRows.filter({
    has: page.getByRole('cell', { name: memberKey, exact: true }),
  });

  const truncatedKemKey = btoa(atob(memberKemKey).slice(0, 64));
  const missingKemMessage =
    "Enter the new member's KEM public key from their Settings page.";
  const invalidBase64Message = 'The member KEM public key is not valid base64.';
  const invalidShapeMessage =
    'The member KEM public key must be a 65-byte uncompressed P-256 ' +
    'public key starting with 0x04.';

  await page.getByPlaceholder('Public Key to add').fill(memberKey);

  await page.getByRole('combobox').selectOption('rw');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect.poll(() => dialogs).toEqual([missingKemMessage]);
  await expect(memberRows).toHaveCount(1);
  await expect(memberRow).toHaveCount(0);

  await page.getByRole('combobox').selectOption('r');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs)
    .toEqual([missingKemMessage, missingKemMessage]);
  await expect(memberRows).toHaveCount(1);
  await expect(memberRow).toHaveCount(0);

  await expect(
    page.getByLabel('Member signing public key', { exact: true }),
  ).toHaveValue(memberKey);
  await page
    .getByLabel('Member KEM public key', { exact: true })
    .fill('not-base64!');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs)
    .toEqual([missingKemMessage, missingKemMessage, invalidBase64Message]);
  await expect(memberRows).toHaveCount(1);
  await expect(memberRow).toHaveCount(0);

  await page
    .getByLabel('Member KEM public key', { exact: true })
    .fill(truncatedKemKey);
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs)
    .toEqual([
      missingKemMessage,
      missingKemMessage,
      invalidBase64Message,
      invalidShapeMessage,
    ]);
  await expect(memberRows).toHaveCount(1);
  await expect(memberRow).toHaveCount(0);

  await page
    .getByLabel('Member KEM public key', { exact: true })
    .fill(memberKemKey);
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect(
    memberRow.getByRole('cell', { name: 'Reader', exact: true }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(memberRows).toHaveCount(2);

  await page.getByLabel('Member KEM public key', { exact: true }).fill('');
  await page.getByRole('combobox').selectOption('rw');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect(
    memberRow.getByRole('cell', { name: 'Editor', exact: true }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(memberRow).toHaveCount(1);
  await expect(memberRows).toHaveCount(2);

  expect(dialogs, 'permission update dialogs').toEqual([
    missingKemMessage,
    missingKemMessage,
    invalidBase64Message,
    invalidShapeMessage,
  ]);
  expect(errors, 'permission update errors').toEqual([]);
});

test('creates a vault and preserves a secret across selection and navigation', async ({
  page,
}) => {
  await page.goto('/login');
  await expect(page.getByLabel('Public Key', { exact: true })).not.toHaveValue(
    '',
  );
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  const name = page
    .getByPlaceholder('Enter a name here...')
    .filter({ visible: true });
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

test('requires a KEM public key before adding a new reader and retries existing readers with one', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  let addedReaders = 0;
  page.on('console', (message) => {
    if (message.text() === 'Added reader') addedReaders += 1;
  });
  const dialogs: string[] = [];
  page.on('dialog', (dialog) => {
    dialogs.push(dialog.message());
    void dialog.accept();
  });

  await page.goto('/login');
  await expect(page.getByLabel('Public Key', { exact: true })).not.toHaveValue(
    '',
  );
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await page.getByText(/^Unnamed Secret/).click();
  await expect(
    page.getByRole('cell', { name: 'Editor', exact: true }),
  ).toHaveCount(1, { timeout: 30_000 });

  const { identityKey, kemKey, otherKemKey } = await page.evaluate(async () => {
    const encode = (bytes: ArrayBuffer) =>
      btoa(String.fromCharCode(...new Uint8Array(bytes)));
    const identity = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    );
    const generateKem = () =>
      crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
        'deriveBits',
      ]);
    const kem = await generateKem();
    const otherKem = await generateKem();
    return {
      identityKey: encode(
        await crypto.subtle.exportKey('raw', identity.publicKey),
      ),
      kemKey: encode(await crypto.subtle.exportKey('raw', kem.publicKey)),
      otherKemKey: encode(
        await crypto.subtle.exportKey('raw', otherKem.publicKey),
      ),
    };
  });

  const memberRows = page
    .getByRole('row')
    .filter({ has: page.getByRole('button', { name: 'Remove' }) });
  await page.getByPlaceholder('Public Key to add').fill(identityKey);
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs)
    .toEqual([
      "Enter the new member's KEM public key from their Settings page.",
    ]);
  await expect(memberRows).toHaveCount(1);

  await page.getByPlaceholder('Member KEM public key').fill(kemKey);
  await page.getByRole('button', { name: 'Set role' }).click();
  const readerRow = memberRows.filter({
    has: page.getByRole('cell', { name: identityKey, exact: true }),
  });
  await expect(readerRow).toHaveCount(1, { timeout: 30_000 });
  await expect(
    readerRow.getByRole('cell', { name: 'Reader', exact: true }),
  ).toHaveCount(1);
  await expect.poll(() => addedReaders).toBe(1);
  expect(dialogs).toHaveLength(1);

  await page.getByRole('button', { name: 'Set role' }).click();
  await expect.poll(() => addedReaders).toBe(2);
  expect(dialogs).toHaveLength(1);

  await page.getByPlaceholder('Member KEM public key').fill(otherKemKey);
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs.slice(1))
    .toEqual([
      'Unable to update document permissions. Verify both public keys and ' +
        'the membership configuration.',
    ]);
  expect(addedReaders).toBe(2);
  await expect(memberRows).toHaveCount(2);
  await expect(
    readerRow.getByRole('cell', { name: 'Reader', exact: true }),
  ).toHaveCount(1);
  expect(errors, 'reader onboarding errors').toEqual([]);
});

test('leaves a vault that failed to create without saving an empty replacement', async ({
  page,
}) => {
  await page.addInitScript(() => {
    const generateKey = SubtleCrypto.prototype.generateKey;
    const injection = window as unknown as { failNextVaultKey?: boolean };
    SubtleCrypto.prototype.generateKey = function (
      this: SubtleCrypto,
      algorithm: AlgorithmIdentifier,
      ...rest: unknown[]
    ) {
      if (
        injection.failNextVaultKey &&
        (algorithm as Algorithm).name === 'AES-GCM'
      ) {
        injection.failNextVaultKey = false;
        return Promise.reject(new Error('Injected vault key failure'));
      }
      return Reflect.apply(generateKey, this, [algorithm, ...rest]);
    } as SubtleCrypto['generateKey'];
  });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  const createVault = page.getByRole('button', {
    name: 'Create a vault',
    exact: true,
  });
  const leaveVault = page.getByRole('button', {
    name: 'Choose another vault',
    exact: true,
  });
  const newSecret = page.getByRole('button', {
    name: 'New Secret',
    exact: true,
  });

  await page.goto('/login');
  await expect(page.getByLabel('Public Key', { exact: true })).not.toHaveValue(
    '',
  );
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await expect(page).toHaveURL(/\/secrets$/);
  await expect(page.getByRole('button')).toHaveText(['Create a vault']);
  await expect(
    page.getByText(
      'Vaults are saved in this browser. Clearing site data removes access to them.',
      {
        exact: true,
      },
    ),
  ).toBeVisible();

  await page.evaluate(() => {
    (window as unknown as { failNextVaultKey?: boolean }).failNextVaultKey =
      true;
  });
  await createVault.click();
  await expect(page.getByRole('alert')).toHaveText(
    'Could not create this vault. Your saved data was left unchanged. Choose another vault',
  );

  await expect(newSecret).toHaveCount(0);

  await leaveVault.click();
  await expect(page.getByRole('button')).toHaveText(['Create a vault']);
  await createVault.click();
  await expect(newSecret).toBeEnabled();
  await expect(leaveVault).toBeVisible();
  await newSecret.click();
  const name = page
    .getByPlaceholder('Enter a name here...')
    .filter({ visible: true });
  await name.fill('Kept secret');
  await expect(page.getByText('Kept secret', { exact: true })).toBeVisible();
  await expect(leaveVault).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);

  expect(errors, 'vault creation errors').toEqual([]);
});
