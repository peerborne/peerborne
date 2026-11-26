import { chromium, expect, test, type Page } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

test('shows an edit as unsaved while signing is still in progress', async ({
  page,
}) => {
  await page.addInitScript(() => {
    const original = SubtleCrypto.prototype.sign;
    const gate = window as unknown as {
      pauseVaultSigning?: boolean;
      releaseVaultSigning?: () => void;
    };
    SubtleCrypto.prototype.sign = async function (
      ...args: Parameters<SubtleCrypto['sign']>
    ) {
      if (gate.pauseVaultSigning)
        await new Promise<void>((resolve) => {
          gate.releaseVaultSigning = resolve;
        });
      return Reflect.apply(original, this, args);
    };
  });
  await page.goto('/login');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await expect(page.getByPlaceholder('Enter a secret here...')).toBeVisible();
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
  await page.evaluate(() => {
    (window as unknown as { pauseVaultSigning?: boolean }).pauseVaultSigning =
      true;
  });
  await page
    .getByPlaceholder('Enter a secret here...')
    .fill('pending signing fixture');
  await expect(page.getByRole('status')).toHaveText('Saving…');
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          typeof (window as unknown as { releaseVaultSigning?: () => void })
            .releaseVaultSigning,
      ),
    )
    .toBe('function');
  await page.evaluate(() => {
    const gate = window as unknown as {
      pauseVaultSigning?: boolean;
      releaseVaultSigning?: () => void;
    };
    gate.pauseVaultSigning = false;
    gate.releaseVaultSigning?.();
  });
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');
});

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

async function openSecretWithStorageFailures(page: Page) {
  await page.addInitScript(() => {
    const failure = window as unknown as {
      failAllWrites?: boolean;
      failCheckpointReads?: boolean;
    };
    for (const method of ['put', 'add'] as const) {
      const original = IDBObjectStore.prototype[method];
      IDBObjectStore.prototype[method] = function (
        this: IDBObjectStore,
        ...args: Parameters<IDBObjectStore['put']>
      ) {
        if (failure.failAllWrites) {
          this.transaction.abort();
          throw new DOMException(
            'Injected quota failure',
            'QuotaExceededError',
          );
        }
        return Reflect.apply(original, this, args);
      };
    }
    const get = IDBObjectStore.prototype.get;
    IDBObjectStore.prototype.get = function (
      ...args: Parameters<IDBObjectStore['get']>
    ) {
      if (failure.failCheckpointReads && this.name === 'documents') {
        this.transaction.abort();
        throw new DOMException('Injected read failure', 'UnknownError');
      }
      return Reflect.apply(get, this, args);
    };
  });
  const status = page.getByRole('status');
  const value = page
    .getByPlaceholder('Enter a secret here...')
    .filter({ visible: true });
  await page.goto('/login');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await page
    .getByPlaceholder('Enter a name here...')
    .filter({ visible: true })
    .fill('Bank');
  await value.fill('old-password');
  await expect(status).toHaveText('Saved in this browser.');
  return {
    status,
    value,
    failStorage: (failures: {
      failAllWrites: boolean;
      failCheckpointReads?: boolean;
    }) =>
      page.evaluate((next) => {
        Object.assign(window, next);
      }, failures),
  };
}

test('discards an edit lost to a write failure and never reports it saved', async ({
  page,
}) => {
  const { status, value, failStorage } =
    await openSecretWithStorageFailures(page);
  const discarded =
    'An edit could not be saved and was discarded. The vault shows its last saved state. Dismiss';

  await failStorage({ failAllWrites: true });
  await value.fill('new-password');
  await expect(page.getByRole('alert')).toHaveText(discarded);
  await expect(status).toHaveText('Vault changes have not been saved.');
  await expect(value).toHaveValue('old-password');

  await failStorage({ failAllWrites: false });
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await expect(page.getByText(/^Unnamed Secret/u)).toBeVisible();
  await expect(page.getByRole('alert')).toHaveText(discarded);
  await expect(status).toHaveText('Vault changes have not been saved.');
  await page.getByText('Bank', { exact: true }).click();
  await expect(value).toHaveValue('old-password');

  await page.reload();
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await page.getByText('Bank', { exact: true }).click();
  await expect(value).toHaveValue('old-password');
});

test('reopens a document retired by a storage failure when the user retries', async ({
  page,
}) => {
  const { status, value, failStorage } =
    await openSecretWithStorageFailures(page);

  await failStorage({ failAllWrites: true, failCheckpointReads: true });
  await value.fill('new-password');
  await expect(status).toHaveText('Vault changes have not been saved.');
  await expect(page.getByRole('alert')).toHaveText(
    'An edit could not be saved, and this tab could not reopen the vault from its last saved state. Retry, or reload the page. Retry saving',
  );

  await failStorage({ failAllWrites: false, failCheckpointReads: false });
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await expect(page.getByText(/^Unnamed Secret/u)).toBeVisible();
  await expect(status).toHaveText('Vault changes have not been saved.');
  await page.getByText('Bank', { exact: true }).click();
  await page.getByRole('button', { name: 'Retry saving', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText(
    'An edit could not be saved and was discarded. The vault shows its last saved state. Dismiss',
  );
  await expect(value).toHaveValue('old-password');
  await expect(status).toHaveText('Vault changes have not been saved.');

  await value.fill('after recovery');
  await expect(value).toHaveValue('after recovery');
  await expect(status).toHaveText('Vault changes have not been saved.');
  await page.getByRole('button', { name: 'Dismiss', exact: true }).click();
  await expect(status).toHaveText('Saved in this browser.');
  await expect(page.getByRole('alert')).toHaveCount(0);

  await page.reload();
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await page.getByText('Bank', { exact: true }).click();
  await expect(value).toHaveValue('after recovery');
});

test('lists a new secret in the vault only after the secret is saved', async ({
  page,
}) => {
  await page.addInitScript(() => {
    const original = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (
      ...args: Parameters<IDBObjectStore['put']>
    ) {
      if (
        this.name === 'documents' &&
        String(args[1]).includes('/passwords/') &&
        (window as unknown as { failSecretWrites?: boolean }).failSecretWrites
      ) {
        this.transaction.abort();
        throw new DOMException('The tab is closing', 'AbortError');
      }
      return Reflect.apply(original, this, args);
    };
  });
  const secrets = page.locator('.list-group-item-action');
  await page.goto('/login');
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page
    .getByRole('button', { name: 'Create a vault', exact: true })
    .click();
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await page
    .getByPlaceholder('Enter a name here...')
    .filter({ visible: true })
    .fill('First secret');
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');

  await page.evaluate(() => {
    (window as unknown as { failSecretWrites?: boolean }).failSecretWrites =
      true;
  });
  await page.getByRole('button', { name: 'New Secret', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText(
    'Could not create the secret. Your saved data was left unchanged.',
  );
  await expect(secrets).toHaveText(['First secret']);
  await expect(page.getByRole('status')).toHaveText('Saved in this browser.');

  await page.reload();
  await page.getByRole('button', { name: 'Login', exact: true }).click();
  await page.getByRole('button', { name: 'Open vault 1', exact: true }).click();
  await expect(secrets).toHaveText(['First secret']);
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

  await page.getByPlaceholder("Existing member's public key").fill(founderKey);
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

test('refuses to add a new member directly', async ({ page }) => {
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
  await expect(page.getByLabel('Member KEM public key')).toHaveCount(0);

  const memberKey = await page.evaluate(async () => {
    const signing = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    );
    const raw = new Uint8Array(
      await crypto.subtle.exportKey('raw', signing.publicKey),
    );
    return btoa(String.fromCharCode(...raw));
  });
  const memberRows = page
    .getByRole('row')
    .filter({ has: page.getByRole('button', { name: 'Remove' }) });
  const newMemberMessage =
    'This example cannot add a new member: a member added directly could ' +
    'never open the secret. Sharing needs an invitation, which this Yjs ' +
    'example does not support.';

  await page.getByPlaceholder("Existing member's public key").fill(memberKey);
  await page.getByRole('combobox').selectOption('r');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect.poll(() => dialogs).toEqual([newMemberMessage]);

  await page.getByRole('combobox').selectOption('rw');
  await page.getByRole('button', { name: 'Set role' }).click();
  await expect
    .poll(() => dialogs)
    .toEqual([newMemberMessage, newMemberMessage]);

  await expect(memberRows).toHaveCount(1);
  await expect(
    memberRows.filter({
      has: page.getByRole('cell', { name: memberKey, exact: true }),
    }),
  ).toHaveCount(0);
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
