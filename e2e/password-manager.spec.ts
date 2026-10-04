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
  await page.getByRole('button', { name: 'Create a vault', exact: true }).click();

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
  await page.getByRole('button', { name: 'Create a vault', exact: true }).click();

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
  const missingKemMessage = "Enter the new member's KEM public key.";
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
