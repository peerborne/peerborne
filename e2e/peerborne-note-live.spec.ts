import { expect, test, type Page } from '@playwright/test';

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

async function createSharedNote(page: Page, role: 'Editor' | 'Reader') {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Create a note' })).toBeEnabled();
  await page.getByRole('button', { name: 'Create a note' }).click();
  const editor = page.getByRole('textbox', { name: 'Note text' });
  await expect(editor).toBeEditable();
  const initial = `Founder ${crypto.randomUUID()}`;
  await editor.fill(initial);
  await expect(page.getByText('Applied locally', { exact: true })).toBeVisible();
  if (role === 'Reader') {
    await page.getByRole('radio', { name: /Reader/u }).check();
  }
  await page.getByRole('button', { name: 'Create 15-minute link' }).click();
  const link = page.getByRole('textbox', { name: 'One-person bearer link' });
  await expect(link).toBeVisible();
  await expect(page.getByText(`Grants ${role === 'Reader' ? 'read-only' : 'editing'} access.`)).toBeVisible();
  return { editor, initial, invitationUrl: await link.inputValue() };
}

test('deployed editor invitation converges fresh edits in both directions', async ({
  browser,
}) => {
  const founderContext = await browser.newContext();
  const recipientContext = await browser.newContext();
  const founder = await founderContext.newPage();
  const recipient = await recipientContext.newPage();
  const founderErrors = failOnRuntimeErrors(founder);
  const recipientErrors = failOnRuntimeErrors(recipient);

  try {
    const shared = await createSharedNote(founder, 'Editor');
    expect(new URL(shared.invitationUrl).hash).toMatch(/^#invite=/u);

    await recipient.goto(shared.invitationUrl);
    await expect.poll(() => new URL(recipient.url()).hash).toBe('');
    await expect(recipient.getByText('Can edit', { exact: true })).toBeVisible();
    await recipient.getByRole('button', { name: 'Accept invitation' }).click();
    const recipientEditor = recipient.getByRole('textbox', { name: 'Note text' });
    await expect(recipientEditor).toHaveValue(shared.initial);

    const recipientEdit = `Recipient ${crypto.randomUUID()}`;
    await recipientEditor.fill(recipientEdit);
    await expect(recipient.getByText('Applied locally', { exact: true })).toBeVisible();
    await expect(shared.editor).toHaveValue(recipientEdit);

    const founderEdit = `Founder again ${crypto.randomUUID()}`;
    await shared.editor.fill(founderEdit);
    await expect(founder.getByText('Applied locally', { exact: true })).toBeVisible();
    await expect(recipientEditor).toHaveValue(founderEdit);

    expect(founderErrors, 'founder runtime errors').toEqual([]);
    expect(recipientErrors, 'recipient runtime errors').toEqual([]);
  } finally {
    await recipientContext.close();
    await founderContext.close();
  }
});

test('deployed reader invitation stays read-only and receives later edits', async ({
  browser,
}) => {
  const founderContext = await browser.newContext();
  const recipientContext = await browser.newContext();
  const founder = await founderContext.newPage();
  const recipient = await recipientContext.newPage();
  const founderErrors = failOnRuntimeErrors(founder);
  const recipientErrors = failOnRuntimeErrors(recipient);

  try {
    const shared = await createSharedNote(founder, 'Reader');
    await recipient.goto(shared.invitationUrl);
    await expect.poll(() => new URL(recipient.url()).hash).toBe('');
    await expect(recipient.getByText('Read only', { exact: true })).toBeVisible();
    await recipient.getByRole('button', { name: 'Accept invitation' }).click();
    const recipientEditor = recipient.getByRole('textbox', { name: 'Note text' });
    await expect(recipientEditor).toHaveValue(shared.initial);
    await expect(recipientEditor).not.toBeEditable();

    const laterEdit = `Founder update ${crypto.randomUUID()}`;
    await shared.editor.fill(laterEdit);
    await expect(founder.getByText('Applied locally', { exact: true })).toBeVisible();
    await expect(recipientEditor).toHaveValue(laterEdit);

    expect(founderErrors, 'founder runtime errors').toEqual([]);
    expect(recipientErrors, 'recipient runtime errors').toEqual([]);
  } finally {
    await recipientContext.close();
    await founderContext.close();
  }
});
