import { chromium, expect, test, type Page } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

let lastTestFinishedAt: number | undefined;

test.beforeEach(async () => {
  if (lastTestFinishedAt === undefined) return;
  // Separate independent sessions to respect the public demo relay's burst cap.
  const cooldown = Math.max(0, 25_000 - (Date.now() - lastTestFinishedAt));
  if (cooldown > 0)
    await new Promise((resolve) => setTimeout(resolve, cooldown));
});

test.afterEach(() => {
  lastTestFinishedAt = Date.now();
});

function failOnRuntimeErrors(page: Page, errors: string[] = []): string[] {
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
  await expect(
    page.getByRole('button', { name: 'Create a note' }),
  ).toBeEnabled();
  await page.getByRole('button', { name: 'Create a note' }).click();
  const editor = page.getByRole('textbox', { name: 'Note text' });
  await expect(editor).toBeEditable();
  const initial = `Founder ${crypto.randomUUID()}`;
  await editor.fill(initial);
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
  if (role === 'Reader') {
    await page.getByRole('radio', { name: /Reader/u }).check();
  }
  await page.getByRole('button', { name: 'Create 15-minute link' }).click();
  const link = page.getByRole('textbox', { name: 'Invitation link' });
  await expect(link).toBeVisible();
  await expect(
    page.getByText(
      `Grants ${role === 'Reader' ? 'read-only' : 'editing'} access.`,
    ),
  ).toBeVisible();
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
    expect(new URL(shared.invitationUrl).hash.startsWith('#invite=')).toBe(
      true,
    );

    await recipient.goto(shared.invitationUrl);
    await expect.poll(() => new URL(recipient.url()).hash).toBe('');
    await expect(
      recipient.getByText('Can edit', { exact: true }),
    ).toBeVisible();
    await recipient.getByRole('button', { name: 'Accept invitation' }).click();
    const recipientEditor = recipient.getByRole('textbox', {
      name: 'Note text',
    });
    await expect(recipientEditor).toHaveValue(shared.initial);

    const recipientEdit = `Recipient ${crypto.randomUUID()}`;
    await recipientEditor.fill(recipientEdit);
    await expect(
      recipient.getByText('Saved in this browser', { exact: true }),
    ).toBeVisible();
    await expect(shared.editor).toHaveValue(recipientEdit);

    const founderEdit = `Founder again ${crypto.randomUUID()}`;
    await shared.editor.fill(founderEdit);
    await expect(
      founder.getByText('Saved in this browser', { exact: true }),
    ).toBeVisible();
    await expect(recipientEditor).toHaveValue(founderEdit);

    expect(founderErrors, 'founder runtime errors').toEqual([]);
    expect(recipientErrors, 'recipient runtime errors').toEqual([]);
  } finally {
    await recipientContext.close();
    await founderContext.close();
  }
});

test('deployed reader invitation receives edits and remains read-only after a browser restart', async ({
  browser,
}) => {
  const founderContext = await browser.newContext();
  const profile = await mkdtemp(join(tmpdir(), 'peerborne-note-reader-'));
  let recipientContext = await chromium.launchPersistentContext(profile);
  const founder = await founderContext.newPage();
  let recipient = await recipientContext.newPage();
  const founderErrors = failOnRuntimeErrors(founder);
  const recipientErrors = failOnRuntimeErrors(recipient);

  try {
    const shared = await createSharedNote(founder, 'Reader');
    await recipient.goto(shared.invitationUrl);
    await expect.poll(() => new URL(recipient.url()).hash).toBe('');
    await expect(
      recipient.getByText('Read only', { exact: true }),
    ).toBeVisible();
    await recipient.getByRole('button', { name: 'Accept invitation' }).click();
    const recipientEditor = recipient.getByRole('textbox', {
      name: 'Note text',
    });
    await expect(recipientEditor).toHaveValue(shared.initial);
    await expect(recipientEditor).not.toBeEditable();

    const laterEdit = `Founder update ${crypto.randomUUID()}`;
    await shared.editor.fill(laterEdit);
    await expect(
      founder.getByText('Saved in this browser', { exact: true }),
    ).toBeVisible();
    await expect(recipientEditor).toHaveValue(laterEdit);
    await expect(
      recipient.getByText('Saved in this browser', { exact: true }),
    ).toBeVisible();
    await recipientContext.close();
    recipientContext = await chromium.launchPersistentContext(profile);
    recipient = await recipientContext.newPage();
    failOnRuntimeErrors(recipient, recipientErrors);
    await recipient.goto(new URL(shared.invitationUrl).origin);
    await recipient
      .getByRole('button', { name: 'Open saved note 1', exact: true })
      .click();
    await expect(
      recipient.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue(laterEdit);
    await expect(
      recipient.getByRole('textbox', { name: 'Note text' }),
    ).not.toBeEditable();
    await expect(
      recipient.getByRole('button', {
        name: 'Create 15-minute link',
        exact: true,
      }),
    ).toHaveCount(0);

    expect(founderErrors, 'founder runtime errors').toEqual([]);
    expect(recipientErrors, 'recipient runtime errors').toEqual([]);
  } finally {
    await recipientContext.close();
    await rm(profile, { recursive: true, force: true });
    await founderContext.close();
  }
});

test('recovers when the first relay WebSocket never opens, then shares a fresh edit', async ({
  browser,
}) => {
  test.skip(
    process.env.PEERBORNE_NOTE_LIVE_FAULTS !== '1',
    'Opt in to live transport fault injection',
  );
  const founderContext = await browser.newContext();
  const recipientContext = await browser.newContext();
  await founderContext.addInitScript(() => {
    const NativeWebSocket = window.WebSocket;
    let injected = false;
    class PendingWebSocket extends EventTarget {
      binaryType = 'arraybuffer';
      readyState: number = NativeWebSocket.CONNECTING;
      close() {
        this.readyState = NativeWebSocket.CLOSED;
        this.dispatchEvent(new CloseEvent('close'));
      }
    }
    window.WebSocket = new Proxy(NativeWebSocket, {
      construct(target, args) {
        if (
          !injected &&
          new URL(String(args[0])).hostname === 'relay.peerborne.io'
        ) {
          injected = true;
          return new PendingWebSocket();
        }
        return Reflect.construct(target, args);
      },
    });
  });
  const founder = await founderContext.newPage();
  const recipient = await recipientContext.newPage();
  const founderErrors = failOnRuntimeErrors(founder);
  const recipientErrors = failOnRuntimeErrors(recipient);
  let observedRetry = false;
  founder.on('console', (message) => {
    if (
      message.type() === 'info' &&
      message.text().startsWith('Peerborne Note relay retry')
    )
      observedRetry = true;
  });
  try {
    const shared = await createSharedNote(founder, 'Editor');
    expect(observedRetry).toBe(true);
    await recipient.goto(shared.invitationUrl);
    await recipient.getByRole('button', { name: 'Accept invitation' }).click();
    const editor = recipient.getByRole('textbox', { name: 'Note text' });
    await expect(editor).toHaveValue(shared.initial);
    const next = `Recovered ${crypto.randomUUID()}`;
    await editor.fill(next);
    await expect(shared.editor).toHaveValue(next);
    expect(founderErrors).toEqual([]);
    expect(recipientErrors).toEqual([]);
  } finally {
    await recipientContext.close();
    await founderContext.close();
  }
});
