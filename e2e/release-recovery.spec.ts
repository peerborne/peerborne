import {
  chromium,
  firefox,
  webkit,
  expect,
  test,
  type BrowserContext,
  type Page,
} from '@playwright/test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test.use({ trace: 'off', screenshot: 'off', video: 'off' });

async function sharedEditors(founder: Page, recipient: Page) {
  await founder.goto('/');
  await founder.getByRole('button', { name: 'Create a note' }).click();
  await founder
    .getByRole('textbox', { name: 'Note text' })
    .fill('Shared baseline\n');
  await expect(
    founder.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
  await founder.getByRole('button', { name: 'Create 15-minute link' }).click();
  const link = await founder
    .getByRole('textbox', { name: 'Invitation link' })
    .inputValue();
  await recipient.goto(link);
  await recipient.getByRole('button', { name: 'Accept invitation' }).click();
  await expect(
    recipient.getByRole('textbox', { name: 'Note text' }),
  ).toHaveValue('Shared baseline\n');
  await expect(
    recipient.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
}

async function savedEdit(page: Page, value: string) {
  await page.getByRole('textbox', { name: 'Note text' }).fill(value);
  await expect(
    page.getByText('Saved in this browser', { exact: true }),
  ).toBeVisible();
}

async function openSaved(page: Page) {
  await page.goto('/');
  await page
    .getByRole('button', { name: /^Open saved note/u })
    .first()
    .click();
  await expect(page.getByRole('textbox', { name: 'Note text' })).toBeVisible();
}

test('installed packages recover concurrent edits after a relay outage and two browser process restarts', async ({
  request,
  baseURL,
}, testInfo) => {
  test.skip(
    Boolean(process.env.PEERBORNE_RELEASE_RELAY_MULTIADDR),
    'Fault injection requires the owned local relay',
  );
  const { ports } = JSON.parse(
    await readFile(process.env.PEERBORNE_RELEASE_CONFIGURATION!, 'utf8'),
  );
  const control = `http://127.0.0.1:${ports.control}`;
  const temporary = await mkdtemp(
    join(tmpdir(), 'peerborne-release-recovery-'),
  );
  const engine = { chromium, firefox, webkit }[
    testInfo.project.use.browserName ?? 'chromium'
  ];
  const contexts: BrowserContext[] = [];
  const errors: string[] = [];
  const pageFor = async (profile: string) => {
    const context = await engine.launchPersistentContext(
      join(temporary, profile),
      { baseURL },
    );
    contexts.push(context);
    const page = await context.newPage();
    page.on('pageerror', () => errors.push('pageerror'));
    return { context, page };
  };
  let relayStopped = false;
  try {
    let founder = await pageFor('founder');
    let recipient = await pageFor('recipient');
    await sharedEditors(founder.page, recipient.page);
    expect((await request.post(`${control}/relay/stop`)).ok()).toBe(true);
    relayStopped = true;
    await Promise.all([
      savedEdit(founder.page, 'Shared baseline\nFounder while disconnected\n'),
      savedEdit(
        recipient.page,
        'Shared baseline\nRecipient while disconnected\n',
      ),
    ]);
    await founder.context.close();
    await recipient.context.close();
    founder = await pageFor('founder');
    recipient = await pageFor('recipient');
    await Promise.all([openSaved(founder.page), openSaved(recipient.page)]);
    await expect(
      founder.page.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue('Shared baseline\nFounder while disconnected\n');
    await expect(
      recipient.page.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue('Shared baseline\nRecipient while disconnected\n');
    expect((await request.post(`${control}/relay/start`)).ok()).toBe(true);
    relayStopped = false;
    for (const page of [founder.page, recipient.page]) {
      await expect(
        page.getByRole('textbox', { name: 'Note text' }),
      ).toHaveValue(/Founder while disconnected/u);
      await expect(
        page.getByRole('textbox', { name: 'Note text' }),
      ).toHaveValue(/Recipient while disconnected/u);
    }
    const merged = await founder.page
      .getByRole('textbox', { name: 'Note text' })
      .inputValue();
    await expect(
      recipient.page.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue(merged);
    expect(merged.split('Founder while disconnected')).toHaveLength(2);
    expect(merged.split('Recipient while disconnected')).toHaveLength(2);
    await savedEdit(founder.page, `${merged}Fresh edit after recovery\n`);
    await expect(
      recipient.page.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue(`${merged}Fresh edit after recovery\n`);
    expect(errors).toEqual([]);
  } finally {
    if (relayStopped) await request.post(`${control}/relay/start`);
    await Promise.all(
      contexts.map((context) => context.close().catch(() => undefined)),
    );
    await rm(temporary, { recursive: true, force: true });
  }
});

test('installed packages preserve an acknowledged local checkpoint after a Chromium process crash', async ({
  baseURL,
}, testInfo) => {
  test.skip(
    testInfo.project.use.browserName !== 'chromium',
    'Browser.crash is a Chromium CDP operation',
  );
  const temporary = await mkdtemp(join(tmpdir(), 'peerborne-release-crash-'));
  let context: BrowserContext | undefined;
  try {
    context = await chromium.launchPersistentContext(temporary, { baseURL });
    let page = await context.newPage();
    await page.goto('/');
    await page.getByRole('button', { name: 'Create a note' }).click();
    await savedEdit(page, 'Acknowledged before the browser crash');
    const closed = context.waitForEvent('close');
    const protocol = await context.browser()!.newBrowserCDPSession();
    const { processInfo } = await protocol.send('SystemInfo.getProcessInfo');
    const browserProcess = processInfo.find(
      (value) => value.type === 'browser',
    );
    if (
      !browserProcess ||
      !Number.isSafeInteger(browserProcess.id) ||
      browserProcess.id <= 0 ||
      browserProcess.id === process.pid
    )
      throw new Error(
        'The owned Chromium browser process could not be identified',
      );
    process.kill(browserProcess.id, 'SIGKILL');
    await closed;
    context = await chromium.launchPersistentContext(temporary, { baseURL });
    page = await context.newPage();
    await openSaved(page);
    await expect(page.getByRole('textbox', { name: 'Note text' })).toHaveValue(
      'Acknowledged before the browser crash',
    );
    await savedEdit(page, 'Edited successfully after the browser crash');
  } finally {
    await context?.close().catch(() => undefined);
    await rm(temporary, { recursive: true, force: true });
  }
});

test('saved notes catch up when the relay has no reservation slot for the returning peer', async ({
  browser,
  request,
  baseURL,
}) => {
  test.skip(
    Boolean(process.env.PEERBORNE_RELEASE_RELAY_MULTIADDR),
    'Reservation limits require the owned local relay',
  );
  const { ports } = JSON.parse(
    await readFile(process.env.PEERBORNE_RELEASE_CONFIGURATION!, 'utf8'),
  );
  const control = `http://127.0.0.1:${ports.control}`;
  const profile = await mkdtemp(
    join(tmpdir(), 'peerborne-reservation-recovery-'),
  );
  const founderContext = await browser.newContext({ baseURL });
  let recipientContext: BrowserContext | undefined;
  try {
    expect((await request.post(`${control}/relay/reservations/one`)).ok()).toBe(
      true,
    );
    recipientContext = await browser
      .browserType()
      .launchPersistentContext(profile, { baseURL });
    const founder = await founderContext.newPage();
    let recipient = await recipientContext.newPage();
    await sharedEditors(founder, recipient);
    await savedEdit(recipient, 'Bidirectional sharing with one reservation\n');
    await expect(
      founder.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue('Bidirectional sharing with one reservation\n');
    await recipientContext.close();
    await savedEdit(founder, 'Missed while the recipient was closed\n');
    recipientContext = await browser
      .browserType()
      .launchPersistentContext(profile, { baseURL });
    recipient = await recipientContext.newPage();
    await openSaved(recipient);
    await expect(
      recipient.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue('Missed while the recipient was closed\n');
    await savedEdit(
      recipient,
      'Fresh edit after recovery without a reservation\n',
    );
    await expect(
      founder.getByRole('textbox', { name: 'Note text' }),
    ).toHaveValue('Fresh edit after recovery without a reservation\n');
  } finally {
    await recipientContext?.close().catch(() => undefined);
    await founderContext.close();
    await rm(profile, { recursive: true, force: true });
    expect(
      (await request.post(`${control}/relay/reservations/reset`)).ok(),
    ).toBe(true);
  }
});
