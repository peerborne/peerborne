import {
  createBrowserSession,
  type BrowserSession,
} from '../../shared/browser-session';

export async function usingSession(
  root: HTMLElement,
  name: string,
  mount: (
    root: HTMLElement,
    session: BrowserSession,
  ) => (() => void | Promise<void>) | Promise<() => void | Promise<void>>,
) {
  const session = await createBrowserSession(`/examples/${name}`);
  try {
    const unmount = await mount(root, session);
    return async () => {
      try {
        await unmount();
      } finally {
        await session.dispose();
      }
    };
  } catch (error) {
    await session.dispose();
    throw error;
  }
}
