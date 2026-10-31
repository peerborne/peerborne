import { mount as mountSvelte, unmount } from 'svelte';
import App from '../App.svelte';
import { usingSession } from '../session-view';
export const mount = (root: HTMLElement) =>
  usingSession(root, 'svelte', (target, session) => {
    target.replaceChildren();
    const app = mountSvelte(App, { target, props: { session } });
    return () => unmount(app);
  });
