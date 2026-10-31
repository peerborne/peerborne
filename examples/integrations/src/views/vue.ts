import { usingSession } from '../session-view';
import { mountVue } from '../vue';
export const mount = (root: HTMLElement) =>
  usingSession(root, 'vue', (target, session) => {
    target.replaceChildren();
    return mountVue(target, session);
  });
