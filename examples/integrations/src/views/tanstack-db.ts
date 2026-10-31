import { usingSession } from '../session-view';
import { mountCollection } from '../collection';
export const mount = (root: HTMLElement) =>
  usingSession(root, 'tanstack-db', mountCollection);
