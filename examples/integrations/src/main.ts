import './style.css';
import { views } from './views';

const root = document.querySelector<HTMLElement>('#app')!;
const name = new URLSearchParams(location.search).get('view') ?? 'vanilla';
const view = views[name as keyof typeof views] ?? views.vanilla;
let cleanup: (() => void | Promise<void>) | undefined;
let disposed = false;
root.innerHTML =
  '<p>This local exercise creates a fresh identity on reload.</p><button>Start local document</button>';
root.querySelector('button')!.addEventListener(
  'click',
  async (event) => {
    (event.currentTarget as HTMLButtonElement).disabled = true;
    try {
      const module = await view.load();
      cleanup = await module.mount(root);
      if (disposed) await cleanup();
    } catch {
      root.innerHTML =
        '<p role="alert">Unable to start this integration example.</p>';
    }
  },
  { once: true },
);
window.addEventListener(
  'pagehide',
  () => {
    disposed = true;
    void Promise.resolve(cleanup?.()).catch(() => {});
  },
  { once: true },
);
