import type { DocumentStore } from '@peerborne/store';

/** Plain DOM binding. The returned cleanup removes both listeners and ownership. */
export function mountTitleForm<Doc, Change, PublicKey>(
  root: HTMLElement,
  store: DocumentStore<Doc, Change, PublicKey>,
  readTitle: (doc: Doc) => string,
  writeTitle: (title: string) => Change,
) {
  root.innerHTML =
    '<section><p role="status" aria-label="Document status"></p><output data-testid="document-title"></output><label>Title <input /></label><button>Save title</button><p role="alert" hidden></p></section>';
  const status = root.querySelector<HTMLElement>('[role="status"]')!;
  const output = root.querySelector<HTMLOutputElement>('output')!;
  const input = root.querySelector<HTMLInputElement>('input')!;
  const button = root.querySelector<HTMLButtonElement>('button')!;
  const alert = root.querySelector<HTMLElement>('[role="alert"]')!;
  const render = () => {
    const snapshot = store.getSnapshot();
    status.textContent = snapshot.status;
    output.textContent =
      snapshot.data === undefined ? 'Untitled' : readTitle(snapshot.data);
    button.disabled = snapshot.status !== 'ready';
    alert.hidden = snapshot.error === undefined;
    alert.textContent =
      snapshot.error === undefined ? '' : 'The document operation failed.';
  };
  const save = async () => {
    try {
      await store.change(writeTitle(input.value));
    } catch {
      alert.hidden = false;
      alert.textContent = 'The document operation failed.';
    }
  };
  const onClick = () => {
    void save();
  };
  button.addEventListener('click', onClick);
  const unsubscribe = store.subscribe(render);
  const release = store.connect();
  render();
  return () => {
    button.removeEventListener('click', onClick);
    unsubscribe();
    release();
  };
}
