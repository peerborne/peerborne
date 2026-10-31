import { createYjsEditorBridge } from '@peerborne/yjs/editor';
import type { BrowserSession } from '../../shared/browser-session';

export async function mountEditorView(
  root: HTMLElement,
  session: BrowserSession,
  mount: (
    target: HTMLElement,
    document: import('yjs').Doc,
  ) => Promise<() => void>,
  richText = false,
) {
  await session.store.start();
  root.innerHTML =
    '<section><p role="status" aria-label="Document status">ready</p><div class="editor"></div><button>Flush editor changes</button><output data-testid="document-title"></output><p role="alert" hidden></p></section>';
  const alert = root.querySelector<HTMLElement>('[role="alert"]')!;
  const reportError = () => {
    alert.hidden = false;
    alert.textContent = 'Editor write failed. Reopen this example to recover.';
  };
  const bridge = createYjsEditorBridge(session.document, {
    onError: reportError,
  });
  let destroyEditor: () => void;
  try {
    destroyEditor = await mount(
      root.querySelector<HTMLElement>('.editor')!,
      bridge.document,
    );
  } catch (error) {
    await bridge.destroy();
    throw error;
  }
  const render = () => {
    root.querySelector('output')!.textContent = richText
      ? session.document.document.getXmlFragment('content').toString()
      : session.document.document.getText('body').toString();
  };
  const unsubscribe = session.store.subscribe(render);
  const button = root.querySelector('button')!;
  const flush = () => {
    void bridge.flush().catch(reportError);
  };
  button.addEventListener('click', flush);
  render();
  return async () => {
    unsubscribe();
    button.removeEventListener('click', flush);
    destroyEditor();
    await bridge.destroy();
  };
}
