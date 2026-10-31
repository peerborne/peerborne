import { editor } from 'monaco-editor/editor/editor.api.js';
import { MonacoBinding } from 'y-monaco';
import EditorWorker from 'monaco-editor/editor/editor.worker.js?worker';
import { usingSession } from '../session-view';
import { mountEditorView } from '../editor-view';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'monaco', (target, session) =>
    mountEditorView(target, session, async (element, document) => {
      (
        self as typeof self & { MonacoEnvironment: { getWorker(): Worker } }
      ).MonacoEnvironment = { getWorker: () => new EditorWorker() };
      const model = editor.createModel('', 'plaintext');
      const view = editor.create(element, {
        model,
        automaticLayout: true,
        minimap: { enabled: false },
      });
      const binding = new MonacoBinding(
        document.getText('body'),
        model,
        new Set([view]),
      );
      return () => {
        binding.destroy();
        view.dispose();
        model.dispose();
      };
    }),
  );
