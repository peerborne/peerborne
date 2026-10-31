import { Editor } from '@tiptap/core';
import StarterKit from '@tiptap/starter-kit';
import Collaboration from '@tiptap/extension-collaboration';
import { usingSession } from '../session-view';
import { mountEditorView } from '../editor-view';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'tiptap', (target, session) =>
    mountEditorView(
      target,
      session,
      async (element, document) => {
        const editor = new Editor({
          element,
          extensions: [
            StarterKit.configure({ undoRedo: false }),
            Collaboration.configure({ document, field: 'content' }),
          ],
        });
        return () => editor.destroy();
      },
      true,
    ),
  );
