import { EditorView } from '@codemirror/view';
import { EditorState } from '@codemirror/state';
import { yCollab } from 'y-codemirror.next';
import { usingSession } from '../session-view';
import { mountEditorView } from '../editor-view';

export const mount = (root: HTMLElement) =>
  usingSession(root, 'codemirror', (target, session) =>
    mountEditorView(target, session, async (parent, document) => {
      const view = new EditorView({
        parent,
        state: EditorState.create({
          extensions: [yCollab(document.getText('body'), null)],
        }),
      });
      return () => view.destroy();
    }),
  );
