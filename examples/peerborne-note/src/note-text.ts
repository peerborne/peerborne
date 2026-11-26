import {
  type Doc,
  type Heads,
  change,
  clone,
  free,
  getCursor,
  getCursorPosition,
  getHeads,
  merge,
  splice,
  view,
} from '@automerge/automerge';

export interface NoteData {
  body?: string;
}

export interface NoteVersion {
  readonly body: string;
  readonly heads: Heads;
}

export interface TextSelection {
  readonly start: number;
  readonly end: number;
}

export interface RebasedText {
  readonly note: NoteVersion;
  readonly body: string;
  readonly selection?: TextSelection;
}

const BODY = ['body'];

export function noteBody(document: Doc<NoteData>): string {
  return typeof document.body === 'string' ? document.body : '';
}

export function noteVersion(document: Doc<NoteData>): NoteVersion {
  return { body: noteBody(document), heads: getHeads(document) };
}

export function sameHeads(a: Heads, b: Heads): boolean {
  if (a.length !== b.length) return false;
  const remaining = new Set(a);
  return b.every((head) => remaining.delete(head));
}

export function applyTextEdit(
  draft: NoteData,
  previous: string,
  next: string,
): void {
  if (typeof draft.body !== 'string') {
    draft.body = next;
    return;
  }
  let prefix = 0;
  while (
    prefix < previous.length &&
    prefix < next.length &&
    previous[prefix] === next[prefix]
  ) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < previous.length - prefix &&
    suffix < next.length - prefix &&
    previous[previous.length - 1 - suffix] === next[next.length - 1 - suffix]
  ) {
    suffix++;
  }
  if (prefix === previous.length && prefix === next.length) return;
  splice(
    draft as Doc<NoteData>,
    BODY,
    prefix,
    previous.length - prefix - suffix,
    next.slice(prefix, next.length - suffix),
  );
}

function mapPosition(
  from: Doc<NoteData>,
  to: Doc<NoteData>,
  position: number,
): number {
  if (position > 0) {
    const anchor = getCursor(from, BODY, position - 1);
    const left = getCursorPosition(
      to,
      BODY,
      getCursor(from, BODY, position - 1, 'before'),
    );
    if (left < noteBody(to).length && getCursor(to, BODY, left) === anchor)
      return left + 1;
  }
  return getCursorPosition(to, BODY, getCursor(from, BODY, position));
}

function mapSelection(
  from: Doc<NoteData>,
  to: Doc<NoteData>,
  selection: TextSelection,
): TextSelection {
  const start = mapPosition(from, to, selection.start);
  return {
    start,
    end:
      selection.end === selection.start
        ? start
        : Math.max(start, mapPosition(from, to, selection.end)),
  };
}

/**
 * Carry text that was edited from `base` onto the document's current state,
 * as Automerge would merge the edit if it were made at `base`, and move the
 * selection with the characters around it.
 */
export function rebaseText(
  document: Doc<NoteData>,
  base: NoteVersion,
  text: string,
  selection?: TextSelection,
): RebasedText {
  const note = noteVersion(document);
  if (sameHeads(base.heads, note.heads)) return { note, body: text, selection };
  if (text === base.body) {
    return {
      note,
      body: note.body,
      selection:
        selection &&
        mapSelection(view(document, base.heads), document, selection),
    };
  }
  const edited = change(clone(view(document, base.heads)), (draft) =>
    applyTextEdit(draft, base.body, text),
  );
  const editedHeads = getHeads(edited);
  const merged = merge(edited, document);
  try {
    return {
      note,
      body: noteBody(merged),
      selection:
        selection && mapSelection(view(merged, editedHeads), merged, selection),
    };
  } finally {
    free(merged);
  }
}
