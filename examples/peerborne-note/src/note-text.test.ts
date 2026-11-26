import {
  type Doc,
  change,
  clone,
  from,
  getHeads,
  load,
  merge,
  save,
  splice,
  view,
} from '@automerge/automerge';
import {
  applyTextEdit,
  noteVersion,
  rebaseText,
  sameHeads,
  type NoteData,
  type NoteVersion,
} from './note-text.js';

function edit(
  document: Doc<NoteData>,
  index: number,
  remove: number,
  insert = '',
): Doc<NoteData> {
  return change(document, (draft) =>
    splice(draft as Doc<NoteData>, ['body'], index, remove, insert),
  );
}

function commit(
  document: Doc<NoteData>,
  base: NoteVersion,
  text: string,
): Doc<NoteData> {
  return change(document, (draft) => applyTextEdit(draft, base.body, text));
}

function pair(body: string) {
  const local: Doc<NoteData> = from({ body });
  return { local, remote: clone(local), base: noteVersion(local) };
}

function random(seed: number) {
  return () => {
    seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
    return seed / 2_147_483_648;
  };
}

test('keeps a remote edit that arrives while the local text is unsaved', () => {
  const body = 'BASE-LINE-'.repeat(3);
  const { local, remote, base } = pair(body);
  const remoteEdited = edit(remote, body.length, 0, 'REMOTE-EDIT');
  const live = merge(local, remoteEdited);
  const typed = 'a'.repeat(40) + body;

  const rebased = rebaseText(live, base, typed, { start: 40, end: 40 });

  expect(rebased.body).toBe(`${'a'.repeat(40)}${body}REMOTE-EDIT`);
  expect(rebased.selection).toEqual({ start: 40, end: 40 });
  expect(sameHeads(rebased.note.heads, getHeads(live))).toBe(true);
  const committed = commit(live, rebased.note, rebased.body);
  expect(committed.body).toBe(rebased.body);
  expect(merge(remoteEdited, committed).body).toBe(rebased.body);
});

test('the old whole-text diff against the live note would delete the remote edit', () => {
  const body = 'BASE-LINE-'.repeat(3);
  const { local, remote } = pair(body);
  const remoteEdited = edit(remote, body.length, 0, 'REMOTE-EDIT');
  const live = merge(local, remoteEdited);
  const typed = 'a'.repeat(40) + body;

  const replaced = commit(live, noteVersion(live), typed);

  expect(merge(remoteEdited, replaced).body).toBe(typed);
});

test('moves the caret with remote text inserted or deleted before it', () => {
  const { local, remote, base } = pair('hello world');
  const live = merge(local, edit(edit(remote, 0, 0, '>> '), 9, 2));

  expect(live.body).toBe('>> hello rld');
  expect(rebaseText(live, base, base.body, { start: 11, end: 11 })).toEqual({
    note: noteVersion(live),
    body: '>> hello rld',
    selection: { start: 12, end: 12 },
  });
  expect(
    rebaseText(live, base, base.body, { start: 6, end: 11 }).selection,
  ).toEqual({ start: 9, end: 12 });
});

test('keeps the caret after local typing when remote text lands at the same place', () => {
  const { local, remote, base } = pair('ab');
  const live = merge(local, edit(remote, 1, 0, 'REMOTE'));

  const rebased = rebaseText(live, base, 'axyzb', { start: 4, end: 4 });

  expect(rebased.body.replace('xyz', '')).toBe('aREMOTEb');
  expect(rebased.body.slice(0, rebased.selection!.start)).toMatch(/xyz$/u);
});

test('places the caret where deleted text used to be', () => {
  const { local, remote, base } = pair('abcdef');
  const live = merge(local, edit(remote, 1, 4));

  expect(rebaseText(live, base, base.body, { start: 3, end: 3 })).toMatchObject(
    {
      body: 'af',
      selection: { start: 1, end: 1 },
    },
  );
  expect(rebaseText(live, base, 'abcdefX', { start: 7, end: 7 })).toMatchObject(
    { body: 'afX', selection: { start: 3, end: 3 } },
  );
});

test('replacing the whole text keeps text appended remotely at the same time', () => {
  const { local, remote, base } = pair('draft');
  const live = merge(local, edit(remote, 5, 0, ' and more'));

  expect(rebaseText(live, base, 'final', { start: 5, end: 5 })).toMatchObject({
    body: 'final and more',
    selection: { start: 5, end: 5 },
  });
});

test('returns unsaved text unchanged when the note has not moved', () => {
  const { local, base } = pair('unchanged');

  expect(rebaseText(local, base, 'unchanged!', { start: 10, end: 10 })).toEqual(
    {
      note: base,
      body: 'unchanged!',
      selection: { start: 10, end: 10 },
    },
  );
});

test('compares heads as sets', () => {
  expect(sameHeads(['a', 'b'], ['b', 'a'])).toBe(true);
  expect(sameHeads(['a', 'a'], ['a', 'b'])).toBe(false);
  expect(sameHeads(['a'], ['a', 'b'])).toBe(false);
});

test('concurrent random edits converge and keep both sides inserted text', () => {
  const next = random(17);
  for (let round = 0; round < 200; round++) {
    const initial = Array.from({ length: Math.floor(next() * 12) }, () =>
      String.fromCharCode(97 + Math.floor(next() * 3)),
    ).join('');
    const { local, remote, base } = pair(initial);
    const localIndex = Math.floor(next() * (initial.length + 1));
    const localRemove = Math.floor(next() * (initial.length - localIndex + 1));
    const localInsert = `<L${round}>`;
    const typed =
      initial.slice(0, localIndex) +
      localInsert +
      initial.slice(localIndex + localRemove);
    const remoteIndex = Math.floor(next() * (initial.length + 1));
    const remoteInsert = `<R${round}>`;
    const remoteEdited = edit(
      remote,
      remoteIndex,
      Math.floor(next() * (initial.length - remoteIndex + 1)),
      remoteInsert,
    );
    const caret = localIndex + localInsert.length;

    const live = merge(local, remoteEdited);
    const rebased = rebaseText(live, base, typed, {
      start: caret,
      end: caret,
    });
    const committed = commit(live, rebased.note, rebased.body);

    const typedAtBase = change(clone(view(live, base.heads)), (draft) =>
      applyTextEdit(draft, initial, typed),
    );
    const automergeMerge = load<NoteData>(
      save(merge(typedAtBase, clone(remoteEdited))),
    ).body!;
    expect(automergeMerge).toContain(localInsert);
    expect(rebased.body.replace(localInsert, '')).toBe(
      automergeMerge.replace(localInsert, ''),
    );
    expect(rebased.body).toContain(localInsert);
    expect(rebased.body).toContain(remoteInsert);
    expect(
      rebased.body.slice(0, rebased.selection!.start).endsWith(localInsert),
    ).toBe(true);
    expect(merge(remoteEdited, committed).body).toBe(rebased.body);
  }
});
