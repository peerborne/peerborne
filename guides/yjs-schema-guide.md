# Y.js Schema Design Guide for Peerborne

A comprehensive reference for designing application schemas that work well with Y.js CRDTs in Peerborne.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Y.js Shared Types Reference](#2-yjs-shared-types-reference)
3. [Schema Design Patterns](#3-schema-design-patterns)
4. [Common Application Schemas](#4-common-application-schemas)
5. [Anti-Patterns](#5-anti-patterns)
6. [Performance Considerations](#6-performance-considerations)
7. [Migration Strategies](#7-migration-strategies)
8. [Integration with Peerborne](#8-integration-with-peerborne)

---

## 1. Introduction

### 1.1 Why Schema Design Matters for CRDTs

In a traditional database, schema design determines how data is stored and queried. In a CRDT-based system like Peerborne, schema design additionally determines **how conflicts are resolved**. Every choice of Y.js shared type carries an implicit conflict resolution policy:

- A `Y.Map` key resolves concurrent writes by last-writer-wins.
- A `Y.Array` preserves all concurrent insertions, ordering them deterministically.
- A `Y.Text` merges character-level edits, interleaving concurrent typing.

Choosing the wrong type means your application gets the wrong conflict behavior. A counter stored as a `Y.Map` value loses increments. A task list stored as a plain JSON object in a `Y.Map` overwrites entire items when any field changes. Schema design is where you encode your application's concurrency semantics.

### 1.2 How Y.js Conflict Resolution Works

Y.js implements the YATA (Yet Another Transformation Approach) algorithm. Internally, every shared type is represented as a linked list of "items." Each item carries a unique ID composed of the originating client's identifier and a logical clock. When concurrent operations target the same position, YATA uses these IDs to impose a deterministic total order so that all peers converge to the same state.

Key properties:

- **Convergence**: All peers applying the same set of operations reach the same document state, regardless of operation order.
- **Intention preservation**: Insertions are never lost. If two users both insert at position 5, both insertions appear in the final document.
- **Last-writer-wins for maps**: When two users set the same key in a `Y.Map`, the operation with the higher client ID wins. There is no merge — one value replaces the other.
- **Tombstones**: Deleted items are marked as tombstones rather than removed, so that late-arriving operations referencing them can still be ordered correctly. Tombstones are a permanent cost.

### 1.3 Y.js Shared Types and Peerborne Documents

In Peerborne, each document wraps a single `Y.Doc`. The `YjsProvider` mediates between Peerborne's generic provider interface and Y.js operations:

```typescript
// Peerborne creates a Y.Doc per document
const provider = new YjsProvider();
const doc: Y.Doc = provider.newDocument();

// Application code accesses shared types on the doc
const metadata = doc.getMap('metadata');
const content = doc.getText('content');
const items = doc.getArray('items');
```

The `document.change(fn)` API passes the `Y.Doc` to your change function, where you manipulate shared types. Peerborne then serializes, signs, encrypts, and broadcasts the resulting update to peers.

```typescript
// Through Peerborne's API
document.change((doc: Y.Doc) => {
  doc.getMap('metadata').set('title', 'Meeting Notes');
  doc.getText('content').insert(0, 'Attendees: ...');
});
```

All shared types accessed via `doc.getMap()`, `doc.getArray()`, `doc.getText()`, etc. are **top-level** shared types identified by name. You can also nest shared types inside each other (e.g., a `Y.Map` inside a `Y.Array`), which is the foundation of most schema designs.

---

## 2. Y.js Shared Types Reference

### 2.1 Y.Map

**Behavior**: A key-value store where each key independently resolves concurrent writes via last-writer-wins (LWW). Values can be primitives, `Uint8Array`, or nested Y.js shared types.

**Conflict resolution**: When two peers concurrently set the same key, the write from the peer with the higher client ID wins. Writes to different keys never conflict.

**When to use**: Metadata, settings, entity fields, any record-like structure where each field is independently editable.

**API summary**:

| Method | Description |
|--------|-------------|
| `set(key, value)` | Add or update an entry |
| `get(key)` | Retrieve a value by key |
| `delete(key)` | Remove a key-value pair |
| `has(key)` | Check if a key exists |
| `size` | Number of entries |
| `entries()` / `keys()` / `values()` | Iterators |
| `toJSON()` | Convert to plain object |
| `observe(fn)` | Listen for direct changes |
| `observeDeep(fn)` | Listen for changes in nested types |

**Example**:

```typescript
const doc = new Y.Doc();
const settings = doc.getMap('settings');

settings.set('theme', 'dark');
settings.set('language', 'en');
settings.set('fontSize', 14);

// Nested shared type: a Y.Map inside a Y.Map
const notifications = new Y.Map();
notifications.set('email', true);
notifications.set('push', false);
settings.set('notifications', notifications);

// Observe changes
settings.observe((event) => {
  event.keysChanged.forEach((key) => {
    console.log(`Key "${key}" changed`);
  });
});
```

### 2.2 Y.Array

**Behavior**: An ordered list that preserves all concurrent insertions. Concurrent inserts at the same position are both kept, ordered deterministically by YATA's client ID tiebreaking.

**Conflict resolution**: Insertions are never lost. Two users inserting at the same index both have their items appear. Deletions of the same item from multiple peers converge (item is deleted). Items can be primitives, `Uint8Array`, or nested shared types.

**When to use**: Ordered collections (task lists, message feeds, array of records), anywhere insertion order matters.

**API summary**:

| Method | Description |
|--------|-------------|
| `insert(index, content[])` | Insert items at index |
| `push(content[])` | Append items |
| `unshift(content[])` | Prepend items |
| `delete(index, length)` | Remove items |
| `get(index)` | Get item at index |
| `slice(start, end)` | Get a range |
| `length` | Number of items |
| `toArray()` | Convert to plain array |
| `toJSON()` | JSON representation |
| `map(fn)` / `forEach(fn)` | Iteration |
| `observe(fn)` | Listen for changes |

**Example**:

```typescript
const doc = new Y.Doc();
const tasks = doc.getArray('tasks');

// Insert structured items using nested Y.Map
const task = new Y.Map();
task.set('id', 'task-001');
task.set('title', 'Buy groceries');
task.set('done', false);
tasks.push([task]);

// Later: toggle completion (LWW on the nested map key)
task.set('done', true);

// Observe changes with delta format
tasks.observe((event) => {
  console.log('Delta:', event.changes.delta);
  // e.g., [{ retain: 1 }, { insert: [newTask] }]
});
```

### 2.3 Y.Text

**Behavior**: A rich text type with character-level conflict resolution. Supports formatting attributes (bold, italic, etc.) that are themselves CRDT-aware. Compatible with Quill's Delta format.

**Conflict resolution**: Concurrent insertions at the same character position interleave (both are kept, ordered by client ID). Concurrent formatting of overlapping ranges merges correctly — non-conflicting attributes are combined, conflicting attributes on the same range resolve by LWW.

**When to use**: Collaborative text editing (prose, code, notes), any content where character-level merge is needed.

**API summary**:

| Method | Description |
|--------|-------------|
| `insert(index, text, [format])` | Insert text, optionally formatted |
| `delete(index, length)` | Remove characters |
| `format(index, length, format)` | Apply formatting to a range |
| `applyDelta(delta)` | Apply a Quill-compatible delta |
| `toString()` | Plain text (no formatting) |
| `toDelta()` | Get Quill delta representation |
| `length` | Character count |
| `observe(fn)` | Listen for changes |

**Example**:

```typescript
const doc = new Y.Doc();
const content = doc.getText('article');

// Insert text
content.insert(0, 'Hello, world!');

// Apply formatting
content.format(0, 5, { bold: true });      // "Hello" is bold
content.format(7, 5, { italic: true });    // "world" is italic

// Get rich text as delta
const delta = content.toDelta();
// [
//   { insert: 'Hello', attributes: { bold: true } },
//   { insert: ', ' },
//   { insert: 'world', attributes: { italic: true } },
//   { insert: '!' }
// ]

// Apply a Quill delta (useful with text diff libraries)
content.applyDelta([
  { retain: 13 },
  { insert: ' Welcome.' }
]);
```

### 2.4 Y.XmlFragment / Y.XmlElement / Y.XmlText

**Behavior**: XML-like tree types designed for rich text editor integrations (ProseMirror, Slate, TipTap). `Y.XmlFragment` is a container for XML nodes. `Y.XmlElement` represents a named node with attributes. `Y.XmlText` extends `Y.Text` with XML node semantics.

**Conflict resolution**: Same as `Y.Array` for child node ordering (all insertions preserved, YATA ordering). Attributes on `Y.XmlElement` use LWW per attribute key, similar to `Y.Map`.

**When to use**: Rich text editors that use a tree-based document model (ProseMirror, Slate, TipTap), structured document editing, any XML/HTML document representation.

**API summary (Y.XmlFragment)**:

| Method | Description |
|--------|-------------|
| `insert(index, content[])` | Insert XML nodes at index |
| `delete(index, length)` | Remove nodes |
| `get(index)` | Get child at index |
| `toDOM()` | Convert to DOM elements |
| `length` | Number of children |

**API summary (Y.XmlElement extends Y.XmlFragment)**:

| Method | Description |
|--------|-------------|
| `nodeName` | Element name (string) |
| `setAttribute(key, value)` | Set an attribute (LWW per key) |
| `getAttribute(key)` | Get an attribute |
| `removeAttribute(key)` | Remove an attribute |
| `getAttributes()` | All attributes as object |

**Example**:

```typescript
const doc = new Y.Doc();
const fragment = doc.getXmlFragment('editor');

// Build a paragraph with text
const paragraph = new Y.XmlElement('paragraph');
const text = new Y.XmlText();
text.insert(0, 'Hello from the editor');
text.format(0, 5, { bold: true });
paragraph.insert(0, [text]);

// Add paragraph to the fragment
fragment.insert(0, [paragraph]);

// XmlElement attributes (LWW per key)
paragraph.setAttribute('align', 'center');
paragraph.setAttribute('indent', '1');
```

---

## 3. Schema Design Patterns

### 3.1 Last-Writer-Wins Register

Use a `Y.Map` to store atomic values where the most recent write should win.

```typescript
const doc = new Y.Doc();
const profile = doc.getMap('profile');

profile.set('displayName', 'Alice');
profile.set('email', 'alice@example.com');
profile.set('avatarUrl', '/avatars/alice.png');
profile.set('updatedAt', Date.now());

// Concurrent writes to 'displayName' from two peers:
// Peer A: profile.set('displayName', 'Alice Smith')
// Peer B: profile.set('displayName', 'A. Smith')
// Result: one wins (determined by client ID). Both peers converge.

// Reads
const name = profile.get('displayName'); // string
```

**When to use**: User preferences, status fields, configuration values, any single value where "latest wins" is acceptable.

### 3.2 Add-Wins Set

Model a set using a `Y.Map` where keys are set members and values are `true`. Under Y.js concurrency semantics, if one peer adds a key while another deletes it, the add wins because the `set()` operation creates a new item that supersedes the tombstone.

```typescript
const doc = new Y.Doc();
const tags = doc.getMap('tags');

// Add members
tags.set('feature-request', true);
tags.set('high-priority', true);

// Remove a member
tags.delete('high-priority');

// Check membership
function hasTag(tag: string): boolean {
  return tags.has(tag);
}

// Get all members
function allTags(): string[] {
  return Array.from(tags.keys());
}

// Concurrent scenario:
// Peer A: tags.set('urgent', true)
// Peer B: tags.delete('urgent')
// If concurrent, the add wins — 'urgent' exists after merge.
```

**When to use**: Tags, labels, feature flags, user-visible sets where losing an add would be surprising.

### 3.3 Ordered List

Use `Y.Array` for sequences. For items with mutable properties, nest `Y.Map` inside the array.

```typescript
const doc = new Y.Doc();
const items = doc.getArray<Y.Map<any>>('items');

// Add an item with mutable fields
function addItem(title: string, priority: number): void {
  const item = new Y.Map();
  item.set('id', crypto.randomUUID());
  item.set('title', title);
  item.set('priority', priority);
  item.set('completed', false);
  item.set('createdAt', Date.now());
  items.push([item]);
}

// Update a field (LWW on the nested map key, no array conflict)
function toggleComplete(index: number): void {
  const item = items.get(index);
  item.set('completed', !item.get('completed'));
}

// Reorder by delete + insert (see Pattern 3.6 for caveats)
function moveItem(fromIndex: number, toIndex: number): void {
  const item = items.get(fromIndex);
  items.delete(fromIndex, 1);
  const adjustedIndex = toIndex > fromIndex ? toIndex - 1 : toIndex;
  items.insert(adjustedIndex, [item]);
}
```

**Important**: Never store plain objects in `Y.Array` if you need to update individual fields. Plain objects are stored as opaque JSON — updating any field requires replacing the entire object, which is LWW on the array slot.

### 3.4 Counter

Y.js has no built-in counter type. A naive `map.set('count', map.get('count') + 1)` is an LWW register — concurrent increments cause lost updates.

**Solution**: Use a per-peer counter map and sum the values.

```typescript
const doc = new Y.Doc();
const counters = doc.getMap<number>('vote-counts');

function increment(peerId: string): void {
  const current = counters.get(peerId) || 0;
  counters.set(peerId, current + 1);
}

function decrement(peerId: string): void {
  const current = counters.get(peerId) || 0;
  counters.set(peerId, current - 1);
}

function getTotal(): number {
  let sum = 0;
  counters.forEach((value) => {
    sum += value;
  });
  return sum;
}

// Peer A increments: counters.set('peer-a', 1)
// Peer B increments: counters.set('peer-b', 1)
// Total: 2 (no lost updates because different keys)
```

**When to use**: Vote counts, view counters, like counts, any numeric aggregation.

**Caveat**: This pattern assumes each peer has a unique identifier. If the same peer identifier is reused across multiple Y.js client instances (e.g., multiple browser tabs), concurrent increments from those instances may still conflict. A single Y.js client's operations are totally ordered by its logical clock, so true concurrency within one client does not occur.

### 3.5 Nested Documents

Use `Y.Map` and `Y.Array` containing other shared types to model hierarchical data.

```typescript
const doc = new Y.Doc();
const root = doc.getMap('root');

// Nested map for a record
const address = new Y.Map();
address.set('street', '123 Main St');
address.set('city', 'Portland');
address.set('state', 'OR');
root.set('address', address);

// Array of nested maps
const contacts = new Y.Array<Y.Map<any>>();
const contact1 = new Y.Map();
contact1.set('name', 'Bob');
contact1.set('phone', '555-1234');
contacts.push([contact1]);
root.set('contacts', contacts);

// Deep observation
root.observeDeep((events) => {
  events.forEach((event) => {
    console.log('Change path:', event.path);
  });
});
```

**Nesting rules**:
- A shared type instance can only belong to **one** parent. Inserting the same instance into two locations throws an error.
- Always create a **new** shared type instance for each insertion.
- Nesting depth affects performance (see Section 6).

### 3.6 Move Operation

Y.js does not have a native "move" operation for arrays. Moving an item requires deleting it from the old position and inserting it at the new position. Under concurrency, this can produce duplicates or ordering anomalies.

```typescript
const doc = new Y.Doc();
const list = doc.getArray<Y.Map<any>>('list');

// Safe single-peer move (no concurrency risk)
function moveItem(fromIndex: number, toIndex: number): void {
  const item = list.get(fromIndex);
  doc.transact(() => {
    list.delete(fromIndex, 1);
    const target = toIndex > fromIndex ? toIndex - 1 : toIndex;
    list.insert(target, [item]);
  });
}
```

**Concurrent move hazards**:
- If Peer A moves item X from index 2 to index 5, and Peer B concurrently moves item X from index 2 to index 0, the result is that X is **deleted** at index 2 by both peers (the deletes converge) but **inserted** at both index 5 and index 0, creating a duplicate.
- **Mitigation**: Use a `Y.Map` keyed by item ID instead of `Y.Array` when moves are frequent. The "position" becomes a sortable field (e.g., a fractional index string) rather than a physical array slot.

**Fractional indexing alternative**:

```typescript
const doc = new Y.Doc();
const items = doc.getMap<Y.Map<any>>('items');

function addItem(id: string, title: string, sortKey: string): void {
  const item = new Y.Map();
  item.set('title', title);
  item.set('sortKey', sortKey);  // e.g., "a0", "a1", "a0V" (between a0 and a1)
  items.set(id, item);
}

function getSorted(): Y.Map<any>[] {
  const result: Y.Map<any>[] = [];
  items.forEach((item) => result.push(item));
  result.sort((a, b) => {
    const ka = a.get('sortKey') as string;
    const kb = b.get('sortKey') as string;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  return result;
}
```

### 3.7 Timestamps and Ordering

Distributed systems have no global clock. Timestamps from different peers can be skewed or deliberately manipulated. Design schemas that do not depend on timestamp accuracy for correctness.

**Rules of thumb**:
- Use timestamps for **display** (e.g., "3 minutes ago") but not for **ordering** or **conflict resolution**.
- For ordering, rely on Y.js's built-in CRDT ordering (array position, insertion order).
- For recency tracking, use Lamport timestamps or vector clocks instead of wall-clock time.

```typescript
const doc = new Y.Doc();
const events = doc.getArray<Y.Map<any>>('events');

function addEvent(peerId: string, description: string): void {
  const event = new Y.Map();
  event.set('id', crypto.randomUUID());
  event.set('description', description);
  event.set('createdBy', peerId);
  // Wall-clock time for display only — not used for ordering
  event.set('timestamp', Date.now());
  events.push([event]);
  // Ordering comes from Y.Array position, not timestamp
}
```

**Lamport timestamp pattern** (for causal ordering):

```typescript
const doc = new Y.Doc();
const meta = doc.getMap('meta');

// Each peer maintains a logical clock
let logicalClock = 0;

function nextTimestamp(): number {
  logicalClock += 1;
  meta.set('clock', logicalClock);
  return logicalClock;
}

// On receiving remote changes, advance clock (Lamport rule: max + 1)
meta.observe(() => {
  const remoteClock = meta.get('clock') as number;
  logicalClock = Math.max(logicalClock, remoteClock) + 1;
});
```

---

## 4. Common Application Schemas

### 4.1 Todo App

A task management application with lists, tasks, status, priority, and assignment.

```typescript
import * as Y from 'yjs';

// Schema: single Y.Doc per todo-list
function createTodoListSchema(doc: Y.Doc) {
  // List metadata (LWW per field)
  const meta = doc.getMap('meta');
  meta.set('title', 'My Tasks');
  meta.set('createdAt', Date.now());
  meta.set('color', '#4A90D9');

  // Tasks: ordered list with mutable nested fields
  const tasks = doc.getArray<Y.Map<any>>('tasks');

  // Labels: add-wins set
  const labels = doc.getMap<boolean>('labels');
  labels.set('work', true);
  labels.set('personal', true);

  return { meta, tasks, labels };
}

function addTask(
  doc: Y.Doc,
  title: string,
  assignee?: string,
  priority: 'low' | 'medium' | 'high' = 'medium',
): void {
  const tasks = doc.getArray<Y.Map<any>>('tasks');
  const task = new Y.Map();
  task.set('id', crypto.randomUUID());
  task.set('title', title);
  task.set('status', 'todo');           // 'todo' | 'in-progress' | 'done'
  task.set('priority', priority);
  task.set('assignee', assignee || null);
  task.set('createdAt', Date.now());
  task.set('completedAt', null);

  // Subtasks as nested array of maps
  const subtasks = new Y.Array<Y.Map<any>>();
  task.set('subtasks', subtasks);

  // Labels for this task (add-wins set)
  const taskLabels = new Y.Map<boolean>();
  task.set('labels', taskLabels);

  tasks.push([task]);
}

function completeTask(task: Y.Map<any>): void {
  task.set('status', 'done');
  task.set('completedAt', Date.now());
}

function assignTask(task: Y.Map<any>, assignee: string): void {
  task.set('assignee', assignee);
}
```

**Conflict scenarios**:
- Two users mark the same task "done" simultaneously: both writes converge (same value).
- Two users assign the same task to different people: LWW — one assignment wins.
- Two users add tasks at the same position: both tasks appear (YATA ordering).

### 4.2 Collaborative Wiki

A wiki with pages containing rich text content, metadata, and inter-page links.

```typescript
import * as Y from 'yjs';

// Each wiki page is a separate Peerborne document (separate Y.Doc).
// A page index document tracks all pages.

// --- Page Index Document ---
function createPageIndex(doc: Y.Doc) {
  // Map of pageId -> page metadata
  const pages = doc.getMap<Y.Map<any>>('pages');
  return { pages };
}

function addPageToIndex(
  doc: Y.Doc,
  pageId: string,
  title: string,
  createdBy: string,
): void {
  const pages = doc.getMap<Y.Map<any>>('pages');
  const entry = new Y.Map();
  entry.set('title', title);
  entry.set('createdBy', createdBy);
  entry.set('createdAt', Date.now());
  entry.set('updatedAt', Date.now());
  pages.set(pageId, entry);
}

// --- Individual Page Document ---
function createPageSchema(doc: Y.Doc) {
  // Metadata (LWW per field)
  const meta = doc.getMap('meta');
  meta.set('title', '');
  meta.set('updatedBy', '');
  meta.set('updatedAt', Date.now());

  // Rich text content (character-level merge)
  const content = doc.getText('content');

  // Tags (add-wins set)
  const tags = doc.getMap<boolean>('tags');

  // Backlinks — other pages linking to this one (add-wins set)
  const backlinks = doc.getMap<boolean>('backlinks');

  return { meta, content, tags, backlinks };
}

// Edit page content
function editPageContent(doc: Y.Doc, index: number, text: string): void {
  doc.getText('content').insert(index, text);
}

// Add a wiki link (updates both source and target)
function addWikiLink(
  sourceDoc: Y.Doc,
  targetPageId: string,
): void {
  // Mark link in source (stored inline in text or as metadata)
  const links = sourceDoc.getMap<boolean>('outlinks');
  links.set(targetPageId, true);
}
```

**Design decisions**:
- Each page is a separate Peerborne document so pages can be loaded lazily.
- The page index is a single document shared by all users.
- Rich text uses `Y.Text` for character-level merging.
- For rich text editors like ProseMirror or Slate, use `Y.XmlFragment` instead of `Y.Text`.

### 4.3 Chat Application

Messages organized by channels with reactions and read receipts.

```typescript
import * as Y from 'yjs';

// Each channel is a separate Peerborne document.

function createChannelSchema(doc: Y.Doc) {
  // Channel metadata
  const meta = doc.getMap('meta');
  meta.set('name', '');
  meta.set('topic', '');
  meta.set('createdAt', Date.now());

  // Members (add-wins set: member join wins over kick in concurrent scenario)
  const members = doc.getMap<boolean>('members');

  // Messages: ordered list
  const messages = doc.getArray<Y.Map<any>>('messages');

  // Pinned messages (set of message IDs)
  const pinned = doc.getMap<boolean>('pinned');

  return { meta, members, messages, pinned };
}

function sendMessage(
  doc: Y.Doc,
  senderId: string,
  text: string,
): string {
  const messages = doc.getArray<Y.Map<any>>('messages');
  const msgId = crypto.randomUUID();

  const msg = new Y.Map();
  msg.set('id', msgId);
  msg.set('senderId', senderId);
  msg.set('text', text);
  msg.set('timestamp', Date.now());
  msg.set('edited', false);

  // Reactions as nested map: emoji -> set of userIds
  const reactions = new Y.Map<Y.Map<boolean>>();
  msg.set('reactions', reactions);

  messages.push([msg]);
  return msgId;
}

function addReaction(
  msg: Y.Map<any>,
  emoji: string,
  userId: string,
): void {
  const reactions = msg.get('reactions') as Y.Map<Y.Map<boolean>>;
  let emojiReactions = reactions.get(emoji);
  if (!emojiReactions) {
    emojiReactions = new Y.Map<boolean>();
    reactions.set(emoji, emojiReactions);
  }
  emojiReactions.set(userId, true);
}

function editMessage(msg: Y.Map<any>, newText: string): void {
  msg.set('text', newText);
  msg.set('edited', true);
  msg.set('editedAt', Date.now());
}
```

**Design decisions**:
- Messages are append-only in a `Y.Array` (no reordering needed).
- Message text uses `Y.Map.set()` (LWW) rather than `Y.Text`, because chat messages are typically edited as a whole rather than character-by-character.
- Reactions use a nested `Y.Map<Y.Map<boolean>>` for add-wins semantics (adding a reaction wins over removing it concurrently).

### 4.4 Form Builder

A dynamic form definition with fields, validation rules, and configurable layout.

```typescript
import * as Y from 'yjs';

function createFormSchema(doc: Y.Doc) {
  // Form metadata
  const meta = doc.getMap('meta');
  meta.set('title', 'Untitled Form');
  meta.set('description', '');
  meta.set('version', 1);

  // Fields: ordered list (drag-and-drop reorderable)
  const fields = doc.getArray<Y.Map<any>>('fields');

  // Form settings
  const settings = doc.getMap('settings');
  settings.set('submitButtonText', 'Submit');
  settings.set('showProgressBar', false);
  settings.set('allowMultipleSubmissions', false);

  return { meta, fields, settings };
}

function addField(
  doc: Y.Doc,
  type: 'text' | 'number' | 'select' | 'checkbox' | 'date' | 'textarea',
  label: string,
): Y.Map<any> {
  const fields = doc.getArray<Y.Map<any>>('fields');

  const field = new Y.Map();
  field.set('id', crypto.randomUUID());
  field.set('type', type);
  field.set('label', label);
  field.set('placeholder', '');
  field.set('required', false);
  field.set('helpText', '');

  // Validation rules as nested map
  const validation = new Y.Map();
  validation.set('minLength', null);
  validation.set('maxLength', null);
  validation.set('pattern', null);
  field.set('validation', validation);

  // Options for select/checkbox fields
  if (type === 'select' || type === 'checkbox') {
    const options = new Y.Array<Y.Map<any>>();
    field.set('options', options);
  }

  fields.push([field]);
  return field;
}

function addSelectOption(
  field: Y.Map<any>,
  label: string,
  value: string,
): void {
  const options = field.get('options') as Y.Array<Y.Map<any>>;
  const option = new Y.Map();
  option.set('label', label);
  option.set('value', value);
  options.push([option]);
}
```

**Conflict scenarios**:
- Two users add fields simultaneously: both fields appear in the list.
- Two users rename the same field: LWW on `label` key — one name wins.
- Two users reorder fields: concurrent moves may duplicate (see Pattern 3.6).

### 4.5 Spreadsheet

Cells, formulas, column/row definitions, and named ranges.

```typescript
import * as Y from 'yjs';

function createSpreadsheetSchema(doc: Y.Doc) {
  // Sheet metadata
  const meta = doc.getMap('meta');
  meta.set('title', 'Sheet 1');

  // Cells: Y.Map keyed by "row:col" string (e.g., "3:2" for row 3, column 2)
  // Using a flat map avoids array index instability.
  const cells = doc.getMap<Y.Map<any>>('cells');

  // Column definitions: ordered array for column headers and widths
  const columns = doc.getArray<Y.Map<any>>('columns');

  // Row definitions: ordered array for row heights
  const rows = doc.getArray<Y.Map<any>>('rows');

  // Named ranges
  const namedRanges = doc.getMap<Y.Map<any>>('namedRanges');

  return { meta, cells, columns, rows, namedRanges };
}

function cellKey(row: number, col: number): string {
  return `${row}:${col}`;
}

function setCell(
  doc: Y.Doc,
  row: number,
  col: number,
  value: string | number,
  formula?: string,
): void {
  const cells = doc.getMap<Y.Map<any>>('cells');
  const key = cellKey(row, col);

  let cell = cells.get(key);
  if (!cell) {
    cell = new Y.Map();
    cells.set(key, cell);
  }

  cell.set('value', value);
  if (formula !== undefined) {
    cell.set('formula', formula);
  }
}

function setCellFormat(
  doc: Y.Doc,
  row: number,
  col: number,
  format: Record<string, any>,
): void {
  const cells = doc.getMap<Y.Map<any>>('cells');
  const key = cellKey(row, col);

  let cell = cells.get(key);
  if (!cell) {
    cell = new Y.Map();
    cells.set(key, cell);
  }

  // Each format property is an independent LWW field
  let cellFormat = cell.get('format') as Y.Map<any> | undefined;
  if (!cellFormat) {
    cellFormat = new Y.Map();
    cell.set('format', cellFormat);
  }

  for (const [prop, val] of Object.entries(format)) {
    cellFormat.set(prop, val);
  }
}

function addNamedRange(
  doc: Y.Doc,
  name: string,
  startRow: number,
  startCol: number,
  endRow: number,
  endCol: number,
): void {
  const ranges = doc.getMap<Y.Map<any>>('namedRanges');
  const range = new Y.Map();
  range.set('startRow', startRow);
  range.set('startCol', startCol);
  range.set('endRow', endRow);
  range.set('endCol', endCol);
  ranges.set(name, range);
}
```

**Design decisions**:
- Cells are keyed by `"row:col"` string in a `Y.Map`, not stored in a 2D array. This avoids index-shift problems when rows/columns are inserted.
- Cell formatting is a nested `Y.Map` so that concurrent format changes to different properties (e.g., one user changes font, another changes color) merge without conflict.
- Formulas are stored alongside values. Formula recalculation is done locally — the computed result is not stored in the CRDT to avoid derived data conflicts.

### 4.6 Kanban Board

Columns with cards that can be dragged between columns and reordered.

```typescript
import * as Y from 'yjs';

function createKanbanSchema(doc: Y.Doc) {
  // Board metadata
  const meta = doc.getMap('meta');
  meta.set('title', 'Project Board');

  // Columns: ordered array of column definitions
  const columns = doc.getArray<Y.Map<any>>('columns');

  // All cards indexed by ID (source of truth for card data)
  const cards = doc.getMap<Y.Map<any>>('cards');

  return { meta, columns, cards };
}

function addColumn(doc: Y.Doc, title: string): string {
  const columns = doc.getArray<Y.Map<any>>('columns');
  const colId = crypto.randomUUID();

  const column = new Y.Map();
  column.set('id', colId);
  column.set('title', title);
  // Card IDs in this column, in display order
  const cardIds = new Y.Array<string>();
  column.set('cardIds', cardIds);

  columns.push([column]);
  return colId;
}

function addCard(
  doc: Y.Doc,
  columnId: string,
  title: string,
  description?: string,
): string {
  const cards = doc.getMap<Y.Map<any>>('cards');
  const columns = doc.getArray<Y.Map<any>>('columns');
  const cardId = crypto.randomUUID();

  // Card data (source of truth)
  const card = new Y.Map();
  card.set('title', title);
  card.set('description', description || '');
  card.set('assignee', null);
  card.set('priority', 'medium');
  card.set('createdAt', Date.now());
  const labels = new Y.Map<boolean>();
  card.set('labels', labels);
  cards.set(cardId, card);

  // Add card reference to column
  for (let i = 0; i < columns.length; i++) {
    const col = columns.get(i);
    if (col.get('id') === columnId) {
      (col.get('cardIds') as Y.Array<string>).push([cardId]);
      break;
    }
  }

  return cardId;
}

function moveCard(
  doc: Y.Doc,
  cardId: string,
  fromColumnId: string,
  toColumnId: string,
  toIndex: number,
): void {
  const columns = doc.getArray<Y.Map<any>>('columns');

  doc.transact(() => {
    // Remove from source column
    for (let i = 0; i < columns.length; i++) {
      const col = columns.get(i);
      if (col.get('id') === fromColumnId) {
        const cardIds = col.get('cardIds') as Y.Array<string>;
        for (let j = 0; j < cardIds.length; j++) {
          if (cardIds.get(j) === cardId) {
            cardIds.delete(j, 1);
            break;
          }
        }
        break;
      }
    }

    // Insert into target column
    for (let i = 0; i < columns.length; i++) {
      const col = columns.get(i);
      if (col.get('id') === toColumnId) {
        const cardIds = col.get('cardIds') as Y.Array<string>;
        cardIds.insert(toIndex, [cardId]);
        break;
      }
    }
  });
}
```

**Design decisions**:
- Card data is stored in a flat `Y.Map` keyed by card ID, separate from column membership. This means card edits (title, description, labels) never conflict with card moves.
- Column membership is tracked by `Y.Array<string>` of card IDs within each column.
- Moves use a transacted delete + insert. Concurrent moves of the same card to different columns may result in the card ID appearing in both columns (see Pattern 3.6). Applications should detect and reconcile duplicates by checking if a card ID appears in multiple columns.

---

## 5. Anti-Patterns

### 5.1 Using Plain Objects Instead of Shared Types

**Problem**: Storing a plain JavaScript object in a `Y.Map` or `Y.Array` makes it an opaque blob. Any change requires replacing the entire object, which is a last-writer-wins replacement of the whole thing.

```typescript
// BAD: plain object — updating 'done' replaces the entire task
const tasks = doc.getArray('tasks');
tasks.push([{ id: '1', title: 'Buy milk', done: false }]);
// Later: tasks.get(0) returns a frozen plain object.
// To mark done, you must delete and re-insert the whole object.

// GOOD: nested Y.Map — each field is independently editable
const task = new Y.Map();
task.set('id', '1');
task.set('title', 'Buy milk');
task.set('done', false);
tasks.push([task]);
// Later: task.set('done', true) — only this field changes.
```

### 5.2 Replacing Entire Y.Maps Instead of Updating Fields

**Problem**: Calling `parentMap.set('config', entireNewConfig)` replaces the shared type at that key. All concurrent field-level edits to the old config are lost.

```typescript
// BAD: replaces entire nested structure
const config = doc.getMap('config');
config.set('settings', { theme: 'dark', lang: 'en' });
// Peer B concurrently: config.get('settings') is now the old object...

// GOOD: set individual keys
const settings = doc.getMap('settings');
settings.set('theme', 'dark');
settings.set('lang', 'en');
```

### 5.3 Using Array Indices as Identifiers

**Problem**: Y.Array indices shift when items are inserted or deleted by other peers. Code that stores an index (e.g., "selected item is at index 3") breaks when another peer inserts or removes items.

```typescript
// BAD: index-based reference
let selectedIndex = 3;
const item = tasks.get(selectedIndex);
// After a peer inserts at index 0, the item at index 3 is now a different item.

// GOOD: ID-based lookup
const selectedId = 'task-abc-123';
function findById(id: string): Y.Map<any> | undefined {
  for (let i = 0; i < tasks.length; i++) {
    const task = tasks.get(i);
    if (task.get('id') === id) return task;
  }
  return undefined;
}
```

### 5.4 Storing Derived or Computed Data in the CRDT

**Problem**: Storing computed values (totals, counts, derived strings) in the CRDT creates conflicts between the source data and the derived data. Two peers computing a total from different states will write different totals.

```typescript
// BAD: storing a computed total
settings.set('taskCount', tasks.length);  // Conflicts if tasks change concurrently

// GOOD: compute on read
function getTaskCount(): number {
  return doc.getArray('tasks').length;
}
```

### 5.5 Deeply Nested Structures

**Problem**: Each level of nesting adds overhead. Y.js must traverse the tree for observations, and deeply nested structures increase the complexity of change tracking and serialization.

```typescript
// BAD: excessive nesting (5+ levels)
root.get('org').get('dept').get('team').get('member').set('name', 'Alice');

// BETTER: flatten with composite keys
const members = doc.getMap('members');
members.set('org:dept:team:alice', memberData);

// OR: separate documents for independent entities
// org-doc, team-doc, member-doc (loaded on demand)
```

**Rule of thumb**: Keep nesting to 2-3 levels. If you need deeper structures, flatten with composite keys or split into separate documents.

### 5.6 Using Y.Text for Non-Text Data

**Problem**: `Y.Text` is optimized for character-level text editing. Using it to store JSON, IDs, or other structured data incurs unnecessary overhead (character-level tombstones) and produces nonsensical merges when concurrent edits happen.

```typescript
// BAD: JSON in Y.Text
const data = doc.getText('config');
data.insert(0, JSON.stringify({ theme: 'dark' }));
// Concurrent edit: another peer inserts characters mid-JSON -> broken JSON

// GOOD: use Y.Map for structured data
const config = doc.getMap('config');
config.set('theme', 'dark');
```

### 5.7 Frequent Delete and Re-Insert in Y.Array

**Problem**: Every deletion in a Y.Array creates a tombstone that is never garbage collected. Patterns that frequently remove and re-add items (e.g., toggling visibility) accumulate tombstones, growing the document size and degrading performance.

```typescript
// BAD: toggle by remove/add
function toggleItem(id: string): void {
  const idx = findIndex(id);
  if (idx >= 0) {
    items.delete(idx, 1);  // creates tombstone
  } else {
    items.push([createItem(id)]);  // new item
  }
}

// GOOD: soft-delete flag
function toggleItem(id: string): void {
  const item = findById(id);
  if (item) {
    item.set('hidden', !item.get('hidden'));  // LWW, no tombstone
  }
}
```

---

## 6. Performance Considerations

### 6.1 Memory Usage per Shared Type

Y.js represents all shared types as linked lists of "items" internally. The memory cost depends on the number of items, not the type itself.

| Type | Per-Item Cost | Notes |
|------|--------------|-------|
| `Y.Map` entry | ~100-150 bytes | Key string + value + metadata |
| `Y.Array` element | ~80-120 bytes | Value + position metadata |
| `Y.Text` character | ~2-4 bytes (amortized) | Adjacent chars from same peer are merged into runs |
| Tombstone (deleted item) | ~40-80 bytes | Permanent; never garbage collected |

Y.Text is heavily optimized: sequential characters typed by the same peer are stored as a single "run" (one item containing the full string), so a 10,000-character paragraph from one author may use only a few items. However, if the text was built by character-by-character interleaving from many authors, each character is a separate item.

### 6.2 Update Overhead

| Operation | Relative Cost | Notes |
|-----------|--------------|-------|
| `Y.Map.set()` | Low | Single key update |
| `Y.Array.push()` | Low | Append is cheapest |
| `Y.Array.insert(0, ...)` | Low-Medium | Must reference predecessor |
| `Y.Array.delete()` | Low | Creates tombstone |
| `Y.Text.insert()` | Low | Merged into runs when possible |
| `Y.Text.format()` | Medium | Creates formatting markers |
| Deep observation | Medium-High | Traverses nested tree on each change |

**Batch operations in transactions** to reduce the number of update events:

```typescript
doc.transact(() => {
  // All changes in this block produce a single update event
  for (const item of newItems) {
    tasks.push([item]);
  }
  meta.set('updatedAt', Date.now());
});
```

### 6.3 Document Size Growth

Y.js documents grow monotonically because deleted items become tombstones. Growth rate depends on editing patterns:

- **Append-only** (e.g., chat messages): Grows linearly with content. Tombstone cost is minimal.
- **Heavy editing** (e.g., collaborative text): Grows with the total number of operations, not the final document size. A 1,000-character document that underwent 50,000 edits stores metadata for all 50,000 operations.
- **Frequent replacements** (e.g., setting map keys repeatedly): Each set creates a new item and tombstones the old one. Document size grows linearly with the number of set operations, not the number of keys.

**Reducing growth**:
- Use `Y.Text` for text content (character runs are compressed).
- Avoid high-frequency `Y.Map.set()` on the same key (e.g., don't store mouse position in the CRDT; use Y.js Awareness protocol instead).
- Periodically merge updates using `Y.mergeUpdates()` to reduce wire-level overhead (does not reduce tombstones, but compresses the binary encoding).

### 6.4 When to Split into Multiple Documents

Split a single Y.Doc into multiple documents when:

1. **Independent entities**: A wiki with 1,000 pages should not load all pages into one document. Each page should be a separate document.
2. **Access control boundaries**: Different parts of the data need different read/write permissions. Peerborne enforces ACL per document.
3. **Document exceeds ~1 MB** of encoded state. Performance degrades with very large documents due to encoding/decoding cost.
4. **High write contention on independent sections**: If two groups of users edit different sections, separate documents reduce merge overhead.
5. **Lazy loading**: Users should not need to download the entire dataset to view one item.

**Pattern**: An index document references child documents by ID.

```typescript
// Index document
const index = doc.getMap<Y.Map<any>>('documents');
index.set('doc-abc', { title: 'Meeting Notes', createdAt: Date.now() });

// Each child is a separate Peerborne document opened on demand
const meetingNotes = await swarm.openDocument('/docs/doc-abc');
```

### 6.5 Undo/Redo Implementation

Y.js provides `Y.UndoManager` for client-side undo/redo that is CRDT-aware. It tracks a stack of local changes and reverses them without affecting remote changes.

```typescript
const doc = new Y.Doc();
const content = doc.getText('content');

// Track changes to the text type
const undoManager = new Y.UndoManager(content);

content.insert(0, 'Hello');
content.insert(5, ' World');

undoManager.undo(); // Removes ' World'
undoManager.redo(); // Restores ' World'

// Only undoes local changes — remote changes are preserved.
```

**Multiple tracked types**:

```typescript
// Track changes to both content and metadata
const undoManager = new Y.UndoManager([content, metadata], {
  // Group changes within 500ms into a single undo step
  captureTimeout: 500,
});
```

---

## 7. Migration Strategies

### 7.1 Evolving Schemas Over Time

Y.js shared types are schema-less — a `Y.Doc` does not enforce a fixed structure. This means schemas evolve by convention, not by constraint. New peers can add new top-level types or nested structures without breaking existing peers.

### 7.2 Adding New Fields

Adding new fields to existing documents is straightforward because `Y.Map.get()` returns `undefined` for missing keys.

```typescript
// Version 1 schema: only 'title' and 'content'
// Version 2 schema: adds 'tags' and 'priority'

function readTask(task: Y.Map<any>) {
  const title = task.get('title') as string;
  const content = task.get('content') as string;

  // New fields — default gracefully when missing (from v1 peers)
  const tags = task.get('tags') as Y.Map<boolean> | undefined;
  const priority = (task.get('priority') as string) ?? 'medium';

  return { title, content, tags, priority };
}

// New peers set the new fields; old peers ignore them
function upgradeTask(task: Y.Map<any>): void {
  if (!task.has('priority')) {
    task.set('priority', 'medium');
  }
  if (!task.has('tags')) {
    task.set('tags', new Y.Map<boolean>());
  }
}
```

### 7.3 Handling Schema Version Mismatches

When peers running different schema versions synchronize, the CRDT merge succeeds at the data level but the application must handle unknown fields gracefully.

**Strategy: Version field with forward compatibility**:

```typescript
const meta = doc.getMap('meta');

// Always set version on document creation
meta.set('schemaVersion', 2);

function onDocumentLoad(doc: Y.Doc): void {
  const meta = doc.getMap('meta');
  const version = (meta.get('schemaVersion') as number) || 1;

  if (version < 2) {
    // Run migration for documents created by v1 peers
    migrateV1toV2(doc);
    meta.set('schemaVersion', 2);
  }

  if (version > 2) {
    // Newer schema — read what we can, ignore what we don't understand
    console.warn(`Document schema version ${version} is newer than supported (2). Some features may not work.`);
  }
}

function migrateV1toV2(doc: Y.Doc): void {
  const tasks = doc.getArray<Y.Map<any>>('tasks');
  for (let i = 0; i < tasks.length; i++) {
    const task = tasks.get(i);
    if (!task.has('priority')) {
      task.set('priority', 'medium');
    }
  }
}
```

**Key principles**:
- **Never remove fields** — old peers may still reference them. Set them to `null` or a sentinel value if deprecated.
- **Never change a field's type** — if `title` was a `string`, don't replace it with a `Y.Text`. Create a new field `titleText` instead.
- **Migrations are idempotent** — multiple peers may run the same migration concurrently. Use `has()` checks to avoid duplicating data.
- **Forward compatibility** — always ignore unknown keys gracefully. Never crash on unexpected data.

### 7.4 Renaming or Restructuring Fields

```typescript
// Renaming: copy data from old key to new key
function migrateRename(doc: Y.Doc): void {
  const meta = doc.getMap('meta');
  if (meta.has('name') && !meta.has('title')) {
    meta.set('title', meta.get('name'));
    // Don't delete 'name' — old peers may still read it
  }
}

// Restructuring: flatten a nested structure
function migrateFlatten(doc: Y.Doc): void {
  const meta = doc.getMap('meta');
  const address = meta.get('address') as Y.Map<any> | undefined;
  if (address && !meta.has('addressCity')) {
    meta.set('addressCity', address.get('city'));
    meta.set('addressState', address.get('state'));
    // Keep old 'address' for backward compatibility
  }
}
```

---

## 8. Integration with Peerborne

### 8.1 How Schemas Map to Peerborne's Provider Pattern

Peerborne's `YjsProvider` wraps `Y.Doc` operations. Your schema defines the structure of each document's `Y.Doc`:

```typescript
import { Peerborne, PeerborneDocument, SubtleCrypto } from '@peerborne/core';
import { YjsProvider, YjsJSONSerializer, YjsACLProvider, YjsKeychainProvider } from '@peerborne/yjs';
import * as Y from 'yjs';

// Initialize Peerborne with Yjs provider
const crdt = new YjsProvider();
const serializer = new YjsJSONSerializer();
const auth = new SubtleCrypto();
const acl = new YjsACLProvider();
const keychain = new YjsKeychainProvider();

// Open a document and apply schema
const swarmDoc = await swarm.openDocument('/projects/project-123');

// Change the document — the change function receives the Y.Doc
swarmDoc.change((doc: Y.Doc) => {
  const meta = doc.getMap('meta');
  meta.set('title', 'My Project');

  const tasks = doc.getArray<Y.Map<any>>('tasks');
  const task = new Y.Map();
  task.set('id', crypto.randomUUID());
  task.set('title', 'First task');
  tasks.push([task]);
});
```

The `YjsProvider.localChange()` method calls your function with the `Y.Doc`, then encodes the resulting state as a `Uint8Array` via `encodeStateAsUpdateV2()`. This binary is then signed, encrypted, and broadcast by Peerborne.

### 8.2 Using Schemas with Peerborne's ACL System

Peerborne enforces access control at the document level. Schema design should align with ACL boundaries:

```typescript
// Pattern: separate documents for different access levels
//
// /projects/proj-123/public   — readable by all members
// /projects/proj-123/admin    — readable/writable by admins only
// /projects/proj-123/secrets  — readable by authorized users only

// Public document: project overview
const publicDoc = await swarm.openDocument('/projects/proj-123/public');
publicDoc.change((doc: Y.Doc) => {
  doc.getMap('meta').set('title', 'Project Alpha');
  doc.getMap('meta').set('description', 'A public project overview');
});

// Admin document: settings and permissions
const adminDoc = await swarm.openDocument('/projects/proj-123/admin');
// Only admin keys are in this document's ACL
```

**Guidelines**:
- Data that different user groups should access belongs in different documents.
- Don't store public and private data in the same Y.Doc — Peerborne encrypts the entire document with one key.
- Use an index document (readable by all) to reference restricted child documents.

### 8.3 Schema Design Implications for Indexing

When Peerborne's indexing support is implemented (WS-5 in the roadmap), indexed fields must be readable from the Y.Doc structure. Design schemas with queryable fields at predictable paths:

```typescript
// GOOD: consistent field paths for indexing
// All task documents have meta.type = 'task', meta.status, meta.assignee
const meta = doc.getMap('meta');
meta.set('type', 'task');
meta.set('status', 'in-progress');
meta.set('assignee', 'alice');

// Index can query: type='task' AND status='in-progress' AND assignee='alice'

// BAD: inconsistent field locations
// Some tasks store status in 'meta.status', others in 'data.state'
// Index cannot reliably query across documents
```

**Recommendations**:
- Maintain consistent top-level `meta` maps across related documents.
- Use a `type` field to distinguish document kinds (tasks, pages, messages).
- Keep indexed fields as primitive values in `Y.Map` (not nested in arrays or text).

### 8.4 Encryption Considerations

Peerborne encrypts the entire Y.Doc state with AES-GCM using a document key managed by the `YjsKeychain`. Schema design implications:

- **All data in a Y.Doc is encrypted with the same key.** You cannot selectively encrypt parts of a document. If some fields need stronger access control, put them in a separate document.
- **Key rotation re-encrypts future updates, not past ones.** When a user is removed and the document key is rotated, the removed user retains access to the document state they already decrypted. Schema design cannot prevent this — it is a fundamental property of CRDTs where state is a function of all past operations.
- **Y.Text content is encrypted at the update level**, not at the character level. An eavesdropper with the document key sees all text content. Use separate documents for text at different classification levels.
- **Large binary data** (images, files) should be stored as separate encrypted documents or external content-addressed blobs, not inline in Y.Text or Y.Map values. This prevents document size bloat and allows independent access control.

```typescript
// Pattern: separate document per sensitivity level
const projectPublic = await swarm.openDocument('/proj/public');   // all members
const projectInternal = await swarm.openDocument('/proj/internal'); // team only
const projectSecret = await swarm.openDocument('/proj/secret');   // leads only
```

---

## Appendix: Schema Design Checklist

Use this checklist when designing a new schema:

1. **Identify entities and their independence**
   - [ ] Which entities are edited independently? (Separate Y.Doc per entity)
   - [ ] Which entities are always loaded together? (Same Y.Doc)

2. **Choose shared types for each field**
   - [ ] Atomic values: `Y.Map` (LWW per key)
   - [ ] Rich text: `Y.Text` or `Y.XmlFragment`
   - [ ] Ordered collections: `Y.Array` with nested `Y.Map`
   - [ ] Sets: `Y.Map<boolean>` (add-wins)
   - [ ] Counters: per-peer `Y.Map<number>` with summing

3. **Plan for concurrency**
   - [ ] What happens if two users edit the same field? (LWW acceptable?)
   - [ ] What happens if two users add items simultaneously? (Both preserved?)
   - [ ] Are there move operations? (Consider fractional indexing)

4. **Validate performance characteristics**
   - [ ] Estimated document size under normal usage
   - [ ] Tombstone growth from delete patterns
   - [ ] Nesting depth (keep to 2-3 levels)
   - [ ] Frequency of updates to the same keys

5. **Plan access control boundaries**
   - [ ] Which data needs different read/write permissions?
   - [ ] Split into separate documents per access level

6. **Plan for schema evolution**
   - [ ] Include a `schemaVersion` field
   - [ ] New fields have sensible defaults
   - [ ] Migrations are idempotent
   - [ ] Old field names are never reused for different purposes

7. **Test concurrent scenarios**
   - [ ] Simulate two peers editing the same field
   - [ ] Simulate two peers adding/removing the same collection item
   - [ ] Verify convergence after offline editing and reconnection
