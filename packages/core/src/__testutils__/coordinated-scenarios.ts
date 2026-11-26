import type { ChangesSerializer } from '../changes-serializer.js';
import type { CRDTProvider } from '../crdt-provider.js';
import { isDocumentRedeliveryFrame } from '../document-redelivery-wire.js';
import {
  coordinatedGroupFixture,
  type GroupPublication,
} from './coordinated-group.js';

export interface ScenarioAdapter<Document, Changes, Change> {
  readonly crdt: CRDTProvider<Document, Changes, Change>;
  readonly serializer: ChangesSerializer<Changes>;
  /** A native edit that depends on everything the editing replica holds. */
  edit(label: string): Change;
  /** A JSON-comparable view of the document. */
  read(document: Document): unknown;
}

/**
 * Members 1 and 2 build a causal chain, each editing after receiving the
 * other's previous frame. Member 0 receives the chain in `order`.
 */
export async function crossAuthorReorderScenario<Document, Changes, Change>(
  adapter: ScenarioAdapter<Document, Changes, Change>,
  order: (chain: readonly GroupPublication[]) => readonly GroupPublication[],
  length = 6,
) {
  const g = await coordinatedGroupFixture(adapter.crdt, adapter.serializer, {
    members: 3,
  });
  const errors: string[] = [];
  const views = () =>
    [0, 1, 2].map((index) => adapter.read(g.doc(index).document));
  try {
    await g.addMember(1);
    await g.addMember(2);
    for (let index = 0; index < 3; index++) await g.open(index);
    for (let index = 0; index < 3; index++)
      await g.doc(index).change(adapter.edit(`m${index}`));
    for (const publication of g.take())
      errors.push(...(await g.deliver(publication, [0, 1, 2])));
    const chain: GroupPublication[] = [];
    for (let step = 0; step < length; step++) {
      const author = 1 + (step % 2);
      await g.doc(author).change(adapter.edit(`c${step}`));
      const [publication] = g.take();
      chain.push(publication);
      errors.push(...(await g.deliver(publication, [3 - author])));
    }
    const held: boolean[] = [];
    for (const publication of order(chain)) {
      try {
        held.push(!(await g.doc(0).receiveSecurityFrame(publication.data)));
      } catch (error) {
        errors.push(`0: ${(error as Error).message}`);
      }
    }
    const reordered = views();
    for (const author of [1, 2]) {
      await g.doc(author).change(adapter.edit(`after${author}`));
      for (const publication of g.take())
        errors.push(...(await g.deliver(publication, [0, 1, 2])));
    }
    return { errors, held, reordered, final: views() };
  } finally {
    await g.close();
  }
}

/**
 * Member 2 receives the first of member 1's frames, misses the second and
 * the controller's edit, then resumes through the controller checkpoint.
 */
export async function missedTailCatchUpScenario<Document, Changes, Change>(
  adapter: ScenarioAdapter<Document, Changes, Change>,
) {
  const g = await coordinatedGroupFixture(adapter.crdt, adapter.serializer, {
    members: 3,
    catchUp: true,
  });
  const errors: string[] = [];
  const edit = async (author: number, label: string, recipients: number[]) => {
    await g.doc(author).change(adapter.edit(label));
    for (const publication of g.take())
      errors.push(...(await g.deliver(publication, recipients)));
  };
  try {
    await g.addMember(1);
    await g.addMember(2);
    for (let index = 0; index < 3; index++) await g.open(index);
    await edit(1, 'one', [0, 2]);
    await edit(1, 'two', [0]);
    await edit(0, 'ctl', [1]);
    const request = await g.doc(2).createSecurityCatchUpRequest();
    const checkpoint = await g.doc(0).createSecurityCatchUpCheckpoint(request);
    await g.doc(2).applySecurityCatchUpCheckpoint(checkpoint);
    await edit(1, 'three', [0, 2]);
    await edit(2, 'four', [0, 1]);
    return {
      errors,
      views: [0, 1, 2].map((index) => adapter.read(g.doc(index).document)),
    };
  } finally {
    await g.close();
  }
}

/**
 * Members 1 and 2 build a causal chain. Member 0 never receives its first
 * frame, holds the rest, and recovers through a redelivery request.
 */
export async function lostFrameRedeliveryScenario<Document, Changes, Change>(
  adapter: ScenarioAdapter<Document, Changes, Change>,
) {
  const g = await coordinatedGroupFixture(adapter.crdt, adapter.serializer, {
    members: 3,
    peers: true,
  });
  const errors: string[] = [];
  const content = () =>
    g.take().filter((publication) => !isDocumentRedeliveryFrame(publication.data));
  try {
    await g.addMember(1);
    await g.addMember(2);
    for (let index = 0; index < 3; index++) await g.open(index);
    const chain: GroupPublication[] = [];
    for (let step = 0; step < 4; step++) {
      const author = 1 + (step % 2);
      await g.doc(author).change(adapter.edit(`c${step}`));
      const [publication] = content();
      chain.push(publication);
      errors.push(...(await g.deliver(publication, [3 - author])));
    }
    for (const publication of chain.slice(1))
      errors.push(...(await g.deliver(publication, [0])));
    const held = adapter.read(g.doc(0).document);
    g.take();
    await g.doc(0).requestSecurityRedelivery();
    const [request] = g
      .take()
      .filter((publication) => isDocumentRedeliveryFrame(publication.data));
    g.dispatch(request, 1);
    g.dispatch(request, 2);
    for (let turn = 0; g.publications.length === 0 && turn < 300; turn++)
      await new Promise((resolve) => setTimeout(resolve, 10));
    await new Promise((resolve) => setTimeout(resolve, 700));
    for (const publication of content())
      errors.push(...(await g.deliver(publication, [0])));
    return {
      errors,
      held,
      views: [0, 1, 2].map((index) => adapter.read(g.doc(index).document)),
    };
  } finally {
    await g.close();
  }
}
