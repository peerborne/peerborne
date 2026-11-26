import type { ChangesSerializer } from '../changes-serializer.js';
import type { CRDTProvider } from '../crdt-provider.js';
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
 * Member 1 edits while its publication fails, then the controller adds
 * member 2 in a new epoch. Member 2 resumes from the controller checkpoint;
 * member 1 learns the epoch, re-signs its unsent edit and keeps editing.
 */
export async function retiredEpochScenario<Document, Changes, Change>(
  adapter: ScenarioAdapter<Document, Changes, Change>,
) {
  const g = await coordinatedGroupFixture(adapter.crdt, adapter.serializer, {
    members: 3,
    catchUp: true,
  });
  const errors: string[] = [];
  const deliverAll = async (recipients: number[]) => {
    for (const publication of g.take())
      errors.push(...(await g.deliver(publication, recipients)));
  };
  try {
    await g.addMember(1);
    await g.open(0);
    await g.open(1);
    await g.doc(0).change(adapter.edit('c0'));
    await g.doc(1).change(adapter.edit('m1a'));
    await deliverAll([0, 1]);
    const publish = g.pubsubs[1].publish;
    g.pubsubs[1].publish = async () => {
      throw new Error('offline');
    };
    let offline = '';
    try {
      await g.doc(1).change(adapter.edit('offlineEdit'));
    } catch (error) {
      offline = (error as Error).message;
    }
    const { delivery, record } = await g.addMember(2, { applyTo: [] });
    await g.open(2);
    const request = await g.doc(2).createSecurityCatchUpRequest();
    await g
      .doc(2)
      .applySecurityCatchUpCheckpoint(
        await g.doc(0).createSecurityCatchUpCheckpoint(request),
      );
    g.pubsubs[1].publish = publish;
    await g.coordinators[1].applyCommit(
      delivery.commit!,
      delivery.controlRecord,
      delivery.welcomes,
    );
    const update = await g.doc(1).applySecurityAuthorityUpdate(record);
    await g.doc(1).retrySecurityPublications();
    await deliverAll([0, 2]);
    await g.doc(1).change(adapter.edit('afterReturn'));
    await deliverAll([0, 2]);
    await g.doc(1).retrySecurityPublications();
    const leftover = g.take().length;
    return {
      offline,
      update,
      errors,
      leftover,
      views: [0, 1, 2].map((index) => adapter.read(g.doc(index).document)),
    };
  } finally {
    await g.close();
  }
}
