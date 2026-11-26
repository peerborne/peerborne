import type { ChangesSerializer } from '../changes-serializer.js';
import type { CRDTProvider } from '../crdt-provider.js';
import { isDocumentRedeliveryFrame } from '../document-redelivery-wire.js';
import {
  isDocumentCatchUpCheckpointFrame,
  isDocumentCatchUpRequestFrame,
} from '../document-catch-up-wire.js';
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

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The publications and pubsub handlers of a fixture group. */
interface FloodGroup {
  take(): GroupPublication[];
  dispatch(publication: GroupPublication, recipient: number): void;
}

/** The coordinated engine behind a fixture member's document. */
export const engineOf = (document: object) =>
  (
    document as unknown as {
      _coordinated: { needsJoinCatchUp(): boolean; hasHeldFrames(): boolean };
    }
  )._coordinated;

/**
 * Flood every publication to every other listed member through its real
 * pubsub handler, as GossipSub would, until `done` holds.
 */
export async function floodUntil(
  g: FloodGroup,
  members: readonly number[],
  done: () => boolean,
  within = 30_000,
  seen: (publication: GroupPublication) => void = () => {},
): Promise<boolean> {
  for (const started = Date.now(); Date.now() - started < within; ) {
    for (const publication of g.take()) {
      seen(publication);
      for (const recipient of members)
        if (recipient !== publication.sender) g.dispatch(publication, recipient);
    }
    if (done()) return true;
    await pause(20);
  }
  return done();
}

/** Catch-up and redelivery messages seen on the topic, by kind and sender. */
function count() {
  const value = { requests: [] as number[], checkpoints: [] as number[], redeliveries: [] as number[] };
  return {
    value,
    seen: ({ sender, data }: GroupPublication) => {
      if (isDocumentCatchUpRequestFrame(data)) value.requests.push(sender);
      else if (isDocumentCatchUpCheckpointFrame(data))
        value.checkpoints.push(sender);
      else if (isDocumentRedeliveryFrame(data)) value.redeliveries.push(sender);
    },
  };
}

function holds(read: (index: number) => unknown) {
  return (index: number, labels: readonly string[]) => {
    const view = JSON.stringify(read(index));
    return labels.every((label) => view.includes(`"${label}"`));
  };
}

/**
 * Members 0 and 1 edit; the controller then adds member 2 in a new epoch.
 * Every replica opens and edits with publications flooded between them, and
 * no member relays a catch-up message itself.
 */
export async function joinCatchUpScenario<Document, Changes, Change>(
  adapter: ScenarioAdapter<Document, Changes, Change>,
) {
  const g = await coordinatedGroupFixture(adapter.crdt, adapter.serializer, {
    members: 3,
    catchUp: true,
    peers: true,
  });
  const has = holds((index) => adapter.read(g.doc(index).document));
  const all = (members: readonly number[], labels: readonly string[]) => () =>
    members.every((index) => has(index, labels));
  try {
    await g.addMember(1);
    await g.open(0);
    await g.open(1);
    await g.doc(0).change(adapter.edit('first'));
    await g.doc(1).change(adapter.edit('second'));
    const before = await floodUntil(
      g,
      [0, 1],
      all([0, 1], ['first', 'second']),
    );
    await g.addMember(2);
    await g.open(2);
    const empty = adapter.read(g.doc(2).document);
    const traffic = count();
    const joined = await floodUntil(
      g,
      [0, 1, 2],
      all([2], ['first', 'second']),
      30_000,
      traffic.seen,
    );
    await g.doc(1).change(adapter.edit('third'));
    await g.doc(2).change(adapter.edit('fourth'));
    const after = await floodUntil(
      g,
      [0, 1, 2],
      all([0, 1, 2], ['first', 'second', 'third', 'fourth']),
    );
    return {
      before,
      empty,
      joined,
      after,
      traffic: traffic.value,
      views: [0, 1, 2].map((index) => adapter.read(g.doc(index).document)),
    };
  } finally {
    await g.close();
  }
}

/**
 * Member 2 misses more of member 1's frames than any peer retains. A later
 * frame of member 1 waits at member 2, redelivery finds nothing to resend,
 * and member 2 resumes from a checkpoint carried on the topic.
 */
export async function missedWindowCatchUpScenario<Document, Changes, Change>(
  adapter: ScenarioAdapter<Document, Changes, Change>,
  missed = 70,
) {
  const g = await coordinatedGroupFixture(adapter.crdt, adapter.serializer, {
    members: 3,
    catchUp: true,
    peers: true,
  });
  const has = holds((index) => adapter.read(g.doc(index).document));
  const labels: string[] = [];
  try {
    await g.addMember(1);
    await g.addMember(2);
    for (let index = 0; index < 3; index++) await g.open(index);
    await g.doc(0).change(adapter.edit('base'));
    const joined = await floodUntil(
      g,
      [0, 1, 2],
      () =>
        [1, 2].every(
          (index) =>
            has(index, ['base']) && !engineOf(g.doc(index)).needsJoinCatchUp(),
        ),
    );
    for (let index = 0; index < missed; index++) {
      const label = `w${index}`;
      labels.push(label);
      await g.doc(1).change(adapter.edit(label));
      for (const publication of g.take())
        if (
          publication.sender === 1 &&
          !isDocumentRedeliveryFrame(publication.data)
        )
          await g.deliver(publication, [0]);
    }
    const behind = !has(2, labels.slice(0, 1));
    await g.doc(1).change(adapter.edit('late'));
    labels.push('late');
    const traffic = count();
    const recovered = await floodUntil(
      g,
      [0, 1, 2],
      () => has(2, labels),
      30_000,
      traffic.seen,
    );
    await g.doc(1).change(adapter.edit('next'));
    labels.push('next');
    const live = await floodUntil(g, [0, 1, 2], () =>
      [0, 1, 2].every((index) => has(index, labels)),
    );
    return {
      joined,
      behind,
      recovered,
      live,
      traffic: traffic.value,
      held: engineOf(g.doc(2)).hasHeldFrames(),
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
