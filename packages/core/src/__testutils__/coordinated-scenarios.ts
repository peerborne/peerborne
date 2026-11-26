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
