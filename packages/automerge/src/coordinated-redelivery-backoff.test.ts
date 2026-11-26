import { expect, jest, test } from '@jest/globals';
import type { Doc } from '@automerge/automerge';
import {
  AutomergeJSONSerializer,
  AutomergeProvider,
} from './peerborne-automerge.js';
import { coordinatedGroupFixture } from '../../core/src/__testutils__/coordinated-group.js';
import { isDocumentRedeliveryFrame } from '../../core/src/document-redelivery-wire.js';

jest.mock('@helia/unixfs', () => ({ unixfs: () => ({}) }));

type State = Record<string, number>;
const edit = (label: string) => (draft: State) => {
  draft[label] = label.length;
};
const read = (document: Doc<State>) => JSON.parse(JSON.stringify(document));
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

test('a frame that cannot be released does not loop redelivery requests or answers', async () => {
  const g = await coordinatedGroupFixture(
    new AutomergeProvider<State>(),
    new AutomergeJSONSerializer(),
    { members: 3, peers: true },
  );
  const isRequest = (publication: { data: Uint8Array }) =>
    isDocumentRedeliveryFrame(publication.data);
  const nextRequest = async (within: number) => {
    for (let waited = 0; waited < within; waited += 10) {
      const index = g.publications.findIndex(
        (publication) => publication.sender === 2 && isRequest(publication),
      );
      if (index >= 0) return g.publications.splice(index, 1)[0];
      await pause(10);
    }
    return undefined;
  };
  try {
    await g.addMember(1);
    await g.open(0);
    await g.open(1);
    await g.doc(0).change(edit('before'));
    for (const publication of g.take().filter((value) => !isRequest(value)))
      expect(await g.deliver(publication, [1])).toEqual([]);
    await g.addMember(2);
    await g.open(2);
    expect(await nextRequest(3_000)).toBeDefined();
    g.take();
    await g.doc(1).change(edit('after'));
    for (const publication of g.take().filter((value) => !isRequest(value)))
      expect(await g.deliver(publication, [0, 2])).toEqual([]);
    expect(read(g.doc(2).document)).toEqual({});
    const request = await nextRequest(3_000);
    expect(request).toBeDefined();
    g.take();
    g.dispatch(request!, 0);
    g.dispatch(request!, 1);
    await pause(700);
    expect(g.take().filter((value) => !isRequest(value))).toEqual([]);
    // The next request waits for the 5 s backoff instead of following every receive.
    expect(await nextRequest(3_500)).toBeUndefined();
    expect(read(g.doc(2).document)).toEqual({});
  } finally {
    await g.close();
  }
}, 30_000);
