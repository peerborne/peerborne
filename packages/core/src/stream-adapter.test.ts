import { describe, expect, test, jest, beforeEach } from '@jest/globals';
import { wrapStream, DuplexStream } from './stream-adapter';

describe('wrapStream', () => {
  let sendMock: any;
  let onDrainMock: any;
  let closeMock: any;
  let wrapped: DuplexStream;

  beforeEach(() => {
    sendMock = jest.fn();
    onDrainMock = jest.fn();
    closeMock = jest.fn();

    async function* asyncGen() {
      yield new Uint8Array([4, 5, 6]);
    }
    const mockStream = {
      send: sendMock,
      onDrain: onDrainMock,
      close: closeMock,
      [Symbol.asyncIterator]: asyncGen,
    } as any;
    wrapped = wrapStream(mockStream);
  });

  test('sends all chunks and then half-closes', async () => {
    sendMock.mockReturnValue(true);
    closeMock.mockResolvedValue(undefined);
    const chunks = [new Uint8Array([1, 2]), new Uint8Array([3, 4])];
    await wrapped.sink(chunks);
    expect(sendMock).toHaveBeenCalledTimes(2);
    expect(closeMock).toHaveBeenCalledTimes(1);
  });

  test('awaits onDrain when send returns false', async () => {
    sendMock.mockReturnValueOnce(false).mockReturnValue(true);
    onDrainMock.mockResolvedValue(undefined);
    closeMock.mockResolvedValue(undefined);
    await wrapped.sink([new Uint8Array([1]), new Uint8Array([2])]);
    expect(onDrainMock).toHaveBeenCalledTimes(1);
    expect(closeMock).toHaveBeenCalledTimes(1);
  });

  test('calls close even with no chunks', async () => {
    sendMock.mockReturnValue(true);
    closeMock.mockResolvedValue(undefined);
    await wrapped.sink([]);
    expect(closeMock).toHaveBeenCalledTimes(1);
    expect(sendMock).not.toHaveBeenCalled();
  });

  test('close delegates to stream.close()', async () => {
    closeMock.mockResolvedValue(undefined);
    await wrapped.close();
    expect(closeMock).toHaveBeenCalledTimes(1);
  });

  test('sink does not close if stream throws during send', async () => {
    const failingStream = {
      send: jest.fn().mockImplementation(() => { throw new Error('send failed'); }),
      onDrain: async () => {},
      close: jest.fn(),
      [Symbol.asyncIterator]: async function* () {},
    } as any;
    const w = wrapStream(failingStream);
    await expect(w.sink([new Uint8Array([1])])).rejects.toThrow('send failed');
    expect(failingStream.close).not.toHaveBeenCalled();
  });
});