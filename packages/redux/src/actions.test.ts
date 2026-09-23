import { describe, expect, test, jest, beforeEach } from '@jest/globals';

const actions = require('./actions');

describe('peerborne-redux sync action creators', () => {
  test('initialize action includes node', () => {
    const node = { id: 'mock-node' };
    const action = actions.initialize(node);
    expect(action.type).toBe('PEERBORNE_INITIALIZE');
    expect(action.node).toBe(node);
  });

  test('initialize action does not include _trace in production', () => {
    const action = actions.initialize({ id: 'n' });
    expect(action._trace).toBeUndefined();
  });

  test('connect action includes addresses', () => {
    const addrs = ['/ip4/1.2.3.4'];
    const action = actions.connect(addrs);
    expect(action.type).toBe('PEERBORNE_CONNECT');
    expect(action.addresses).toEqual(addrs);
  });

  test('openDocument action includes documentId and ref', () => {
    const action = actions.openDocument('/test/doc', { document: {} });
    expect(action.type).toBe('PEERBORNE_OPEN_DOCUMENT');
    expect(action.documentId).toBe('/test/doc');
  });

  test('closeDocument action includes documentId', () => {
    const action = actions.closeDocument('/test/doc');
    expect(action.type).toBe('PEERBORNE_CLOSE_DOCUMENT');
    expect(action.documentId).toBe('/test/doc');
  });

  test('syncDocument action includes documentId and document', () => {
    const action = actions.syncDocument('/test/doc', { text: 'synced' });
    expect(action.type).toBe('PEERBORNE_SYNC_DOCUMENT');
    expect(action.documentId).toBe('/test/doc');
  });

  test('peerConnect action includes address', () => {
    expect(actions.peerConnect('peer-addr-1').peerAddress).toBe('peer-addr-1');
  });

  test('action type constants are defined', () => {
    expect(actions.INITIALIZE).toBe('PEERBORNE_INITIALIZE');
    expect(actions.CONNECT).toBe('PEERBORNE_CONNECT');
    expect(actions.OPEN_DOCUMENT).toBe('PEERBORNE_OPEN_DOCUMENT');
    expect(actions.CLOSE_DOCUMENT).toBe('PEERBORNE_CLOSE_DOCUMENT');
    expect(actions.CHANGE_DOCUMENT).toBe('PEERBORNE_CHANGE_DOCUMENT');
    expect(actions.PEER_CONNECT).toBe('PEERBORNE_PEER_CONNECT');
    expect(actions.PEER_DISCONNECT).toBe('PEERBORNE_PEER_DISCONNECT');
  });
});

describe('peerborne-redux async thunks', () => {
  let dispatch: any;
  let getState: any;
  let mockNode: any;
  let mockDocRef: any;

  beforeEach(() => {
    dispatch = jest.fn();
    mockNode = {
      initialize: jest.fn().mockResolvedValue(undefined),
      connect: jest.fn().mockResolvedValue(undefined),
      doc: jest.fn().mockReturnValue(null),
      subscribeToPeerConnect: jest.fn(),
      subscribeToPeerDisconnect: jest.fn(),
    };
    mockDocRef = {
      document: { text: 'init' },
      open: jest.fn().mockResolvedValue(true),
      create: jest.fn().mockResolvedValue(false),
      close: jest.fn().mockResolvedValue(undefined),
      change: jest.fn().mockImplementation(async (fn: any) => mockDocRef.document),
      subscribe: jest.fn(),
      unsubscribe: jest.fn(),
    };
    getState = jest.fn();
  });

  test('connectAsync warns when node not initialized', async () => {
    getState.mockReturnValue({ documents: {}, peers: [] });
    await expect(actions.connectAsync(['addr1'])(dispatch, getState)).resolves.toBeUndefined();
  });

  test('connectAsync connects and dispatches when node exists', async () => {
    getState.mockReturnValue({ node: mockNode, documents: {}, peers: [] });
    await actions.connectAsync(['addr1'])(dispatch, getState);
    expect(mockNode.connect).toHaveBeenCalledWith(['addr1']);
    expect(dispatch).toHaveBeenCalledWith(expect.objectContaining({ type: 'PEERBORNE_CONNECT' }));
  });

  test('openDocumentAsync warns when node not initialized', async () => {
    getState.mockReturnValue({ documents: {}, peers: [] });
    const result = await actions.openDocumentAsync('/doc')(dispatch, getState);
    expect(result).toBeNull();
  });

  test('openDocumentAsync warns when no doc for path', async () => {
    mockNode.doc = jest.fn().mockReturnValue(null);
    getState.mockReturnValue({ node: mockNode, documents: {}, peers: [] });
    const result = await actions.openDocumentAsync('/doc')(dispatch, getState);
    expect(result).toBeNull();
  });

  test('openDocumentAsync opens document and dispatches', async () => {
    mockNode.doc = jest.fn().mockReturnValue(mockDocRef);
    getState.mockReturnValue({ node: mockNode, documents: {}, peers: [] });
    const result = await actions.openDocumentAsync('/doc')(dispatch, getState);
    expect(result).toBe(mockDocRef);
    expect(mockDocRef.open).toHaveBeenCalled();
  });

  test('creates only when explicitly requested', async () => {
    mockNode.doc.mockReturnValue(mockDocRef);
    getState.mockReturnValue({ node: mockNode, documents: {}, peers: [] });
    await actions.openDocumentAsync('/new', undefined, 'create')(dispatch, getState);
    expect(mockDocRef.create).toHaveBeenCalledTimes(1);
    expect(mockDocRef.open).not.toHaveBeenCalled();
  });

  test('does not create after an open failure and releases its subscription', async () => {
    mockNode.doc.mockReturnValue(mockDocRef);
    getState.mockReturnValue({ node: mockNode, documents: {}, peers: [] });
    mockDocRef.open.mockRejectedValue(new Error('No trusted state'));
    await expect(actions.openDocumentAsync('/existing')(dispatch, getState)).rejects.toThrow('No trusted state');
    expect(mockDocRef.create).not.toHaveBeenCalled();
    expect(mockDocRef.unsubscribe).toHaveBeenCalledWith('/existing');
    expect(mockDocRef.close).toHaveBeenCalledTimes(1);
    expect(dispatch).not.toHaveBeenCalled();
  });

  test('closeDocumentAsync closes open document', async () => {
    getState.mockReturnValue({
      documents: { '/doc': { documentRef: mockDocRef, document: {} } },
      peers: [],
    });
    await actions.closeDocumentAsync('/doc')(dispatch, getState);
    expect(mockDocRef.unsubscribe).toHaveBeenCalledWith('/doc');
    expect(mockDocRef.close).toHaveBeenCalled();
    expect(dispatch).toHaveBeenCalledWith(expect.objectContaining({ type: 'PEERBORNE_CLOSE_DOCUMENT' }));
  });

  test('changeDocumentAsync throws when document not open', async () => {
    getState.mockReturnValue({ documents: {}, peers: [] });
    await expect(actions.changeDocumentAsync('/doc', {})(dispatch, getState)).rejects.toThrow(/not opened/);
  });

  test('changeDocumentAsync changes document and dispatches', async () => {
    const changeFn = {};
    getState.mockReturnValue({
      documents: { '/doc': { documentRef: mockDocRef, document: { text: 'old' } } },
      peers: [],
    });
    await actions.changeDocumentAsync('/doc', changeFn, 'a message')(dispatch, getState);
    expect(mockDocRef.change).toHaveBeenCalledWith(changeFn, 'a message');
    expect(dispatch).toHaveBeenCalledWith(expect.objectContaining({ type: 'PEERBORNE_CHANGE_DOCUMENT' }));
  });
});
