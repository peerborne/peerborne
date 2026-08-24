import { Action } from 'redux';
import { ThunkAction } from 'redux-thunk';
import { PeerborneState } from './reducers.js';
import { defaultStateSelector } from './default-state-selector.js';
import {
  Peerborne,
  PeerborneDocument,
  PeerborneConfig,
  defaultConfig,
  defaultBootstrapConfig,
} from '@peerborne/core';

/**
 * Captures the current call stack for debugging when in development mode.
 * Returns undefined in production to avoid performance overhead.
 */
function captureTrace(): string | undefined {
  if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'development') {
    return new Error().stack;
  }
  return undefined;
}

export function initializeAsync<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
  RootStateType = PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
>(
  config: PeerborneConfig | undefined = undefined,
  selectPeerborneState: (
    rootState: RootStateType,
  ) => PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > = defaultStateSelector,
): ThunkAction<
  Promise<
    Peerborne<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  >,
  RootStateType,
  unknown,
  | InitializeAction<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  | PeerConnectAction
  | PeerDisconnectAction
> {
  if (!config) {
    config = defaultConfig(defaultBootstrapConfig([]));
  }
  return async (dispatch, getState) => {
    const { node } = selectPeerborneState(getState());
    node.subscribeToPeerConnect('peer-connect', (address: string) => {
      dispatch(peerConnect(address, captureTrace()));
    });
    node.subscribeToPeerDisconnect('peer-disconnect', (address: string) => {
      dispatch(peerDisconnect(address, captureTrace()));
    });
    await node.initialize(config);
    dispatch(initialize(node, captureTrace()));
    return node;
  };
}

export const INITIALIZE = 'COLLABSWARM_INITIALIZE';
export interface InitializeAction<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> extends Action<typeof INITIALIZE> {
  node: Peerborne<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
  _trace?: string;
}
export function initialize<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
>(
  node: Peerborne<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
  _trace?: string,
): InitializeAction<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> {
  return { type: INITIALIZE, node, ...(_trace != null && { _trace }) };
}

export function connectAsync<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
  RootStateType = PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
>(
  addresses: string[],
  selectPeerborneState: (
    rootState: RootStateType,
  ) => PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > = defaultStateSelector,
): ThunkAction<Promise<void>, RootStateType, unknown, ConnectAction> {
  return async (dispatch, getState) => {
    const { node } = selectPeerborneState(getState());
    if (!node) {
      console.warn(
        'Node not initialized yet! Unable to connect to:',
        addresses,
      );
      return;
    }
    await node.connect(addresses);
    dispatch(connect(addresses, captureTrace()));
  };
}

export const CONNECT = 'COLLABSWARM_CONNECT';
export interface ConnectAction extends Action<typeof CONNECT> {
  addresses: string[];
  _trace?: string;
}
export function connect(addresses: string[], _trace?: string): ConnectAction {
  return { type: CONNECT, addresses, ...(_trace != null && { _trace }) };
}

export function openDocumentAsync<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
  RootStateType = PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
>(
  documentId: string,
  selectPeerborneState: (
    rootState: RootStateType,
  ) => PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > = defaultStateSelector,
): ThunkAction<
  Promise<PeerborneDocument<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > | null>,
  RootStateType,
  unknown,
  | OpenDocumentAction<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  | CloseDocumentAction
  | SyncDocumentAction<DocType>
> {
  return async (dispatch, getState) => {
    const { node } = selectPeerborneState(getState());
    if (!node) {
      console.warn(
        'Node not initialized yet! Unable to open document:',
        documentId,
      );
      return null;
    }
    // Close previous document if one is already open with this ID.
    const { documents } = selectPeerborneState(getState());
    if (documents[documentId] && documents[documentId].documentRef) {
      const prevRef = documents[documentId].documentRef;
      prevRef.unsubscribe(documentId);
      await prevRef.close();
      dispatch(closeDocument(documentId, captureTrace()));
    }

    const documentRef = node.doc(documentId);
    if (documentRef) {
      documentRef.subscribe(
        documentId,
        (document) => {
          dispatch(syncDocument(documentId, document, captureTrace()));
        },
        'remote',
      );
      const loaded = await documentRef.open();
      if (!loaded) {
        // Assume this is a new document.
        console.log(
          'Failed to load document from peers, assuming this is a new document...',
          documentRef,
        );
        // await documentRef.pin();
      }
      dispatch(openDocument(documentId, documentRef, captureTrace()));
      return documentRef;
    } else {
      console.warn('Unable to find document:', documentId);
      return null;
    }
  };
}

export const OPEN_DOCUMENT = 'COLLABSWARM_OPEN_DOCUMENT';
export interface OpenDocumentAction<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> extends Action<typeof OPEN_DOCUMENT> {
  documentId: string;
  documentRef: PeerborneDocument<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
  _trace?: string;
}
export function openDocument<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
>(
  documentId: string,
  documentRef: PeerborneDocument<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
  _trace?: string,
): OpenDocumentAction<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> {
  return { type: OPEN_DOCUMENT, documentId, documentRef, ...(_trace != null && { _trace }) };
}

export function closeDocumentAsync<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
  RootStateType = PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
>(
  documentId: string,
  selectPeerborneState: (
    rootState: RootStateType,
  ) => PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > = defaultStateSelector,
): ThunkAction<
  Promise<void>,
  RootStateType,
  unknown,
  CloseDocumentAction | SyncDocumentAction<DocType>
> {
  return async (dispatch, getState) => {
    const { documents } = selectPeerborneState(getState());
    if (documents[documentId] && documents[documentId].documentRef) {
      const documentRef = documents[documentId].documentRef;
      documentRef.unsubscribe(documentId);
      await documentRef.close();
      dispatch(closeDocument(documentId, captureTrace()));
    } else {
      console.warn('Closing a document that was not opened:', documentId);
    }
  };
}

export const CLOSE_DOCUMENT = 'COLLABSWARM_CLOSE_DOCUMENT';
export interface CloseDocumentAction extends Action<typeof CLOSE_DOCUMENT> {
  documentId: string;
  _trace?: string;
}
export function closeDocument(documentId: string, _trace?: string): CloseDocumentAction {
  return { type: CLOSE_DOCUMENT, documentId, ...(_trace != null && { _trace }) };
}

export const SYNC_DOCUMENT = 'COLLABSWARM_SYNC_DOCUMENT';
export interface SyncDocumentAction<DocType>
  extends Action<typeof SYNC_DOCUMENT> {
  documentId: string;
  document: DocType;
  _trace?: string;
}
export function syncDocument<DocType>(
  documentId: string,
  document: DocType,
  _trace?: string,
): SyncDocumentAction<DocType> {
  return { type: SYNC_DOCUMENT, documentId, document, ...(_trace != null && { _trace }) };
}

export function changeDocumentAsync<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
  RootStateType = PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >,
>(
  documentId: string,
  changeFn: ChangeFnType,
  message?: string,
  selectPeerborneState: (
    rootState: RootStateType,
  ) => PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > = defaultStateSelector,
): ThunkAction<
  Promise<DocType>,
  RootStateType,
  unknown,
  ChangeDocumentAction<DocType>
> {
  return async (dispatch, getState) => {
    const { documents } = selectPeerborneState(getState());
    if (documents[documentId] && documents[documentId].documentRef) {
      const documentRef = documents[documentId].documentRef;
      const changePromise = documentRef.change(changeFn, message);
      dispatch(changeDocument(documentId, documentRef.document, captureTrace()));
      await changePromise;
      return documentRef.document;
    } else {
      throw new Error(
        `Trying to edit a document that is not opened: ${documentId}`,
      );
    }
  };
}

export const CHANGE_DOCUMENT = 'COLLABSWARM_CHANGE_DOCUMENT';
export interface ChangeDocumentAction<DocType>
  extends Action<typeof CHANGE_DOCUMENT> {
  documentId: string;
  document: DocType;
  _trace?: string;
}
export function changeDocument<DocType>(
  documentId: string,
  document: DocType,
  _trace?: string,
): ChangeDocumentAction<DocType> {
  return { type: CHANGE_DOCUMENT, documentId, document, ...(_trace != null && { _trace }) };
}

export const PEER_CONNECT = 'COLLABSWARM_PEER_CONNECT';
export interface PeerConnectAction extends Action<typeof PEER_CONNECT> {
  peerAddress: string;
  _trace?: string;
}
export function peerConnect(peerAddress: string, _trace?: string): PeerConnectAction {
  return { type: PEER_CONNECT, peerAddress, ...(_trace != null && { _trace }) };
}

export const PEER_DISCONNECT = 'COLLABSWARM_PEER_DISCONNECT';
export interface PeerDisconnectAction extends Action<typeof PEER_DISCONNECT> {
  peerAddress: string;
  _trace?: string;
}
export function peerDisconnect(peerAddress: string, _trace?: string): PeerDisconnectAction {
  return { type: PEER_DISCONNECT, peerAddress, ...(_trace != null && { _trace }) };
}

export type PeerborneActions<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> =
  | InitializeAction<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  | ConnectAction
  | OpenDocumentAction<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >
  | CloseDocumentAction
  | SyncDocumentAction<DocType>
  | ChangeDocumentAction<DocType>
  | PeerConnectAction
  | PeerDisconnectAction;
