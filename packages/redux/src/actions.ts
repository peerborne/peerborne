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
  type ChangeDeliveryFailure,
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

function deliverySubscriptionId(documentId: string): string {
  return `${documentId}#delivery`;
}

function releaseDocument(
  documentRef: Pick<
    PeerborneDocument<unknown, unknown, unknown, unknown, unknown, unknown>,
    'unsubscribe' | 'unsubscribeDeliveryFailures'
  >,
  documentId: string,
): void {
  documentRef.unsubscribe(documentId);
  documentRef.unsubscribe(deliverySubscriptionId(documentId));
  documentRef.unsubscribeDeliveryFailures(documentId);
}

function requirePeerborneState<RootStateType, State>(
  selectPeerborneState: (rootState: RootStateType) => State,
  rootState: RootStateType,
): State {
  const state = selectPeerborneState(rootState);
  const { node, documents, peers } = (state ?? {}) as Partial<
    Record<'node' | 'documents' | 'peers', unknown>
  >;
  if (
    typeof node !== 'object' ||
    node === null ||
    typeof documents !== 'object' ||
    documents === null ||
    !Array.isArray(peers)
  ) {
    throw new TypeError(
      'Peerborne Redux state was not found. The default selector expects ' +
        'peerborneReducer at the root of the store; pass a selector such as ' +
        '(state) => state.peerborne when the reducer is nested.',
    );
  }
  return state;
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
    const { node } = requirePeerborneState(selectPeerborneState, getState());
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

export const INITIALIZE = 'PEERBORNE_INITIALIZE';
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
    const { node } = requirePeerborneState(selectPeerborneState, getState());
    await node.connect(addresses);
    dispatch(connect(addresses, captureTrace()));
  };
}

export const CONNECT = 'PEERBORNE_CONNECT';
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
  initialization: 'open' | 'create' = 'open',
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
  | DeliveryFailureAction
> {
  return async (dispatch, getState) => {
    const { node } = requirePeerborneState(selectPeerborneState, getState());
    // Close previous document if one is already open with this ID.
    const { documents } = requirePeerborneState(selectPeerborneState, getState());
    if (documents[documentId] && documents[documentId].documentRef) {
      const prevRef = documents[documentId].documentRef;
      releaseDocument(prevRef, documentId);
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
      try {
        await documentRef[initialization]();
      } catch (error) {
        documentRef.unsubscribe(documentId);
        await documentRef.close().catch(() => undefined);
        throw error;
      }
      dispatch(openDocument(documentId, documentRef, captureTrace()));
      const reportDelivery = () => {
        const current =
          selectPeerborneState(getState())?.documents?.[documentId];
        if (
          current?.documentRef === documentRef &&
          current.deliveryFailure !== documentRef.deliveryFailure
        ) {
          dispatch(
            deliveryFailure(
              documentId,
              documentRef.deliveryFailure,
              captureTrace(),
            ),
          );
        }
      };
      documentRef.subscribeDeliveryFailures(documentId, reportDelivery);
      documentRef.subscribe(
        deliverySubscriptionId(documentId),
        reportDelivery,
        'local',
      );
      return documentRef;
    } else {
      console.warn('Unable to find document:', documentId);
      return null;
    }
  };
}

export const OPEN_DOCUMENT = 'PEERBORNE_OPEN_DOCUMENT';
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
    const { documents } = requirePeerborneState(selectPeerborneState, getState());
    if (documents[documentId] && documents[documentId].documentRef) {
      const documentRef = documents[documentId].documentRef;
      releaseDocument(documentRef, documentId);
      await documentRef.close();
      dispatch(closeDocument(documentId, captureTrace()));
    } else {
      console.warn('Closing a document that was not opened:', documentId);
    }
  };
}

export const CLOSE_DOCUMENT = 'PEERBORNE_CLOSE_DOCUMENT';
export interface CloseDocumentAction extends Action<typeof CLOSE_DOCUMENT> {
  documentId: string;
  _trace?: string;
}
export function closeDocument(documentId: string, _trace?: string): CloseDocumentAction {
  return { type: CLOSE_DOCUMENT, documentId, ...(_trace != null && { _trace }) };
}

export const SYNC_DOCUMENT = 'PEERBORNE_SYNC_DOCUMENT';
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
    const { documents } = requirePeerborneState(selectPeerborneState, getState());
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

export const CHANGE_DOCUMENT = 'PEERBORNE_CHANGE_DOCUMENT';
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

export const DELIVERY_FAILURE = 'PEERBORNE_DELIVERY_FAILURE';
/**
 * The document's latest local change that is committed but undelivered, or
 * `undefined` once a later local change's frame is published and carries it.
 */
export interface DeliveryFailureAction extends Action<typeof DELIVERY_FAILURE> {
  documentId: string;
  deliveryFailure: ChangeDeliveryFailure | undefined;
  _trace?: string;
}
export function deliveryFailure(
  documentId: string,
  failure: ChangeDeliveryFailure | undefined,
  _trace?: string,
): DeliveryFailureAction {
  return {
    type: DELIVERY_FAILURE,
    documentId,
    deliveryFailure: failure,
    ...(_trace != null && { _trace }),
  };
}

export const PEER_CONNECT = 'PEERBORNE_PEER_CONNECT';
export interface PeerConnectAction extends Action<typeof PEER_CONNECT> {
  peerAddress: string;
  _trace?: string;
}
export function peerConnect(peerAddress: string, _trace?: string): PeerConnectAction {
  return { type: PEER_CONNECT, peerAddress, ...(_trace != null && { _trace }) };
}

export const PEER_DISCONNECT = 'PEERBORNE_PEER_DISCONNECT';
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
  | DeliveryFailureAction
  | PeerConnectAction
  | PeerDisconnectAction;
