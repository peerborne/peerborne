import {
  PeerborneActions,
  CONNECT,
  OPEN_DOCUMENT,
  SYNC_DOCUMENT,
  CHANGE_DOCUMENT,
  INITIALIZE,
  CLOSE_DOCUMENT,
  PEER_CONNECT,
  PEER_DISCONNECT,
} from './actions.js';
import {
  ACLProvider,
  AuthProvider,
  ChangesSerializer,
  Peerborne,
  PeerborneDocument,
  CRDTProvider,
  KeychainProvider,
  LoadMessageSerializer,
  SyncMessageSerializer,
} from '@peerborne/core';

export interface PeerborneDocumentState<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> {
  documentRef: PeerborneDocument<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
  document: DocType;
  peers?: string[];
}

export interface PeerborneState<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> {
  node: Peerborne<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  >;
  documents: {
    [documentPath: string]: PeerborneDocumentState<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >;
  };
  peers: string[];
}

export function initialState<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
>(
  privateKey: PrivateKey,
  publicKey: PublicKey,
  provider: CRDTProvider<DocType, ChangesType, ChangeFnType>,
  changesSerializer: ChangesSerializer<ChangesType>,
  syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,
  loadMessageSerializer: LoadMessageSerializer,
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  aclProvider: ACLProvider<ChangesType, PublicKey>,
  keychainProvider: KeychainProvider<ChangesType, DocumentKey>,
): PeerborneState<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
> {
  return {
    node: new Peerborne(
      privateKey,
      publicKey,
      provider,
      changesSerializer,
      syncMessageSerializer,
      loadMessageSerializer,
      authProvider,
      aclProvider,
      keychainProvider,
    ),
    documents: {},
    peers: [],
  };
}

export function peerborneReducer<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey
>(
  privateKey: PrivateKey,
  publicKey: PublicKey,
  provider: CRDTProvider<DocType, ChangesType, ChangeFnType>,
  changesSerializer: ChangesSerializer<ChangesType>,
  syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,
  loadMessageSerializer: LoadMessageSerializer,
  authProvider: AuthProvider<PrivateKey, PublicKey, DocumentKey>,
  aclProvider: ACLProvider<ChangesType, PublicKey>,
  keychainProvider: KeychainProvider<ChangesType, DocumentKey>,
): (
  state: PeerborneState<DocType, ChangesType, ChangeFnType, PrivateKey, PublicKey, DocumentKey> | undefined,
  action: PeerborneActions<DocType, ChangesType, ChangeFnType, PrivateKey, PublicKey, DocumentKey>,
) => PeerborneState<DocType, ChangesType, ChangeFnType, PrivateKey, PublicKey, DocumentKey> {
  return (
    state: PeerborneState<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    > = initialState(
      privateKey,
      publicKey,
      provider,
      changesSerializer,
      syncMessageSerializer,
      loadMessageSerializer,
      authProvider,
      aclProvider,
      keychainProvider,
    ),
    action: PeerborneActions<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,
  ): PeerborneState<
    DocType,
    ChangesType,
    ChangeFnType,
    PrivateKey,
    PublicKey,
    DocumentKey
  > => {
    switch (action.type) {
      // Initialization
      case INITIALIZE: {
        // Changes happen within the node, force a change to redux by creating a new object.
        return {
          ...state,
        };
      }
      // Connection
      case CONNECT: {
        // Changes happen within the node, force a change to redux by creating a new object.
        return {
          ...state,
        };
      }
      case OPEN_DOCUMENT: {
        if (state.documents[action.documentId]) {
          console.warn('Overwriting already open document:', action.documentId);
          console.warn('Action:', action);
          console.warn('State:', state);
        }

        const documents = { ...state.documents };
        documents[action.documentId] = {
          documentRef: action.documentRef,
          document: action.documentRef.document,
          peers: [],
        };

        return {
          ...state,
          documents,
        };
      }
      case CLOSE_DOCUMENT: {
        if (!state.documents[action.documentId]) {
          console.warn(
            'Trying to close a document that is not currently open:',
            action.documentId,
          );
          console.warn('Action:', action);
          console.warn('State:', state);
          return state;
        }

        const documents = { ...state.documents };
        delete documents[action.documentId];

        return {
          ...state,
          documents,
        };
      }
      // Document Sync
      case CHANGE_DOCUMENT:
      case SYNC_DOCUMENT: {
        if (!state.documents[action.documentId]) {
          console.warn(
            'Trying to sync document that is not open',
            action,
            state,
          );
          return state;
        }
        const documents = { ...state.documents };
        const documentState = { ...documents[action.documentId] };
        documentState.document = action.document;
        documents[action.documentId] = documentState;
        return {
          ...state,
          documents,
        };
      }
      case PEER_CONNECT: {
        const currentPeers = new Set(state.peers);
        if (currentPeers.has(action.peerAddress)) {
          return state;
        }
        currentPeers.add(action.peerAddress);
        const peers = [...currentPeers];
        return {
          ...state,
          peers,
        };
      }
      case PEER_DISCONNECT: {
        const peers = state.peers.filter((addr) => addr !== action.peerAddress);
        if (state.peers.length === peers.length) {
          return state;
        }
        return {
          ...state,
          peers,
        };
      }
      default: {
        return state;
      }
    }
  };
}
