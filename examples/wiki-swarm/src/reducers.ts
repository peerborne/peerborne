import { combineReducers } from 'redux';
import { WikiSwarmArticle } from './models';
import { WikiSwarmActions, SEARCH } from './actions';
import { AutomergeSwarmActions, AutomergeSwarmState } from './utils';
import { peerborneReducer } from '@peerborne/redux';
import {
  AutomergeACLProvider,
  AutomergeJSONSerializer,
  AutomergeKeychainProvider,
  AutomergeProvider,
} from '@peerborne/automerge';
import { SubtleCrypto } from '@peerborne/core';

export interface WikiAppState {}

export const wikiAppInitialState: WikiAppState = {};

export function wikiAppReducer(
  state: WikiAppState = wikiAppInitialState,
  action: any,
): WikiAppState {
  switch (action.type) {
    case SEARCH: {
      return {
        ...state,
      };
    }
    default: {
      return state;
    }
  }
}

/** State managed by the wiki application and its Automerge integration. */
export type RootState = {
  automergeSwarm: AutomergeSwarmState<WikiSwarmArticle>;
  wikiApp: WikiAppState;
};

/** Create the wiki reducer using the supplied signing key pair. */
export const createRootReducer = (
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): (
  state: RootState | undefined,
  action: WikiSwarmActions,
) => RootState => combineReducers({
  // automergeSwarm: peerborneReducer(new AutomergeProvider<WikiSwarmArticle>()),
  automergeSwarm: peerborneReducer(
    privateKey,
    publicKey,
    new AutomergeProvider(),
    new AutomergeJSONSerializer(),
    new AutomergeJSONSerializer(),
    new AutomergeJSONSerializer(),
    new SubtleCrypto(),
    new AutomergeACLProvider(),
    new AutomergeKeychainProvider(),
  ) as (
    state: AutomergeSwarmState<WikiSwarmArticle> | undefined,
    action: AutomergeSwarmActions,
  ) => AutomergeSwarmState<WikiSwarmArticle>,
  wikiApp: wikiAppReducer,
});

export function selectAutomergeSwarmState(
  rootState: RootState,
): AutomergeSwarmState<WikiSwarmArticle> {
  return rootState.automergeSwarm;
}
