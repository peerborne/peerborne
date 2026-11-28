import { Action } from "redux";
import { WikiSwarmArticle } from "./models";
import { AutomergeSwarmActions } from "./utils";


export const SEARCH = 'WIKI_SWARM_SEARCH';
export interface SearchAction extends Action<typeof SEARCH> {
  query: string;
}
export function search(query: string): SearchAction {
  return {
    type: SEARCH,
    query,
  };
}

export type ArticleSaveStatus = 'saving' | 'saved' | 'failed';

export const ARTICLE_SAVE = 'WIKI_SWARM_ARTICLE_SAVE';
export interface ArticleSaveAction extends Action<typeof ARTICLE_SAVE> {
  documentId: string;
  status: ArticleSaveStatus;
}
export function articleSave(
  documentId: string,
  status: ArticleSaveStatus,
): ArticleSaveAction {
  return {
    type: ARTICLE_SAVE,
    documentId,
    status,
  };
}

export type WikiSwarmActions =
  AutomergeSwarmActions<WikiSwarmArticle> |
  SearchAction |
  ArticleSaveAction;
