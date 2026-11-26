import React from 'react';
import { createRoot } from 'react-dom/client';
import 'bootstrap/dist/css/bootstrap.css'
import './index.css';
import App from './App';
import { Provider } from 'react-redux';
import { createStore, applyMiddleware, Middleware } from 'redux';
import { createRootReducer } from './reducers';
import { withExtraArgument } from 'redux-thunk';
import { BrowserRouter } from 'react-router-dom';
import { SubtleCrypto } from '@peerborne/core';
import { ArticleStore, getWikiIdentity } from './article-store';
import { ArticleSession } from './articles';

const logger: Middleware = () => (next) => (action) => {
  console.debug('dispatching', (action as { type?: unknown }).type);
  return next(action);
};

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('Missing #root element');
}

if (!window.crypto?.subtle || !window.indexedDB) {
  const message = 'Web Crypto and IndexedDB require HTTPS or localhost';
  console.warn(message);
  rootElement.textContent = message;
} else {
  try {
    const identity = await getWikiIdentity();
    const owner = await new SubtleCrypto().serializePublicKey(
      identity.signing.publicKey,
    );
    const session = new ArticleSession(
      identity,
      new ArticleStore(identity, owner),
    );
    const middleware: Middleware[] = [withExtraArgument(session)];
    if (import.meta.env.DEV) middleware.push(logger);
    const store = createStore(
      createRootReducer(
        identity.signing.privateKey,
        identity.signing.publicKey,
      ),
      applyMiddleware(...middleware),
    );

    createRoot(rootElement).render(
      <Provider store={store}>
        <React.StrictMode>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </React.StrictMode>
      </Provider>,
    );
  } catch {
    rootElement.textContent =
      'The wiki could not restore this browser’s identity. Saved articles were left unchanged.';
  }
}
