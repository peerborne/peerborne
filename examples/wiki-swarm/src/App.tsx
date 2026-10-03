import React from 'react';
import './App.css';
import { Route, Routes, useNavigate, useParams } from 'react-router-dom';
import WikiNavbar from './containers/WikiNavbar';
import WikiArticle from './containers/WikiArticle';
import { WikiHome } from './containers/WikiHome';

function WikiArticleRoute({ create = false }: { create?: boolean }) {
  const { documentId } = useParams();
  const navigate = useNavigate();
  // Keep the mounted article when a successful creation replaces its
  // /create/ URL, so reloading opens the article instead of founding it again.
  return documentId ? (
    <WikiArticle
      key={documentId}
      documentId={documentId}
      create={create}
      onCreated={() =>
        navigate(`/document/${encodeURIComponent(documentId)}`, {
          replace: true,
        })
      }
    />
  ) : (
    <WikiHome />
  );
}

export default function App() {
  return (
    <div>
      <WikiNavbar />
      <Routes>
        <Route path="/create/:documentId" element={<WikiArticleRoute create />} />
        <Route path="/document/:documentId" element={<WikiArticleRoute />} />
        <Route path="*" element={<WikiHome />} />
      </Routes>
    </div>
  );
}
