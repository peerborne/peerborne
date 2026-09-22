import React from 'react';
import './App.css';
import { Route, Routes, useParams } from 'react-router-dom';
import WikiNavbar from './containers/WikiNavbar';
import WikiArticle from './containers/WikiArticle';
import { WikiHome } from './containers/WikiHome';

function WikiArticleRoute() {
  const { documentId } = useParams();
  return documentId ? (
    <WikiArticle key={documentId} documentId={documentId} />
  ) : (
    <WikiHome />
  );
}

export default function App() {
  return (
    <div>
      <WikiNavbar />
      <Routes>
        <Route path="/document/:documentId" element={<WikiArticleRoute />} />
        <Route path="*" element={<WikiHome />} />
      </Routes>
    </div>
  );
}
