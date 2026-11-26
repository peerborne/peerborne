import React, { useState } from 'react';
import FormControl from 'react-bootstrap/FormControl';
import InputGroup from 'react-bootstrap/InputGroup';
import { useDispatch } from 'react-redux';
import { Link, useNavigate } from 'react-router-dom';
import { articleExists, type WikiDispatch } from '../articles';

export default function WikiNavbar() {
  const [currentSearch, setCurrentSearch] = useState('');
  const [existingId, setExistingId] = useState<string>();
  const dispatch = useDispatch<WikiDispatch>();
  const navigate = useNavigate();

  return <div className="m-3">
    <InputGroup className="mb-3">
      <InputGroup.Text id="document-prefix">/documents/</InputGroup.Text>
      <FormControl
        placeholder="Document ID"
        aria-label="Document ID"
        aria-describedby="document-prefix"
        value={currentSearch}
        onChange={e => {
          setCurrentSearch(e.target.value);
          setExistingId(undefined);
        }}
      />
      <Link
        className="btn btn-outline-secondary"
        to={`/document/${encodeURIComponent(currentSearch)}`}
        onClick={() => setExistingId(undefined)}
      >
        Search
      </Link>
      {currentSearch && <Link
        className="btn btn-primary"
        to={`/create/${encodeURIComponent(currentSearch)}`}
        onClick={(event) => {
          event.preventDefault();
          const documentId = currentSearch;
          const create = () =>
            navigate(`/create/${encodeURIComponent(documentId)}`);
          void dispatch(articleExists(documentId)).then(
            (exists) => (exists ? setExistingId(documentId) : create()),
            create,
          );
        }}
      >
        Create article
      </Link>}
    </InputGroup>
    {existingId !== undefined && <p role="alert" className="text-danger">
      An article with the ID “{existingId}” already exists in this browser.
      Use Search to open it instead of creating it again.
    </p>}
  </div>
}
