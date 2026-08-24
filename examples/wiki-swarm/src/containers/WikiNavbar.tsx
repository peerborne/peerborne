import React, { useState } from 'react';
import FormControl from 'react-bootstrap/FormControl';
import InputGroup from 'react-bootstrap/InputGroup';
import { Link } from 'react-router-dom';

export default function WikiNavbar() {
  const [currentSearch, setCurrentSearch] = useState('');

  return <div className="m-3">
    <InputGroup className="mb-3">
      <InputGroup.Text id="document-prefix">/documents/</InputGroup.Text>
      <FormControl
        placeholder="Document ID"
        aria-label="Document ID"
        aria-describedby="document-prefix"
        value={currentSearch}
        onChange={e => setCurrentSearch(e.target.value)}
      />
      <Link className="btn btn-outline-secondary" to={`/document/${currentSearch}`}>
        Search
      </Link>
    </InputGroup>
  </div>
}
