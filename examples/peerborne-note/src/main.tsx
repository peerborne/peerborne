import { createRoot } from 'react-dom/client';
import App from './App.js';
import { consumeInvitationFragment } from './invitation-link.js';
import './styles.css';

const initialFragment = consumeInvitationFragment(window.location, window.history);
const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Missing #root element');

createRoot(rootElement).render(<App initialFragment={initialFragment} />);
