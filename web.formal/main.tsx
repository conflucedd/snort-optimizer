import './styles/main.scss';

import React from 'react';
import { createRoot } from 'react-dom/client';

import App from './App';

const rootElement = document.getElementById('app');

if (!rootElement) {
  throw new Error('App root element "#app" was not found.');
}

createRoot(rootElement).render(<App />);
