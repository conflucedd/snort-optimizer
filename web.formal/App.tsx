import React from 'react';
import { HashRouter } from 'react-router-dom';

import { AppShell } from './components/AppShell';

export default function App() {
  return (
    <HashRouter>
      <AppShell />
    </HashRouter>
  );
}
