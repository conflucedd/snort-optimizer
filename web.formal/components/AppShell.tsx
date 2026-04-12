import React from 'react';
import { Route, Routes } from 'react-router-dom';

import { ConnectionsPage } from '../pages/ConnectionsPage';
import { OverviewPage } from '../pages/OverviewPage';
import { SideBar } from './SideBar';
import styles from './AppShell.module.scss';

export function AppShell() {
  return (
    <div className={styles.app}>
      <SideBar />
      <main className={styles.content}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/connections" element={<ConnectionsPage />} />
        </Routes>
      </main>
    </div>
  );
}
