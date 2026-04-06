import React from 'react';

import { createMockConnectionsStream } from '../api/mock';
import { ContentHeader } from '../components/ContentHeader';
import { GenericTable } from '../components/GenericTable';
import { useConnectionsTable } from '../hooks/useConnectionsTable';
import { useLiveSnapshot } from '../hooks/useLiveSnapshot';
import { ConnectionsSnapshot } from '../types';
import { formatTime } from '../utils/format';
import styles from './ConnectionsPage.module.scss';

const initialSnapshot: ConnectionsSnapshot = {
  rows: [],
  updatedAt: 0,
};

export function ConnectionsPage() {
  const snapshot = useLiveSnapshot({
    initialSnapshot,
    path: '/ws/connections',
    createMockStream: createMockConnectionsStream,
  });
  const table = useConnectionsTable(snapshot.rows);
  const compactColumns = table.columns.filter((column) => {
    const options = table.filterOptions[column] ?? [];
    return options.length > 1 && options.length <= 4;
  }).slice(0, 2);

  return (
    <div>
      <ContentHeader title="Connections" />
      <div className={styles.toolbar}>
        <input
          className={styles.search}
          type="text"
          placeholder="Search"
          value={table.keyword}
          onChange={(event) => table.setKeyword(event.target.value)}
        />
        <div className={styles.checks}>
          {compactColumns.map((column) => {
            const options = table.filterOptions[column] ?? [];

            return (
              <div key={column} className={styles.group}>
                <span className={styles.groupTitle}>{column}:</span>
                {options.map((option) => {
                  const activeValues = table.filters[column] ?? [];
                  const checked = activeValues.length === 0 || activeValues.includes(option);

                  return (
                    <label key={`${column}-${option}`} className={styles.check}>
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(event) =>
                          table.toggleFilterValue(column, option, event.target.checked)
                        }
                      />
                      <span>{option}</span>
                    </label>
                  );
                })}
              </div>
            );
          })}
        </div>
        <div className={styles.meta}>Rows: {table.sortedRows.length}</div>
        <div className={styles.meta}>
          Updated: {snapshot.updatedAt ? formatTime(snapshot.updatedAt) : '--:--:--'}
        </div>
      </div>
      <GenericTable
        columns={table.columns}
        rows={table.sortedRows}
        sortState={table.sortState}
        onSort={table.toggleSort}
      />
    </div>
  );
}
