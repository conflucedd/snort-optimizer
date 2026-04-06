import React from 'react';

import { GenericRow } from '../types';
import { formatCellValue, toLabel } from '../utils/format';
import { SortState } from '../hooks/useConnectionsTable';
import styles from './GenericTable.module.scss';

type Props = {
  columns: string[];
  rows: GenericRow[];
  sortState: SortState | null;
  onSort: (column: string) => void;
};

export function GenericTable({ columns, rows, sortState, onSort }: Props) {
  if (!rows.length) {
    return <div className={styles.empty}>No rows match the current filters.</div>;
  }

  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            {columns.map((column) => {
              const suffix =
                sortState?.column === column ? (sortState.direction === 'asc' ? ' ↑' : ' ↓') : '';

              return (
                <th key={column} className={styles.headCell} onClick={() => onSort(column)}>
                  {toLabel(column)}
                  {suffix}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id} className={styles.row}>
              {columns.map((column) => (
                <td key={`${row.id}-${column}`} className={styles.cell}>
                  {formatCellValue(row[column])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
