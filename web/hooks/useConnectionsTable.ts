import { useMemo, useState } from 'react';

import { GenericRow } from '../types';
import { formatCellValue } from '../utils/format';

type SortDirection = 'asc' | 'desc';

export type SortState = {
  column: string;
  direction: SortDirection;
};

export function useConnectionsTable(rows: GenericRow[]) {
  const columns = useMemo(() => {
    const keys = new Set<string>();

    rows.forEach((row) => {
      Object.keys(row).forEach((key) => {
        if (key !== 'id') {
          keys.add(key);
        }
      });
    });

    return Array.from(keys);
  }, [rows]);

  const [sortState, setSortState] = useState<SortState | null>(null);
  const [filters, setFilters] = useState<Record<string, string[]>>({});
  const [keyword, setKeyword] = useState('');

  const filterOptions = useMemo(() => {
    return columns.reduce<Record<string, string[]>>((accumulator, column) => {
      accumulator[column] = Array.from(
        new Set(rows.map((row) => formatCellValue(row[column])))
      ).sort((left, right) => left.localeCompare(right, 'zh-CN', { numeric: true }));
      return accumulator;
    }, {});
  }, [columns, rows]);

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      const matchesKeyword =
        keyword.trim() === '' ||
        columns.some((column) =>
          formatCellValue(row[column]).toLowerCase().includes(keyword.trim().toLowerCase())
        );

      if (!matchesKeyword) {
        return false;
      }

      return Object.entries(filters).every(([column, selectedValues]) => {
        if (!selectedValues.length) {
          return true;
        }

        return selectedValues.includes(formatCellValue(row[column]));
      });
    });
  }, [columns, filters, keyword, rows]);

  const sortedRows = useMemo(() => {
    if (!sortState) {
      return filteredRows;
    }

    const { column, direction } = sortState;
    const multiplier = direction === 'asc' ? 1 : -1;

    return [...filteredRows].sort((left, right) => {
      const leftValue = left[column];
      const rightValue = right[column];

      if (typeof leftValue === 'number' && typeof rightValue === 'number') {
        return (leftValue - rightValue) * multiplier;
      }

      return (
        formatCellValue(leftValue).localeCompare(formatCellValue(rightValue), 'zh-CN', {
          numeric: true,
        }) * multiplier
      );
    });
  }, [filteredRows, sortState]);

  function toggleSort(column: string) {
    setSortState((previous) => {
      if (!previous || previous.column !== column) {
        return { column, direction: 'asc' };
      }

      return {
        column,
        direction: previous.direction === 'asc' ? 'desc' : 'asc',
      };
    });
  }

  function toggleFilterValue(column: string, value: string, checked: boolean) {
    setFilters((previous) => {
      const allValues = filterOptions[column] ?? [];
      const currentValues = previous[column] ?? [];
      const normalizedCurrentValues = currentValues.length === 0 ? allValues : currentValues;
      const nextValues = checked
        ? Array.from(new Set([...normalizedCurrentValues, value]))
        : normalizedCurrentValues.filter((item) => item !== value);

      return {
        ...previous,
        [column]: nextValues.length === allValues.length ? [] : nextValues,
      };
    });
  }

  function clearFilters() {
    setFilters({});
  }

  return {
    columns,
    filterOptions,
    filters,
    keyword,
    sortedRows,
    sortState,
    setKeyword,
    toggleSort,
    toggleFilterValue,
    clearFilters,
  };
}
