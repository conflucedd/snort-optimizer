import React from 'react';

import styles from './StatCards.module.scss';

type Item = {
  label: string;
  value: string | number;
};

type Props = {
  items: Item[];
};

export function StatCards({ items }: Props) {
  return (
    <section className={styles.grid}>
      {items.map((item) => (
        <div key={item.label} className={styles.card}>
          <div className={styles.label}>{item.label}</div>
          <div className={styles.value}>{item.value}</div>
        </div>
      ))}
    </section>
  );
}
