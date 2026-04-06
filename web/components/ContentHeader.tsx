import React from 'react';

import styles from './ContentHeader.module.scss';

type Props = {
  title: string;
};

export function ContentHeader({ title }: Props) {
  return (
    <div className={styles.root}>
      <h1 className={styles.title}>{title}</h1>
    </div>
  );
}
