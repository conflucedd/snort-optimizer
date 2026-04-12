import cx from 'clsx';
import React from 'react';
import { FcAreaChart, FcLink } from 'react-icons/fc';
import { Link, useLocation } from 'react-router-dom';

import styles from './SideBar.module.scss';

const items = [
  { to: '/', label: 'Overview', Icon: FcAreaChart },
  { to: '/connections', label: 'Conns', Icon: FcLink },
];

export function SideBar() {
  const location = useLocation();

  return (
    <aside className={styles.root}>
      <div className={styles.rows}>
        {items.map(({ to, label, Icon }) => (
          <Link
            key={to}
            to={to}
            className={cx(styles.row, location.pathname === to ? styles.rowActive : null)}
          >
            <Icon />
            <div className={styles.label}>{label}</div>
          </Link>
        ))}
      </div>
    </aside>
  );
}
