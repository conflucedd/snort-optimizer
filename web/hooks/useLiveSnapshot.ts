import { useEffect, useState } from 'react';

import { subscribeJsonStream } from '../api/ws';

type Options<T> = {
  initialSnapshot: T;
  path: string;
  createMockStream?: (onData: (snapshot: T) => void) => () => void;
};

export function useLiveSnapshot<T>({ initialSnapshot, path, createMockStream }: Options<T>) {
  const [snapshot, setSnapshot] = useState(initialSnapshot);

  useEffect(() => {
    return subscribeJsonStream({
      path,
      onData: setSnapshot,
      createMockStream,
    });
  }, [createMockStream, path]);

  return snapshot;
}
