export function createResource<T>(getPromise: (key: string) => Promise<T>) {
  let cache: Record<string, T> = {};
  const inflight: Record<string, Promise<void>> = {};
  const errors: Record<string, unknown> = {};

  function load(key = 'default') {
    inflight[key] = getPromise(key)
      .then((value) => {
        delete inflight[key];
        cache[key] = value;
      })
      .catch((error) => {
        errors[key] = error;
      });

    return inflight[key];
  }

  function read(key = 'default') {
    if (cache[key] !== undefined) {
      return cache[key];
    }

    if (errors[key]) {
      throw errors[key];
    }

    if (inflight[key]) {
      throw inflight[key];
    }

    throw load(key);
  }

  return { read };
}
