type Envelope<T> = {
  payload?: T;
};

type StreamOptions<T> = {
  path: string;
  onData: (snapshot: T) => void;
  createMockStream?: (onData: (snapshot: T) => void) => () => void;
};

function getBaseUrl() {
  const mount = document.getElementById('app');
  const configuredBase = mount?.dataset.baseUrl;

  if (configuredBase) {
    return new URL(configuredBase, window.location.href);
  }

  return new URL(window.location.href);
}

function toWebSocketUrl(path: string) {
  const base = getBaseUrl();
  const protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
  return new URL(path, `${protocol}//${base.host}`).toString();
}

function unwrapPayload<T>(raw: string): T {
  const data = JSON.parse(raw) as T | Envelope<T>;

  if (typeof data === 'object' && data !== null && 'payload' in data && data.payload !== undefined) {
    return data.payload;
  }

  return data as T;
}

export function subscribeJsonStream<T>({ path, onData, createMockStream }: StreamOptions<T>) {
  let socket: WebSocket | null = null;
  let mockCleanup: (() => void) | null = null;
  let hasMessage = false;

  const startMock = () => {
    if (!mockCleanup && createMockStream) {
      mockCleanup = createMockStream(onData);
    }
  };

  try {
    socket = new WebSocket(toWebSocketUrl(path));
    socket.addEventListener('message', (event) => {
      hasMessage = true;
      onData(unwrapPayload<T>(event.data));
    });
    socket.addEventListener('error', startMock);
    socket.addEventListener('close', () => {
      if (!hasMessage) {
        startMock();
      }
    });
  } catch (_error) {
    startMock();
  }

  return () => {
    if (socket && socket.readyState < WebSocket.CLOSING) {
      socket.close();
    }

    if (mockCleanup) {
      mockCleanup();
    }
  };
}
