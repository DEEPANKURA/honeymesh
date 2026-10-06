import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { LiveMessage } from "./api";

type Handler = (message: LiveMessage) => void;

interface LiveContextValue {
  connected: boolean;
  lastError: string | null;
  subscribe: (handler: Handler) => () => void;
}

const LiveContext = createContext<LiveContextValue>({
  connected: false,
  lastError: null,
  subscribe: () => () => undefined,
});

/** Single reconnecting WebSocket shared by every page. */
export function LiveProvider({ children }: { children: ReactNode }): ReactNode {
  const [connected, setConnected] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const handlers = useRef(new Set<Handler>());

  useEffect(() => {
    let socket: WebSocket | null = null;
    let closed = false;
    let retry = 1000;
    let timer: number | undefined;

    const connect = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      try {
        socket = new WebSocket(`${protocol}//${window.location.host}/ws/events`);
      } catch (error) {
        setLastError(String(error));
        return;
      }
      socket.onopen = () => {
        retry = 1000;
        setConnected(true);
        setLastError(null);
      };
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data as string) as LiveMessage;
          if (message.type === "connected" || message.type === "pong") return;
          handlers.current.forEach((handler) => handler(message));
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onerror = () => setLastError("websocket error");
      socket.onclose = () => {
        setConnected(false);
        if (!closed) {
          timer = window.setTimeout(connect, retry);
          retry = Math.min(retry * 2, 15000);
        }
      };
    };

    connect();
    const ping = window.setInterval(() => {
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "ping" }));
      }
    }, 20000);

    return () => {
      closed = true;
      window.clearInterval(ping);
      if (timer) window.clearTimeout(timer);
      socket?.close();
    };
  }, []);

  const subscribe = useCallback((handler: Handler) => {
    handlers.current.add(handler);
    return () => {
      handlers.current.delete(handler);
    };
  }, []);

  const value = useMemo(
    () => ({ connected, lastError, subscribe }),
    [connected, lastError, subscribe],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

/** Subscribes to the shared live stream for as long as the component is mounted. */
export function useLive(handler: Handler): boolean {
  const { subscribe } = useContext(LiveContext);
  const stable = useRef(handler);
  stable.current = handler;
  useEffect(() => subscribe((message) => stable.current(message)), [subscribe]);
  return useContext(LiveContext).connected;
}

export function useLiveConnection(): { connected: boolean; lastError: string | null } {
  const { connected, lastError } = useContext(LiveContext);
  return { connected, lastError };
}

/** Polls an API endpoint on an interval and on window focus. */
export function usePoll<T>(
  fetcher: () => Promise<T>,
  intervalMs: number,
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);
  const fn = useRef(fetcher);
  fn.current = fetcher;

  const refresh = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let alive = true;
    const run = async () => {
      try {
        const result = await fn.current();
        if (alive) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (alive) setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (alive) setLoading(false);
      }
    };
    void run();
    const id = window.setInterval(run, intervalMs);
    const onFocus = () => void run();
    window.addEventListener("focus", onFocus);
    return () => {
      alive = false;
      window.clearInterval(id);
      window.removeEventListener("focus", onFocus);
    };
  }, [intervalMs, nonce]);

  return { data, error, loading, refresh };
}
