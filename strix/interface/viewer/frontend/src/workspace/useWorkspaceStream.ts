import { useEffect, useReducer, useRef } from "react";

import { parseWorkspaceStream } from "./contracts";
import { initialWorkspaceStore, workspaceReducer } from "./store";

export function useWorkspaceStream(onError: (message: string) => void) {
  const [store, dispatch] = useReducer(workspaceReducer, initialWorkspaceStore);
  const reconnect = useReducer((value: number) => value + 1, 0);
  const reconnectEpoch = reconnect[0];
  const requestReconnect = reconnect[1];
  const lastEventAt = useRef(Date.now());

  useEffect(() => {
    const stream = new EventSource("/api/app/events");
    stream.onopen = () => {
      lastEventAt.current = Date.now();
      dispatch({ type: "stream.open" });
    };
    stream.onerror = () => dispatch({ type: "stream.close" });
    stream.onmessage = (event) => {
      lastEventAt.current = Date.now();
      let raw: unknown;
      try {
        raw = JSON.parse(event.data);
      } catch {
        onError("Invalid workspace update; reconnecting for a fresh snapshot.");
        stream.close();
        dispatch({ type: "stream.close" });
        requestReconnect();
        return;
      }
      const envelope = parseWorkspaceStream(raw);
      if (envelope === null) {
        onError("Invalid workspace update; reconnecting for a fresh snapshot.");
        stream.close();
        dispatch({ type: "stream.close" });
        requestReconnect();
        return;
      }
      dispatch({ type: "stream.message", envelope });
    };
    const heartbeat = () => {
      lastEventAt.current = Date.now();
    };
    stream.addEventListener?.("heartbeat", heartbeat);
    const watchdog = window.setInterval(() => {
      if (Date.now() - lastEventAt.current <= 15_000) return;
      stream.close();
      dispatch({ type: "stream.close" });
      onError("Live updates stalled; reconnecting and resynchronizing state.");
      requestReconnect();
    }, 5_000);
    return () => {
      window.clearInterval(watchdog);
      stream.removeEventListener?.("heartbeat", heartbeat);
      stream.close();
    };
  }, [onError, reconnectEpoch]);

  return store;
}
