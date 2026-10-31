"use client";

// One EventSource('/api/stream') shared through context (11 §SSE handling). EventSource reconnects on its own;
// we track the state for the "Live" dot.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";

type Handler = (data: unknown) => void;
type Status = "connecting" | "live" | "reconnecting";

interface StreamCtx {
  status: Status;
  subscribe: (event: string, h: Handler) => () => void;
}

const Ctx = createContext<StreamCtx | null>(null);

export function StreamProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("connecting");
  const handlers = useRef(new Map<string, Set<Handler>>());
  const es = useRef<EventSource | null>(null);
  const attached = useRef(new Set<string>());

  useEffect(() => {
    const source = new EventSource("/api/stream");
    const names = attached.current;
    es.current = source;
    source.onopen = () => setStatus("live");
    source.onerror = () => setStatus("reconnecting");
    for (const name of handlers.current.keys()) attach(name);
    return () => {
      source.close();
      es.current = null;
      names.clear();
    };
  }, []);

  function attach(name: string) {
    const source = es.current;
    if (!source || attached.current.has(name)) return;
    attached.current.add(name);
    source.addEventListener(name, (e) => {
      let data: unknown;
      try {
        data = JSON.parse((e as MessageEvent<string>).data);
      } catch {
        return;
      }
      handlers.current.get(name)?.forEach((h) => h(data));
    });
  }

  const subscribe = (name: string, h: Handler) => {
    if (!handlers.current.has(name)) handlers.current.set(name, new Set());
    handlers.current.get(name)!.add(h);
    attach(name);
    return () => {
      handlers.current.get(name)?.delete(h);
    };
  };

  return <Ctx.Provider value={{ status, subscribe }}>{children}</Ctx.Provider>;
}

export function useStream<T>(event: string, handler: (data: T) => void) {
  const ctx = useContext(Ctx);
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    if (!ctx) return;
    return ctx.subscribe(event, (d) => ref.current(d as T));
  }, [ctx, event]);
}

export function useStreamStatus(): Status {
  return useContext(Ctx)?.status ?? "connecting";
}
