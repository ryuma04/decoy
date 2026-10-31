"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api, HttpError } from "@/lib/api";
import { ago, istFull, istTime } from "@/lib/format";
import { StreamProvider, useStream, useStreamStatus } from "@/lib/stream";
import type { Event, User } from "@/lib/types";

export default function Home() {
  return (
    <StreamProvider>
      <Shell />
    </StreamProvider>
  );
}

function Shell() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    api.me().then((r) => setUser(r.user)).catch((e) => {
      if (e instanceof HttpError && e.status === 401) router.replace("/login");
    });
  }, [router]);

  async function logout() {
    await api.logout().catch(() => undefined);
    router.replace("/login");
  }

  return (
    <div className="min-h-screen">
      <header className="flex h-14 items-center justify-between border-b border-hairline bg-canvas px-6">
        <div className="flex items-center gap-3">
          <span className="text-[16px] font-semibold tracking-[-0.4px]">Deception SOC</span>
          <span className="eyebrow">lab environment</span>
        </div>
        <div className="flex items-center gap-4">
          <LiveDot />
          {user && <span className="text-body">{user.email} · {user.role}</span>}
          <button className="btn" onClick={logout}>Log out</button>
        </div>
      </header>
      <main className="mx-auto max-w-[1200px] px-6 py-8">
        <p className="eyebrow">Live events</p>
        <h1 className="mt-2 text-[32px] font-semibold leading-10 tracking-[-1.28px]">What the decoys see</h1>
        <p className="mt-1 text-body">Every event from every sensor, newest first. Updates live.</p>
        <EventsTable />
      </main>
    </div>
  );
}

function LiveDot() {
  const status = useStreamStatus();
  const colour = status === "live" ? "bg-[#0070f3]" : "bg-warning";
  const label = status === "live" ? "Live" : status === "connecting" ? "Connecting" : "Reconnecting";
  return (
    <span className="flex items-center gap-2 text-body" aria-live="polite">
      <span className={`h-2 w-2 rounded-full ${colour}`} aria-hidden />
      {label}
    </span>
  );
}

function EventsTable() {
  const [events, setEvents] = useState<Event[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<Event | null>(null);

  const load = useCallback(async (after?: string) => {
    setLoading(true);
    try {
      const page = await api.listEvents({ limit: "50", ...(after ? { cursor: after } : {}) });
      setEvents((prev) => (after ? [...prev, ...page.items] : page.items));
      setCursor(page.next_cursor);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load events");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  useStream<Event>("event", (ev) => {
    if (paused) return;
    setEvents((prev) => (prev.some((p) => p.event_id === ev.event_id) ? prev : [ev, ...prev].slice(0, 500)));
  });

  async function open(ev: Event) {
    setSelected(ev);
    try {
      setSelected(await api.getEvent(ev.event_id));
    } catch {
      /* keep the row data */
    }
  }

  return (
    <section className="card mt-6 overflow-hidden">
      <div className="flex items-center justify-between border-b border-hairline px-4 py-3">
        <span className="text-body">{events.length} events loaded</span>
        <div className="flex gap-2">
          <button className="btn" onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
            {paused ? "Resume live" : "Pause live"}
          </button>
          <button className="btn" onClick={() => void load()}>Refresh</button>
        </div>
      </div>
      {error && (
        <div role="alert" className="flex items-center justify-between bg-error-soft px-4 py-3 text-error">
          {error}
          <button className="btn" onClick={() => void load()}>Retry</button>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead className="eyebrow border-b border-hairline">
            <tr>
              {["Time (IST)", "Service", "Type", "Actor", "Source IP", "Summary"].map((h) => (
                <th key={h} scope="col" className="px-4 py-2 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.event_id} tabIndex={0} onClick={() => void open(ev)}
                onKeyDown={(k) => k.key === "Enter" && void open(ev)}
                className="cursor-pointer border-b border-hairline-soft hover:bg-hairline-soft focus:bg-hairline-soft focus:outline-none">
                <td className="whitespace-nowrap px-4 py-2 font-mono text-[12px]" title={istFull(ev.ts)}>{istTime(ev.ts)}</td>
                <td className="px-4 py-2">{ev.service}</td>
                <td className="px-4 py-2 font-mono text-[12px]">{ev.type}</td>
                <td className="px-4 py-2">{ev.actor_label ?? <span className="text-faint">—</span>}</td>
                <td className="px-4 py-2 font-mono text-[12px]">{ev.src_ip}</td>
                <td className="max-w-[420px] truncate px-4 py-2 font-mono text-[12px]" title={ev.summary}>{ev.summary}</td>
              </tr>
            ))}
            {!loading && events.length === 0 && !error && (
              <tr><td colSpan={6} className="px-4 py-10 text-center text-body">No events yet — the decoys are listening.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {cursor && (
        <div className="border-t border-hairline px-4 py-3">
          <button className="btn" disabled={loading} onClick={() => void load(cursor)}>{loading ? "Loading…" : "Load older"}</button>
        </div>
      )}
      {selected && <EventDrawer ev={selected} onClose={() => setSelected(null)} />}
    </section>
  );
}

function EventDrawer({ ev, onClose }: { ev: Event; onClose: () => void }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-10 flex justify-end bg-black/20" onClick={onClose}>
      <aside role="dialog" aria-modal="true" aria-label="Event details" onClick={(e) => e.stopPropagation()}
        className="h-full w-full max-w-[560px] overflow-y-auto border-l border-hairline bg-elevated p-6 shadow-[0_8px_16px_-4px_rgba(0,0,0,0.08)]">
        <div className="flex items-start justify-between">
          <div>
            <p className="eyebrow">{ev.type}</p>
            <h2 className="mt-1 break-all font-mono text-[16px] font-semibold">{ev.summary}</h2>
            <p className="mt-1 text-body">{istFull(ev.ts)} · {ago(ev.ts)}</p>
          </div>
          <button className="btn" onClick={onClose} autoFocus>Close</button>
        </div>
        <dl className="mt-6 grid grid-cols-[120px_1fr] gap-y-2 text-[14px]">
          <dt className="text-mute">Sensor</dt><dd className="font-mono">{ev.sensor_id}</dd>
          <dt className="text-mute">Session</dt><dd className="break-all font-mono text-[12px]">{ev.session_id}</dd>
          <dt className="text-mute">Actor</dt><dd>{ev.actor_label ?? "not linked yet"}</dd>
          <dt className="text-mute">Origin</dt><dd>{ev.origin}</dd>
        </dl>
        <p className="eyebrow mt-6">Raw envelope</p>
        <pre className="mt-2 overflow-x-auto rounded-[12px] border border-hairline bg-canvas p-4 font-mono text-[12px] leading-5">
          {JSON.stringify(ev.envelope ?? ev.data, null, 2)}
        </pre>
      </aside>
    </div>
  );
}
