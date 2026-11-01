"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { useStream } from "@/lib/stream";
import { ago, istTime } from "@/lib/format";
import type { Event, Overview, Severity, TechniqueCount, TimeseriesPoint } from "@/lib/types";
import { KpiCard } from "@/components/KpiCard";
import { ServiceIcon } from "@/components/ServiceIcon";
import { EventDrawer } from "@/components/EventDrawer";
import { SeverityPill } from "@/components/SeverityPill";
import { getEventSeverity } from "@/lib/event-risk";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Pause,
  Play,
  Radio,
  Users,
} from "@/components/icons";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export default function OverviewPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [timeseries, setTimeseries] = useState<TimeseriesPoint[]>([]);
  const [techniques, setTechniques] = useState<TechniqueCount[]>([]);
  const [liveFeed, setLiveFeed] = useState<Event[]>([]);
  const [paused, setPaused] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);

  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  // Every number on this page comes from the analyst API (database), never from the browser counting events.
  const loadStats = useCallback(async () => {
    const [ov, ts, tech] = await Promise.all([
      api.getOverview("1h").catch(() => null),
      api.getTimeseries({ window: "1h", step: "1m" }).catch(() => null),
      api.getTechniques("24h").catch(() => null),
    ]);
    if (ov) setOverview(ov);
    if (ts?.points) setTimeseries(fillMinutes(ts.points, 60));
    if (tech?.items) setTechniques(tech.items);
    if (ov || ts || tech) setUpdatedAt(new Date());
  }, []);

  // Live updates: any new event / finding / actor / incident / sensor change re-reads the stats, at most every 3 s.
  const pending = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastLoad = useRef(0);
  const scheduleRefresh = useCallback(() => {
    if (pending.current) return;
    const wait = Math.max(0, 3000 - (Date.now() - lastLoad.current));
    pending.current = setTimeout(() => {
      pending.current = null;
      lastLoad.current = Date.now();
      void loadStats();
    }, wait);
  }, [loadStats]);

  useEffect(() => {
    lastLoad.current = Date.now();
    void loadStats();
    api.listEvents({ limit: "25" })
      .then((evs) => setLiveFeed(evs.items))
      .catch(() => undefined);
    const tick = setInterval(scheduleRefresh, 15000); // rolls the 1-hour window forward even when it is quiet
    return () => {
      clearInterval(tick);
      if (pending.current) clearTimeout(pending.current);
    };
  }, [loadStats, scheduleRefresh]);

  useStream<Event>("event", (newEvent) => {
    if (!paused) {
      setLiveFeed((prev) => [newEvent, ...prev.slice(0, 49)]);
    }
    scheduleRefresh();
  });
  useStream<unknown>("finding", scheduleRefresh);
  useStream<unknown>("actor", scheduleRefresh);
  useStream<unknown>("incident", scheduleRefresh);
  useStream<unknown>("sensor", scheduleRefresh);

  const topActor = overview?.top_actor;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">SOC Overview</h1>
          <p className="mt-1 text-body text-[13px]">
            Deception telemetry, correlated threat actors, and high-fidelity active defense across the lab.
          </p>
          <p className="mt-1 font-mono text-[11px] text-mute">
            {updatedAt ? `Live from the database · updated ${istTime(updatedAt.toISOString())}` : "Loading live data…"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/events" className="btn text-[13px]">
            <span>View All Events</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Events (1h)"
          value={overview?.events ?? "—"}
          subtitle="Real-time telemetry intake"
          icon={<Activity className="h-4 w-4" />}
        />
        <KpiCard
          title="Active Actors"
          value={overview?.active_actors ?? "—"}
          subtitle={`${overview?.new_actors ?? 0} new in window`}
          icon={<Users className="h-4 w-4" />}
        />
        <KpiCard
          title="Critical Incidents"
          value={overview?.open_incidents?.critical ?? 0}
          subtitle={`${overview?.open_incidents?.high ?? 0} high, ${overview?.open_incidents?.medium ?? 0} med`}
          icon={<AlertTriangle className="h-4 w-4" />}
          alert={(overview?.open_incidents?.critical ?? 0) > 0}
        />
        <KpiCard
          title="Honeytoken Hits"
          value={overview?.token_hits ?? 0}
          subtitle="High-fidelity decoys tripped"
          icon={<Radio className="h-4 w-4" />}
          alert={(overview?.token_hits ?? 0) > 0}
        />
      </div>

      {/* Main Grid: Highest Risk Actor + Timeseries */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Highest Risk Actor Banner */}
        <div className="card lg:col-span-1 flex flex-col">
          <div className="flex items-center justify-between border-b border-hairline px-4 py-2.5">
            <span className="text-[12px] font-semibold uppercase tracking-wide text-body">Highest-risk actor</span>
            {topActor && <span className="font-mono text-[11px] text-mute">seen {ago(topActor.last_seen)}</span>}
          </div>

          {topActor ? (
            <div className="flex flex-1 flex-col px-4 py-3">
              <div className="flex items-baseline justify-between">
                <Link href={`/actors/${topActor.actor_id}`} className="font-mono text-[18px] font-semibold text-ink hover:underline">
                  {topActor.label}
                </Link>
                <span className="font-mono text-[13px]">
                  <span className="font-semibold text-ink">{topActor.risk_score}</span>
                  <span className="text-mute">/100 </span>
                  <span className={`uppercase font-semibold ${sevText(topActor.severity)}`}>{topActor.severity}</span>
                </span>
              </div>
              <RiskBar score={topActor.risk_score} severity={topActor.severity} />

              <dl className="mt-3 divide-y divide-hairline-soft border-y border-hairline-soft text-[12px]">
                <Row k="Stage" v={topActor.kill_chain_stage.replaceAll("_", " ")} />
                <Row k="Behaviour" v={topActor.behaviour_class.replaceAll("_", "-")} />
                <Row
                  k="Services"
                  v={
                    <span className="flex flex-wrap justify-end gap-2">
                      {topActor.services.map((s) => (
                        <span key={s} className="inline-flex items-center gap-1">
                          <ServiceIcon service={s} className="h-3.5 w-3.5 text-mute" />
                          {s}
                        </span>
                      ))}
                    </span>
                  }
                />
                <Row
                  k="Source IPs"
                  v={topActor.ips.length > 2 ? `${topActor.ips.slice(0, 2).join(", ")} +${topActor.ips.length - 2}` : topActor.ips.join(", ") || "—"}
                  mono
                />
                <Row k="ATT&CK" v={topActor.top_techniques.slice(0, 4).join(" · ") || "—"} mono />
                <Row k="Honeytokens / maze" v={`${topActor.token_hits} hits · depth ${topActor.maze_depth}`} mono />
                <Row k="Sessions" v={`${topActor.session_count} · ${(topActor.confidence * 100).toFixed(0)}% linked`} mono />
                {topActor.touched_production && <Row k="Production" v={<span className="font-semibold text-error">touched</span>} />}
              </dl>

              <Link
                href={`/actors/${topActor.actor_id}`}
                className="mt-auto pt-3 inline-flex items-center gap-1 self-start text-[12px] font-medium text-link hover:underline"
              >
                Open {topActor.label} <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          ) : (
            <div className="px-4 py-10 text-[13px] text-mute">No actor above low risk yet.</div>
          )}
        </div>

        {/* Timeseries Graph */}
        <div className="card p-5 lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between border-b border-hairline pb-3">
            <div>
              <span className="eyebrow">Telemetry Velocity</span>
              <h3 className="text-[15px] font-semibold text-ink">Events per minute</h3>
            </div>
            <span className="text-[11px] font-mono text-mute">Past 60 minutes</span>
          </div>

          <div className="mt-4 h-[220px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeseries}>
                <defs>
                  <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0070f3" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#0070f3" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="t"
                  tickFormatter={(t) => istTime(t)}
                  stroke="#8f8f8f"
                  fontSize={10}
                  fontFamily="monospace"
                  tickLine={false}
                />
                <YAxis stroke="#8f8f8f" fontSize={10} fontFamily="monospace" tickLine={false} />
                <Tooltip
                  labelFormatter={(t) => istTime(t as string)}
                  contentStyle={{
                    backgroundColor: "#ffffff",
                    borderColor: "#ebebeb",
                    borderRadius: "8px",
                    fontSize: "12px",
                    fontFamily: "monospace",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="v"
                  name="Events"
                  stroke="#0070f3"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Secondary Row: Live Stream Feed + Top ATT&CK Techniques */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Live Event Stream */}
        <div className="card p-5 flex flex-col">
          <div className="flex items-center justify-between border-b border-hairline pb-3">
            <div className="flex items-center gap-2">
              <span className="eyebrow">Real-Time Event Stream</span>
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
            </div>
            <button
              onClick={() => setPaused(!paused)}
              className="btn text-[11px] font-mono h-7 px-2.5"
            >
              {paused ? (
                <>
                  <Play className="h-3 w-3 text-emerald-600" />
                  <span>Resume</span>
                </>
              ) : (
                <>
                  <Pause className="h-3 w-3 text-amber-600" />
                  <span>Pause</span>
                </>
              )}
            </button>
          </div>

          <div className="mt-3 divide-y divide-hairline max-h-[360px] overflow-y-auto">
            {liveFeed.length === 0 ? (
              <p className="py-8 text-center text-[13px] text-mute italic">
                Listening for decoy events...
              </p>
            ) : (
              liveFeed.slice(0, 15).map((ev) => (
                <div
                  key={ev.event_id}
                  onClick={() => setSelectedEvent(ev)}
                  className="py-2.5 px-1 hover:bg-canvas rounded cursor-pointer transition-colors flex items-center justify-between gap-3 text-[12px]"
                >
                  <div className="flex items-center gap-2 truncate">
                    <SeverityPill severity={getEventSeverity(ev)} size="sm" />
                    <ServiceIcon service={ev.service} className="h-3.5 w-3.5 shrink-0" />
                    <span className="font-mono font-semibold text-ink shrink-0">{ev.src_ip}</span>
                    <span className="text-body truncate font-mono text-[11px]">{ev.summary}</span>
                  </div>
                  <span className="font-mono text-[10px] text-mute shrink-0">
                    {ago(ev.ts)}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top ATT&CK Techniques Bar Chart */}
        <div className="card p-5 flex flex-col">
          <div className="flex items-center justify-between border-b border-hairline pb-3">
            <div>
              <span className="eyebrow">Threat Taxonomy</span>
              <h3 className="text-[15px] font-semibold text-ink">Top MITRE ATT&CK Techniques</h3>
            </div>
            <span className="text-[11px] font-mono text-mute">Last 24h</span>
          </div>

          <div className="mt-4 h-[320px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={techniques}
                layout="vertical"
                margin={{ left: 20, right: 20, top: 10, bottom: 10 }}
              >
                <XAxis type="number" stroke="#8f8f8f" fontSize={10} fontFamily="monospace" />
                <YAxis
                  dataKey="technique"
                  type="category"
                  stroke="#8f8f8f"
                  fontSize={11}
                  fontFamily="monospace"
                  width={70}
                />
                <Tooltip
                  formatter={(value, _name, item) => [
                    `${value ?? 0} occurrences`,
                    `${(item?.payload as TechniqueCount)?.name ?? ""} (${(item?.payload as TechniqueCount)?.tactic ?? ""})`,
                  ]}
                  contentStyle={{
                    backgroundColor: "#ffffff",
                    borderColor: "#ebebeb",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" fill="#171717" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Event Drawer Modal */}
      <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
}

// fillMinutes returns one point per minute for the last n minutes, 0 where nothing happened (the API only returns
// minutes that had events, which would hide quiet periods on the chart).
function fillMinutes(points: TimeseriesPoint[], n: number): TimeseriesPoint[] {
  const byMinute = new Map<number, number>();
  for (const p of points) byMinute.set(Math.floor(new Date(p.t).getTime() / 60000), p.v);
  const now = Math.floor(Date.now() / 60000);
  const out: TimeseriesPoint[] = [];
  for (let m = now - n + 1; m <= now; m++) {
    out.push({ t: new Date(m * 60000).toISOString(), v: byMinute.get(m) ?? 0 });
  }
  return out;
}


// ---- highest-risk actor card helpers ----

function Row({ k, v, mono = false }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1.5">
      <dt className="shrink-0 text-mute">{k}</dt>
      <dd className={`text-right text-ink ${mono ? "font-mono text-[11px]" : ""}`}>{v}</dd>
    </div>
  );
}

const SEV_BAR: Record<Severity, string> = { low: "bg-faint", medium: "bg-warning", high: "bg-orange-600", critical: "bg-error" };

function sevText(s: Severity): string {
  return { low: "text-mute", medium: "text-warning-deep", high: "text-orange-700", critical: "text-error" }[s];
}

/** 20 flat segments, one per 5 risk points: reads like a meter on a console, not a decorative gauge. */
function RiskBar({ score, severity }: { score: number; severity: Severity }) {
  const filled = Math.round(Math.max(0, Math.min(100, score)) / 5);
  return (
    <div className="mt-2 flex gap-[2px]" aria-label={`risk ${score} of 100`}>
      {Array.from({ length: 20 }, (_, i) => (
        <span key={i} className={`h-1.5 flex-1 ${i < filled ? SEV_BAR[severity] : "bg-hairline"}`} />
      ))}
    </div>
  );
}
