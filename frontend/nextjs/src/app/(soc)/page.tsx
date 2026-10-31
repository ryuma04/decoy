"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useStream } from "@/lib/stream";
import { ago, istTime } from "@/lib/format";
import type { Event, Overview, TechniqueCount, TimeseriesPoint } from "@/lib/types";
import { KpiCard } from "@/components/KpiCard";
import { RiskGauge } from "@/components/RiskGauge";
import { SeverityPill } from "@/components/SeverityPill";
import { BehaviourBadge } from "@/components/BehaviourBadge";
import { ServiceIcon } from "@/components/ServiceIcon";
import { EventDrawer } from "@/components/EventDrawer";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Pause,
  Play,
  Radio,
  Server,
  Users,
} from "lucide-react";
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

  useEffect(() => {
    Promise.all([
      api.getOverview("1h").catch(() => null),
      api.getTimeseries({ window: "1h", step: "1m" }).catch(() => ({ points: [] })),
      api.getTechniques("24h").catch(() => ({ items: [] })),
      api.listEvents({ limit: "25" }).catch(() => ({ items: [], next_cursor: null })),
    ]).then(([ov, ts, tech, evs]) => {
      if (ov) setOverview(ov);
      if (ts?.points) setTimeseries(ts.points);
      if (tech?.items) setTechniques(tech.items);
      if (evs?.items) setLiveFeed(evs.items);
    });
  }, []);

  // Live SSE stream handler
  useStream<Event>("event", (newEvent) => {
    if (!paused) {
      setLiveFeed((prev) => [newEvent, ...prev.slice(0, 49)]);
    }
    // Increment overview stats dynamically
    setOverview((prev) => {
      if (!prev) return null;
      return { ...prev, events: prev.events + 1 };
    });
  });

  const topActor = overview?.top_actor;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">SOC Overview</h1>
          <p className="mt-1 text-body text-[13px]">
            Deception telemetry, correlated threat actors, and decoy sensor health across the lab.
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
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
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
        <KpiCard
          title="Sensor Fleet"
          value={`${overview?.sensors_ok ?? 0} / ${overview?.sensors_total ?? 0}`}
          subtitle="All decoys operational"
          icon={<Server className="h-4 w-4" />}
        />
      </div>

      {/* Main Grid: Highest Risk Actor + Timeseries */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Highest Risk Actor Banner */}
        <div className="card p-5 lg:col-span-1 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-hairline pb-3">
              <span className="eyebrow">Priority Threat Actor</span>
              {topActor && <SeverityPill severity={topActor.severity} size="sm" />}
            </div>

            {topActor ? (
              <div className="mt-4 flex flex-col items-center text-center">
                <RiskGauge score={topActor.risk_score} size={96} />
                <h3 className="mt-3 font-mono text-[20px] font-bold text-ink">
                  {topActor.label}
                </h3>
                <div className="mt-2 flex flex-wrap justify-center gap-1.5">
                  <BehaviourBadge behaviourClass={topActor.behaviour_class} size="sm" />
                  {topActor.touched_production && (
                    <span className="rounded-full bg-red-100 text-red-800 border border-red-200 px-2 py-0.5 text-[10px] font-mono font-bold">
                      Touched Production
                    </span>
                  )}
                </div>

                <div className="mt-4 w-full grid grid-cols-2 gap-2 text-left font-mono text-[11px] bg-canvas p-3 rounded-lg border border-hairline">
                  <div>
                    <span className="text-mute block">Sessions</span>
                    <span className="text-ink font-semibold">{topActor.session_count} decoys</span>
                  </div>
                  <div>
                    <span className="text-mute block">Confidence</span>
                    <span className="text-ink font-semibold">{(topActor.confidence * 100).toFixed(0)}% match</span>
                  </div>
                  <div>
                    <span className="text-mute block">Token Hits</span>
                    <span className="text-ink font-semibold">{topActor.token_hits}</span>
                  </div>
                  <div>
                    <span className="text-mute block">Maze Depth</span>
                    <span className="text-ink font-semibold">{topActor.maze_depth} lures</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-mute text-[13px] italic">
                No active threats detected.
              </div>
            )}
          </div>

          {topActor && (
            <Link
              href={`/actors/${topActor.actor_id}`}
              className="btn btn-primary mt-4 w-full justify-center gap-2"
            >
              <span>Inspect Actor Dossier</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
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
