"use client";

import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState, useMemo, Suspense } from "react";
import { api } from "@/lib/api";
import { ago, istTime } from "@/lib/format";
import { useStream } from "@/lib/stream";
import type { Event, Severity } from "@/lib/types";
import { ServiceIcon } from "@/components/ServiceIcon";
import { SeverityPill } from "@/components/SeverityPill";
import { EventDrawer } from "@/components/EventDrawer";
import { Search, RefreshCw, AlertTriangle, ArrowUpDown } from "@/components/icons";
import { getEventSeverity, getEventRiskScore } from "@/lib/event-risk";

export default function EventsPageWrapper() {
  return (
    <Suspense fallback={<div className="p-8 text-center font-mono text-mute">Loading events...</div>}>
      <EventsPage />
    </Suspense>
  );
}

function EventsPage() {
  const searchParams = useSearchParams();
  const [events, setEvents] = useState<Event[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null);
  const [loading, setLoading] = useState(true);

  // Filters state
  const [q, setQ] = useState(searchParams.get("q") ?? "");
  const [service, setService] = useState(searchParams.get("service") ?? "");
  const [actor, setActor] = useState(searchParams.get("actor_id") ?? "");
  const [ip, setIp] = useState(searchParams.get("src_ip") ?? "");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [sortByRisk, setSortByRisk] = useState<boolean>(false);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { limit: "100" };
      if (q) params.q = q;
      if (service) params.service = service;
      if (actor) params.actor_id = actor;
      if (ip) params.src_ip = ip;
      const res = await api.listEvents(params);
      setEvents(res.items);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }, [q, service, actor, ip]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  // Prepend live SSE events if they match current filters
  useStream<Event>("event", (ev) => {
    if (service && ev.service !== service) return;
    if (ip && ev.src_ip !== ip) return;
    if (actor && ev.actor_id !== actor && ev.actor_label !== actor) return;
    if (q && !ev.summary.toLowerCase().includes(q.toLowerCase())) return;
    setEvents((prev) => [ev, ...prev]);
  });

  // Filter and sort events based on risk / severity
  const displayedEvents = useMemo(() => {
    let list = events;
    if (severityFilter) {
      list = list.filter((ev) => getEventSeverity(ev) === severityFilter);
    }
    if (sortByRisk) {
      return [...list].sort((a, b) => getEventRiskScore(b) - getEventRiskScore(a));
    }
    return list;
  }, [events, severityFilter, sortByRisk]);

  const criticalCount = useMemo(() => {
    return events.filter((ev) => getEventSeverity(ev) === "critical").length;
  }, [events]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-[28px] font-semibold tracking-tight text-ink">Live Telemetry Events</h1>
            {criticalCount > 0 && (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 text-[11px] font-mono font-bold animate-pulse">
                <AlertTriangle className="h-3 w-3" />
                {criticalCount} Critical
              </span>
            )}
          </div>
          <p className="mt-1 text-body text-[13px]">
            Real-time decoy telemetry and production alerts, classified and leveled by active threat risk.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setSortByRisk(!sortByRisk)}
            className={`btn text-[13px] gap-1.5 ${sortByRisk ? "border-ink bg-canvas font-semibold" : ""}`}
            title="Sort by highest risk score first"
          >
            <ArrowUpDown className="h-3.5 w-3.5" />
            <span>{sortByRisk ? "Sorted by Risk" : "Sort by Risk"}</span>
          </button>
          <button onClick={loadEvents} className="btn text-[13px] gap-1.5" disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-mute" />
            <input
              type="text"
              placeholder="Search summary or payload..."
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="h-8.5 w-full rounded-[6px] border border-hairline bg-canvas pl-9 pr-3 text-[12px] font-mono text-ink placeholder:text-mute focus:outline-none focus:ring-2 focus:ring-link"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="h-8.5 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink focus:outline-none focus:ring-2 focus:ring-link"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical Risk Only</option>
            <option value="high">High Risk Only</option>
            <option value="medium">Medium Risk Only</option>
            <option value="low">Low Risk Only</option>
          </select>

          <select
            value={service}
            onChange={(e) => setService(e.target.value)}
            className="h-8.5 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink focus:outline-none focus:ring-2 focus:ring-link"
          >
            <option value="">All Services</option>
            <option value="ssh">SSH Decoy</option>
            <option value="web">Web Admin Decoy</option>
            <option value="k8s">Kubernetes API</option>
            <option value="beacon">Token Beacon</option>
            <option value="appauth">Production App Auth</option>
            <option value="firewall">Perimeter Firewall</option>
          </select>

          <input
            type="text"
            placeholder="Filter by Source IP..."
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            className="h-8.5 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink placeholder:text-mute focus:outline-none focus:ring-2 focus:ring-link"
          />

          <input
            type="text"
            placeholder="Filter by Actor (e.g. ACT-0007)..."
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            className="h-8.5 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink placeholder:text-mute focus:outline-none focus:ring-2 focus:ring-link"
          />
        </div>
      </div>

      {/* Events Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead className="border-b border-hairline bg-canvas text-[11px] font-mono uppercase text-mute">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Time (IST)</th>
                <th className="px-4 py-3">Service</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Summary / Action</th>
                <th className="px-4 py-3">Tokens</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline font-mono text-[12px]">
              {displayedEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-mute italic">
                    {loading ? "Loading events..." : "No matching decoy events found."}
                  </td>
                </tr>
              ) : (
                displayedEvents.map((ev) => {
                  const isProd = ev.origin === "production";
                  const sev: Severity = getEventSeverity(ev);
                  const isCritical = sev === "critical";

                  return (
                    <tr
                      key={ev.event_id}
                      onClick={() => setSelectedEvent(ev)}
                      className={`cursor-pointer transition-colors ${
                        isCritical
                          ? "bg-rose-50/40 hover:bg-rose-50/70 dark:bg-rose-950/20"
                          : isProd
                          ? "bg-red-50/30 hover:bg-red-50/60"
                          : "hover:bg-canvas/80"
                      }`}
                    >
                      <td className="px-4 py-3 whitespace-nowrap">
                        <SeverityPill severity={sev} size="sm" />
                      </td>
                      <td className="px-4 py-3 text-mute whitespace-nowrap" title={ev.ts}>
                        {istTime(ev.ts)} ({ago(ev.ts)})
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <ServiceIcon service={ev.service} className="h-3.5 w-3.5" />
                          <span className="uppercase text-ink font-medium">{ev.service}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap text-ink font-medium">
                        {ev.type}
                        {isProd && (
                          <span className="ml-1.5 rounded bg-red-100 text-red-800 text-[10px] px-1 py-0.2 font-bold">
                            PROD
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap font-semibold text-ink">
                        {ev.src_ip}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {ev.actor_label ? (
                          <span className="text-link font-medium">{ev.actor_label}</span>
                        ) : (
                          <span className="text-mute">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 max-w-[380px] truncate text-ink">
                        {ev.summary}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {ev.tokens && ev.tokens.length > 0 ? (
                          <div className="flex gap-1">
                            {ev.tokens.map((t) => (
                              <span
                                key={t}
                                className="rounded bg-rose-50 border border-rose-200 px-1.5 py-0.5 text-[10px] text-rose-700 font-semibold"
                              >
                                {t}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-mute">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
}
