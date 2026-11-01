"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ago, istTime } from "@/lib/format";
import { useStream } from "@/lib/stream";
import type { Incident } from "@/lib/types";
import { SeverityPill } from "@/components/SeverityPill";
import { ArrowRight, Filter } from "@/components/icons";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const params: Record<string, string> = {};
    if (statusFilter) params.status = statusFilter;
    if (severityFilter) params.severity = severityFilter;

    api.listIncidents(params)
      .then((res) => setIncidents(res.items))
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, [statusFilter, severityFilter]);

  // Live SSE stream listener for incident updates
  useStream<Incident>("incident", (updated) => {
    setIncidents((prev) => {
      const idx = prev.findIndex((i) => i.incident_id === updated.incident_id);
      if (idx >= 0) {
        const copy = [...prev];
        copy[idx] = updated;
        return copy;
      }
      return [updated, ...prev];
    });
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">Security Incidents</h1>
          <p className="mt-1 text-body text-[13px]">
            Aggregated threat incidents requiring analyst triage, response, and containment.
          </p>
        </div>
      </div>

      {/* Filter Row */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 text-mute text-[12px] font-mono">
            <Filter className="h-3.5 w-3.5" />
            <span>Filters:</span>
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="h-8 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="ack">Acknowledged</option>
            <option value="contained">Contained</option>
            <option value="closed">Closed</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="h-8 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead className="border-b border-hairline bg-canvas text-[11px] font-mono uppercase text-mute">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Opened (IST)</th>
                <th className="px-4 py-3">Last Activity</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline font-mono text-[12px]">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-mute italic">
                    {loading ? "Loading incidents..." : "No incidents found matching filters."}
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.incident_id} className="hover:bg-canvas/60 transition-colors">
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <SeverityPill severity={inc.severity} size="sm" />
                    </td>

                    <td className="px-4 py-3.5 font-medium text-ink max-w-[360px] truncate">
                      <Link href={`/incidents/${inc.incident_id}`} className="hover:text-link">
                        {inc.title}
                      </Link>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <Link
                        href={`/actors/${inc.actor_id}`}
                        className="text-link font-semibold hover:underline"
                      >
                        {inc.actor_label}
                      </Link>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span
                        className={`rounded px-2 py-0.5 text-[11px] uppercase font-bold ${
                          inc.status === "open"
                            ? "bg-red-50 text-red-700 border border-red-200"
                            : inc.status === "ack"
                            ? "bg-amber-50 text-amber-700 border border-amber-200"
                            : inc.status === "contained"
                            ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                            : "bg-gray-100 text-gray-700"
                        }`}
                      >
                        {inc.status}
                      </span>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap font-bold text-ink">
                      {inc.risk_score}
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-mute" title={inc.opened_at}>
                      {istTime(inc.opened_at)}
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-mute" title={inc.updated_at}>
                      {istTime(inc.updated_at)} ({ago(inc.updated_at)})
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-right">
                      <Link
                        href={`/incidents/${inc.incident_id}`}
                        className="btn text-[12px] h-7 px-2.5 inline-flex items-center gap-1"
                      >
                        <span>Investigate</span>
                        <ArrowRight className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
