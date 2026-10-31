import React, { useState } from "react";
import type { TimelineItem } from "@/lib/types";
import { ago, istTime } from "@/lib/format";
import { ServiceIcon } from "@/components/ServiceIcon";
import { AlertCircle, Compass, Shield, Terminal, ArrowUpRight } from "lucide-react";

interface Props {
  items: TimelineItem[];
  onSelectEvent?: (eventId: string) => void;
}

export function Timeline({ items, onSelectEvent }: Props) {
  const [filter, setFilter] = useState<"all" | "event" | "finding" | "maze">("all");

  const filtered = items.filter((item) => {
    if (filter === "all") return true;
    return item.kind === filter;
  });

  return (
    <div className="flex flex-col gap-4">
      {/* Filters */}
      <div className="flex items-center gap-2">
        {(["all", "event", "finding", "maze"] as const).map((k) => (
          <button
            key={k}
            onClick={() => setFilter(k)}
            className={`btn text-[12px] font-mono capitalize ${
              filter === k ? "btn-primary" : ""
            }`}
          >
            {k === "all" ? "All Activity" : `${k}s`}
          </button>
        ))}
        <span className="ml-auto font-mono text-[12px] text-mute">
          {filtered.length} entries
        </span>
      </div>

      {/* Timeline Stream */}
      <div className="relative border-l-2 border-hairline ml-3 pl-6 space-y-6">
        {filtered.length === 0 ? (
          <p className="py-4 text-[13px] text-mute italic">No matching timeline entries.</p>
        ) : (
          filtered.map((item, idx) => {
            if (item.kind === "event") {
              const ev = item.event;
              const isProd = ev.origin === "production";
              return (
                <div key={`ev-${ev.event_id}-${idx}`} className="relative group">
                  {/* Timeline dot */}
                  <div
                    className={`absolute -left-[31px] top-1.5 flex h-5 w-5 items-center justify-center rounded-full border bg-elevated shadow-xs ${
                      isProd
                        ? "border-red-500 text-red-600 bg-red-50 ring-2 ring-red-100"
                        : "border-link text-link"
                    }`}
                  >
                    {isProd ? <Shield className="h-3 w-3" /> : <Terminal className="h-3 w-3" />}
                  </div>

                  <div
                    className={`card p-4 transition-all hover:border-link/50 cursor-pointer ${
                      isProd ? "border-red-200 bg-red-50/40" : ""
                    }`}
                    onClick={() => onSelectEvent?.(ev.event_id)}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <ServiceIcon service={ev.service} className="h-4 w-4" />
                        <span className="font-mono text-[12px] font-semibold text-ink">
                          {ev.type}
                        </span>
                        {isProd && (
                          <span className="rounded bg-red-600 text-white font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 tracking-wide">
                            Production Alert
                          </span>
                        )}
                        <span className="text-mute font-mono text-[12px]">·</span>
                        <span className="font-mono text-[12px] text-body">{ev.src_ip}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] text-mute" title={item.ts}>
                          {istTime(item.ts)} ({ago(item.ts)})
                        </span>
                        <ArrowUpRight className="h-3.5 w-3.5 text-mute opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </div>

                    <p className="mt-2 font-mono text-[13px] text-ink bg-canvas/80 p-2.5 rounded border border-hairline break-all">
                      {ev.summary}
                    </p>

                    {ev.tokens && ev.tokens.length > 0 && (
                      <div className="mt-2 flex items-center gap-1.5">
                        <span className="text-[11px] font-mono text-mute">Honeytoken:</span>
                        {ev.tokens.map((t) => (
                          <span
                            key={t}
                            className="rounded bg-rose-50 border border-rose-200 px-1.5 py-0.2 text-[10px] font-mono font-semibold text-rose-700"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            }

            if (item.kind === "finding") {
              const f = item.finding;
              return (
                <div key={`find-${f.finding_id}-${idx}`} className="relative">
                  <div className="absolute -left-[31px] top-1.5 flex h-5 w-5 items-center justify-center rounded-full border border-amber-500 bg-amber-50 text-amber-600 shadow-xs ring-2 ring-amber-100">
                    <AlertCircle className="h-3 w-3" />
                  </div>

                  <div className="card border-amber-200 bg-amber-50/20 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] font-bold text-amber-800 bg-amber-100 px-2 py-0.5 rounded border border-amber-300">
                          {f.technique ?? "T-UNKNOWN"}
                        </span>
                        <span className="font-semibold text-[13px] text-ink">{f.title}</span>
                      </div>
                      <span className="font-mono text-[11px] text-mute">{istTime(item.ts)}</span>
                    </div>

                    {f.evidence.matched && (
                      <p className="mt-2 text-[12px] font-mono text-body bg-canvas p-2 rounded border border-hairline break-all">
                        Evidence: {f.evidence.matched}
                      </p>
                    )}
                  </div>
                </div>
              );
            }

            if (item.kind === "maze") {
              return (
                <div key={`maze-${item.node_id}-${idx}`} className="relative">
                  <div className="absolute -left-[31px] top-1.5 flex h-5 w-5 items-center justify-center rounded-full border border-purple-500 bg-purple-50 text-purple-600 shadow-xs">
                    <Compass className="h-3 w-3" />
                  </div>

                  <div className="card border-purple-200 bg-purple-50/20 p-3.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] font-semibold uppercase text-purple-700">
                        Maze Node Unlocked: {item.node_id} ({item.state})
                      </span>
                      <span className="font-mono text-[11px] text-mute">{istTime(item.ts)}</span>
                    </div>
                    <p className="mt-1 text-[12px] text-body">{item.reason}</p>
                  </div>
                </div>
              );
            }

            return null;
          })
        )}
      </div>
    </div>
  );
}
