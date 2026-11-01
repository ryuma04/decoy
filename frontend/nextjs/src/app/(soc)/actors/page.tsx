"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ago, istTime } from "@/lib/format";
import { useStream } from "@/lib/stream";
import type { ActorSummary } from "@/lib/types";
import { SeverityPill } from "@/components/SeverityPill";
import { BehaviourBadge } from "@/components/BehaviourBadge";
import { ServiceIcon } from "@/components/ServiceIcon";
import { ArrowUpDown, ArrowRight } from "@/components/icons";

export default function ActorsPage() {
  const [actors, setActors] = useState<ActorSummary[]>([]);
  const [sortKey, setSortKey] = useState<"risk" | "last_seen">("risk");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listActors({ sort: sortKey })
      .then((res) => setActors(res.items))
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, [sortKey]);

  // Live SSE updates for actor creations / score updates
  useStream<ActorSummary>("actor", (updated) => {
    setActors((prev) => {
      const idx = prev.findIndex((a) => a.actor_id === updated.actor_id);
      if (idx >= 0) {
        const copy = [...prev];
        copy[idx] = updated;
        return copy;
      }
      return [updated, ...prev];
    });
  });

  const sorted = [...actors].sort((a, b) => {
    if (sortKey === "risk") return b.risk_score - a.risk_score;
    return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">Correlated Threat Actors</h1>
          <p className="mt-1 text-body text-[13px]">
            Activity linked across decoys via credential lineage, cryptographic keys, and behavioural metrics.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setSortKey(sortKey === "risk" ? "last_seen" : "risk")}
            className="btn text-[12px] font-mono gap-1.5"
          >
            <ArrowUpDown className="h-3.5 w-3.5" />
            <span>Sort: {sortKey === "risk" ? "Highest Risk" : "Recently Active"}</span>
          </button>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead className="border-b border-hairline bg-canvas text-[11px] font-mono uppercase text-mute">
              <tr>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Risk Score</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Correlation Confidence</th>
                <th className="px-4 py-3">Observed Behaviour</th>
                <th className="px-4 py-3">Decoys Visited</th>
                <th className="px-4 py-3">Sessions</th>
                <th className="px-4 py-3">Top ATT&CK</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline font-mono text-[12px]">
              {sorted.length === 0 ? (
                <tr>
                  <td colSpan={10} className="px-4 py-8 text-center text-mute italic">
                    {loading ? "Loading actors..." : "No correlated actors detected."}
                  </td>
                </tr>
              ) : (
                sorted.map((actor) => (
                  <tr key={actor.actor_id} className="hover:bg-canvas/60 transition-colors">
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <Link
                        href={`/actors/${actor.actor_id}`}
                        className="font-bold text-ink hover:text-link flex items-center gap-1.5 text-[14px]"
                      >
                        <span>{actor.label}</span>
                        {actor.touched_production && (
                          <span
                            className="h-2 w-2 rounded-full bg-red-600"
                            title="Touched Production Systems"
                          />
                        )}
                      </Link>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-20 rounded-full bg-hairline overflow-hidden">
                          <div
                            className={`h-full ${
                              actor.risk_score >= 80
                                ? "bg-red-600"
                                : actor.risk_score >= 60
                                ? "bg-amber-500"
                                : "bg-blue-500"
                            }`}
                            style={{ width: `${actor.risk_score}%` }}
                          />
                        </div>
                        <span className="font-bold text-ink">{actor.risk_score}</span>
                      </div>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <SeverityPill severity={actor.severity} size="sm" />
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-mute">
                      <span className="font-semibold text-ink">
                        {(actor.confidence * 100).toFixed(0)}%
                      </span>{" "}
                      (likely same operator)
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <BehaviourBadge behaviourClass={actor.behaviour_class} size="sm" />
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {actor.services.map((svc) => (
                          <ServiceIcon key={svc} service={svc} className="h-3.5 w-3.5" />
                        ))}
                      </div>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-ink">
                      {actor.session_count}
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <div className="flex gap-1">
                        {actor.top_techniques.slice(0, 3).map((t) => (
                          <span
                            key={t}
                            className="rounded bg-canvas border border-hairline px-1.5 py-0.5 text-[10px] text-body"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-mute" title={actor.last_seen}>
                      {istTime(actor.last_seen)} ({ago(actor.last_seen)})
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-right">
                      <Link
                        href={`/actors/${actor.actor_id}`}
                        className="btn text-[12px] h-7 px-2.5 inline-flex items-center gap-1"
                      >
                        <span>Profile</span>
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
