"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ago, istTime } from "@/lib/format";
import type { Honeytoken } from "@/lib/types";
import { KeyRound, Flame, CheckCircle2 } from "@/components/icons";

export default function HoneytokensPage() {
  const [tokens, setTokens] = useState<Honeytoken[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listHoneytokens()
      .then(setTokens)
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">Planted Honeytokens</h1>
          <p className="mt-1 text-body text-[13px]">
            Zero-false-positive lures planted in files, environment variables, and shell histories.
          </p>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead className="border-b border-hairline bg-canvas text-[11px] font-mono uppercase text-mute">
              <tr>
                <th className="px-4 py-3">Token ID</th>
                <th className="px-4 py-3">Kind</th>
                <th className="px-4 py-3">Planted Location</th>
                <th className="px-4 py-3">Sensitivity</th>
                <th className="px-4 py-3">Exfiltrations (Seen)</th>
                <th className="px-4 py-3">Triggered (Used)</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Last Hit</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline font-mono text-[12px]">
              {tokens.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-mute italic">
                    {loading ? "Loading honeytokens..." : "No honeytokens registered."}
                  </td>
                </tr>
              ) : (
                tokens.map((tok) => (
                  <tr key={tok.token_id} className="hover:bg-canvas/60 transition-colors">
                    <td className="px-4 py-3.5 whitespace-nowrap font-bold text-ink flex items-center gap-2">
                      <KeyRound className="h-4 w-4 text-mute shrink-0" />
                      <span>{tok.token_id}</span>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-mute">
                      <span className="bg-canvas border border-hairline px-2 py-0.5 rounded text-[11px] text-body">
                        {tok.kind}
                      </span>
                    </td>

                    <td className="px-4 py-3.5 text-body max-w-[280px] truncate" title={tok.planted_at}>
                      {tok.planted_at}
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span className="font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded text-[11px]">
                        Level {tok.sensitivity} / 5
                      </span>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-ink">
                      {tok.hits_seen}
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span
                        className={`font-bold ${
                          tok.hits_used > 0 ? "text-rose-600" : "text-mute"
                        }`}
                      >
                        {tok.hits_used}
                      </span>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      {tok.burned ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-bold text-red-700 bg-red-50 border border-red-200 px-2 py-0.5 rounded">
                          <Flame className="h-3 w-3" />
                          Burned
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                          <CheckCircle2 className="h-3 w-3" />
                          Active
                        </span>
                      )}
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap text-mute">
                      {tok.last_hit ? `${istTime(tok.last_hit)} (${ago(tok.last_hit)})` : "Never"}
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
