"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, HttpError } from "@/lib/api";
import { ago } from "@/lib/format";
import type { Diversion } from "@/lib/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Shuffle, Undo2, ShieldCheck } from "@/components/icons";

type Pending = { ip: string; action: "divert" | "release" } | null;

export default function DiversionsPage() {
  const [items, setItems] = useState<Diversion[]>([]);
  const [loading, setLoading] = useState(true);
  const [ip, setIp] = useState("");
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    api.listDiversions()
      .then(setItems)
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  async function apply() {
    if (!pending) return;
    setBusy(true);
    setError("");
    try {
      await api.setDiversion(pending.ip, pending.action);
      setPending(null);
      setIp("");
      load();
    } catch (e) {
      setError(e instanceof HttpError ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-[28px] font-semibold tracking-tight text-ink">Diversions</h1>
        <p className="mt-1 text-body text-[13px]">
          Visitors the divert proxy serves from the Aetees honeypot clone, on the same URL. Release a false positive to
          send them back to the real shop; the proxy picks the change up within 5 seconds.
        </p>
      </div>

      <div className="card p-4 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-[12px] text-mute">
          IP address
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value.trim())}
            placeholder="203.0.113.7"
            className="h-9 w-56 rounded-md border border-hairline bg-elevated px-3 font-mono text-[13px] text-ink"
          />
        </label>
        <button
          disabled={!ip}
          onClick={() => setPending({ ip, action: "divert" })}
          className="h-9 rounded-md bg-ink px-3 text-[13px] font-medium text-canvas disabled:opacity-40 flex items-center gap-1.5"
        >
          <Shuffle className="h-4 w-4" /> Divert to clone
        </button>
        <button
          disabled={!ip}
          onClick={() => setPending({ ip, action: "release" })}
          className="h-9 rounded-md border border-hairline px-3 text-[13px] font-medium text-ink disabled:opacity-40 flex items-center gap-1.5"
        >
          <Undo2 className="h-4 w-4" /> Release to real shop
        </button>
        {error && <span className="text-[12px] text-rose-600">{error}</span>}
      </div>

      <div className="card overflow-hidden">
        <table className="w-full text-left text-[13px]">
          <thead className="border-b border-hairline bg-canvas text-[11px] font-mono uppercase text-mute">
            <tr>
              <th className="px-4 py-3">IP</th>
              <th className="px-4 py-3">State</th>
              <th className="px-4 py-3">Reason</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Since</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-hairline font-mono text-[12px]">
            {items.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-mute italic">
                  {loading ? "Loading..." : "Nobody is diverted. Visitors all see the real shop."}
                </td>
              </tr>
            ) : (
              items.map((d) => (
                <tr key={d.ip} className="hover:bg-canvas/60">
                  <td className="px-4 py-3 font-bold text-ink">{d.ip}</td>
                  <td className="px-4 py-3">
                    {d.state === "diverted" ? (
                      <span className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] font-bold text-amber-800">
                        In honeypot clone
                      </span>
                    ) : (
                      <span className="rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[11px] font-bold text-emerald-800 inline-flex items-center gap-1">
                        <ShieldCheck className="h-3 w-3" /> Released
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-body max-w-[320px] truncate" title={d.reason}>{d.reason || "analyst action"}</td>
                  <td className="px-4 py-3">
                    {d.actor_label ? <Link className="text-link hover:underline" href={`/actors/${d.actor_label}`}>{d.actor_label}</Link> : "—"}
                  </td>
                  <td className="px-4 py-3 text-mute">{d.at ? ago(d.at) : "—"}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => setPending({ ip: d.ip, action: d.state === "diverted" ? "release" : "divert" })}
                      className="rounded-md border border-hairline px-2.5 py-1 text-[12px] text-ink hover:bg-canvas"
                    >
                      {d.state === "diverted" ? "Release" : "Divert again"}
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(o) => !o && setPending(null)}
        title={pending?.action === "release" ? `Release ${pending.ip}?` : `Divert ${pending?.ip ?? ""}?`}
        description={
          pending?.action === "release"
            ? "False positive: this visitor gets the real shop again and is not re-diverted on weak signals for 24 hours."
            : "This visitor will be served the honeypot clone on the same URL for 24 hours, and every request is recorded."
        }
        confirmLabel={pending?.action === "release" ? "Release" : "Divert"}
        danger={pending?.action === "divert"}
        onConfirm={apply}
        loading={busy}
      />
    </div>
  );
}
