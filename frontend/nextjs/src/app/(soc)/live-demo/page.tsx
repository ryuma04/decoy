"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useStream, useStreamStatus } from "@/lib/stream";
import { api } from "@/lib/api";
import { istTime } from "@/lib/format";
import type { Event } from "@/lib/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Send,
  ShieldAlert,
  ShieldCheck,
  Undo2,
} from "@/components/icons";

interface ProxyResponse {
  success: boolean;
  status: number;
  statusText: string;
  latencyMs: number;
  contentType: string;
  bodySnippet: string;
  upstream: "clone" | "real" | "proxy_direct" | "none";
  targetUrl?: string;
}

export default function LiveDemoPage() {
  const streamStatus = useStreamStatus();

  // Service health
  const [health, setHealth] = useState<{
    proxyOnline: boolean;
    coreOnline: boolean;
    proxyUrl: string;
    coreUrl: string;
  } | null>(null);

  // Live telemetry events from SSE stream
  const [liveEvents, setLiveEvents] = useState<Event[]>([]);

  // Attacker state
  const [attackerBusy, setAttackerBusy] = useState(false);
  const [attackerLastResp, setAttackerLastResp] = useState<ProxyResponse | null>(null);
  const [attackerCustomPath, setAttackerCustomPath] = useState("/search?q=cake' UNION SELECT 1,2,3--");
  const [isDiverted, setIsDiverted] = useState(false);

  // Customer state
  const [customerBusy, setCustomerBusy] = useState(false);
  const [customerLastResp, setCustomerLastResp] = useState<ProxyResponse | null>(null);

  // Confirmation dialog for release
  const [confirmRelease, setConfirmRelease] = useState(false);
  const [releaseBusy, setReleaseBusy] = useState(false);

  // Poll health of proxy & core
  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch("/api/demo-proxy", { cache: "no-store" });
      const data = await res.json();
      setHealth(data);
    } catch {
      setHealth({ proxyOnline: false, coreOnline: false, proxyUrl: ":8200", coreUrl: ":8090" });
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  // Listen for real incoming SSE events
  useStream<Event>("event", (ev) => {
    setLiveEvents((prev) => [ev, ...prev.slice(0, 19)]);
    if (ev.type === "session.diverted" || ev.type === "input.suspicious") {
      setIsDiverted(true);
    }
    if (ev.type === "session.released") {
      setIsDiverted(false);
    }
  });

  // Execute request through the divert proxy via server route handler
  async function execRequest(
    session: "attacker" | "customer",
    method: "GET" | "POST",
    path: string,
    body?: unknown
  ) {
    if (session === "attacker") setAttackerBusy(true);
    else setCustomerBusy(true);

    try {
      const res = await fetch("/api/demo-proxy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session, method, path, body }),
      });
      const data: ProxyResponse = await res.json();
      if (session === "attacker") {
        setAttackerLastResp(data);
        if (data.upstream === "clone" || data.status === 503) {
          setIsDiverted(true);
        }
      } else {
        setCustomerLastResp(data);
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const errResp: ProxyResponse = {
        success: false,
        status: 500,
        statusText: "Client Fetch Error",
        latencyMs: 0,
        contentType: "text/plain",
        bodySnippet: errMsg,
        upstream: "none",
      };
      if (session === "attacker") setAttackerLastResp(errResp);
      else setCustomerLastResp(errResp);
    } finally {
      if (session === "attacker") setAttackerBusy(false);
      else setCustomerBusy(false);
    }
  }

  // Handle analyst release
  async function handleRelease() {
    setReleaseBusy(true);
    try {
      await api.setDiversion("127.0.0.1", "release");
      setIsDiverted(false);
      setConfirmRelease(false);
    } catch (e) {
      console.error("Release error:", e);
    } finally {
      setReleaseBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Top Banner / Explainer */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[28px] font-semibold tracking-tight text-ink">
              Live In-Session Diversion Showcase
            </h1>
            <span className="rounded-full bg-emerald-100 dark:bg-emerald-950 px-2.5 py-0.5 text-[11px] font-mono font-medium text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
              Zero Mock Data
            </span>
          </div>
          <p className="mt-1 text-body text-[13px] max-w-3xl">
            Watch the live USP in action: An attacker probing the live website is transparently trapped in an identical honeypot clone, while real customers checkout on production without interruption.
          </p>
        </div>

        {/* Backend Connectivity Status */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 card px-3 py-1.5 text-[12px] font-mono">
            <span
              className={`h-2 w-2 rounded-full ${
                health?.proxyOnline ? "bg-emerald-500 animate-pulse" : "bg-rose-500"
              }`}
            />
            <span className="text-mute">Proxy (:8200):</span>
            <span className={health?.proxyOnline ? "text-ink font-semibold" : "text-rose-600"}>
              {health?.proxyOnline ? "Connected" : "Offline"}
            </span>
          </div>
          <div className="flex items-center gap-2 card px-3 py-1.5 text-[12px] font-mono">
            <span
              className={`h-2 w-2 rounded-full ${
                streamStatus === "live" ? "bg-emerald-500" : "bg-amber-500"
              }`}
            />
            <span className="text-mute">SOC SSE:</span>
            <span className={streamStatus === "live" ? "text-ink font-semibold" : "text-amber-600"}>
              {streamStatus === "live" ? "Live Streaming" : "Connecting"}
            </span>
          </div>
          <button
            onClick={() => {
              setAttackerLastResp(null);
              setCustomerLastResp(null);
              setLiveEvents([]);
              setIsDiverted(false);
            }}
            className="btn text-[12px] gap-1"
            title="Clear display state"
          >
            <RefreshCw className="h-3 w-3" />
            <span>Reset View</span>
          </button>
        </div>
      </div>

      {!health?.proxyOnline && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 dark:bg-amber-950/40 p-4 text-[13px] text-amber-900 dark:text-amber-200 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold">Divert Proxy not detected on :8200.</span>
            <p className="mt-0.5 text-amber-800 dark:text-amber-300">
              To drive this live, ensure the lab is started: run{" "}
              <code className="bg-amber-100 dark:bg-amber-900 px-1.5 py-0.5 rounded font-mono text-[12px]">
                scripts/aetees-lab.sh
              </code>{" "}
              and{" "}
              <code className="bg-amber-100 dark:bg-amber-900 px-1.5 py-0.5 rounded font-mono text-[12px]">
                go run ./cmd/divert-proxy
              </code>
              .
            </p>
          </div>
        </div>
      )}

      {/* 3-Panel Split Screen */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ========================================================= */}
        {/* PANEL 1: ATTACKER VIEW */}
        {/* ========================================================= */}
        <div className="card flex flex-col border-rose-200/80 dark:border-rose-950/60 overflow-hidden shadow-xs">
          <div className="p-4 border-b border-hairline bg-rose-50/50 dark:bg-rose-950/20 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-rose-600 text-white">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <div>
                <h2 className="text-[14px] font-semibold text-ink">Window 1: Attacker View</h2>
                <span className="text-[11px] font-mono text-mute">Session Cookie: _aet_v=atk-live</span>
              </div>
            </div>
            {isDiverted ? (
              <span className="rounded-full bg-rose-100 dark:bg-rose-950 px-2.5 py-0.5 text-[11px] font-mono font-bold text-rose-700 dark:text-rose-300 border border-rose-300 animate-pulse">
                TRAPPED IN CLONE
              </span>
            ) : (
              <span className="rounded-full bg-zinc-100 dark:bg-zinc-800 px-2 py-0.5 text-[11px] font-mono text-mute">
                Undiverted
              </span>
            )}
          </div>

          <div className="p-4 space-y-4 flex-1 flex flex-col">
            <div className="space-y-1.5">
              <label className="text-[11px] font-mono font-medium uppercase text-mute">
                Live Attack Triggers (Same URL: localhost:8200)
              </label>
              <div className="grid grid-cols-1 gap-2">
                <button
                  disabled={attackerBusy}
                  onClick={() =>
                    execRequest(
                      "attacker",
                      "GET",
                      "/search?q=cake' UNION SELECT 1,2,3--"
                    )
                  }
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-rose-300 hover:bg-rose-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
                      SQLi in Search Bar
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      GET /search?q=cake&apos; UNION SELECT...
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-rose-600 transition" />
                </button>

                <button
                  disabled={attackerBusy}
                  onClick={() => execRequest("attacker", "GET", "/.env")}
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-rose-300 hover:bg-rose-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
                      Probe Sensitive File
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      GET /.env (triggers Hard divert)
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-rose-600 transition" />
                </button>

                <button
                  disabled={attackerBusy}
                  onClick={() =>
                    execRequest("attacker", "GET", "/backup/aetees_db_FINAL.sql.gz")
                  }
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-rose-300 hover:bg-rose-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
                      Inspect Backup Lure
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      GET /backup/aetees_db_FINAL.sql.gz
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-rose-600 transition" />
                </button>

                <button
                  disabled={attackerBusy}
                  onClick={() =>
                    execRequest(
                      "attacker",
                      "POST",
                      "/api/checkout",
                      { name: "Attacker", cart: ["cake"] }
                    )
                  }
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-rose-300 hover:bg-rose-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
                      Attempt Checkout While Diverted
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      POST /api/checkout (held with 503)
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-rose-600 transition" />
                </button>
              </div>
            </div>

            {/* Custom URL Input */}
            <div className="pt-2">
              <label className="text-[11px] font-mono text-mute block mb-1">Custom Request</label>
              <div className="flex gap-2">
                <input
                  value={attackerCustomPath}
                  onChange={(e) => setAttackerCustomPath(e.target.value)}
                  placeholder="/search?q=..."
                  className="h-8 flex-1 rounded-md border border-hairline bg-elevated px-2.5 font-mono text-[12px] text-ink"
                />
                <button
                  disabled={attackerBusy}
                  onClick={() => execRequest("attacker", "GET", attackerCustomPath)}
                  className="h-8 px-3 rounded-md bg-ink text-canvas text-[12px] font-medium disabled:opacity-40"
                >
                  Send
                </button>
              </div>
            </div>

            {/* Live Response Box */}
            <div className="flex-1 flex flex-col space-y-1.5 pt-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-mono font-medium uppercase text-mute">
                  Live HTTP Response Received
                </label>
                {attackerLastResp && (
                  <span
                    className={`text-[11px] font-mono px-2 py-0.5 rounded font-semibold ${
                      attackerLastResp.upstream === "clone"
                        ? "bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-300"
                        : "bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300"
                    }`}
                  >
                    Served by: {attackerLastResp.upstream.toUpperCase()}
                  </span>
                )}
              </div>

              <div className="flex-1 min-h-[140px] rounded-md border border-hairline bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300 overflow-y-auto">
                {attackerLastResp ? (
                  <div className="space-y-1.5">
                    <div className="text-zinc-400">
                      HTTP/1.1 <span className={attackerLastResp.status < 400 ? "text-emerald-400" : "text-amber-400"}>{attackerLastResp.status} {attackerLastResp.statusText}</span> ({attackerLastResp.latencyMs} ms)
                    </div>
                    <div className="text-zinc-500">Content-Type: {attackerLastResp.contentType}</div>
                    <div className="border-t border-zinc-800 pt-2 text-zinc-300 whitespace-pre-wrap break-all">
                      {attackerLastResp.bodySnippet || "(Empty response)"}
                    </div>
                  </div>
                ) : (
                  <div className="h-full flex items-center justify-center text-zinc-600">
                    Click an attack button to execute against the live proxy...
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* PANEL 2: REAL CUSTOMER VIEW */}
        {/* ========================================================= */}
        <div className="card flex flex-col border-emerald-200/80 dark:border-emerald-950/60 overflow-hidden shadow-xs">
          <div className="p-4 border-b border-hairline bg-emerald-50/50 dark:bg-emerald-950/20 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-emerald-600 text-white">
                <ShieldCheck className="h-4 w-4" />
              </div>
              <div>
                <h2 className="text-[14px] font-semibold text-ink">Window 2: Customer View</h2>
                <span className="text-[11px] font-mono text-mute">Session Cookie: _aet_v=cust-live</span>
              </div>
            </div>
            <span className="rounded-full bg-emerald-100 dark:bg-emerald-950 px-2.5 py-0.5 text-[11px] font-mono font-bold text-emerald-800 dark:text-emerald-300 border border-emerald-300">
              PRODUCTION SHOP
            </span>
          </div>

          <div className="p-4 space-y-4 flex-1 flex flex-col">
            <div className="space-y-1.5">
              <label className="text-[11px] font-mono font-medium uppercase text-mute">
                Normal Customer Actions (Same URL: localhost:8200)
              </label>
              <div className="grid grid-cols-1 gap-2">
                <button
                  disabled={customerBusy}
                  onClick={() => execRequest("customer", "GET", "/menu")}
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-emerald-300 hover:bg-emerald-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                      Browse Bakery Menu
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      GET /menu (clean navigation)
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-emerald-600 transition" />
                </button>

                <button
                  disabled={customerBusy}
                  onClick={() =>
                    execRequest(
                      "customer",
                      "POST",
                      "/api/contact",
                      { message: "Mom's cake; less sugar -- urgent" }
                    )
                  }
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-emerald-300 hover:bg-emerald-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                      Customer Message (with ; and --)
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      POST /api/contact (Mom&apos;s cake; less sugar -- urgent)
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-emerald-600 transition" />
                </button>

                <button
                  disabled={customerBusy}
                  onClick={() =>
                    execRequest(
                      "customer",
                      "POST",
                      "/api/cart",
                      { productId: 1, quantity: 2, size: "1 kg" }
                    )
                  }
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-emerald-300 hover:bg-emerald-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                      Add Chocolate Truffle to Cart
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      POST /api/cart (chocolate cake, 1 kg)
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-emerald-600 transition" />
                </button>

                <button
                  disabled={customerBusy}
                  onClick={() =>
                    execRequest(
                      "customer",
                      "POST",
                      "/api/checkout",
                      {
                        name: "Aarav Sharma",
                        email: "aarav@example.com",
                        address: "42, Bandra Hill, Mumbai",
                        cart: [{ id: 1, qty: 1 }],
                      }
                    )
                  }
                  className="w-full text-left p-2.5 rounded-md border border-hairline hover:border-emerald-300 hover:bg-emerald-50/30 transition text-[12px] flex items-center justify-between group"
                >
                  <div>
                    <div className="font-medium text-ink flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                      Place Production Order
                    </div>
                    <code className="text-[11px] text-mute font-mono">
                      POST /api/checkout (writes to real.db)
                    </code>
                  </div>
                  <Send className="h-3.5 w-3.5 text-mute group-hover:text-emerald-600 transition" />
                </button>
              </div>
            </div>

            {/* Zero Collateral Guarantee Box */}
            <div className="p-3 rounded-md bg-emerald-50/60 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900 text-[12px] text-emerald-900 dark:text-emerald-200">
              <span className="font-semibold block">Zero Collateral Damage</span>
              <p className="text-[11px] text-emerald-800 dark:text-emerald-300 mt-0.5">
                Real customer transactions are never routed to the honeypot clone, never logged to the SOC, and real money/orders are fully protected.
              </p>
            </div>

            {/* Live Customer Response Box */}
            <div className="flex-1 flex flex-col space-y-1.5 pt-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-mono font-medium uppercase text-mute">
                  Live HTTP Response Received
                </label>
                {customerLastResp && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded font-semibold bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300">
                    Served by: REAL SHOP (:3100)
                  </span>
                )}
              </div>

              <div className="flex-1 min-h-[140px] rounded-md border border-hairline bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300 overflow-y-auto">
                {customerLastResp ? (
                  <div className="space-y-1.5">
                    <div className="text-zinc-400">
                      HTTP/1.1 <span className="text-emerald-400">{customerLastResp.status} {customerLastResp.statusText}</span> ({customerLastResp.latencyMs} ms)
                    </div>
                    <div className="text-zinc-500">Content-Type: {customerLastResp.contentType}</div>
                    <div className="border-t border-zinc-800 pt-2 text-zinc-300 whitespace-pre-wrap break-all">
                      {customerLastResp.bodySnippet || "(Empty response)"}
                    </div>
                  </div>
                ) : (
                  <div className="h-full flex items-center justify-center text-zinc-600">
                    Click a customer action to execute against the live proxy...
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* PANEL 3: SOC ANALYST VIEW */}
        {/* ========================================================= */}
        <div className="card flex flex-col border-indigo-200/80 dark:border-indigo-950/60 overflow-hidden shadow-xs">
          <div className="p-4 border-b border-hairline bg-indigo-50/50 dark:bg-indigo-950/20 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-md bg-indigo-600 text-white">
                <Activity className="h-4 w-4" />
              </div>
              <div>
                <h2 className="text-[14px] font-semibold text-ink">Window 3: Live SOC Stream</h2>
                <span className="text-[11px] font-mono text-mute">Core SSE: /v1/events/stream</span>
              </div>
            </div>
            <Link
              href="/events"
              className="text-[11px] font-mono text-indigo-600 dark:text-indigo-400 hover:underline flex items-center gap-1"
            >
              Open Full SOC <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="p-4 space-y-4 flex-1 flex flex-col">
            {/* Quick Analyst Actions */}
            <div className="flex items-center justify-between card p-3 bg-canvas">
              <div>
                <span className="text-[12px] font-medium text-ink block">Analyst Intervention</span>
                <span className="text-[11px] text-mute">Release diverted visitor back to real shop</span>
              </div>
              <button
                disabled={!isDiverted || releaseBusy}
                onClick={() => setConfirmRelease(true)}
                className="h-8 px-3 rounded-md bg-ink text-canvas text-[12px] font-medium disabled:opacity-40 flex items-center gap-1.5"
              >
                <Undo2 className="h-3.5 w-3.5" />
                <span>Release Visitor</span>
              </button>
            </div>

            {/* Live SSE Telemetry Feed */}
            <div className="flex-1 flex flex-col space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-[11px] font-mono font-medium uppercase text-mute">
                  Incoming Decoy Telemetry Events
                </label>
                <span className="text-[10px] font-mono text-mute">{liveEvents.length} events buffered</span>
              </div>

              <div className="flex-1 min-h-[280px] rounded-md border border-hairline bg-zinc-950 p-2.5 font-mono text-[11px] overflow-y-auto space-y-2">
                {liveEvents.length > 0 ? (
                  liveEvents.map((ev, i) => (
                    <div
                      key={ev.event_id || i}
                      className="p-2 rounded bg-zinc-900/80 border border-zinc-800 text-zinc-300 space-y-1 transition hover:bg-zinc-800/80"
                    >
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="text-zinc-400">{istTime(ev.ts)}</span>
                        <span
                          className={`px-1.5 py-0.2 rounded font-semibold uppercase ${
                            ev.type.includes("diverted") || ev.type.includes("suspicious")
                              ? "bg-rose-950 text-rose-300 border border-rose-800"
                              : "bg-zinc-800 text-zinc-300"
                          }`}
                        >
                          {ev.type}
                        </span>
                      </div>
                      <div className="text-[11px] text-zinc-200 font-medium">
                        {ev.summary || ev.type}
                      </div>
                      {ev.actor_label && (
                        <div className="text-[10px] text-indigo-400">
                          Actor: <Link href={`/actors/${ev.actor_id || ev.actor_label}`} className="hover:underline">{ev.actor_label}</Link>
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-zinc-600 gap-1 p-4 text-center">
                    <Activity className="h-6 w-6 animate-pulse text-zinc-700" />
                    <span>Listening for live events from Core...</span>
                    <span className="text-[10px] text-zinc-700">Trigger an attack in Window 1 to see telemetry stream in real time.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Dialog */}
      <ConfirmDialog
        open={confirmRelease}
        onOpenChange={setConfirmRelease}
        title="Release Diverted Visitor"
        description="Are you sure you want to release this visitor? The proxy will stop redirecting them to the honeypot clone and restore their connection to the real shop."
        confirmLabel="Release to Real Shop"
        danger={false}
        onConfirm={handleRelease}
        loading={releaseBusy}
      />
    </div>
  );
}
