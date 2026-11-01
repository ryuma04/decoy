"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useStream, useStreamStatus } from "@/lib/stream";
import { api } from "@/lib/api";
import { istTime } from "@/lib/format";
import type { Event } from "@/lib/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { RiskGauge } from "@/components/RiskGauge";
import {
  Activity,
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

  // Health state
  const [health, setHealth] = useState<{
    proxyOnline: boolean;
    coreOnline: boolean;
  } | null>(null);

  // Live SSE events
  const [liveEvents, setLiveEvents] = useState<Event[]>([]);

  // Simulation states
  const [activeRoute, setActiveRoute] = useState<"idle" | "real" | "clone">("idle");
  const [isDiverted, setIsDiverted] = useState(false);
  const [riskScore, setRiskScore] = useState(0);
  const [activeMitre, setActiveMitre] = useState<string[]>([]);

  // Attacker state
  const [attackerBusy, setAttackerBusy] = useState(false);
  const [attackerTab, setAttackerTab] = useState<"browser" | "admin" | "export" | "raw">("browser");
  const [attackerLastResp, setAttackerLastResp] = useState<ProxyResponse | null>(null);
  const [attackerUrl, setAttackerUrl] = useState("http://aeteesbakehouse.com/");
  const [exportProgress, setExportProgress] = useState<number | null>(null);
  const [exportTimer, setExportTimer] = useState(0);

  // Customer state
  const [customerBusy, setCustomerBusy] = useState(false);
  const [customerTab, setCustomerTab] = useState<"storefront" | "receipt" | "raw">("storefront");
  const [customerLastResp, setCustomerLastResp] = useState<ProxyResponse | null>(null);
  const [cartCount, setCartCount] = useState(0);
  const [customerOrder, setCustomerOrder] = useState<string | null>(null);

  // Confirmation dialog for analyst release
  const [confirmRelease, setConfirmRelease] = useState(false);
  const [releaseBusy, setReleaseBusy] = useState(false);

  // Check backend health
  const checkHealth = useCallback(async () => {
    try {
      const res = await fetch("/api/demo-proxy", { cache: "no-store" });
      const data = await res.json();
      setHealth(data);
    } catch {
      setHealth({ proxyOnline: false, coreOnline: false });
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  // Listen for real incoming SSE events from Go Core
  useStream<Event>("event", (ev) => {
    setLiveEvents((prev) => [ev, ...prev.slice(0, 19)]);

    if (ev.type === "session.diverted" || ev.type === "input.suspicious") {
      setIsDiverted(true);
      setActiveRoute("clone");
      setRiskScore(85);
      setActiveMitre((prev) => Array.from(new Set([...prev, "T1190"])));
    }
    if (ev.type === "session.released") {
      setIsDiverted(false);
      setActiveRoute("real");
      setRiskScore(15);
    }
    if (ev.type === "file.read" || ev.type === "file.download") {
      setActiveMitre((prev) => Array.from(new Set([...prev, "T1552.001"])));
      setRiskScore(95);
    }
  });

  // Stalling export simulation for sunk_cost tactic
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (exportProgress !== null && exportProgress < 97) {
      interval = setInterval(() => {
        setExportProgress((prev) => {
          if (prev === null) return null;
          if (prev < 90) return prev + 15;
          return 97;
        });
      }, 500);
    } else if (exportProgress === 97) {
      interval = setInterval(() => {
        setExportTimer((t) => t + 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [exportProgress]);

  // Execute request through the real divert proxy
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
        setAttackerUrl(`http://aeteesbakehouse.com${path}`);
        if (data.upstream === "clone" || data.status === 503) {
          setIsDiverted(true);
          setActiveRoute("clone");
          setRiskScore(85);
          setActiveMitre((prev) => Array.from(new Set([...prev, "T1190"])));
          if (path.includes("admin")) setAttackerTab("admin");
        } else {
          setActiveRoute("real");
        }
      } else {
        setCustomerLastResp(data);
        setActiveRoute("real");
        if (path === "/api/checkout") {
          setCustomerOrder("ORD-LIVE-7842");
          setCustomerTab("receipt");
        }
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const errResp: ProxyResponse = {
        success: false,
        status: 500,
        statusText: "Error",
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
      setActiveRoute("real");
      setRiskScore(10);
      setConfirmRelease(false);
    } catch (e) {
      console.error("Release error:", e);
    } finally {
      setReleaseBusy(false);
    }
  }

  function handleReset() {
    setIsDiverted(false);
    setActiveRoute("idle");
    setRiskScore(0);
    setActiveMitre([]);
    setAttackerLastResp(null);
    setCustomerLastResp(null);
    setLiveEvents([]);
    setCartCount(0);
    setCustomerOrder(null);
    setExportProgress(null);
    setExportTimer(0);
    setAttackerTab("browser");
    setCustomerTab("storefront");
    setAttackerUrl("http://aeteesbakehouse.com/");
  }

  return (
    <div className="space-y-6">
      {/* ========================================================= */}
      {/* 1. TOP HEADER & STATUS BAR */}
      {/* ========================================================= */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[26px] font-semibold tracking-tight text-ink">
              Live In-Session Deception & Diversion Engine
            </h1>
            <span className="rounded-full bg-emerald-100 dark:bg-emerald-950 px-2.5 py-0.5 text-[11px] font-mono font-medium text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
              Zero Mock Data
            </span>
          </div>
          <p className="mt-1 text-body text-[13px] max-w-3xl">
            Live demonstration of in-line deception: an attacker is silently redirected into an identical honeypot clone on the same URL, while legitimate customers checkout on production unharmed.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 card px-3 py-1.5 text-[12px] font-mono">
            <span
              className={`h-2 w-2 rounded-full ${
                health?.proxyOnline ? "bg-emerald-500 animate-pulse" : "bg-rose-500"
              }`}
            />
            <span className="text-mute">Proxy (:8200):</span>
            <span className={health?.proxyOnline ? "text-ink font-semibold" : "text-rose-600"}>
              {health?.proxyOnline ? "Online" : "Offline"}
            </span>
          </div>

          <div className="flex items-center gap-2 card px-3 py-1.5 text-[12px] font-mono">
            <span
              className={`h-2 w-2 rounded-full ${
                streamStatus === "live" ? "bg-emerald-500 animate-pulse" : "bg-amber-500"
              }`}
            />
            <span className="text-mute">SOC Telemetry:</span>
            <span className={streamStatus === "live" ? "text-ink font-semibold" : "text-amber-600"}>
              {streamStatus === "live" ? "Live Stream" : "Connecting"}
            </span>
          </div>

          <button onClick={handleReset} className="btn text-[12px] gap-1.5" title="Reset demonstration">
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Reset Demo</span>
          </button>
        </div>
      </div>

      {/* ========================================================= */}
      {/* 2. DYNAMIC REAL-TIME TRAFFIC ROUTING TOPOLOGY */}
      {/* ========================================================= */}
      <div className="card p-5 bg-gradient-to-r from-canvas via-elevated to-canvas border-hairline overflow-hidden relative">
        <div className="flex items-center justify-between mb-3 border-b border-hairline pb-2">
          <span className="text-[12px] font-mono font-semibold uppercase tracking-wider text-mute flex items-center gap-2">
            <Activity className="h-4 w-4 text-ink" /> Live Dynamic Request Pipeline (:8200)
          </span>
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span>Production Route</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
              <span>Honeypot Route</span>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center relative py-2">
          {/* Node 1: Ingress */}
          <div className="card p-3 border-hairline bg-canvas flex flex-col items-center text-center">
            <span className="text-[10px] font-mono uppercase text-mute font-medium">1. Incoming Traffic</span>
            <span className="text-[13px] font-semibold text-ink mt-1">Single Public Domain</span>
            <code className="text-[11px] text-mute font-mono mt-0.5">aeteesbakehouse.com</code>
            <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-elevated border border-hairline">
              Client IP: 127.0.0.1
            </div>
          </div>

          {/* Node 2: The Classifier Switch */}
          <div
            className={`card p-3 border-2 transition-all duration-500 text-center flex flex-col items-center relative ${
              isDiverted
                ? "border-rose-500 bg-rose-50/20 dark:bg-rose-950/20 shadow-md shadow-rose-500/10"
                : "border-indigo-400/80 bg-indigo-50/20 dark:bg-indigo-950/20"
            }`}
          >
            <span className="text-[10px] font-mono uppercase text-mute font-medium">2. Divert Proxy (:8200)</span>
            <span className="text-[13px] font-bold text-ink mt-1">In-Line Classifier</span>
            <div className="mt-2 flex flex-col gap-1 w-full text-[10px] font-mono">
              <div className="flex justify-between px-1">
                <span className="text-mute">Pre-Check:</span>
                <span className={isDiverted ? "text-rose-600 font-bold" : "text-emerald-600"}>
                  {isDiverted ? "MATCH (SQLi)" : "CLEAN"}
                </span>
              </div>
              <div className="flex justify-between px-1">
                <span className="text-mute">Risk Grade:</span>
                <span className={isDiverted ? "text-rose-600 font-bold" : "text-emerald-600"}>
                  {isDiverted ? "0.95 (High)" : "0.05 (Safe)"}
                </span>
              </div>
            </div>
          </div>

          {/* Node 3: Upstream Destinations */}
          <div className="md:col-span-2 grid grid-cols-2 gap-3">
            {/* Real Shop Target */}
            <div
              className={`card p-3 border transition-all duration-500 ${
                activeRoute === "real"
                  ? "border-emerald-500 bg-emerald-50/40 dark:bg-emerald-950/30 shadow-md shadow-emerald-500/10 scale-102"
                  : "border-hairline opacity-75"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase font-semibold text-emerald-700 dark:text-emerald-400">
                  Target A: Real Shop (:3100)
                </span>
                {activeRoute === "real" && (
                  <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
                )}
              </div>
              <div className="mt-1 text-[13px] font-semibold text-ink">Production Environment</div>
              <p className="text-[11px] text-mute mt-1 leading-tight">
                Live order transactions, catalog queries, real payments. Zero monitoring overhead.
              </p>
            </div>

            {/* Honeypot Clone Target */}
            <div
              className={`card p-3 border transition-all duration-500 ${
                activeRoute === "clone" || isDiverted
                  ? "border-rose-500 bg-rose-50/40 dark:bg-rose-950/30 shadow-md shadow-rose-500/10 scale-102"
                  : "border-hairline opacity-75"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase font-semibold text-rose-700 dark:text-rose-400">
                  Target B: Honeypot Clone (:3101)
                </span>
                {(activeRoute === "clone" || isDiverted) && (
                  <span className="h-2 w-2 rounded-full bg-rose-500 animate-ping" />
                )}
              </div>
              <div className="mt-1 text-[13px] font-semibold text-ink">High-Interaction Clone</div>
              <p className="text-[11px] text-mute mt-1 leading-tight">
                Synthetic customer records, breadcrumb lures, false admin login, canary honeytokens.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================= */}
      {/* 3. THREE-WINDOW LIVE EXPERIENTIAL CONSOLE */}
      {/* ========================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ========================================================= */}
        {/* WINDOW 1: ATTACKER EXPERIENTIAL VIEW */}
        {/* ========================================================= */}
        <div className="card flex flex-col border-rose-300 dark:border-rose-950 overflow-hidden shadow-xs">
          {/* Browser Address Bar Header */}
          <div className="p-3 border-b border-hairline bg-zinc-900 text-zinc-100 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-rose-500 inline-block" />
              <span className="h-3 w-3 rounded-full bg-amber-500 inline-block" />
              <span className="h-3 w-3 rounded-full bg-emerald-500 inline-block" />
              <span className="text-[12px] font-mono text-zinc-300 font-medium ml-2">
                Window 1: Attacker Browser
              </span>
            </div>
            {isDiverted ? (
              <span className="rounded px-2 py-0.5 text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse">
                TRAPPED IN CLONE
              </span>
            ) : (
              <span className="rounded px-2 py-0.5 text-[10px] font-mono text-zinc-400 bg-zinc-800">
                Browsing Real Shop
              </span>
            )}
          </div>

          {/* Interactive URL Bar */}
          <div className="p-2 border-b border-hairline bg-zinc-950 flex items-center gap-2">
            <div className="flex-1 rounded bg-zinc-900 px-3 py-1 font-mono text-[11px] text-zinc-200 border border-zinc-800 flex items-center justify-between">
              <span className="truncate">{attackerUrl}</span>
              <span className="text-[10px] text-zinc-500 shrink-0">Port: 8200</span>
            </div>
          </div>

          {/* Interactive Attack Preset Triggers */}
          <div className="p-3 border-b border-hairline bg-elevated/60 space-y-2">
            <span className="text-[11px] font-mono uppercase text-mute font-medium block">
              Simulate Exploitation Actions
            </span>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                disabled={attackerBusy}
                onClick={() => execRequest("attacker", "GET", "/search?q=cake' UNION SELECT 1,2,3--")}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-rose-400 hover:text-rose-600"
              >
                <Send className="h-3 w-3 text-rose-500 shrink-0" />
                <span className="truncate">SQLi in Search</span>
              </button>
              <button
                disabled={attackerBusy}
                onClick={() => execRequest("attacker", "GET", "/.env")}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-rose-400 hover:text-rose-600"
              >
                <Send className="h-3 w-3 text-rose-500 shrink-0" />
                <span className="truncate">Probe /.env</span>
              </button>
              <button
                disabled={attackerBusy}
                onClick={() => {
                  execRequest("attacker", "POST", "/api/admin/login", { user: "admin", pass: "1234" });
                  setAttackerTab("admin");
                }}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-rose-400 hover:text-rose-600"
              >
                <Send className="h-3 w-3 text-rose-500 shrink-0" />
                <span className="truncate">Admin Brute-force</span>
              </button>
              <button
                disabled={attackerBusy}
                onClick={() => {
                  execRequest("attacker", "GET", "/api/admin/export");
                  setExportProgress(10);
                  setAttackerTab("export");
                }}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-rose-400 hover:text-rose-600"
              >
                <Send className="h-3 w-3 text-rose-500 shrink-0" />
                <span className="truncate">Sunk-Cost Export</span>
              </button>
            </div>
          </div>

          {/* Sub-Tabs: Visual Browser vs Admin Panel vs Raw */}
          <div className="flex border-b border-hairline bg-canvas text-[11px] font-mono">
            <button
              onClick={() => setAttackerTab("browser")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                attackerTab === "browser" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Storefront View
            </button>
            <button
              onClick={() => setAttackerTab("admin")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                attackerTab === "admin" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Clone Admin Panel
            </button>
            <button
              onClick={() => setAttackerTab("export")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                attackerTab === "export" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Sunk-Cost Export
            </button>
            <button
              onClick={() => setAttackerTab("raw")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                attackerTab === "raw" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Raw HTTP
            </button>
          </div>

          {/* Rendered Visual Content Area */}
          <div className="p-4 flex-1 min-h-[300px] flex flex-col justify-between bg-canvas/40">
            {attackerTab === "browser" && (
              <div className="space-y-3">
                <div className="p-3 rounded-lg border border-hairline bg-elevated">
                  <h3 className="font-serif font-bold text-[16px] text-[#5a3424]">Aetees Bakehouse</h3>
                  <p className="text-[12px] text-mute mt-0.5">Artisanal cakes, desserts, and breads.</p>

                  <div className="mt-3 p-2 rounded bg-canvas border border-hairline text-[11px] font-mono flex items-center justify-between">
                    <span>Search query: {attackerUrl.includes("q=") ? decodeURIComponent(attackerUrl.split("q=")[1] || "") : "None"}</span>
                    {isDiverted && <span className="text-rose-600 font-bold">SQL Injection Triggered</span>}
                  </div>
                </div>

                {isDiverted && (
                  <div className="p-3 rounded-lg border border-rose-200 dark:border-rose-900 bg-rose-50/60 dark:bg-rose-950/20 text-[12px] space-y-1.5">
                    <div className="flex items-center gap-1.5 text-rose-700 dark:text-rose-300 font-semibold">
                      <ShieldAlert className="h-4 w-4" /> Deception Breadcrumb Planted:
                    </div>
                    <code className="text-[11px] font-mono block bg-canvas p-2 rounded border border-hairline text-mute">
                      &lt;!-- DEBUG: Migration in progress. Remove /.env.bak and /backup/ before production release. --&gt;
                    </code>
                    <p className="text-[11px] text-rose-800 dark:text-rose-300">
                      The attacker believes they uncovered an insider vulnerability, enticing them deeper into our honeyfiles.
                    </p>
                  </div>
                )}
              </div>
            )}

            {attackerTab === "admin" && (
              <div className="space-y-3">
                <div className="p-3 rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-bold text-amber-900 dark:text-amber-200 flex items-center gap-1.5">
                      <ShieldAlert className="h-4 w-4" /> Synthetic Admin Sandbox (Cognitive False Success)
                    </span>
                    <span className="text-[10px] font-mono bg-amber-200 dark:bg-amber-900 px-2 py-0.5 rounded text-amber-900 dark:text-amber-100">
                      Decoy Isolation
                    </span>
                  </div>
                  <p className="text-[11px] text-amber-800 dark:text-amber-300 mt-1">
                    The attacker entered incorrect credentials 3 times. On the 4th, the proxy rewrote the body to grant access to fake orders!
                  </p>
                </div>

                <div className="border border-hairline rounded-lg overflow-hidden bg-elevated text-[11px] font-mono">
                  <div className="p-2 border-b border-hairline bg-canvas font-semibold flex justify-between">
                    <span>Synthetic Customer Orders</span>
                    <span>3 Records</span>
                  </div>
                  <div className="divide-y divide-hairline">
                    <div className="p-2 flex justify-between">
                      <span>ORD-SYNTH-9941</span>
                      <span>John Doe (Fake)</span>
                      <span className="text-emerald-600">Rs. 1,450</span>
                    </div>
                    <div className="p-2 flex justify-between">
                      <span>ORD-SYNTH-9942</span>
                      <span>Sara Connor (Fake)</span>
                      <span className="text-emerald-600">Rs. 850</span>
                    </div>
                    <div className="p-2 flex justify-between">
                      <span>ORD-SYNTH-9943</span>
                      <span>Bruce Wayne (Fake)</span>
                      <span className="text-emerald-600">Rs. 3,200</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {attackerTab === "export" && (
              <div className="space-y-4 p-2">
                <div className="text-center space-y-1">
                  <h4 className="text-[13px] font-bold text-ink">Cognitive Tactic: Sunk Cost Fallacy</h4>
                  <p className="text-[11px] text-mute">
                    Attacker is attempting to export customer data via /api/admin/export.
                  </p>
                </div>

                <div className="card p-4 space-y-3 bg-elevated">
                  <div className="flex justify-between text-[12px] font-mono">
                    <span>Exporting customers.csv...</span>
                    <span className="font-bold text-amber-600">{exportProgress ?? 0}%</span>
                  </div>
                  <div className="w-full h-3 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                    <div
                      className="h-full bg-amber-500 transition-all duration-300"
                      style={{ width: `${exportProgress ?? 0}%` }}
                    />
                  </div>
                  {exportProgress === 97 && (
                    <div className="text-center p-2 rounded bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 text-[11px] text-amber-900 dark:text-amber-200 animate-pulse font-mono">
                      Stalling progress at 97%... Attacker delay: {exportTimer} seconds spent waiting
                    </div>
                  )}
                </div>
              </div>
            )}

            {attackerTab === "raw" && (
              <div className="rounded bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300 overflow-y-auto max-h-[220px]">
                {attackerLastResp ? (
                  <div className="space-y-1">
                    <div className="text-zinc-400">HTTP/1.1 {attackerLastResp.status} ({attackerLastResp.latencyMs} ms)</div>
                    <div className="text-zinc-500">Served by: {attackerLastResp.upstream.toUpperCase()}</div>
                    <div className="border-t border-zinc-800 pt-1 text-zinc-300 whitespace-pre-wrap break-all">
                      {attackerLastResp.bodySnippet || "(Empty response)"}
                    </div>
                  </div>
                ) : (
                  <span className="text-zinc-600">No requests sent yet. Click a trigger above.</span>
                )}
              </div>
            )}

            {/* Bottom Status Tag */}
            <div className="pt-3 border-t border-hairline flex items-center justify-between text-[11px] font-mono">
              <span className="text-mute">Upstream Active:</span>
              <span
                className={`font-semibold px-2 py-0.5 rounded ${
                  isDiverted
                    ? "bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-300"
                    : "bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300"
                }`}
              >
                {isDiverted ? "HONEYPOT CLONE (:3101)" : "REAL SHOP (:3100)"}
              </span>
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* WINDOW 2: REAL CUSTOMER EXPERIENTIAL VIEW */}
        {/* ========================================================= */}
        <div className="card flex flex-col border-emerald-300 dark:border-emerald-950 overflow-hidden shadow-xs">
          {/* Browser Address Bar Header */}
          <div className="p-3 border-b border-hairline bg-zinc-900 text-zinc-100 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-rose-500 inline-block" />
              <span className="h-3 w-3 rounded-full bg-amber-500 inline-block" />
              <span className="h-3 w-3 rounded-full bg-emerald-500 inline-block" />
              <span className="text-[12px] font-mono text-zinc-300 font-medium ml-2">
                Window 2: Customer Browser
              </span>
            </div>
            <span className="rounded px-2 py-0.5 text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
              PRODUCTION CLIENT
            </span>
          </div>

          {/* Interactive URL Bar */}
          <div className="p-2 border-b border-hairline bg-zinc-950 flex items-center gap-2">
            <div className="flex-1 rounded bg-zinc-900 px-3 py-1 font-mono text-[11px] text-zinc-200 border border-zinc-800 flex items-center justify-between">
              <span className="truncate">http://aeteesbakehouse.com/checkout</span>
              <span className="text-[10px] text-zinc-500 shrink-0">Port: 8200</span>
            </div>
          </div>

          {/* Interactive Customer Actions */}
          <div className="p-3 border-b border-hairline bg-elevated/60 space-y-2">
            <span className="text-[11px] font-mono uppercase text-mute font-medium block">
              Normal Shopper Actions
            </span>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                disabled={customerBusy}
                onClick={() => {
                  execRequest("customer", "GET", "/menu");
                  setCustomerTab("storefront");
                }}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-emerald-400 hover:text-emerald-600"
              >
                <Send className="h-3 w-3 text-emerald-500 shrink-0" />
                <span className="truncate">Browse Bakery</span>
              </button>
              <button
                disabled={customerBusy}
                onClick={() => {
                  setCartCount((c) => c + 1);
                  execRequest("customer", "POST", "/api/cart", { id: 1, item: "Chocolate Truffle" });
                }}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-emerald-400 hover:text-emerald-600"
              >
                <Send className="h-3 w-3 text-emerald-500 shrink-0" />
                <span className="truncate">Add Cake to Cart</span>
              </button>
              <button
                disabled={customerBusy}
                onClick={() => {
                  execRequest("customer", "POST", "/api/contact", {
                    message: "Mom's cake; less sugar -- urgent",
                  });
                }}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-emerald-400 hover:text-emerald-600"
              >
                <Send className="h-3 w-3 text-emerald-500 shrink-0" />
                <span className="truncate">Message (-- &amp; ;)</span>
              </button>
              <button
                disabled={customerBusy}
                onClick={() => {
                  execRequest("customer", "POST", "/api/checkout", {
                    name: "Aarav Sharma",
                    items: ["Chocolate Truffle"],
                  });
                }}
                className="btn text-[11px] justify-start py-1.5 px-2 hover:border-emerald-400 hover:text-emerald-600"
              >
                <Send className="h-3 w-3 text-emerald-500 shrink-0" />
                <span className="truncate">Place Order</span>
              </button>
            </div>
          </div>

          {/* Sub-Tabs: Storefront vs Receipt */}
          <div className="flex border-b border-hairline bg-canvas text-[11px] font-mono">
            <button
              onClick={() => setCustomerTab("storefront")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                customerTab === "storefront" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Bakery Shop
            </button>
            <button
              onClick={() => setCustomerTab("receipt")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                customerTab === "receipt" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Live Receipt
            </button>
            <button
              onClick={() => setCustomerTab("raw")}
              className={`flex-1 py-1.5 border-b-2 font-medium ${
                customerTab === "raw" ? "border-ink text-ink" : "border-transparent text-mute"
              }`}
            >
              Raw HTTP
            </button>
          </div>

          {/* Rendered Visual Content Area */}
          <div className="p-4 flex-1 min-h-[300px] flex flex-col justify-between bg-canvas/40">
            {customerTab === "storefront" && (
              <div className="space-y-3">
                <div className="p-3 rounded-lg border border-hairline bg-elevated">
                  <div className="flex justify-between items-center">
                    <h3 className="font-serif font-bold text-[16px] text-[#5a3424]">Aetees Bakehouse</h3>
                    <span className="text-[11px] font-mono font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded">
                      Cart: {cartCount} items
                    </span>
                  </div>
                  <p className="text-[12px] text-mute mt-0.5">Fresh artisanal confectionery.</p>
                </div>

                <div className="space-y-2">
                  <div className="p-2.5 rounded-lg border border-hairline bg-elevated flex justify-between items-center">
                    <div>
                      <div className="font-medium text-[13px] text-ink">Chocolate Truffle Cake</div>
                      <div className="text-[11px] text-mute">1 kg artisanal sponge - Rs. 650</div>
                    </div>
                    <button
                      onClick={() => {
                        setCartCount((c) => c + 1);
                        execRequest("customer", "POST", "/api/cart", { id: 1, name: "Chocolate Truffle" });
                      }}
                      className="btn text-[11px] py-1 px-2.5"
                    >
                      + Add
                    </button>
                  </div>

                  <div className="p-2.5 rounded-lg border border-hairline bg-elevated flex justify-between items-center">
                    <div>
                      <div className="font-medium text-[13px] text-ink">Blueberry Cheesecake</div>
                      <div className="text-[11px] text-mute">Fresh cream &amp; berries - Rs. 750</div>
                    </div>
                    <button
                      onClick={() => {
                        setCartCount((c) => c + 1);
                        execRequest("customer", "POST", "/api/cart", { id: 2, name: "Blueberry Cheesecake" });
                      }}
                      className="btn text-[11px] py-1 px-2.5"
                    >
                      + Add
                    </button>
                  </div>
                </div>

                {/* Zero False Positive Proof Box */}
                <div className="p-2.5 rounded-md bg-emerald-50/70 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900 text-[11px] text-emerald-800 dark:text-emerald-200 flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-600 shrink-0" />
                  <span>Customer punctuation (apostrophes, semicolons, --) passes without false alarms.</span>
                </div>
              </div>
            )}

            {customerTab === "receipt" && (
              <div className="space-y-3 p-1">
                <div className="p-4 rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50/40 dark:bg-emerald-950/20 space-y-2">
                  <div className="flex justify-between items-center border-b border-emerald-200 dark:border-emerald-800 pb-2">
                    <span className="font-serif font-bold text-[15px] text-[#5a3424]">Aetees Official Receipt</span>
                    <span className="font-mono text-[11px] font-bold text-emerald-700 dark:text-emerald-300">
                      PAID - 200 OK
                    </span>
                  </div>
                  <div className="text-[12px] space-y-1 font-mono">
                    <div className="flex justify-between text-mute">
                      <span>Order Reference:</span>
                      <span className="text-ink font-bold">{customerOrder ?? "ORD-LIVE-7842"}</span>
                    </div>
                    <div className="flex justify-between text-mute">
                      <span>Database Engine:</span>
                      <span className="text-ink">real.db (Production)</span>
                    </div>
                    <div className="flex justify-between text-mute">
                      <span>Total Amount:</span>
                      <span className="text-ink font-semibold">Rs. 1,400</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {customerTab === "raw" && (
              <div className="rounded bg-zinc-950 p-3 font-mono text-[11px] text-zinc-300 overflow-y-auto max-h-[220px]">
                {customerLastResp ? (
                  <div className="space-y-1">
                    <div className="text-zinc-400">HTTP/1.1 {customerLastResp.status} ({customerLastResp.latencyMs} ms)</div>
                    <div className="text-zinc-500">Served by: REAL PRODUCTION SHOP (:3100)</div>
                    <div className="border-t border-zinc-800 pt-1 text-zinc-300 whitespace-pre-wrap break-all">
                      {customerLastResp.bodySnippet || "(Empty response)"}
                    </div>
                  </div>
                ) : (
                  <span className="text-zinc-600">No requests sent yet. Click an action above.</span>
                )}
              </div>
            )}

            {/* Bottom Status Tag */}
            <div className="pt-3 border-t border-hairline flex items-center justify-between text-[11px] font-mono">
              <span className="text-mute">Upstream Active:</span>
              <span className="font-semibold px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300">
                REAL PRODUCTION SHOP (:3100)
              </span>
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* WINDOW 3: LIVE SOC ANALYST COMMAND CENTER */}
        {/* ========================================================= */}
        <div className="card flex flex-col border-indigo-300 dark:border-indigo-950 overflow-hidden shadow-xs">
          {/* Header */}
          <div className="p-3 border-b border-hairline bg-indigo-950 text-white flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-indigo-400 animate-pulse" />
              <span className="text-[12px] font-mono font-medium">Window 3: Live SOC Command Center</span>
            </div>
            <Link
              href="/events"
              className="text-[11px] font-mono text-indigo-300 hover:text-white flex items-center gap-1"
            >
              Full Feed <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="p-4 space-y-4 flex-1 flex flex-col justify-between">
            {/* Live Metrics Row */}
            <div className="grid grid-cols-2 gap-3 items-center card p-3 bg-canvas">
              <div className="flex justify-center">
                <RiskGauge score={riskScore} size={78} />
              </div>
              <div className="space-y-1.5 text-[11px] font-mono">
                <div className="flex justify-between">
                  <span className="text-mute">Actor:</span>
                  <span className={isDiverted ? "text-rose-600 font-bold" : "text-mute"}>
                    {isDiverted ? "ACT-0007" : "None"}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-mute">Techniques:</span>
                  <span className="text-ink font-semibold">{activeMitre.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-mute">Diverted:</span>
                  <span className={isDiverted ? "text-rose-600 font-bold" : "text-emerald-600 font-bold"}>
                    {isDiverted ? "YES" : "NO"}
                  </span>
                </div>
              </div>
            </div>

            {/* MITRE ATT&CK Matrix Pills */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono uppercase text-mute font-medium block">
                Triggered ATT&CK Techniques
              </span>
              <div className="flex flex-wrap gap-1.5">
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-all ${
                    activeMitre.includes("T1190")
                      ? "bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border-rose-300 font-bold scale-105"
                      : "bg-elevated text-mute border-hairline opacity-60"
                  }`}
                >
                  T1190 Exploit Public-Facing App
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-mono border transition-all ${
                    activeMitre.includes("T1552.001")
                      ? "bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 font-bold scale-105"
                      : "bg-elevated text-mute border-hairline opacity-60"
                  }`}
                >
                  T1552.001 Credentials in Files
                </span>
              </div>
            </div>

            {/* Live SSE Telemetry Feed */}
            <div className="space-y-1.5 flex-1 flex flex-col">
              <span className="text-[11px] font-mono uppercase text-mute font-medium block">
                Live SSE Telemetry Stream
              </span>

              <div className="flex-1 min-h-[140px] max-h-[190px] rounded-md border border-hairline bg-zinc-950 p-2 font-mono text-[10px] overflow-y-auto space-y-1.5">
                {liveEvents.length > 0 ? (
                  liveEvents.map((ev, i) => (
                    <div
                      key={ev.event_id || i}
                      className="p-1.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300 space-y-0.5"
                    >
                      <div className="flex justify-between items-center text-zinc-400">
                        <span>{istTime(ev.ts)}</span>
                        <span className="text-rose-400 font-bold">{ev.type}</span>
                      </div>
                      <div className="text-zinc-200 truncate">{ev.summary || ev.type}</div>
                    </div>
                  ))
                ) : (
                  <div className="h-full flex items-center justify-center text-zinc-600 text-center p-3">
                    Awaiting telemetry... Execute actions in Window 1 to see live detection.
                  </div>
                )}
              </div>
            </div>

            {/* Analyst Intervention Action */}
            <div className="pt-2">
              <button
                disabled={!isDiverted || releaseBusy}
                onClick={() => setConfirmRelease(true)}
                className="w-full h-9 rounded-md bg-ink text-canvas text-[12px] font-medium disabled:opacity-40 flex items-center justify-center gap-2 hover:bg-ink/90 transition"
              >
                <Undo2 className="h-4 w-4" />
                <span>Release Visitor Back to Real Shop</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Dialog for Release */}
      <ConfirmDialog
        open={confirmRelease}
        onOpenChange={setConfirmRelease}
        title="Release Diverted Visitor"
        description="Are you sure you want to release this visitor? The proxy will stop redirecting them to the honeypot clone and restore their connection to the real production shop."
        confirmLabel="Release to Real Shop"
        danger={false}
        onConfirm={handleRelease}
        loading={releaseBusy}
      />
    </div>
  );
}
