"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { api, HttpError } from "@/lib/api";
import { ago, istTime } from "@/lib/format";
import { useStream } from "@/lib/stream";
import type {
  ActorDetail,
  DeceptionTactic,
  MazeGraph as MazeGraphType,
  Narrative,
  TimelineItem,
  Event,
} from "@/lib/types";
import { SeverityPill } from "@/components/SeverityPill";
import { RiskGauge } from "@/components/RiskGauge";
import { BehaviourBadge } from "@/components/BehaviourBadge";
import { SessionGraph } from "@/components/SessionGraph";
import { Timeline } from "@/components/Timeline";
import { AttackMatrix } from "@/components/AttackMatrix";
import { MazeGraph } from "@/components/MazeGraph";
import { EventDrawer } from "@/components/EventDrawer";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import {
  ShieldAlert,
  Sparkles,
  Activity,
  AlertCircle,
  Network,
  Wrench,
  Brain,
  Shuffle,
} from "lucide-react";

export default function ActorProfilePage() {
  const params = useParams();
  const actorId = params.id as string;

  const [actor, setActor] = useState<ActorDetail | null>(null);
  const [timeline, setTimeline] = useState<TimelineItem[]>([]);
  const [maze, setMaze] = useState<MazeGraphType | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [inspectedEvent, setInspectedEvent] = useState<Event | null>(null);
  const [loading, setLoading] = useState(true);
  const [tactics, setTactics] = useState<DeceptionTactic[]>([]);
  const [divert, setDivert] = useState<{ ip: string; action: "divert" | "release" } | null>(null);
  const [divertBusy, setDivertBusy] = useState(false);
  const [divertMsg, setDivertMsg] = useState("");

  useEffect(() => {
    if (!actorId) return;
    api.getActorTactics(actorId).then(setTactics).catch(() => undefined);

    Promise.all([
      api.getActor(actorId).catch(() => null),
      api.getActorTimeline(actorId).catch(() => ({ items: [] })),
      api.getActorMaze(actorId).catch(() => null),
    ]).then(([act, tl, mz]) => {
      if (act) setActor(act);
      if (tl?.items) setTimeline(tl.items);
      if (mz) setMaze(mz);
      setLoading(false);
    });
  }, [actorId]);

  // Load event details for drawer when selected
  useEffect(() => {
    if (!selectedEventId) {
      setInspectedEvent(null);
      return;
    }
    api.getEvent(selectedEventId).then(setInspectedEvent).catch(() => undefined);
  }, [selectedEventId]);

  // Real-time SSE updates for live narrative replacement
  useStream<{ kind: string; ref_id: string; narrative: Narrative }>("narrative", (msg) => {
    if (msg.kind === "actor" && msg.ref_id === actorId) {
      setActor((prev) => (prev ? { ...prev, narrative: msg.narrative } : null));
    }
  });

  if (loading) {
    return <div className="p-12 text-center font-mono text-mute">Loading actor profile...</div>;
  }

  if (!actor) {
    return (
      <div className="p-12 text-center">
        <h2 className="text-xl font-bold">Actor Not Found</h2>
        <p className="mt-2 text-mute text-sm">No telemetry records exist for actor ID {actorId}</p>
        <Link href="/actors" className="btn btn-primary mt-4">
          Back to Actors
        </Link>
      </div>
    );
  }

  const rb = actor.risk_breakdown;
  const bf = actor.behaviour.features;

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="card p-6 border-hairline bg-elevated">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <RiskGauge score={actor.risk_score} size={84} />
            <div>
              <div className="flex items-center gap-3">
                <h1 className="font-mono text-[30px] font-bold tracking-tight text-ink">
                  {actor.label}
                </h1>
                <SeverityPill severity={actor.severity} />
                {actor.touched_production && (
                  <span className="rounded-full bg-red-100 text-red-800 border border-red-200 px-2.5 py-0.5 text-[11px] font-mono font-bold tracking-wide uppercase">
                    Touched Production
                  </span>
                )}
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-3 text-[12px] font-mono text-body">
                <span>Correlation: {(actor.confidence * 100).toFixed(0)}% (likely same operator)</span>
                <span>·</span>
                <span>First seen: {istTime(actor.first_seen)} ({ago(actor.first_seen)})</span>
                <span>·</span>
                <span>Last active: {istTime(actor.last_seen)} ({ago(actor.last_seen)})</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <BehaviourBadge behaviourClass={actor.behaviour_class} size="md" />
            {actor.incident_id && (
              <Link href={`/incidents/${actor.incident_id}`} className="btn btn-primary gap-1.5 text-[12px]">
                <ShieldAlert className="h-4 w-4" />
                <span>Open Incident</span>
              </Link>
            )}
          </div>
        </div>
      </div>

      {/* 1b. What Happened Card */}
      <div className="card p-6 border-link-soft bg-[#f6f9ff]">
        <div className="flex items-center justify-between border-b border-link/20 pb-2.5">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-link" />
            <span className="eyebrow text-link font-semibold">What Happened</span>
          </div>
          <span className="text-[11px] font-mono text-mute">
            {actor.narrative?.source === "llm" ? `AI Generated (${actor.narrative.model})` : "Template Narrative"} · Updated live
          </span>
        </div>

        {actor.narrative ? (
          <div className="mt-3">
            <h3 className="text-[18px] font-semibold tracking-tight text-ink">
              {actor.narrative.headline}
            </h3>
            <p className="mt-2 text-[14px] leading-relaxed text-body">{actor.narrative.text}</p>
            {actor.narrative.bullets.length > 0 && (
              <ul className="mt-3 space-y-1.5 pl-5 list-disc text-[13px] text-body">
                {actor.narrative.bullets.map((b, i) => (
                  <li key={i}>{b}</li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <p className="mt-3 text-[13px] text-mute italic">
            Not enough activity yet to synthesize narrative.
          </p>
        )}
      </div>

      {/* 8. Profile Summary Cards (Source, Tools, Behaviour, Risk Equation) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Source Card */}
        <div className="card p-4">
          <span className="eyebrow flex items-center gap-1.5">
            <Network className="h-3.5 w-3.5" />
            <span>1. Source & Infrastructure</span>
          </span>
          <div className="mt-3 font-mono text-[12px] space-y-1.5">
            <div className="flex justify-between">
              <span className="text-mute">Egress IPs:</span>
              <span className="text-ink font-semibold">{actor.ips.join(", ")}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-mute">Firewall Denies:</span>
              <span className="text-red-700 font-bold">{actor.external?.firewall_denies ?? 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-mute">Production Targets:</span>
              <span className="text-ink">{actor.external?.systems?.length ?? 0} systems</span>
            </div>
          </div>
        </div>

        {/* Tools Card */}
        <div className="card p-4">
          <span className="eyebrow flex items-center gap-1.5">
            <Wrench className="h-3.5 w-3.5" />
            <span>2. Attacker Toolset</span>
          </span>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {actor.tool_tags && actor.tool_tags.length > 0 ? (
              actor.tool_tags.map((t) => (
                <span
                  key={t.tool}
                  className="rounded-md border border-hairline bg-canvas px-2 py-1 text-[11px] font-mono text-ink font-medium"
                  title={t.evidence}
                >
                  {t.tool}
                </span>
              ))
            ) : (
              <span className="text-mute text-[12px] font-mono italic">No automated tools identified</span>
            )}
          </div>
        </div>

        {/* Behaviour Card */}
        <div className="card p-4">
          <span className="eyebrow flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5" />
            <span>3. Kill-Chain Progress</span>
          </span>
          <div className="mt-3 space-y-1 font-mono text-[11px]">
            <div className="flex justify-between">
              <span className="text-mute">Stage:</span>
              <span className="text-ink font-bold uppercase">{actor.kill_chain_stage}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-mute">Keystroke Cadence:</span>
              <span className="text-body">{bf.median_gap_ms} ms</span>
            </div>
            <div className="flex justify-between">
              <span className="text-mute">Breadcrumbs Followed:</span>
              <span className="text-body">{bf.breadcrumbs_followed}</span>
            </div>
          </div>
        </div>

        {/* 9. Risk Breakdown Card */}
        <div className="card p-4">
          <span className="eyebrow flex items-center gap-1.5">
            <AlertCircle className="h-3.5 w-3.5" />
            <span>4. Risk Formulation</span>
          </span>
          <div className="mt-3 font-mono text-[11px] text-body space-y-1">
            <div className="text-ink font-semibold">
              Risk {actor.risk_score} = r+{rb.contributions.recon} · a+{rb.contributions.access} · p+{rb.contributions.post_access} · l+{rb.contributions.lateral}
            </div>
            {rb.override && (
              <div className="text-rose-700 font-bold text-[10px] bg-rose-50 px-1.5 py-0.5 rounded border border-rose-200">
                Override: {rb.override}
              </div>
            )}
            <div className="text-mute text-[10px]">Scorer Weights v{rb.weights_version} (bias {rb.bias})</div>
          </div>
        </div>
      </div>

      {/* 2. Linked Sessions Graph */}
      <div className="card p-6">
        <SessionGraph sessions={actor.sessions} />
      </div>

      {/* 4. MITRE ATT&CK Matrix */}
      <div className="card p-6">
        <div className="mb-4">
          <span className="eyebrow">Tactical Profiling</span>
          <h3 className="text-[17px] font-semibold text-ink">MITRE ATT&CK kill-chain mapping</h3>
        </div>
        <AttackMatrix findings={actor.findings} onSelectEvent={(id) => setSelectedEventId(id)} />
      </div>

      {/* 5. Behaviour Panel & 6. Maze Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Behaviour Panel */}
        <div className="card p-6 flex flex-col">
          <span className="eyebrow">Behavioural Telemetry</span>
          <h3 className="mt-1 text-[17px] font-semibold text-ink">
            Machine Learning & Metric Features
          </h3>

          <div className="mt-4 space-y-3 font-mono text-[12px]">
            <div>
              <div className="flex justify-between text-[11px]">
                <span className="text-mute">Agent-like probability:</span>
                <span className="font-semibold">{((actor.behaviour.scores.agent_like ?? 0) * 100).toFixed(0)}%</span>
              </div>
              <div className="h-2 w-full rounded-full bg-hairline mt-1 overflow-hidden">
                <div
                  className="h-full bg-purple-600 rounded-full"
                  style={{ width: `${(actor.behaviour.scores.agent_like ?? 0) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-[11px]">
                <span className="text-mute">Scripted automation probability:</span>
                <span className="font-semibold">{((actor.behaviour.scores.scripted ?? 0) * 100).toFixed(0)}%</span>
              </div>
              <div className="h-2 w-full rounded-full bg-hairline mt-1 overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full"
                  style={{ width: `${(actor.behaviour.scores.scripted ?? 0) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-[11px]">
                <span className="text-mute">Human-like operator probability:</span>
                <span className="font-semibold">{((actor.behaviour.scores.human_like ?? 0) * 100).toFixed(0)}%</span>
              </div>
              <div className="h-2 w-full rounded-full bg-hairline mt-1 overflow-hidden">
                <div
                  className="h-full bg-emerald-500 rounded-full"
                  style={{ width: `${(actor.behaviour.scores.human_like ?? 0) * 100}%` }}
                />
              </div>
            </div>

            <div className="mt-4 border-t border-hairline pt-3 grid grid-cols-2 gap-3 text-[11px] text-body">
              <div>• Output dependence: {(bf.output_dependence * 100).toFixed(0)}%</div>
              <div>• Paste rate: {(bf.paste_rate * 100).toFixed(0)}%</div>
              <div>• Edit/backspace rate: {(bf.edit_rate * 100).toFixed(0)}%</div>
              <div>• Command count: {bf.commands} commands</div>
            </div>
          </div>
        </div>

        {/* Maze Panel */}
        <div className="card p-6 flex flex-col">
          <span className="eyebrow">Deception Traversal</span>
          <h3 className="mt-1 text-[17px] font-semibold text-ink">
            Actor Maze Traversal ({actor.maze_depth} lures encountered)
          </h3>
          <div className="mt-4 flex-1">
            {maze ? <MazeGraph graph={maze} height={280} /> : <p className="text-mute text-sm italic">Loading maze...</p>}
          </div>
        </div>
      </div>

      {/* 6b. Cognitive tactics + shop diversion */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="card p-6">
          <span className="eyebrow">Cognitive Deception</span>
          <h3 className="mt-1 text-[17px] font-semibold text-ink flex items-center gap-2">
            <Brain className="h-4 w-4 text-mute" /> Tactics applied ({tactics.length})
          </h3>
          <div className="mt-3 divide-y divide-hairline">
            {tactics.length === 0 ? (
              <p className="py-2 text-[13px] text-mute italic">No tactics applied to this actor yet.</p>
            ) : (
              tactics.map((t) => (
                <div key={t.tactic_id} className="py-2.5 text-[12px]">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-ink">{t.tactic}</span>
                    <span className="rounded border border-hairline bg-canvas px-2 py-0.5 font-mono text-[11px] text-body">
                      {t.bias_pattern.replace("_", " ")}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-3 text-mute font-mono text-[11px]">
                    <span>{ago(t.ts)}</span>
                    {t.lure_id && <span>lure: {t.lure_id}</span>}
                    {Object.entries(t.effect).map(([k, v]) => (
                      <span key={k}>{k}: {String(v)}</span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="card p-6">
          <span className="eyebrow">Product Website</span>
          <h3 className="mt-1 text-[17px] font-semibold text-ink flex items-center gap-2">
            <Shuffle className="h-4 w-4 text-mute" /> Aetees shop diversion
          </h3>
          <p className="mt-1 text-[12px] text-body">
            Divert serves this actor the honeypot clone on the same URL; release sends a false positive back to the real shop.
          </p>
          <div className="mt-3 divide-y divide-hairline">
            {actor.ips.map((ip) => (
              <div key={ip} className="py-2 flex items-center justify-between font-mono text-[12px]">
                <span className="text-ink">{ip}</span>
                <span className="flex gap-2">
                  <button className="rounded-md border border-hairline px-2.5 py-1 hover:bg-canvas" onClick={() => setDivert({ ip, action: "divert" })}>
                    Divert
                  </button>
                  <button className="rounded-md border border-hairline px-2.5 py-1 hover:bg-canvas" onClick={() => setDivert({ ip, action: "release" })}>
                    Release
                  </button>
                </span>
              </div>
            ))}
          </div>
          {divertMsg && <p className="mt-2 text-[12px] text-body">{divertMsg}</p>}
        </div>
      </div>

      <ConfirmDialog
        open={divert !== null}
        onOpenChange={(o) => !o && setDivert(null)}
        title={divert?.action === "release" ? `Release ${divert.ip} to the real shop?` : `Divert ${divert?.ip ?? ""} to the clone?`}
        description={
          divert?.action === "release"
            ? "Use this for a false positive. The visitor gets the real shop again within 5 seconds."
            : "The visitor keeps the same URL but is served the honeypot clone for 24 hours; every request is recorded."
        }
        confirmLabel={divert?.action === "release" ? "Release" : "Divert"}
        danger={divert?.action === "divert"}
        loading={divertBusy}
        onConfirm={async () => {
          if (!divert) return;
          setDivertBusy(true);
          try {
            await api.setDiversion(divert.ip, divert.action);
            setDivertMsg(`${divert.ip}: ${divert.action === "divert" ? "diverted to the clone" : "released to the real shop"}.`);
            setDivert(null);
          } catch (e) {
            setDivertMsg(e instanceof HttpError ? e.message : "Action failed");
          } finally {
            setDivertBusy(false);
          }
        }}
      />

      {/* 7. Fingerprints */}
      <div className="card p-6">
        <span className="eyebrow">Cryptographic & Network Fingerprints</span>
        <div className="mt-3 divide-y divide-hairline">
          {actor.fingerprints.map((fp, i) => (
            <div key={i} className="py-2.5 flex items-center justify-between text-[12px] font-mono">
              <span className="text-mute font-semibold uppercase">{fp.kind}</span>
              <span className="text-ink bg-canvas px-2.5 py-1 rounded border border-hairline break-all">
                {fp.value}
              </span>
              <span className="text-body text-[11px]">{fp.session_ids.length} session(s)</span>
            </div>
          ))}
        </div>
      </div>

      {/* 3. Attack Timeline */}
      <div className="card p-6">
        <div className="mb-4">
          <span className="eyebrow">Unified Timeline</span>
          <h3 className="text-[17px] font-semibold text-ink">Correlated Activity Timeline</h3>
        </div>
        <Timeline items={timeline} onSelectEvent={(id) => setSelectedEventId(id)} />
      </div>

      <EventDrawer event={inspectedEvent} onClose={() => setSelectedEventId(null)} />
    </div>
  );
}
