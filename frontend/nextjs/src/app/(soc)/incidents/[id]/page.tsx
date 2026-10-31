"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { istFull, istTime } from "@/lib/format";
import type {
  FeedbackResult,
  IncidentDetail,
  IncidentStatus,
} from "@/lib/types";
import { SeverityPill } from "@/components/SeverityPill";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import {
  Download,
  Copy,
  Check,
  Sparkles,
  CheckCircle2,
  XCircle,
  Send,
} from "lucide-react";

export default function IncidentDetailPage() {
  const params = useParams();
  const incidentId = params.id as string;

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [newNote, setNewNote] = useState("");
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);

  // Response Action Dialog
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<{ action: string; target: string; why: string } | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  // Feedback State
  const [allowlistSource, setAllowlistSource] = useState(false);
  const [feedbackToast, setFeedbackToast] = useState<FeedbackResult | null>(null);
  const [feedbackLoading, setFeedbackLoading] = useState(false);

  useEffect(() => {
    if (!incidentId) return;
    api.getIncident(incidentId)
      .then(setIncident)
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, [incidentId]);

  async function handleStatusChange(status: IncidentStatus) {
    if (!incident) return;
    try {
      const updated = await api.patchIncident(incident.incident_id, { status });
      setIncident(updated);
    } catch {
      // Fallback update
      setIncident({ ...incident, status });
    }
  }

  async function handleAddNote(e: React.FormEvent) {
    e.preventDefault();
    if (!incident || !newNote.trim()) return;
    try {
      const updated = await api.patchIncident(incident.incident_id, { note: newNote.trim() });
      setIncident(updated);
      setNewNote("");
    } catch {
      // Optimistic update
      setIncident({
        ...incident,
        notes: [
          ...incident.notes,
          { author: "analyst@soc.local", body: newNote.trim(), ts: new Date().toISOString() },
        ],
      });
      setNewNote("");
    }
  }

  async function executeAction() {
    if (!incident || !pendingAction) return;
    setActionLoading(true);
    try {
      const res = await api.takeAction(incident.incident_id, pendingAction.action, pendingAction.target);
      setIncident({
        ...incident,
        actions: [res, ...incident.actions],
      });
    } catch (err) {
      alert("Failed to apply action: " + String(err));
    } finally {
      setActionLoading(false);
      setPendingAction(null);
    }
  }

  async function handleFeedback(label: "confirmed" | "false_positive") {
    if (!incident) return;
    setFeedbackLoading(true);
    try {
      const res = await api.giveFeedback(incident.incident_id, {
        label,
        allowlist_source: allowlistSource,
      });
      setFeedbackToast(res);
      setTimeout(() => setFeedbackToast(null), 8000);
    } catch (err) {
      alert("Failed to submit feedback: " + String(err));
    } finally {
      setFeedbackLoading(false);
    }
  }

  async function downloadReport() {
    if (!incident) return;
    const md = await api.getIncidentReport(incident.incident_id, "md");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-${incident.incident_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopiedIoc(text);
    setTimeout(() => setCopiedIoc(null), 2000);
  }

  function exportIocsCsv() {
    if (!incident) return;
    const rows = [["Type", "Value"], ...incident.iocs.map((i) => [i.kind, i.value])];
    const csv = rows.map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iocs-${incident.incident_id}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading) {
    return <div className="p-12 text-center font-mono text-mute">Loading incident details...</div>;
  }

  if (!incident) {
    return (
      <div className="p-12 text-center">
        <h2 className="text-xl font-bold">Incident Not Found</h2>
        <Link href="/incidents" className="btn btn-primary mt-4">
          Back to Incidents
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Toast for Feedback Result */}
      {feedbackToast && (
        <div className="rounded-[12px] border border-blue-200 bg-blue-50 p-4 shadow-lg flex items-center justify-between animate-in fade-in">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-link" />
            <div>
              <p className="font-semibold text-ink text-[14px]">
                Analyst Feedback Recorded
              </p>
              <p className="text-[12px] font-mono text-body mt-0.5">
                Risk score adjusted: {feedbackToast.old_risk} → {feedbackToast.new_risk} (Scorer Weights updated to v{feedbackToast.weights_version})
              </p>
            </div>
          </div>
          <button onClick={() => setFeedbackToast(null)} className="btn text-[11px]">
            Dismiss
          </button>
        </div>
      )}

      {/* Header Banner */}
      <div className="card p-6">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <SeverityPill severity={incident.severity} />
              <h1 className="text-[24px] font-semibold tracking-tight text-ink">
                {incident.title}
              </h1>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-[12px] font-mono text-mute">
              <span>ID: {incident.incident_id}</span>
              <span>·</span>
              <span>
                Actor:{" "}
                <Link
                  href={`/actors/${incident.actor_id}`}
                  className="font-bold text-link hover:underline"
                >
                  {incident.actor_label}
                </Link>
              </span>
              <span>·</span>
              <span>Opened: {istFull(incident.opened_at)}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Status Selector */}
            <select
              value={incident.status}
              onChange={(e) => handleStatusChange(e.target.value as IncidentStatus)}
              className="h-8.5 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono uppercase font-bold text-ink focus:outline-none focus:ring-2 focus:ring-link"
            >
              <option value="open">Status: Open</option>
              <option value="ack">Status: Acknowledged</option>
              <option value="contained">Status: Contained</option>
              <option value="closed">Status: Closed</option>
            </select>

            <button onClick={downloadReport} className="btn gap-1.5 text-[12px]">
              <Download className="h-4 w-4" />
              <span>Export Report (.md)</span>
            </button>
          </div>
        </div>
      </div>

      {/* Narrative & Incident Summary */}
      <div className="card p-6 border-link-soft bg-[#f6f9ff]">
        <div className="flex items-center justify-between border-b border-link/20 pb-2.5">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-link" />
            <span className="eyebrow text-link font-semibold">Incident Narrative</span>
          </div>
          <span className="text-[11px] font-mono text-mute">
            {incident.summary_src === "llm" ? "AI Model Summary" : "Template Summary"} · Sent to Discord/Slack
          </span>
        </div>

        <p className="mt-3 text-[14px] leading-relaxed text-body">
          {incident.narrative?.text ?? incident.summary}
        </p>

        {incident.narrative?.bullets && incident.narrative.bullets.length > 0 && (
          <ul className="mt-3 list-disc space-y-1.5 pl-5 text-[13px] text-body">
            {incident.narrative.bullets.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        )}
      </div>

      {/* Recommended Actions + Feedback Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recommended Actions */}
        <div className="card p-5 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-hairline pb-2.5">
            <div>
              <span className="eyebrow">Containment & Defense</span>
              <h3 className="text-[15px] font-semibold text-ink">Recommended Response Actions</h3>
            </div>
            <span className="rounded bg-amber-100 text-amber-900 border border-amber-200 px-2 py-0.5 text-[10px] font-mono font-bold uppercase">
              Lab Environment Only
            </span>
          </div>

          <div className="mt-3 space-y-2.5">
            {incident.recommended_actions.map((act, i) => (
              <div
                key={i}
                className="flex items-center justify-between gap-3 p-3 rounded-lg border border-hairline bg-canvas"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[12px] font-bold text-ink uppercase">
                      {act.action.replace(/_/g, " ")}:
                    </span>
                    <span className="font-mono text-[12px] text-link bg-link/5 px-1.5 py-0.5 rounded border border-link/20">
                      {act.target}
                    </span>
                  </div>
                  <p className="text-[12px] text-mute mt-1">{act.why}</p>
                </div>
                <button
                  onClick={() => {
                    setPendingAction(act);
                    setConfirmOpen(true);
                  }}
                  className="btn btn-primary text-[12px] shrink-0"
                >
                  Execute
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Analyst Feedback Box */}
        <div className="card p-5 flex flex-col justify-between">
          <div>
            <span className="eyebrow">Scorer Reinforcement</span>
            <h3 className="text-[15px] font-semibold text-ink">Ground-Truth Feedback</h3>
            <p className="mt-1 text-[12px] text-body leading-relaxed">
              Label this actor to train the single-neuron risk weights in the live intelligence engine.
            </p>

            <label className="mt-4 flex items-center gap-2 text-[12px] font-mono text-ink cursor-pointer">
              <input
                type="checkbox"
                checked={allowlistSource}
                onChange={(e) => setAllowlistSource(e.target.checked)}
                className="h-4 w-4 rounded border-hairline"
              />
              <span>Allowlist source IP if false positive</span>
            </label>
          </div>

          <div className="mt-6 flex flex-col gap-2">
            <button
              onClick={() => handleFeedback("confirmed")}
              disabled={feedbackLoading}
              className="btn btn-primary justify-center gap-2 text-[12px]"
            >
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <span>Confirmed Attacker (+Risk)</span>
            </button>
            <button
              onClick={() => handleFeedback("false_positive")}
              disabled={feedbackLoading}
              className="btn justify-center gap-2 text-[12px] border-hairline hover:bg-red-50 hover:text-red-700"
            >
              <XCircle className="h-4 w-4 text-red-600" />
              <span>False Positive (-Risk)</span>
            </button>
          </div>
        </div>
      </div>

      {/* IOCs & Action History */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Indicators of Compromise (IOCs) */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-hairline pb-3">
            <div>
              <span className="eyebrow">Forensics</span>
              <h3 className="text-[15px] font-semibold text-ink">Indicators of Compromise (IOCs)</h3>
            </div>
            <button onClick={exportIocsCsv} className="btn text-[11px] font-mono h-7">
              Export CSV
            </button>
          </div>

          <div className="mt-3 divide-y divide-hairline">
            {incident.iocs.map((ioc, idx) => (
              <div key={idx} className="py-2.5 flex items-center justify-between gap-3 text-[12px] font-mono">
                <span className="uppercase text-mute font-medium text-[11px] w-20 shrink-0">
                  {ioc.kind}
                </span>
                <span className="font-semibold text-ink truncate max-w-[320px] bg-canvas px-2 py-0.5 rounded border border-hairline">
                  {ioc.value}
                </span>
                <button
                  onClick={() => copyToClipboard(ioc.value)}
                  className="p-1.5 text-mute hover:text-ink rounded hover:bg-canvas"
                  title="Copy IOC"
                >
                  {copiedIoc === ioc.value ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Executed Action History */}
        <div className="card p-5">
          <div className="flex items-center justify-between border-b border-hairline pb-3">
            <div>
              <span className="eyebrow">Audit Trail</span>
              <h3 className="text-[15px] font-semibold text-ink">Response Actions Applied</h3>
            </div>
            <span className="text-[11px] font-mono text-mute">{incident.actions.length} applied</span>
          </div>

          <div className="mt-3 space-y-2">
            {incident.actions.length === 0 ? (
              <p className="py-6 text-center text-mute text-[12px] italic">
                No defensive actions taken yet.
              </p>
            ) : (
              incident.actions.map((act) => (
                <div key={act.action_id} className="p-3 rounded-lg border border-hairline bg-canvas flex items-center justify-between text-[12px]">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-ink uppercase">{act.action}</span>
                      <span className="font-mono text-link">{act.target}</span>
                      <span className="rounded bg-emerald-50 text-emerald-800 text-[10px] font-mono font-bold px-1.5 py-0.2 border border-emerald-200">
                        {act.status}
                      </span>
                    </div>
                    <span className="text-mute text-[11px] font-mono">
                      By {act.requested_by} · {istTime(act.ts)}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Analyst Notes */}
      <div className="card p-5">
        <span className="eyebrow">Collaboration</span>
        <h3 className="text-[15px] font-semibold text-ink mt-0.5">Analyst Triage Notes</h3>

        <div className="mt-4 space-y-3">
          {incident.notes.map((n, i) => (
            <div key={i} className="p-3 rounded-lg border border-hairline bg-canvas">
              <div className="flex items-center justify-between text-[11px] font-mono text-mute">
                <span className="font-semibold text-ink">{n.author}</span>
                <span>{istFull(n.ts)}</span>
              </div>
              <p className="mt-1 text-[13px] text-body">{n.body}</p>
            </div>
          ))}
        </div>

        <form onSubmit={handleAddNote} className="mt-4 flex gap-2">
          <input
            type="text"
            placeholder="Add investigation note..."
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            className="input text-[13px]"
          />
          <button type="submit" className="btn btn-primary gap-1.5 shrink-0">
            <Send className="h-3.5 w-3.5" />
            <span>Add Note</span>
          </button>
        </form>
      </div>

      {/* Confirm Dialog */}
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={`Confirm Action: ${pendingAction?.action.toUpperCase()}`}
        description={`Are you sure you want to execute ${pendingAction?.action} on target "${pendingAction?.target}"? This will modify the lab decoy network and core routing policy.`}
        confirmLabel="Execute Lab Action"
        danger={true}
        loading={actionLoading}
        onConfirm={executeAction}
      />
    </div>
  );
}
