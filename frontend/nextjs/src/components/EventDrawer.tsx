import React, { useState } from "react";
import type { Event, Narrative } from "@/lib/types";
import { api } from "@/lib/api";
import { ago, istFull } from "@/lib/format";
import { ServiceIcon } from "@/components/ServiceIcon";
import { SeverityPill } from "@/components/SeverityPill";
import { getEventSeverity } from "@/lib/event-risk";
import { X, Sparkles, Loader2, ShieldAlert } from "@/components/icons";

interface Props {
  event: Event | null;
  onClose: () => void;
}

export function EventDrawer({ event, onClose }: Props) {
  const [narrative, setNarrative] = useState<Narrative | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);

  if (!event) return null;

  async function handleExplain() {
    if (!event) return;
    setExplaining(true);
    setExplainError(null);
    try {
      const res = await api.explainEvent(event.event_id);
      setNarrative(res);
    } catch {
      setExplainError("Unable to fetch AI explanation. Showing raw telemetry details.");
    } finally {
      setExplaining(false);
    }
  }

  const envelope = event.envelope ?? {
    event_id: event.event_id,
    ts: event.ts,
    type: event.type,
    origin: event.origin,
    service: event.service,
    sensor_id: event.sensor_id,
    session_id: event.session_id,
    src_ip: event.src_ip,
    data: event.data,
  };

  const severity = getEventSeverity(event);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30 backdrop-blur-xs animate-in fade-in" onClick={onClose}>
      <aside
        className="h-full w-full max-w-[560px] overflow-y-auto border-l border-hairline bg-elevated p-6 shadow-2xl animate-in slide-in-from-right duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-hairline pb-4">
          <div className="flex items-center gap-2">
            <ServiceIcon service={event.service} className="h-4 w-4" />
            <span className="font-mono text-[13px] font-semibold text-ink">{event.type}</span>
            <SeverityPill severity={severity} size="sm" />
            {event.origin === "production" && (
              <span className="rounded-full bg-red-100 px-2 py-0.5 text-[11px] font-mono font-bold text-red-800">
                PROD ACCESS
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1.5 text-mute hover:bg-hairline hover:text-ink"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4">
          <p className="eyebrow">Summary</p>
          <p className="mt-1 font-mono text-[14px] font-medium text-ink bg-canvas p-3 rounded-md border border-hairline break-all">
            {event.summary}
          </p>
        </div>

        {/* Explain Section */}
        <div className="mt-4">
          {!narrative && !explaining && (
            <button
              onClick={handleExplain}
              className="btn btn-primary w-full justify-center gap-2"
            >
              <Sparkles className="h-4 w-4 text-warning" />
              <span>Explain this activity with AI</span>
            </button>
          )}

          {explaining && (
            <div className="flex items-center justify-center gap-2 rounded-md border border-hairline bg-canvas p-4 text-mute text-[13px]">
              <Loader2 className="h-4 w-4 animate-spin text-link" />
              <span>Analyzing attack patterns and MITRE context...</span>
            </div>
          )}

          {narrative && (
            <div className="rounded-[12px] border border-link-soft bg-[#f0f6ff] p-4 text-ink">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-[12px] font-mono font-medium text-link">
                  <Sparkles className="h-3.5 w-3.5" />
                  {narrative.source === "llm" ? "AI Analysis" : "Pattern Template"}
                </span>
                {narrative.model && (
                  <span className="text-[11px] font-mono text-mute">{narrative.model}</span>
                )}
              </div>
              <h4 className="mt-2 text-[15px] font-semibold tracking-tight text-ink">
                {narrative.headline}
              </h4>
              <p className="mt-1 text-[13px] leading-relaxed text-body">{narrative.text}</p>
              {narrative.bullets.length > 0 && (
                <ul className="mt-2 list-disc space-y-1 pl-4 text-[12px] text-body">
                  {narrative.bullets.map((b, i) => (
                    <li key={i}>{b}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {explainError && (
            <div className="mt-2 flex items-center gap-2 rounded-md bg-amber-50 p-3 text-[12px] text-amber-800 border border-amber-200">
              <ShieldAlert className="h-4 w-4 shrink-0" />
              <span>{explainError}</span>
            </div>
          )}
        </div>

        {/* Details List */}
        <dl className="mt-6 grid grid-cols-2 gap-y-3 gap-x-4 border-t border-hairline pt-4 text-[13px]">
          <div>
            <dt className="eyebrow">Timestamp (IST)</dt>
            <dd className="font-mono mt-0.5 text-body" title={event.ts}>
              {istFull(event.ts)} ({ago(event.ts)})
            </dd>
          </div>
          <div>
            <dt className="eyebrow">Event ID</dt>
            <dd className="font-mono mt-0.5 text-body break-all">{event.event_id}</dd>
          </div>
          <div>
            <dt className="eyebrow">Source IP</dt>
            <dd className="font-mono mt-0.5 font-semibold text-ink">{event.src_ip}</dd>
          </div>
          <div>
            <dt className="eyebrow">Sensor</dt>
            <dd className="font-mono mt-0.5 text-body">{event.sensor_id}</dd>
          </div>
          <div>
            <dt className="eyebrow">Actor</dt>
            <dd className="mt-0.5 font-mono text-body font-medium">
              {event.actor_label ? (
                <span className="text-link hover:underline">{event.actor_label}</span>
              ) : (
                <span className="text-mute">Uncorrelated</span>
              )}
            </dd>
          </div>
          <div>
            <dt className="eyebrow">Session ID</dt>
            <dd className="font-mono mt-0.5 text-body break-all">{event.session_id}</dd>
          </div>
          {event.tokens.length > 0 && (
            <div className="col-span-2">
              <dt className="eyebrow">Honeytokens Touched</dt>
              <dd className="mt-1 flex flex-wrap gap-1.5">
                {event.tokens.map((tok) => (
                  <span
                    key={tok}
                    className="rounded bg-rose-50 border border-rose-200 px-2 py-0.5 text-[11px] font-mono font-bold text-rose-700"
                  >
                    {tok}
                  </span>
                ))}
              </dd>
            </div>
          )}
        </dl>

        {/* Raw JSON */}
        <div className="mt-6 border-t border-hairline pt-4">
          <div className="flex items-center justify-between">
            <span className="eyebrow">Raw Envelope JSON</span>
            <button
              onClick={() => navigator.clipboard.writeText(JSON.stringify(envelope, null, 2))}
              className="text-[11px] font-mono text-link hover:underline"
            >
              Copy JSON
            </button>
          </div>
          <pre className="mt-2 max-h-[320px] overflow-auto rounded-[12px] border border-hairline bg-canvas p-3.5 font-mono text-[11px] leading-relaxed text-ink">
            {JSON.stringify(envelope, null, 2)}
          </pre>
        </div>
      </aside>
    </div>
  );
}
