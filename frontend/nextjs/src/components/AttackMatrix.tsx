import React from "react";
import type { Finding } from "@/lib/types";
import { Sparkles, Terminal, Code, Cpu } from "lucide-react";

interface Props {
  findings: Finding[];
  onSelectEvent?: (eventId: string) => void;
}

export function AttackMatrix({ findings, onSelectEvent }: Props) {
  const killChainStages = [
    { key: "recon", label: "1. Reconnaissance" },
    { key: "access", label: "2. Initial Access" },
    { key: "post_access", label: "3. Post Access / Discovery" },
    { key: "lateral", label: "4. Lateral Movement" },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {killChainStages.map((stage) => {
        const stageFindings = findings.filter((f) => f.stage === stage.key);
        return (
          <div key={stage.key} className="flex flex-col rounded-[12px] border border-hairline bg-canvas/60 p-3.5">
            <div className="flex items-center justify-between border-b border-hairline pb-2.5">
              <span className="eyebrow text-[11px] font-semibold text-ink">{stage.label}</span>
              <span className="rounded-full bg-elevated border border-hairline px-2 py-0.5 font-mono text-[11px] text-mute font-medium">
                {stageFindings.length}
              </span>
            </div>

            <div className="mt-3 flex flex-col gap-2.5 flex-1">
              {stageFindings.length === 0 ? (
                <div className="flex flex-1 items-center justify-center p-4 text-center">
                  <span className="text-[12px] text-mute italic">No activity detected</span>
                </div>
              ) : (
                stageFindings.map((f) => (
                  <div
                    key={f.finding_id}
                    className="card p-3 transition-shadow hover:shadow-xs border-hairline bg-elevated"
                  >
                    <div className="flex items-start justify-between gap-1">
                      <span className="font-mono text-[11px] font-semibold text-link bg-link/5 border border-link/20 px-1.5 py-0.5 rounded">
                        {f.technique ?? "T-UNKNOWN"}
                      </span>
                      <span className="font-mono text-[11px] font-bold text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200">
                        +{f.points} pts
                      </span>
                    </div>

                    <h5 className="mt-2 text-[13px] font-medium leading-snug text-ink">
                      {f.technique_name ?? f.title}
                    </h5>

                    {f.evidence.matched && (
                      <div className="mt-2 rounded bg-canvas p-1.5 font-mono text-[11px] text-mute break-all border border-hairline-soft">
                        <span className="text-ink font-medium">Matched:</span> {f.evidence.matched}
                      </div>
                    )}

                    {f.evidence.ml && (
                      <div className="mt-1.5 flex items-center gap-1.5 text-[11px] font-mono text-purple-700 bg-purple-50 p-1.5 rounded border border-purple-200">
                        <Sparkles className="h-3 w-3 shrink-0" />
                        <span>
                          ML: {f.evidence.ml.label} ({(f.evidence.ml.risk * 100).toFixed(0)}%)
                        </span>
                        {f.evidence.ml.was_encoded && (
                          <span className="bg-purple-200 text-purple-900 px-1 rounded text-[9px] uppercase font-bold">
                            Encoded
                          </span>
                        )}
                      </div>
                    )}

                    <div className="mt-2.5 flex items-center justify-between border-t border-hairline pt-2 text-[11px]">
                      <span className="flex items-center gap-1 text-mute font-mono">
                        {f.source === "rule" && <Terminal className="h-3 w-3" />}
                        {f.source === "ml" && <Sparkles className="h-3 w-3 text-purple-600" />}
                        {f.source === "rule+ml" && <Cpu className="h-3 w-3 text-link" />}
                        <span className="uppercase">{f.source}</span>
                      </span>

                      {f.evidence.event_ids.length > 0 && onSelectEvent && f.evidence.event_ids[0] && (
                        <button
                          onClick={() => onSelectEvent(f.evidence.event_ids[0]!)}
                          className="font-mono text-link hover:underline text-[11px] flex items-center gap-1"
                        >
                          <Code className="h-3 w-3" />
                          <span>{f.evidence.event_ids.length} event(s)</span>
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
