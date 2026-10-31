import React, { useMemo } from "react";
import type { Session } from "@/lib/types";
import {
  ReactFlow,
  Background,
  Controls,
  type Node,
  type Edge,
  Position,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ServiceIcon } from "@/components/ServiceIcon";
import { istTime } from "@/lib/format";

interface Props {
  sessions: Session[];
}

function SessionCustomNode({ data }: { data: { session: Session } }) {
  const s = data.session;
  return (
    <div className="rounded-[12px] border border-hairline bg-elevated p-3 shadow-md min-w-[190px] border-hairline hover:border-link transition-colors">
      <div className="flex items-center justify-between border-b border-hairline pb-2">
        <div className="flex items-center gap-1.5">
          <ServiceIcon service={s.service} className="h-4 w-4" />
          <span className="font-mono text-[12px] font-semibold text-ink uppercase">
            {s.service}
          </span>
        </div>
        <span className="rounded bg-canvas px-1.5 py-0.5 text-[10px] font-mono text-mute">
          {s.event_count} evs
        </span>
      </div>
      <div className="mt-2 space-y-1 font-mono text-[11px]">
        <div className="flex justify-between">
          <span className="text-mute">IP:</span>
          <span className="text-ink font-medium">{s.src_ip}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-mute">Time:</span>
          <span className="text-body">{istTime(s.started_at)}</span>
        </div>
        {s.link_score !== null && (
          <div className="flex justify-between text-link font-medium pt-1 border-t border-hairline-soft">
            <span>Link Score:</span>
            <span>{(s.link_score * 100).toFixed(0)}%</span>
          </div>
        )}
      </div>
    </div>
  );
}

const nodeTypes = {
  sessionNode: SessionCustomNode,
};

export function SessionGraph({ sessions }: Props) {
  const { nodes, edges } = useMemo(() => {
    const nList: Node[] = [];
    const eList: Edge[] = [];

    sessions.forEach((s, i) => {
      // Position nodes in a nice layout (horizontal progression)
      const x = 50 + (i % 3) * 260;
      const y = 50 + Math.floor(i / 3) * 160;

      nList.push({
        id: s.session_id,
        type: "sessionNode",
        position: { x, y },
        data: { session: s },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });

      // Link reasons to edges
      s.link_reasons.forEach((lr, edgeIdx) => {
        if (lr.matched_session) {
          eList.push({
            id: `edge-${s.session_id}-${lr.matched_session}-${edgeIdx}`,
            source: lr.matched_session,
            target: s.session_id,
            label: lr.value || lr.signal.replace(/_/g, " "),
            animated: true,
            style: { stroke: "#0070f3", strokeWidth: 2 },
            labelStyle: { fill: "#171717", fontWeight: 500, fontSize: 11, fontFamily: "monospace" },
            labelBgStyle: { fill: "#ffffff", fillOpacity: 0.95, rx: 4, ry: 4 },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: "#0070f3",
            },
          });
        }
      });
    });

    return { nodes: nList, edges: eList };
  }, [sessions]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <span className="eyebrow">Correlation Graph</span>
        <span className="text-[12px] font-mono text-mute">
          Likely same operator correlation
        </span>
      </div>

      <div className="h-[360px] w-full rounded-[14px] border border-hairline bg-canvas/40 overflow-hidden shadow-xs">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          attributionPosition="bottom-right"
        >
          <Background color="#ebebeb" gap={16} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>

      {/* Sessions Table */}
      <div className="overflow-x-auto rounded-[12px] border border-hairline bg-elevated">
        <table className="w-full text-left text-[13px]">
          <thead className="border-b border-hairline bg-canvas text-[11px] font-mono uppercase text-mute">
            <tr>
              <th className="px-4 py-2.5">Service</th>
              <th className="px-4 py-2.5">Session ID</th>
              <th className="px-4 py-2.5">Source IP</th>
              <th className="px-4 py-2.5">Started (IST)</th>
              <th className="px-4 py-2.5">Events</th>
              <th className="px-4 py-2.5">Correlation Link</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-hairline font-mono text-[12px]">
            {sessions.map((s) => (
              <tr key={s.session_id} className="hover:bg-canvas/50">
                <td className="px-4 py-2.5 font-medium flex items-center gap-1.5">
                  <ServiceIcon service={s.service} className="h-3.5 w-3.5" />
                  <span className="uppercase text-ink">{s.service}</span>
                </td>
                <td className="px-4 py-2.5 text-mute">{s.sensor_session_id}</td>
                <td className="px-4 py-2.5 text-ink font-semibold">{s.src_ip}</td>
                <td className="px-4 py-2.5 text-body">{istTime(s.started_at)}</td>
                <td className="px-4 py-2.5">{s.event_count}</td>
                <td className="px-4 py-2.5">
                  {s.link_score !== null ? (
                    <span className="text-link font-medium">
                      {(s.link_score * 100).toFixed(0)}% (
                      {s.link_reasons.map((r) => r.signal).join(", ") || "likely same operator"}
                      )
                    </span>
                  ) : (
                    <span className="text-mute">Origin session</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
