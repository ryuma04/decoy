import React, { useMemo } from "react";
import type { MazeGraph as MazeGraphType, MazeNode } from "@/lib/types";
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
import { Compass, Sparkles, CheckCircle2, Eye, EyeOff } from "lucide-react";

interface Props {
  graph: MazeGraphType;
  height?: number | string;
}

function MazeCustomNode({ data }: { data: { node: MazeNode } }) {
  const n = data.node;
  const state = n.state ?? n.default ?? "visible"; // global definition: the node's starting visibility

  let containerStyle = "border-hairline bg-elevated text-ink";
  let statusBadge = null;

  if (state === "visited") {
    containerStyle = "border-purple-500 bg-purple-50/80 text-purple-950 shadow-md ring-2 ring-purple-200";
    statusBadge = (
      <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-purple-700 bg-purple-100 px-1.5 py-0.5 rounded">
        <CheckCircle2 className="h-3 w-3" />
        Visited
      </span>
    );
  } else if (state === "visible") {
    containerStyle = "border-blue-400 bg-blue-50/50 text-blue-950 shadow-sm";
    statusBadge = (
      <span className="flex items-center gap-1 text-[10px] font-mono font-medium text-blue-700 bg-blue-100 px-1.5 py-0.5 rounded">
        <Eye className="h-3 w-3" />
        Unlocked
      </span>
    );
  } else if (state === "hidden") {
    containerStyle = "border-dashed border-gray-300 bg-gray-50/60 text-gray-400 opacity-60";
    statusBadge = (
      <span className="flex items-center gap-1 text-[10px] font-mono text-gray-500">
        <EyeOff className="h-3 w-3" />
        Hidden
      </span>
    );
  }

  return (
    <div className={`rounded-[12px] border p-3 min-w-[210px] transition-all ${containerStyle}`}>
      <div className="flex items-center justify-between border-b border-hairline/60 pb-1.5">
        <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-mute">
          {n.kind} {n.theme ? `· ${n.theme}` : ""}
        </span>
        {statusBadge}
      </div>

      <div className="mt-2 flex items-start gap-2">
        {n.service ? (
          <ServiceIcon service={n.service} className="h-4 w-4 shrink-0 mt-0.5" />
        ) : (
          <Compass className="h-4 w-4 shrink-0 mt-0.5 text-mute" />
        )}
        <div className="flex flex-col">
          <span className="text-[12px] font-semibold leading-tight">{n.label}</span>
          <span className="font-mono text-[10px] text-mute">{n.id}</span>
        </div>
      </div>

      {n.stretch && (
        <div className="mt-2 flex items-center gap-1 font-mono text-[10px] text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200">
          <Sparkles className="h-3 w-3" />
          <span>Stretch lure (AI generated)</span>
        </div>
      )}
    </div>
  );
}

const nodeTypes = {
  mazeNode: MazeCustomNode,
};

export function MazeGraph({ graph, height = 400 }: Props) {
  const { nodes, edges } = useMemo(() => {
    const nList: Node[] = [];
    const eList: Edge[] = [];

    // Layout nodes neatly
    graph.nodes.forEach((node, i) => {
      // 3 columns
      const col = i % 3;
      const row = Math.floor(i / 3);
      const x = 50 + col * 280;
      const y = 40 + row * 160;

      nList.push({
        id: node.id,
        type: "mazeNode",
        position: { x, y },
        data: { node },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      });
    });

    graph.edges.forEach((edge, i) => {
      eList.push({
        id: `maze-edge-${edge.from}-${edge.to}-${i}`,
        source: edge.from,
        target: edge.to,
        label: edge.label,
        animated: true,
        style: { stroke: "#7928ca", strokeWidth: 2 },
        labelStyle: { fill: "#171717", fontWeight: 500, fontSize: 10, fontFamily: "monospace" },
        labelBgStyle: { fill: "#ffffff", fillOpacity: 0.95, rx: 4, ry: 4 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#7928ca",
        },
      });
    });

    return { nodes: nList, edges: eList };
  }, [graph]);

  return (
    <div className="flex flex-col gap-3">
      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 text-[12px] font-mono border-b border-hairline pb-2.5">
        <span className="eyebrow">Legend:</span>
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-purple-600 ring-2 ring-purple-200" />
          <span>Visited</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-blue-500" />
          <span>Unlocked Lure</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-gray-300 border border-dashed border-gray-400" />
          <span>Hidden / Locked</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Sparkles className="h-3 w-3 text-amber-600" />
          <span>Stretch Node</span>
        </div>
      </div>

      <div
        className="w-full rounded-[14px] border border-hairline bg-canvas/40 overflow-hidden shadow-xs"
        style={{ height }}
      >
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
    </div>
  );
}
