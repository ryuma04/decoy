"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useStream } from "@/lib/stream";
import type { ActorSummary, MazeGraph as MazeGraphType, MazeMessage } from "@/lib/types";
import { MazeGraph } from "@/components/MazeGraph";
import { Compass } from "lucide-react";

export default function GlobalMazePage() {
  const [globalMaze, setGlobalMaze] = useState<MazeGraphType | null>(null);
  const [actors, setActors] = useState<ActorSummary[]>([]);
  const [selectedActorId, setSelectedActorId] = useState<string>("");
  const [actorMaze, setActorMaze] = useState<MazeGraphType | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.getMaze().catch(() => null),
      api.listActors().catch(() => ({ items: [] })),
    ]).then(([gm, actList]) => {
      if (gm) setGlobalMaze(gm);
      if (actList?.items) setActors(actList.items);
      setLoading(false);
    });
  }, []);

  const [lastChange, setLastChange] = useState<MazeMessage | null>(null);

  useEffect(() => {
    if (!selectedActorId) {
      setActorMaze(null);
      return;
    }
    api.getActorMaze(selectedActorId).then(setActorMaze).catch(() => undefined);
  }, [selectedActorId]);

  // Live: the engine publishes every visit / unlock; refresh the overlay and the actor list (depth) when it happens.
  useStream<MazeMessage>("maze", (m) => {
    setLastChange(m);
    if (m.actor_id === selectedActorId) {
      api.getActorMaze(selectedActorId).then(setActorMaze).catch(() => undefined);
    }
    api.listActors().then((a) => setActors(a.items)).catch(() => undefined);
  });

  const activeGraph = actorMaze ?? globalMaze;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">
            Adaptive Deception Maze
          </h1>
          <p className="mt-1 text-body text-[13px]">
            Decoy topology, dynamic lures, and actor traversal tracking with strict bounded limits.
          </p>
          {lastChange && (
            <p className="mt-1 font-mono text-[11px] text-mute">
              Last change: {actors.find((a) => a.actor_id === lastChange.actor_id)?.label ?? lastChange.actor_id.slice(0, 8)} ·{" "}
              {lastChange.node_id} → {lastChange.state} ({lastChange.reason})
            </p>
          )}
        </div>

        {/* Actor Overlay Selector */}
        <div className="flex items-center gap-2">
          <span className="text-[12px] font-mono text-mute">Overlay Actor:</span>
          <select
            value={selectedActorId}
            onChange={(e) => setSelectedActorId(e.target.value)}
            className="h-8.5 rounded-[6px] border border-hairline bg-canvas px-3 text-[12px] font-mono text-ink focus:outline-none focus:ring-2 focus:ring-link"
          >
            <option value="">Global Maze Definition</option>
            {actors.map((a) => (
              <option key={a.actor_id} value={a.actor_id}>
                {a.label} (Depth: {a.maze_depth} lures, Risk: {a.risk_score})
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="card p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Compass className="h-4 w-4 text-purple-600" />
            <h3 className="text-[16px] font-semibold text-ink">
              {selectedActorId
                ? `Overlaying Traversal Path for Actor ${
                    actors.find((a) => a.actor_id === selectedActorId)?.label ?? selectedActorId
                  }`
                : "Active Deception Topology Architecture"}
            </h3>
          </div>
          <span className="text-[12px] font-mono text-mute">
            {activeGraph?.nodes?.length ?? 0} Nodes · {activeGraph?.edges?.length ?? 0} Transitions
          </span>
        </div>

        {loading ? (
          <div className="h-[460px] flex items-center justify-center font-mono text-mute">
            Loading maze graph...
          </div>
        ) : activeGraph ? (
          <MazeGraph graph={activeGraph} height={520} />
        ) : (
          <div className="h-[460px] flex items-center justify-center font-mono text-mute italic">
            Maze topology unavailable.
          </div>
        )}
      </div>
    </div>
  );
}
