"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ago } from "@/lib/format";
import type { ScorerState } from "@/lib/types";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { RotateCcw, CheckCircle2, XCircle } from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

export default function ScorerPage() {
  const [scorer, setScorer] = useState<ScorerState | null>(null);
  const [resetOpen, setResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  useEffect(() => {
    api.getScorer()
      .then(setScorer)
      .catch(() => undefined);
  }, []);

  async function handleReset() {
    setResetting(true);
    try {
      const updated = await api.resetScorer();
      setScorer(updated);
    } catch (err) {
      alert("Failed to reset scorer: " + String(err));
    } finally {
      setResetting(false);
    }
  }

  const chartData = scorer
    ? [
        { stage: "Recon", weight: scorer.weights.recon },
        { stage: "Initial Access", weight: scorer.weights.access },
        { stage: "Post-Access", weight: scorer.weights.post_access },
        { stage: "Lateral Move", weight: scorer.weights.lateral },
      ]
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-[28px] font-semibold tracking-tight text-ink">
              Adaptive Risk Scorer
            </h1>
            <span
              className={`rounded-full px-2.5 py-0.5 text-[11px] font-mono font-medium border ${
                scorer?.learning_enabled
                  ? "bg-purple-50 text-purple-700 border-purple-200"
                  : "bg-gray-100 text-gray-700 border-gray-300"
              }`}
            >
              Online Learning: {scorer?.learning_enabled ? "Enabled (η = 0.05)" : "Disabled"}
            </span>
          </div>
          <p className="mt-1 text-body text-[13px]">
            Single-neuron logistic classifier weights continuously tuned from analyst ground-truth feedback.
          </p>
        </div>

        <button
          onClick={() => setResetOpen(true)}
          className="btn gap-1.5 text-[12px] border-hairline hover:bg-canvas"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          <span>Reset Weights to v1</span>
        </button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-5">
          <span className="eyebrow">Active Version</span>
          <p className="mt-2 font-mono text-[32px] font-bold text-ink">
            v{scorer?.version ?? 1}
          </p>
          <span className="text-[11px] text-mute font-mono">
            Updated {scorer?.updated_at ? ago(scorer.updated_at) : "recently"}
          </span>
        </div>

        <div className="card p-5">
          <span className="eyebrow">Neuron Bias Term</span>
          <p className="mt-2 font-mono text-[32px] font-bold text-ink">
            {scorer?.bias.toFixed(2) ?? "—"}
          </p>
          <span className="text-[11px] text-mute font-mono">Baseline threshold shift</span>
        </div>

        <div className="card p-5">
          <span className="eyebrow flex items-center gap-1.5 text-emerald-700">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>Confirmed Attacks</span>
          </span>
          <p className="mt-2 font-mono text-[32px] font-bold text-emerald-700">
            {scorer?.feedback_confirmed ?? 0}
          </p>
          <span className="text-[11px] text-mute font-mono">Positive reinforcements</span>
        </div>

        <div className="card p-5">
          <span className="eyebrow flex items-center gap-1.5 text-red-700">
            <XCircle className="h-3.5 w-3.5" />
            <span>False Positives</span>
          </span>
          <p className="mt-2 font-mono text-[32px] font-bold text-red-700">
            {scorer?.feedback_false_positive ?? 0}
          </p>
          <span className="text-[11px] text-mute font-mono">Negative penalizations</span>
        </div>
      </div>

      {/* Stage Weights Chart */}
      <div className="card p-6">
        <div className="mb-4">
          <span className="eyebrow">Per-Stage Neuron Weights ($w_i$)</span>
          <h3 className="text-[16px] font-semibold text-ink">Kill-chain stage contributions</h3>
        </div>

        <div className="h-[280px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
              <XAxis dataKey="stage" stroke="#8f8f8f" fontSize={12} fontFamily="monospace" />
              <YAxis stroke="#8f8f8f" fontSize={11} fontFamily="monospace" domain={[0, 1.2]} />
              <Tooltip
                formatter={(val) => [`Weight: ${val ?? 0}`, "Stage Coefficient"]}
                contentStyle={{
                  backgroundColor: "#ffffff",
                  borderColor: "#ebebeb",
                  borderRadius: "8px",
                  fontSize: "12px",
                  fontFamily: "monospace",
                }}
              />
              <Bar dataKey="weight" fill="#171717" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Reset Confirmation Dialog */}
      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Reset Scorer Weights to v1"
        description="Are you sure you want to revert all online learned weights to baseline v1 defaults? This will erase accumulated feedback adaptations in the live core."
        confirmLabel="Reset to v1"
        danger={true}
        loading={resetting}
        onConfirm={handleReset}
      />
    </div>
  );
}
