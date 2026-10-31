import React from "react";
import type { Severity } from "@/lib/types";

interface Props {
  severity: Severity;
  className?: string;
  size?: "sm" | "md";
}

export function SeverityPill({ severity, className = "", size = "md" }: Props) {
  const styles: Record<Severity, string> = {
    critical: "bg-[#ffe5e5] text-[#ee0000] border-[#ee0000]/30",
    high: "bg-[#ffefcf] text-[#ab570a] border-[#f5a623]/40",
    medium: "bg-[#fff8e5] text-[#ab570a] border-[#f5a623]/30",
    low: "bg-[#eef2ff] text-[#3b82f6] border-[#3b82f6]/30",
  };

  const labels: Record<Severity, string> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };

  const sizeClass = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-[12px]";

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-mono font-medium uppercase tracking-wide ${styles[severity]} ${sizeClass} ${className}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      {labels[severity]}
    </span>
  );
}
