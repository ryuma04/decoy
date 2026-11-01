import React from "react";
import type { BehaviourClass } from "@/lib/types";
import { User, Terminal, Sparkles, Bot, HelpCircle } from "@/components/icons";

interface Props {
  behaviourClass: BehaviourClass;
  className?: string;
  size?: "sm" | "md";
}

export function BehaviourBadge({ behaviourClass, className = "", size = "md" }: Props) {
  const configs: Record<BehaviourClass, { label: string; icon: React.ComponentType<{ className?: string }>; style: string }> = {
    agent_like: {
      label: "Agent-like",
      icon: Bot,
      style: "bg-purple-50 text-purple-700 border-purple-200",
    },
    ai_assisted: {
      label: "AI-assisted",
      icon: Sparkles,
      style: "bg-indigo-50 text-indigo-700 border-indigo-200",
    },
    scripted: {
      label: "Scripted",
      icon: Terminal,
      style: "bg-amber-50 text-amber-700 border-amber-200",
    },
    human_like: {
      label: "Human-like",
      icon: User,
      style: "bg-emerald-50 text-emerald-700 border-emerald-200",
    },
    unknown: {
      label: "Unknown",
      icon: HelpCircle,
      style: "bg-gray-50 text-gray-600 border-gray-200",
    },
  };

  const config = configs[behaviourClass] ?? configs.unknown;
  const Icon = config.icon;
  const sizeClass = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-[12px]";

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-mono font-medium ${config.style} ${sizeClass} ${className}`}
      title={`Observed behaviour pattern: ${config.label} (describes activity pattern, not identity)`}
    >
      <Icon className="h-3.5 w-3.5" />
      <span>{config.label}</span>
    </span>
  );
}
