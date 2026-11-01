import React from "react";
import type { Service } from "@/lib/types";
import { Terminal, Globe, Database, Boxes, Radio, Cpu, ShieldAlert, KeyRound, Lock } from "@/components/icons";

interface Props {
  service: Service | string;
  className?: string;
  showLabel?: boolean;
}

export function ServiceIcon({ service, className = "h-4 w-4", showLabel = false }: Props) {
  const iconMap: Record<string, { icon: React.ComponentType<{ className?: string }>; label: string; color: string }> = {
    ssh: { icon: Terminal, label: "SSH Decoy", color: "text-blue-600 bg-blue-50 border-blue-200" },
    web: { icon: Globe, label: "Web Decoy", color: "text-emerald-600 bg-emerald-50 border-emerald-200" },
    dbadmin: { icon: Database, label: "Database Decoy", color: "text-amber-600 bg-amber-50 border-amber-200" },
    k8s: { icon: Boxes, label: "K8s API Decoy", color: "text-indigo-600 bg-indigo-50 border-indigo-200" },
    beacon: { icon: Radio, label: "Token Beacon", color: "text-rose-600 bg-rose-50 border-rose-200" },
    engine: { icon: Cpu, label: "Core Engine", color: "text-purple-600 bg-purple-50 border-purple-200" },
    firewall: { icon: ShieldAlert, label: "Perimeter Firewall", color: "text-red-600 bg-red-50 border-red-200" },
    hostauth: { icon: KeyRound, label: "Host Auth", color: "text-orange-600 bg-orange-50 border-orange-200" },
    appauth: { icon: Lock, label: "App Auth", color: "text-teal-600 bg-teal-50 border-teal-200" },
  };

  const item = iconMap[service] ?? { icon: Globe, label: service, color: "text-gray-600 bg-gray-50 border-gray-200" };
  const Icon = item.icon;

  if (showLabel) {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[12px] font-mono ${item.color}`}>
        <Icon className={className} />
        <span>{item.label}</span>
      </span>
    );
  }

  return (
    <span title={item.label} className="inline-flex items-center justify-center">
      <Icon className={className} />
    </span>
  );
}
