import React from "react";

interface Props {
  title: string;
  value: string | number;
  subtitle?: string;
  badge?: React.ReactNode;
  icon?: React.ReactNode;
  alert?: boolean;
}

export function KpiCard({ title, value, subtitle, badge, icon, alert }: Props) {
  return (
    <div className={`card p-5 transition-shadow hover:shadow-sm ${alert ? "border-error/40 bg-error/5" : ""}`}>
      <div className="flex items-center justify-between">
        <span className="eyebrow">{title}</span>
        {icon && <div className="text-mute">{icon}</div>}
      </div>
      <div className="mt-3 flex items-baseline justify-between gap-2">
        <span className="font-mono text-[36px] font-semibold tracking-tight text-ink">
          {value}
        </span>
        {badge}
      </div>
      {subtitle && <p className="mt-2 text-[12px] text-mute">{subtitle}</p>}
    </div>
  );
}
