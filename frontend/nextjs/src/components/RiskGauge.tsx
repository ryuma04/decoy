import React from "react";

interface Props {
  score: number;
  size?: number;
  showLabel?: boolean;
}

export function RiskGauge({ score, size = 88, showLabel = true }: Props) {
  const clamped = Math.max(0, Math.min(100, score));
  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clamped / 100) * circumference;

  let color = "#3b82f6"; // blue low
  if (clamped >= 80) color = "#ee0000"; // red critical
  else if (clamped >= 60) color = "#f5a623"; // orange high
  else if (clamped >= 30) color = "#ab570a"; // amber medium

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90 transform">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="var(--color-hairline)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-bold tracking-tight" style={{ color }}>
            {clamped}
          </span>
          <span className="text-[10px] uppercase font-mono text-mute">/ 100</span>
        </div>
      </div>
      {showLabel && (
        <span className="font-mono text-[11px] text-mute uppercase tracking-wider">
          Risk Score
        </span>
      )}
    </div>
  );
}
