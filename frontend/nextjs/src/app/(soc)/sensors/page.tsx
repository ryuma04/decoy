"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ago } from "@/lib/format";
import type { Sensor } from "@/lib/types";
import { ServiceIcon } from "@/components/ServiceIcon";
import { CheckCircle2, AlertOctagon } from "@/components/icons";

export default function SensorsPage() {
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listSensors()
      .then(setSensors)
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-[28px] font-semibold tracking-tight text-ink">Decoy Sensor Fleet</h1>
          <p className="mt-1 text-body text-[13px]">
            Decoy micro-services and telemetry collectors deployed across isolated lab subnets.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
        {sensors.length === 0 ? (
          <div className="col-span-full py-12 text-center text-mute text-sm font-mono">
            {loading ? "Loading sensor fleet..." : "No decoy sensors registered."}
          </div>
        ) : (
          sensors.map((s) => {
            const isOk = s.status === "ok";
            return (
              <div
                key={s.sensor_id}
                className={`card p-5 transition-shadow hover:shadow-xs flex flex-col justify-between ${
                  !isOk ? "border-red-300 bg-red-50/20" : ""
                }`}
              >
                <div>
                  <div className="flex items-center justify-between border-b border-hairline pb-3">
                    <div className="flex items-center gap-2">
                      <ServiceIcon service={s.service} className="h-4 w-4" />
                      <span className="font-mono text-[12px] font-bold text-ink uppercase">
                        {s.service}
                      </span>
                    </div>

                    <span
                      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-mono font-medium ${
                        isOk
                          ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          : "bg-red-100 text-red-800 border border-red-300 font-bold"
                      }`}
                    >
                      {isOk ? (
                        <>
                          <CheckCircle2 className="h-3 w-3" />
                          <span>OK</span>
                        </>
                      ) : (
                        <>
                          <AlertOctagon className="h-3 w-3" />
                          <span>SILENT</span>
                        </>
                      )}
                    </span>
                  </div>

                  <div className="mt-4">
                    <span className="eyebrow">Sensor Identifier</span>
                    <p className="mt-1 font-mono text-[16px] font-bold text-ink">{s.sensor_id}</p>
                  </div>
                </div>

                <div className="mt-6 pt-3 border-t border-hairline font-mono text-[11px] text-body space-y-1">
                  <div className="flex justify-between">
                    <span className="text-mute">Version:</span>
                    <span>v{s.version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-mute">Last Heartbeat:</span>
                    <span>{s.last_seen ? `${ago(s.last_seen)}` : "Never"}</span>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
