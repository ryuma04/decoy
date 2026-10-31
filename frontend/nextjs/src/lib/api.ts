// Typed client for the analyst API (04 §B). The browser only calls /api/...; next.config.ts forwards to core.
import type {
  ActorDetail,
  ActorSummary,
  ApiError,
  Event,
  FeedbackResult,
  Honeytoken,
  Incident,
  IncidentDetail,
  IncidentStatus,
  MazeGraph,
  Narrative,
  Overview,
  Page,
  ResponseAction,
  ScorerState,
  Sensor,
  TechniqueCount,
  TimelineItem,
  TimeseriesPoint,
  User,
} from "@/lib/types";

import mockOverview from "@/mocks/overview.json";
import mockTimeseries from "@/mocks/timeseries.json";
import mockTechniques from "@/mocks/techniques.json";
import mockActors from "@/mocks/actors.json";
import mockActorDetail from "@/mocks/actor_act0007.json";
import mockActorTimeline from "@/mocks/actor_act0007_timeline.json";
import mockActorMaze from "@/mocks/actor_act0007_maze.json";
import mockIncidents from "@/mocks/incidents.json";
import mockIncidentDetail from "@/mocks/incident_inc001.json";
import mockMaze from "@/mocks/maze.json";
import mockHoneytokens from "@/mocks/honeytokens.json";
import mockSensors from "@/mocks/sensors.json";
import mockScorer from "@/mocks/scorer.json";
import mockEvents from "@/mocks/events.json";

export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

const USE_MOCKS = process.env.NEXT_PUBLIC_USE_MOCKS === "1";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const body: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (body as ApiError | null)?.error;
    throw new HttpError(res.status, err?.code ?? "http_error", err?.message ?? `HTTP ${res.status}`);
  }
  return body as T;
}

export const api = {
  // Auth
  login: async (email: string, password: string): Promise<{ user: User }> => {
    if (USE_MOCKS) return { user: { user_id: "usr-mock-01", email, role: "admin" } };
    return call<{ user: User }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
  },
  logout: async (): Promise<void> => {
    if (USE_MOCKS) return;
    return call<void>("/auth/logout", { method: "POST" });
  },
  me: async (): Promise<{ user: User }> => {
    if (USE_MOCKS) return { user: { user_id: "usr-mock-01", email: "analyst@soc.local", role: "admin" } };
    return call<{ user: User }>("/auth/me");
  },

  // Stats & Overview
  getOverview: async (window = "1h"): Promise<Overview> => {
    if (USE_MOCKS) return mockOverview as unknown as Overview;
    return call<Overview>(`/stats/overview?window=${encodeURIComponent(window)}`);
  },
  getTimeseries: async (params: Record<string, string> = {}): Promise<{ points: TimeseriesPoint[] }> => {
    if (USE_MOCKS) return mockTimeseries as { points: TimeseriesPoint[] };
    return call<{ points: TimeseriesPoint[] }>(`/stats/timeseries?${new URLSearchParams(params).toString()}`);
  },
  getTechniques: async (window = "24h"): Promise<{ items: TechniqueCount[] }> => {
    if (USE_MOCKS) return mockTechniques as { items: TechniqueCount[] };
    return call<{ items: TechniqueCount[] }>(`/stats/techniques?window=${encodeURIComponent(window)}`);
  },

  // Events
  listEvents: async (params: Record<string, string> = {}): Promise<Page<Event>> => {
    if (USE_MOCKS) return mockEvents as unknown as Page<Event>;
    return call<Page<Event>>(`/events?${new URLSearchParams(params).toString()}`);
  },
  getEvent: async (id: string): Promise<Event> => {
    if (USE_MOCKS) {
      const found = (mockEvents.items as unknown as Event[]).find((e) => e.event_id === id);
      return found ?? (mockEvents.items[0] as unknown as Event);
    }
    return call<Event>(`/events/${encodeURIComponent(id)}`);
  },
  explainEvent: async (id: string): Promise<Narrative> => {
    if (USE_MOCKS) {
      return {
        headline: "Attacker executed suspicious discovery command",
        text: `The command evaluated in event ${id} exhibited patterns of reconnaissance and attempts to read local credentials.`,
        bullets: ["Command matched sensitive filesystem paths", "High confidence threat scoring"],
        source: "llm",
        model: "gemini-3.5-flash-lite",
        generated_at: new Date().toISOString(),
      };
    }
    return call<Narrative>(`/events/${encodeURIComponent(id)}/explain`);
  },

  // Actors
  listActors: async (params: Record<string, string> = {}): Promise<Page<ActorSummary>> => {
    if (USE_MOCKS) return { items: mockActors as unknown as ActorSummary[], next_cursor: null };
    const res = await call<Page<ActorSummary> | ActorSummary[]>(`/actors?${new URLSearchParams(params).toString()}`);
    if (Array.isArray(res)) return { items: res, next_cursor: null };
    return res;
  },
  getActor: async (id: string): Promise<ActorDetail> => {
    if (USE_MOCKS) return mockActorDetail as unknown as ActorDetail;
    return call<ActorDetail>(`/actors/${encodeURIComponent(id)}`);
  },
  getActorTimeline: async (id: string, params: Record<string, string> = {}): Promise<Page<TimelineItem>> => {
    if (USE_MOCKS) return { items: mockActorTimeline as unknown as TimelineItem[], next_cursor: null };
    const res = await call<Page<TimelineItem> | TimelineItem[]>(
      `/actors/${encodeURIComponent(id)}/timeline?${new URLSearchParams(params).toString()}`
    );
    if (Array.isArray(res)) return { items: res, next_cursor: null };
    return res;
  },
  getActorMaze: async (id: string): Promise<MazeGraph> => {
    if (USE_MOCKS) return mockActorMaze as unknown as MazeGraph;
    return call<MazeGraph>(`/actors/${encodeURIComponent(id)}/maze`);
  },

  // Incidents
  listIncidents: async (params: Record<string, string> = {}): Promise<Page<Incident>> => {
    if (USE_MOCKS) return { items: mockIncidents as unknown as Incident[], next_cursor: null };
    const res = await call<Page<Incident> | Incident[]>(`/incidents?${new URLSearchParams(params).toString()}`);
    if (Array.isArray(res)) return { items: res, next_cursor: null };
    return res;
  },
  getIncident: async (id: string): Promise<IncidentDetail> => {
    if (USE_MOCKS) return mockIncidentDetail as unknown as IncidentDetail;
    return call<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`);
  },
  patchIncident: async (id: string, data: { status?: IncidentStatus; note?: string }): Promise<IncidentDetail> => {
    if (USE_MOCKS) {
      return {
        ...(mockIncidentDetail as unknown as IncidentDetail),
        status: data.status ?? (mockIncidentDetail.status as IncidentStatus),
      };
    }
    return call<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },
  takeAction: async (id: string, action: string, target: string): Promise<ResponseAction> => {
    if (USE_MOCKS) {
      return {
        action_id: Math.floor(Math.random() * 1000) + 10,
        action,
        target,
        status: "applied",
        requested_by: "analyst@soc.local",
        ts: new Date().toISOString(),
      };
    }
    return call<ResponseAction>(`/incidents/${encodeURIComponent(id)}/actions`, {
      method: "POST",
      body: JSON.stringify({ action, target }),
    });
  },
  getIncidentReport: async (id: string, format: "md" | "json" = "md"): Promise<string> => {
    if (USE_MOCKS) {
      return `# Incident Report: ${id}\n\n**Severity:** CRITICAL\n**Actor:** ACT-0007\n\n## Summary\nCritical exfiltration of planted honeytokens across multiple decoys.\n\n## IOCs\n- 10.66.0.23\n- 10.66.0.41\n- tok_aws_k7\n`;
    }
    const res = await fetch(`/api/incidents/${encodeURIComponent(id)}/report?format=${format}`, {
      credentials: "same-origin",
      cache: "no-store",
    });
    return res.text();
  },
  giveFeedback: async (
    id: string,
    data: { label: "confirmed" | "false_positive"; allowlist_source?: boolean; note?: string }
  ): Promise<FeedbackResult> => {
    if (USE_MOCKS) {
      return {
        feedback_id: 42,
        old_risk: 88,
        new_risk: data.label === "confirmed" ? 92 : 44,
        weights_version: 4,
      };
    }
    return call<FeedbackResult>(`/incidents/${encodeURIComponent(id)}/feedback`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  // Maze
  getMaze: async (): Promise<MazeGraph> => {
    if (USE_MOCKS) return mockMaze as unknown as MazeGraph;
    return call<MazeGraph>("/maze");
  },

  // Honeytokens
  listHoneytokens: async (): Promise<Honeytoken[]> => {
    if (USE_MOCKS) return mockHoneytokens as unknown as Honeytoken[];
    const res = await call<Page<Honeytoken> | Honeytoken[]>("/honeytokens");
    return Array.isArray(res) ? res : res.items;
  },

  // Sensors
  listSensors: async (): Promise<Sensor[]> => {
    if (USE_MOCKS) return mockSensors as unknown as Sensor[];
    const res = await call<Page<Sensor> | Sensor[]>("/sensors");
    return Array.isArray(res) ? res : res.items;
  },

  // Scorer
  getScorer: async (): Promise<ScorerState> => {
    if (USE_MOCKS) return mockScorer as unknown as ScorerState;
    return call<ScorerState>("/scorer");
  },
  resetScorer: async (): Promise<ScorerState> => {
    if (USE_MOCKS) return { ...(mockScorer as unknown as ScorerState), version: 1 };
    return call<ScorerState>("/scorer/reset", { method: "POST" });
  },
};
