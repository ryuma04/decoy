// Copied verbatim from docs/04-api-contract.md §B. Change 04 first, then this file.

export type Severity = "low" | "medium" | "high" | "critical";
export type BehaviourClass = "human_like" | "scripted" | "ai_assisted" | "agent_like" | "unknown";
export type Service = "ssh" | "web" | "dbadmin" | "k8s" | "beacon" | "engine" | "firewall" | "hostauth" | "appauth";
export type Origin = "decoy" | "production";
export type Stage = "recon" | "access" | "post_access" | "lateral";
export type IncidentStatus = "open" | "ack" | "contained" | "closed";

export interface User { user_id: string; email: string; role: "analyst" | "admin"; }

export interface Overview {
  window: string;
  events: number; active_actors: number; new_actors: number;
  open_incidents: Record<Severity, number>;
  token_hits: number; sensors_ok: number; sensors_total: number;
  top_actor: ActorSummary | null;
  ml_input: boolean;                  // input-risk model reachable
  narration: "llm" | "template";      // readable activity source right now
}

export interface Narrative {
  headline: string; text: string; bullets: string[];
  source: "llm" | "template"; model: string | null; generated_at: string;
}

export interface Event {
  event_id: string; ts: string; type: string; origin: Origin; service: Service; sensor_id: string;
  session_id: string; actor_id: string | null; actor_label: string | null;
  src_ip: string; data: Record<string, unknown>; tokens: string[];
  summary: string;                    // server-made one-liner, e.g. "cat ~/.aws/credentials"
  envelope?: Record<string, unknown>;
}

export interface ActorSummary {
  actor_id: string; label: string; first_seen: string; last_seen: string;
  risk_score: number; severity: Severity; confidence: number;
  behaviour_class: BehaviourClass; services: Service[]; session_count: number;
  ips: string[]; top_techniques: string[]; token_hits: number; maze_depth: number;
  kill_chain_stage: Stage; touched_production: boolean; tools: string[];
}

export interface LinkReason { signal: string; weight: number; matched_session: string | null; value: string; }

export interface Session {
  session_id: string; sensor_session_id: string; actor_id: string; service: Service; sensor_id: string;
  src_ip: string; started_at: string; ended_at: string | null; event_count: number;
  link_score: number | null; link_reasons: LinkReason[];
}

export interface Fingerprint { kind: string; value: string; session_ids: string[]; }

export interface Finding {
  finding_id: number; actor_id: string; session_id: string; rule_id: string; title: string;
  tactic: string | null; technique: string | null; technique_name: string | null;
  stage: Stage; points: number; confidence: number; source: "rule" | "ml" | "rule+ml";
  evidence: { event_ids: string[]; matched?: string;
              ml?: { label: string; risk: number; confidence: number; top_features: string[]; was_encoded: boolean } };
  ts: string;
}

export interface BehaviourDetail {
  class: BehaviourClass; scores: Partial<Record<BehaviourClass, number>>; source: "rules";
  features: { median_gap_ms: number; gap_cv: number; edit_rate: number; paste_rate: number;
              output_dependence: number; services_visited: number; breadcrumbs_followed: number;
              param_mutation_retries: number; commands: number };
}

export interface RiskBreakdown {
  p: number; z: number; weights_version: number;
  stage_scores: Record<Stage, number>;
  contributions: Record<Stage, number>;          // w_i * S_i, for the "why this score" bar
  bias: number; override: string | null;         // e.g. "token_used_sensitivity_5"
}
export interface ToolTag { tool: string; first_seen: string; event_id: string; evidence: string; }
export interface ExternalSummary { firewall_denies: number; real_auth_failed: number; real_auth_success: number; systems: string[]; }
export interface ScorerState {
  version: number; weights: Record<Stage, number>; bias: number; learning_rate: number; learning_enabled: boolean;
  feedback_confirmed: number; feedback_false_positive: number; updated_at: string;
}

export interface ActorDetail extends ActorSummary {
  risk_breakdown: RiskBreakdown; tool_tags: ToolTag[]; external: ExternalSummary;
  sessions: Session[]; fingerprints: Fingerprint[]; findings: Finding[];
  behaviour: BehaviourDetail; interest: Record<"cloud" | "k8s" | "db" | "ci", number>;
  incident_id: string | null;
  narrative: Narrative | null;                  // "What happened" card
}

export type TimelineItem =
  | { kind: "event"; ts: string; event: Event }          // event.origin = "production" for firewall/auth logs
  | { kind: "finding"; ts: string; finding: Finding }
  | { kind: "maze"; ts: string; node_id: string; state: "visible" | "visited"; reason: string };

export interface MazeNode {
  id: string; label: string; kind: "entry" | "lure" | "service"; theme: "cloud" | "k8s" | "db" | "ci" | null;
  service: Service | null; stretch: boolean; state?: "hidden" | "visible" | "visited";
}
export interface MazeEdge { from: string; to: string; label?: string; }
export interface MazeGraph { nodes: MazeNode[]; edges: MazeEdge[]; actor_id?: string; }

export interface Incident {
  incident_id: string; actor_id: string; actor_label: string; severity: Severity; status: IncidentStatus;
  title: string; opened_at: string; updated_at: string; risk_score: number;
}
export interface IOC { kind: "ip" | "sha256" | "credential" | "url" | "token"; value: string; }
export interface ResponseAction {
  action_id: number; action: string; target: string; status: "pending" | "applied" | "failed" | "reverted";
  requested_by: string; ts: string;
}
export interface IncidentDetail extends Incident {
  summary: string; summary_src: "template" | "llm"; narrative: Narrative | null; actor: ActorSummary; findings: Finding[];
  iocs: IOC[]; actions: ResponseAction[]; notes: { author: string; body: string; ts: string }[];
  recommended_actions: { action: string; target: string; why: string }[];
}

export interface Honeytoken {
  token_id: string; kind: string; planted_at: string; sensitivity: number; burned: boolean;
  hits_seen: number; hits_used: number; last_hit: string | null;
}
export interface Sensor { sensor_id: string; service: Service; version: string; last_seen: string | null; status: "ok" | "silent" | "unknown"; }

// ---- Response shapes described in the 04 §B endpoint table (not in the type block above) ----
export interface Page<T> { items: T[]; next_cursor: string | null; }
export interface TimeseriesPoint { t: string; v: number; }
export interface TechniqueCount { technique: string; name: string; tactic: string; count: number; }
export interface MazeMessage { actor_id: string; node_id: string; state: "visible" | "visited"; reason: string; }
export interface NarrativeMessage { kind: "actor" | "incident"; ref_id: string; narrative: Narrative; }
export interface FeedbackResult { feedback_id: number; old_risk: number; new_risk: number; weights_version: number; }
export interface ApiError { error: { code: string; message: string } }
export type ResponseActionName = "block_ip" | "unblock_ip" | "kill_session" | "rotate_token";
