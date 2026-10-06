export const TOKEN_KEY = "honeymesh.token";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(token: string): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`/api/v1${path}`, { ...init, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: string };
      if (payload.detail) detail = payload.detail;
    } catch {
      /* body was not json */
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export interface Paged<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  attacker_id: string | null;
  source_ip: string;
  sensor: string;
  event_type: string;
  severity: Severity;
  session_id: string | null;
  metadata: Record<string, unknown>;
}

export interface Attacker {
  attacker_id: string;
  source_ip: string;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  risk_band: string;
  current_stage: string;
  status: string;
  event_count: number;
}

export interface AttackerDetail extends Attacker {
  stage_order: string[];
  live_scores: Record<string, number>;
  latest_behavior: Record<string, number>;
}

export interface BehaviorPoint {
  timestamp: string;
  [behavior: string]: string | number;
}

export interface TimelineEntry {
  kind: "event" | "deception";
  timestamp: string;
  label: string;
  severity: Severity | string;
  detail: Record<string, unknown>;
}

export interface DeceptionAction {
  id: string;
  attacker_id: string;
  timestamp: string;
  policy: string;
  action: string;
  target: string | null;
  reason: string;
  confidence: number;
  previous_state: string;
  new_state: string;
}

export interface Decoy {
  name: string;
  type: string;
  port: number;
  deception_level: number;
  active: boolean;
  status: string;
  activated_at: string | null;
}

export interface DeceptionState {
  level: number;
  active_decoys: string[];
  strategy: string;
  telemetry_level: string;
  flags: string[];
  applied_actions: string[];
  updated_at: string;
  adaptive_mode: boolean;
  max_level: number;
  cooldown_seconds: number;
}

export interface Overview {
  total_events: number;
  total_attackers: number;
  high_risk_attackers: number;
  active_decoys: string[];
  open_sessions: number;
  deception_level: number;
  deception_strategy: string;
  telemetry_level: string;
  engagement_score: number | null;
  uptime_seconds: number;
  adaptive_mode: boolean;
}

export interface Metrics {
  events_received_total: number;
  events_emitted_by_sensor: number;
  events_processed_total: number;
  active_attackers: number;
  active_decoys: number;
  deception_actions_total: number;
  profiles_in_memory: number;
  uptime_seconds: number;
  websocket_subscribers: number;
}

export interface Engagement {
  attacker_id: string;
  engagement_score: number;
  components: Record<string, number>;
  weights: Record<string, number>;
  raw: Record<string, number>;
  totals: { events: number; suspicious_events: number; deception_actions: number };
  formula: string;
}

export interface LiveMessage {
  type: string;
  data: Record<string, unknown>;
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}
