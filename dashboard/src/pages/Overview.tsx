import { useState } from "react";
import type { ReactNode } from "react";
import {
  api,
  type LiveMessage,
  type Metrics,
  type Overview,
  type SecurityEvent,
} from "../lib/api";
import { useLive, usePoll } from "../lib/live";
import {
  Empty,
  ErrorBox,
  Loading,
  SeverityBadge,
  StatCard,
  formatDuration,
} from "../components/ui";

function feedLabel(message: LiveMessage): { time: string; text: string; severity: string } | null {
  const data = message.data;
  if (message.type === "security_event") {
    const event = data as unknown as SecurityEvent;
    return {
      time: new Date(event.timestamp).toLocaleTimeString(),
      text: `${event.sensor}/${event.event_type} · ${event.source_ip}`,
      severity: event.severity,
    };
  }
  if (message.type === "attacker_updated") {
    const attacker = data as unknown as { source_ip?: string; risk_band?: string };
    return {
      time: new Date().toLocaleTimeString(),
      text: `attacker ${attacker.source_ip ?? "?"} → ${attacker.risk_band ?? "updated"}`,
      severity: attacker.risk_band?.toLowerCase() ?? "info",
    };
  }
  if (message.type === "behavior_changed") {
    const payload = data as unknown as { attacker_id?: string };
    return {
      time: new Date().toLocaleTimeString(),
      text: `behavior update · ${payload.attacker_id ?? ""}`,
      severity: "info",
    };
  }
  return null;
}

export function OverviewPage(): ReactNode {
  const overview = usePoll<Overview>(() => api<Overview>("/overview"), 5000);
  const metrics = usePoll<Metrics>(() => api<Metrics>("/metrics"), 5000);
  const [feed, setFeed] = useState<{ id: string; time: string; text: string; severity: string }[]>(
    [],
  );

  useLive((message) => {
    const entry = feedLabel(message);
    if (!entry) return;
    setFeed((current) =>
      [{ id: `${Date.now()}-${Math.random()}`, ...entry }, ...current].slice(0, 60),
    );
  });

  if (overview.error?.includes("authentication")) {
    return <ErrorBox text="authentication required" />;
  }
  if (overview.loading && !overview.data) return <Loading />;

  const data = overview.data;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Overview</h1>
          <div className="page-sub">
            live posture of the honeynet, adaptive engine and deception surface
          </div>
        </div>
        <div className="controls">
          {overview.error ? <span className="badge critical">refresh failed</span> : null}
          <button type="button" className="btn" onClick={overview.refresh}>
            refresh
          </button>
        </div>
      </div>

      {overview.error ? <ErrorBox text={overview.error} /> : null}

      <div className="grid cols-4" style={{ marginBottom: 14 }}>
        <StatCard label="events processed" value={data?.total_events ?? 0} hint="persisted" />
        <StatCard label="attackers tracked" value={data?.total_attackers ?? 0} hint="profiles" />
        <StatCard
          label="high risk"
          value={data?.high_risk_attackers ?? 0}
          hint="high + critical bands"
        />
        <StatCard
          label="active decoys"
          value={data?.active_decoys.length ?? 0}
          hint={data?.active_decoys.join(", ") || "none live"}
        />
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h3>Adaptive deception engine</h3>
          <dl className="kv">
            <dt>deception level</dt>
            <dd>
              {data?.deception_level ?? "-"} / {data ? 5 : "-"}
            </dd>
            <dt>strategy</dt>
            <dd>{data?.deception_strategy ?? "-"}</dd>
            <dt>telemetry level</dt>
            <dd>{data?.telemetry_level ?? "-"}</dd>
            <dt>adaptive mode</dt>
            <dd>{data?.adaptive_mode ? "enabled" : "manual"}</dd>
            <dt>engagement score</dt>
            <dd>{data?.engagement_score ?? "-"}</dd>
            <dt>uptime</dt>
            <dd>{formatDuration(data?.uptime_seconds ?? 0)}</dd>
          </dl>
        </div>

        <div className="card">
          <h3>Pipeline metrics</h3>
          <dl className="kv">
            <dt>events received</dt>
            <dd>{metrics.data?.events_received_total ?? "-"}</dd>
            <dt>sensor emitted</dt>
            <dd>{metrics.data?.events_emitted_by_sensor ?? "-"}</dd>
            <dt>deception actions</dt>
            <dd>{metrics.data?.deception_actions_total ?? "-"}</dd>
            <dt>profiles in memory</dt>
            <dd>{metrics.data?.profiles_in_memory ?? "-"}</dd>
            <dt>open sessions</dt>
            <dd>{data?.open_sessions ?? "-"}</dd>
            <dt>ws subscribers</dt>
            <dd>{metrics.data?.websocket_subscribers ?? "-"}</dd>
          </dl>
        </div>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <h3>Live event stream</h3>
        {feed.length === 0 ? (
          <Empty text="waiting for events - drive traffic with scripts/attack_simulator.py" />
        ) : (
          <div className="feed">
            {feed.map((item) => (
              <div className="feed-item" key={item.id}>
                <span className="mono muted">{item.time}</span>
                <span>{item.text}</span>
                <SeverityBadge severity={item.severity} />
              </div>
            ))}
          </div>
        )}
      </div>

      <RiskSummary />
    </>
  );
}

function RiskSummary(): ReactNode {
  const attackers = usePoll(() => api<{ items: { risk_band: string }[] }>("/attackers?limit=500"), 8000);
  const bands: Record<string, number> = {};
  for (const item of attackers.data?.items ?? []) {
    bands[item.risk_band] = (bands[item.risk_band] ?? 0) + 1;
  }
  const total = Object.values(bands).reduce((sum, value) => sum + value, 0);
  return (
    <div className="card" style={{ marginTop: 14 }}>
      <h3>Risk distribution</h3>
      {total === 0 ? (
        <Empty text="no attackers profiled yet" />
      ) : (
        <>
          {["CRITICAL", "HIGH", "MODERATE", "LOW"].map((band) => (
            <div className="bar-row" key={band}>
              <span className="muted">{band}</span>
              <span className="bar-track">
                <span
                  className="bar-fill"
                  style={{ width: `${(((bands[band] ?? 0) / total) * 100).toFixed(1)}%` }}
                />
              </span>
              <span className="mono" style={{ textAlign: "right" }}>
                {bands[band] ?? 0}
              </span>
            </div>
          ))}
          <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            {total} attacker profiles tracked
          </div>
        </>
      )}
    </div>
  );
}
