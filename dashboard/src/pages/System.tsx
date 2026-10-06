import type { ReactNode } from "react";
import { api, type Metrics, type Overview } from "../lib/api";
import { usePoll } from "../lib/live";
import { ErrorBox, Loading, StatCard, formatDuration } from "../components/ui";

export function SystemPage(): ReactNode {
  const metrics = usePoll<Metrics>(() => api<Metrics>("/metrics"), 4000);
  const overview = usePoll<Overview>(() => api<Overview>("/overview"), 6000);

  if (metrics.error || overview.error) {
    return <ErrorBox text={metrics.error ?? overview.error ?? "error"} />;
  }
  if (!metrics.data || !overview.data) return <Loading />;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">System</h1>
          <div className="page-sub">runtime counters exported by the API</div>
        </div>
        <div className="controls">
          <button
            type="button"
            className="btn"
            onClick={() => {
              metrics.refresh();
              overview.refresh();
            }}
          >
            refresh
          </button>
        </div>
      </div>

      <div className="grid cols-4">
        <StatCard
          label="uptime"
          value={formatDuration(metrics.data.uptime_seconds)}
          hint="since process start"
        />
        <StatCard
          label="events received"
          value={metrics.data.events_received_total}
          hint="collector accepted"
        />
        <StatCard
          label="events persisted"
          value={metrics.data.events_processed_total}
          hint="database rows"
        />
        <StatCard
          label="sensor emitted"
          value={metrics.data.events_emitted_by_sensor}
          hint="raw emissions"
        />
        <StatCard
          label="deception actions"
          value={metrics.data.deception_actions_total}
          hint="engine decisions"
        />
        <StatCard
          label="profiles in memory"
          value={metrics.data.profiles_in_memory}
          hint="live attacker profiles"
        />
        <StatCard
          label="ws subscribers"
          value={metrics.data.websocket_subscribers}
          hint="dashboard streams"
        />
        <StatCard
          label="active decoys"
          value={metrics.data.active_decoys}
          hint="deception assets live"
        />
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <h3>posture</h3>
        <dl className="kv">
          <dt>adaptive mode</dt>
          <dd>{overview.data.adaptive_mode ? "enabled" : "manual"}</dd>
          <dt>deception strategy</dt>
          <dd>{overview.data.deception_strategy}</dd>
          <dt>telemetry level</dt>
          <dd>{overview.data.telemetry_level}</dd>
          <dt>open sessions</dt>
          <dd>{overview.data.open_sessions}</dd>
          <dt>attackers (high risk)</dt>
          <dd>
            {overview.data.total_attackers} / {overview.data.high_risk_attackers} high
          </dd>
        </dl>
      </div>
    </>
  );
}
