import { useState } from "react";
import type { ReactNode } from "react";
import {
  api,
  isApiError,
  requestLogin,
  type Decoy,
  type DeceptionAction,
  type DeceptionState,
  type Paged,
} from "../lib/api";
import { usePoll } from "../lib/live";
import { Empty, ErrorBox, Loading, formatTime } from "../components/ui";

function stateLabel(value: unknown): string {
  if (value && typeof value === "object") {
    const snapshot = value as { level?: number; strategy?: string };
    return `L${snapshot.level ?? "?"}/${snapshot.strategy ?? "-"}`;
  }
  if (value === null || value === undefined || value === "") return "-";
  return String(value);
}

export function DeceptionPage(): ReactNode {
  const state = usePoll<DeceptionState>(() => api<DeceptionState>("/deception/state"), 5000);
  const decoys = usePoll<{ items: Decoy[]; total: number }>(
    () => api("/deception/decoys"),
    5000,
  );
  const actions = usePoll<Paged<DeceptionAction>>(
    () => api<Paged<DeceptionAction>>("/deception/actions?limit=100"),
    6000,
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const toggle = async (decoy: Decoy) => {
    setBusy(decoy.name);
    setError(null);
    try {
      await api(`/deception/decoys/${encodeURIComponent(decoy.name)}/${
        decoy.active ? "deactivate" : "activate"
      }`, { method: "POST" });
      decoys.refresh();
      state.refresh();
    } catch (err) {
      if (isApiError(err) && err.status === 401) {
        setError("admin sign-in required for decoy changes");
        requestLogin();
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Deception</h1>
          <div className="page-sub">
            adaptive state, decoy inventory and the action log of the engine
          </div>
        </div>
        <div className="controls">
          <button type="button" className="btn" onClick={() => { state.refresh(); decoys.refresh(); actions.refresh(); }}>
            refresh
          </button>
        </div>
      </div>

      {error ? <ErrorBox text={error} /> : null}
      {state.error ? <ErrorBox text={state.error} /> : null}

      <div className="grid cols-4">
        <div className="card">
          <div className="stat-label">deception level</div>
          <div className="stat-value">
            {state.data?.level ?? "-"}
            <span className="muted" style={{ fontSize: 15 }}>
              {" "}
              / {state.data?.max_level ?? 5}
            </span>
          </div>
          <div className="stat-delta">cooldown {state.data?.cooldown_seconds ?? "-"}s</div>
        </div>
        <div className="card">
          <div className="stat-label">strategy</div>
          <div className="stat-value" style={{ fontSize: 21 }}>
            {state.data?.strategy ?? "-"}
          </div>
          <div className="stat-delta">
            {state.data?.adaptive_mode ? "adaptive engine on" : "manual"}
          </div>
        </div>
        <div className="card">
          <div className="stat-label">telemetry level</div>
          <div className="stat-value" style={{ fontSize: 21 }}>
            {state.data?.telemetry_level ?? "-"}
          </div>
          <div className="stat-delta">sensor verbosity</div>
        </div>
        <div className="card">
          <div className="stat-label">active decoys</div>
          <div className="stat-value">{state.data?.active_decoys.length ?? "-"}</div>
          <div className="stat-delta">
            {state.data?.active_decoys.join(", ") || "none active"}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <h3>decoy inventory</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>name</th>
                <th>type</th>
                <th>port</th>
                <th>level</th>
                <th>status</th>
                <th>activated at</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(decoys.data?.items ?? []).map((decoy) => (
                <tr key={decoy.name}>
                  <td className="mono">{decoy.name}</td>
                  <td className="mono">{decoy.type}</td>
                  <td className="mono">{decoy.port}</td>
                  <td className="mono">{decoy.deception_level}</td>
                  <td>
                    <span className={`badge ${decoy.active ? "low" : "neutral"}`}>
                      {decoy.status}
                    </span>
                  </td>
                  <td className="mono nowrap">{formatTime(decoy.activated_at)}</td>
                  <td>
                    <button
                      type="button"
                      className={`btn ${decoy.active ? "danger" : "primary"}`}
                      disabled={busy === decoy.name}
                      onClick={() => void toggle(decoy)}
                    >
                      {decoy.active ? "deactivate" : "activate"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {decoys.loading && !decoys.data ? <Loading /> : null}
        {(decoys.data?.items.length ?? 0) === 0 && !decoys.loading ? (
          <Empty text="no decoys registered" />
        ) : null}
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <h3>action log</h3>
        {actions.loading && !actions.data ? <Loading /> : null}
        {(actions.data?.items.length ?? 0) === 0 && !actions.loading ? (
          <Empty text="no deception actions applied yet" />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>time</th>
                  <th>attacker</th>
                  <th>policy</th>
                  <th>action</th>
                  <th>target</th>
                  <th>reason</th>
                  <th>state</th>
                </tr>
              </thead>
              <tbody>
                {(actions.data?.items ?? []).map((action) => (
                  <tr key={action.id}>
                    <td className="mono nowrap">{formatTime(action.timestamp)}</td>
                    <td className="mono">
                      <a href={`#/attackers/${action.attacker_id}`}>{action.attacker_id}</a>
                    </td>
                    <td className="mono">{action.policy}</td>
                    <td className="mono">{action.action}</td>
                    <td className="mono">{action.target ?? "-"}</td>
                    <td className="muted">{action.reason}</td>
                    <td className="mono muted">
                      {stateLabel(action.previous_state)} → {stateLabel(action.new_state)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
