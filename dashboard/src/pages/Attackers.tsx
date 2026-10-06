import type { ReactNode } from "react";
import {
  api,
  type Attacker,
  type AttackerDetail,
  type BehaviorPoint,
  type DeceptionAction,
  type Engagement,
  type Paged,
  type TimelineEntry,
} from "../lib/api";
import { usePoll } from "../lib/live";
import { matchRoute, useRoute } from "../lib/router";
import {
  Bar,
  Empty,
  ErrorBox,
  Loading,
  RiskBadge,
  SeverityBadge,
  StageBadge,
  formatTime,
} from "../components/ui";

export function AttackersPage(): ReactNode {
  const [path] = useRoute();
  const detailMatch = matchRoute("/attackers/:id", path);
  if (detailMatch) return <AttackerDetailPage id={detailMatch.id} />;
  return <AttackerList />;
}

function AttackerList(): ReactNode {
  const [path, navigate] = useRoute();
  const attackers = usePoll<Paged<Attacker>>(
    () => api<Paged<Attacker>>("/attackers?limit=200"),
    5000,
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Attackers</h1>
          <div className="page-sub">
            profiled by source ip - behavior scores, kill-chain stage and risk band
          </div>
        </div>
        <div className="controls">
          <button type="button" className="btn" onClick={attackers.refresh}>
            refresh
          </button>
        </div>
      </div>

      {attackers.error ? <ErrorBox text={attackers.error} /> : null}
      {attackers.loading && !attackers.data ? <Loading /> : null}

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>attacker</th>
                <th>source ip</th>
                <th>risk</th>
                <th>stage</th>
                <th>events</th>
                <th>status</th>
                <th>last seen</th>
              </tr>
            </thead>
            <tbody>
              {(attackers.data?.items ?? []).map((attacker) => (
                <tr
                  key={attacker.attacker_id}
                  className="clickable"
                  onClick={() => navigate(`${path.replace(/\/$/, "")}/${attacker.attacker_id}`)}
                >
                  <td className="mono">{attacker.attacker_id}</td>
                  <td className="mono">{attacker.source_ip}</td>
                  <td>
                    <RiskBadge band={attacker.risk_band} score={attacker.risk_score} />
                  </td>
                  <td>
                    <StageBadge stage={attacker.current_stage} />
                  </td>
                  <td className="mono">{attacker.event_count}</td>
                  <td className="muted">{attacker.status}</td>
                  <td className="mono nowrap muted">{formatTime(attacker.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(attackers.data?.items.length ?? 0) === 0 && !attackers.loading ? (
          <Empty text="no attackers profiled yet - run scripts/attack_simulator.py" />
        ) : null}
      </div>
    </>
  );
}

function AttackerDetailPage({ id }: { id: string }): ReactNode {
  const [, navigate] = useRoute();
  const detail = usePoll<AttackerDetail>(() => api<AttackerDetail>(`/attackers/${id}`), 5000);
  const behavior = usePoll<{ live_scores: Record<string, number>; history: BehaviorPoint[] }>(
    () => api(`/attackers/${id}/behavior`),
    6000,
  );
  const timeline = usePoll<{ items: TimelineEntry[] }>(
    () => api(`/attackers/${id}/timeline?limit=80`),
    6000,
  );
  const engagement = usePoll<Engagement>(() => api(`/attackers/${id}/engagement`), 8000);
  const actions = usePoll<{ items: DeceptionAction[] }>(
    () => api(`/deception/actions?attacker_id=${encodeURIComponent(id)}&limit=50`),
    8000,
  );

  if (detail.error && detail.error.includes("not found")) {
    return (
      <>
        <ErrorBox text={`attacker ${id} not found`} />
        <button type="button" className="btn" onClick={() => navigate("/attackers")}>
          back
        </button>
      </>
    );
  }
  if (detail.loading && !detail.data) return <Loading />;

  const attacker = detail.data;
  const scores = behavior.data?.live_scores ?? attacker?.live_scores ?? {};
  const stageOrder = attacker?.stage_order ?? [];
  const currentStage = attacker?.current_stage ?? "UNKNOWN";

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title mono">{id}</h1>
          <div className="page-sub">
            {attacker?.source_ip} · {attacker?.event_count} events · first seen{" "}
            {formatTime(attacker?.first_seen)}
          </div>
        </div>
        <div className="controls">
          <RiskBadge band={attacker?.risk_band ?? "LOW"} score={attacker?.risk_score} />
          <button type="button" className="btn" onClick={() => navigate("/attackers")}>
            back
          </button>
        </div>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h3>kill chain stage</h3>
          <div className="stage-ladder">
            {stageOrder.map((stage) => {
              const index = stageOrder.indexOf(stage);
              const currentIndex = stageOrder.indexOf(currentStage);
              const cls = stage === currentStage ? "current" : index < currentIndex ? "done" : "";
              return (
                <span className={`stage ${cls}`} key={stage}>
                  {stage}
                </span>
              );
            })}
          </div>

          <h3 style={{ marginTop: 18 }}>behavior scores (live)</h3>
          {Object.keys(scores).length === 0 ? (
            <Empty text="no scores yet" />
          ) : (
            Object.entries(scores)
              .sort((a, b) => b[1] - a[1])
              .map(([name, value]) => <Bar key={name} label={name} value={value} />))}
        </div>

        <div className="card">
          <h3>engagement</h3>
          {engagement.loading && !engagement.data ? <Loading /> : null}
          {engagement.data ? (
            <>
              <div className="stat-value">{engagement.data.engagement_score}</div>
              <div className="stat-label">lab engagement score / 100</div>
              <div style={{ marginTop: 12 }}>
                {Object.entries(engagement.data.components).map(([name, value]) => (
                  <Bar key={name} label={name} value={value} />
                ))}
              </div>
              <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
                {engagement.data.formula}
              </div>
            </>
          ) : null}

          <h3 style={{ marginTop: 18 }}>totals</h3>
          <dl className="kv">
            <dt>events</dt>
            <dd>{engagement.data?.totals.events ?? "-"}</dd>
            <dt>suspicious events</dt>
            <dd>{engagement.data?.totals.suspicious_events ?? "-"}</dd>
            <dt>deception actions</dt>
            <dd>{engagement.data?.totals.deception_actions ?? "-"}</dd>
          </dl>
        </div>
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h3>timeline</h3>
          {timeline.loading && !timeline.data ? <Loading /> : null}
          {(timeline.data?.items.length ?? 0) === 0 ? (
            <Empty text="no timeline entries" />
          ) : (
            <div className="feed">
              {(timeline.data?.items ?? []).map((entry, index) => (
                <div className="feed-item" key={`${entry.timestamp}-${index}`}>
                  <span className="mono muted">{formatTime(entry.timestamp)}</span>
                  <span>
                    {entry.label}
                    {entry.kind === "deception" ? (
                      <span className="badge live" style={{ marginLeft: 6 }}>
                        deception
                      </span>
                    ) : null}
                  </span>
                  <SeverityBadge severity={entry.severity} />
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <h3>deception actions</h3>
          {actions.loading && !actions.data ? <Loading /> : null}
          {(actions.data?.items.length ?? 0) === 0 ? (
            <Empty text="engine has not acted on this attacker yet" />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>time</th>
                    <th>policy</th>
                    <th>action</th>
                    <th>target</th>
                    <th>conf</th>
                  </tr>
                </thead>
                <tbody>
                  {(actions.data?.items ?? []).map((action) => (
                    <tr key={action.id}>
                      <td className="mono nowrap">{formatTime(action.timestamp)}</td>
                      <td className="mono">{action.policy}</td>
                      <td className="mono">{action.action}</td>
                      <td className="mono">{action.target ?? "-"}</td>
                      <td className="mono">{action.confidence.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
