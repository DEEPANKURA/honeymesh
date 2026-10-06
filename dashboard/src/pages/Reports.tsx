import { useState } from "react";
import type { ReactNode } from "react";
import { api, getToken, type Attacker, type Paged } from "../lib/api";
import { usePoll } from "../lib/live";
import { Empty, ErrorBox, JsonBlock, Loading, RiskBadge } from "../components/ui";

interface ReportPayload {
  attacker_id?: string;
  generated_at?: string;
  [key: string]: unknown;
}

export function ReportsPage(): ReactNode {
  const attackers = usePoll<Paged<Attacker>>(
    () => api<Paged<Attacker>>("/attackers?limit=200"),
    8000,
  );
  const [selected, setSelected] = useState("");
  const [report, setReport] = useState<ReportPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const generate = async (format: "json" | "html") => {
    if (!selected) return;
    setError(null);
    setLoading(true);
    try {
      if (format === "html") {
        const response = await fetch(
          `/api/v1/reports/${encodeURIComponent(selected)}?format=html`,
          { headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {} },
        );
        if (!response.ok) throw new Error(await response.text());
        const html = await response.text();
        const blob = new Blob([html], { type: "text/html" });
        window.open(URL.createObjectURL(blob), "_blank", "noopener");
      } else {
        const payload = await api<ReportPayload>(
          `/reports/${encodeURIComponent(selected)}?format=json`,
        );
        setReport(payload);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Reports</h1>
          <div className="page-sub">
            generated engagement reports - json for tooling, html for sharing
          </div>
        </div>
        <div className="controls">
          <select
            className="select"
            value={selected}
            onChange={(event) => {
              setSelected(event.target.value);
              setReport(null);
            }}
          >
            <option value="">select attacker</option>
            {(attackers.data?.items ?? []).map((attacker) => (
              <option key={attacker.attacker_id} value={attacker.attacker_id}>
                {attacker.attacker_id} · {attacker.source_ip} · {attacker.risk_band}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn primary"
            disabled={!selected || loading}
            onClick={() => void generate("json")}
          >
            json
          </button>
          <button
            type="button"
            className="btn"
            disabled={!selected || loading}
            onClick={() => void generate("html")}
          >
            html
          </button>
        </div>
      </div>

      {error ? <ErrorBox text={error} /> : null}
      {attackers.loading && !attackers.data ? <Loading /> : null}
      {(attackers.data?.items.length ?? 0) === 0 && !attackers.loading ? (
        <Empty text="no attackers to report on yet" />
      ) : null}

      {loading ? <Loading text="generating" /> : null}
      {report ? (
        <div className="card">
          <h3>report preview</h3>
          <JsonBlock data={report} />
        </div>
      ) : null}

      <div className="card" style={{ marginTop: 14 }}>
        <h3>available subjects</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>attacker</th>
                <th>source ip</th>
                <th>risk</th>
                <th>events</th>
              </tr>
            </thead>
            <tbody>
              {(attackers.data?.items ?? []).map((attacker) => (
                <tr key={attacker.attacker_id}>
                  <td className="mono">{attacker.attacker_id}</td>
                  <td className="mono">{attacker.source_ip}</td>
                  <td>
                    <RiskBadge band={attacker.risk_band} score={attacker.risk_score} />
                  </td>
                  <td className="mono">{attacker.event_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
