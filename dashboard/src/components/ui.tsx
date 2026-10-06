import type { ReactNode } from "react";

export function bandClass(band: string): string {
  const normalized = band.toLowerCase();
  if (normalized === "moderate") return "moderate";
  if (["info", "low", "unknown"].includes(normalized)) return "info";
  if (["critical", "high", "medium"].includes(normalized)) return normalized;
  return "neutral";
}

export function RiskBadge({ band, score }: { band: string; score?: number }): ReactNode {
  return (
    <span className={`badge ${bandClass(band)}`}>
      {band}
      {score === undefined ? "" : ` ${score.toFixed(2)}`}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }): ReactNode {
  return <span className={`badge ${bandClass(severity)}`}>{severity}</span>;
}

export function StageBadge({ stage }: { stage: string }): ReactNode {
  return <span className="badge live">{stage}</span>;
}

export function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}): ReactNode {
  return (
    <div className="card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint ? <div className="stat-delta">{hint}</div> : null}
    </div>
  );
}

export function Bar({ label, value }: { label: string; value: number }): ReactNode {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="bar-row">
      <span className="muted">{label}</span>
      <span className="bar-track">
        <span className="bar-fill" style={{ width: `${pct.toFixed(1)}%` }} />
      </span>
      <span className="mono" style={{ textAlign: "right" }}>
        {value.toFixed(2)}
      </span>
    </div>
  );
}

export function Empty({ text }: { text: string }): ReactNode {
  return <div className="empty">{text}</div>;
}

export function Loading({ text = "loading" }: { text?: string }): ReactNode {
  return (
    <div className="empty">
      <span className="spinner" /> {text}
    </div>
  );
}

export function ErrorBox({ text }: { text: string }): ReactNode {
  return <div className="alert">{text}</div>;
}

export function JsonBlock({ data }: { data: unknown }): ReactNode {
  return <pre className="json">{JSON.stringify(data, null, 2)}</pre>;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}
