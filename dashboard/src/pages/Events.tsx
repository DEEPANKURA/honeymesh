import { useState } from "react";
import type { ReactNode } from "react";
import { api, type Paged, type SecurityEvent } from "../lib/api";
import { usePoll } from "../lib/live";
import {
  Empty,
  ErrorBox,
  JsonBlock,
  Loading,
  SeverityBadge,
  formatTime,
} from "../components/ui";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const SENSORS = ["", "honeyssh", "honeyweb", "honeynet"];

export function EventsPage(): ReactNode {
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [severity, setSeverity] = useState("");
  const [sensor, setSensor] = useState("");
  const [eventType, setEventType] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (severity) query.set("severity", severity);
  if (sensor) query.set("sensor", sensor);
  if (eventType) query.set("event_type", eventType);

  const events = usePoll<Paged<SecurityEvent>>(
    () => api<Paged<SecurityEvent>>(`/events?${query.toString()}`),
    4000,
  );

  const detail = events.data?.items.find((item) => item.event_id === selected) ?? null;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Events</h1>
          <div className="page-sub">normalized telemetry from every sensor surface</div>
        </div>
        <div className="controls">
          <select
            className="select"
            value={sensor}
            onChange={(event) => {
              setSensor(event.target.value);
              setOffset(0);
            }}
          >
            {SENSORS.map((value) => (
              <option key={value} value={value}>
                {value === "" ? "all sensors" : value}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              setOffset(0);
            }}
          >
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value === "" ? "all severities" : value}
              </option>
            ))}
          </select>
          <input
            className="input"
            placeholder="event type"
            value={eventType}
            onChange={(event) => {
              setEventType(event.target.value);
              setOffset(0);
            }}
          />
          <button type="button" className="btn" onClick={events.refresh}>
            refresh
          </button>
        </div>
      </div>

      {events.error ? <ErrorBox text={events.error} /> : null}
      {events.loading && !events.data ? <Loading /> : null}

      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>time</th>
                <th>severity</th>
                <th>sensor</th>
                <th>event</th>
                <th>source ip</th>
                <th>attacker</th>
                <th>session</th>
              </tr>
            </thead>
            <tbody>
              {(events.data?.items ?? []).map((event) => (
                <tr
                  key={event.event_id}
                  className="clickable"
                  onClick={() =>
                    setSelected((current) => (current === event.event_id ? null : event.event_id))
                  }
                >
                  <td className="mono nowrap">{formatTime(event.timestamp)}</td>
                  <td>
                    <SeverityBadge severity={event.severity} />
                  </td>
                  <td className="mono">{event.sensor}</td>
                  <td className="mono">{event.event_type}</td>
                  <td className="mono">{event.source_ip}</td>
                  <td className="mono muted">{event.attacker_id ?? "-"}</td>
                  <td className="mono muted">{event.session_id ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(events.data?.items.length ?? 0) === 0 && !events.loading ? (
          <Empty text="no events match these filters" />
        ) : null}

        <div className="pager">
          <button
            type="button"
            className="btn"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - limit))}
          >
            previous
          </button>
          <button
            type="button"
            className="btn"
            disabled={offset + limit >= (events.data?.total ?? 0)}
            onClick={() => setOffset(offset + limit)}
          >
            next
          </button>
          <span>
            {offset + 1}-{Math.min(offset + limit, events.data?.total ?? 0)} of{" "}
            {events.data?.total ?? 0}
          </span>
          <select
            className="select"
            value={limit}
            onChange={(event) => {
              setLimit(Number(event.target.value));
              setOffset(0);
            }}
          >
            {[25, 50, 100, 250].map((value) => (
              <option key={value} value={value}>
                {value} per page
              </option>
            ))}
          </select>
        </div>
      </div>

      {detail ? (
        <div className="card" style={{ marginTop: 14 }}>
          <h3>event {detail.event_id}</h3>
          <JsonBlock data={detail} />
        </div>
      ) : null}
    </>
  );
}
