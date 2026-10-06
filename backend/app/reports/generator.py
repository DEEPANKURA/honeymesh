from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from typing import Any

from app.database.repository import Repository
from app.metrics import engagement_metrics

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def build_report(repository: Repository, attacker_id: str) -> dict[str, Any] | None:
    attacker = await repository.get_attacker(attacker_id)
    if attacker is None:
        return None
    events, total = await repository.list_events(limit=10000, attacker_id=attacker_id)
    actions = await repository.list_deception_actions(limit=1000, attacker_id=attacker_id)
    behavior_history = await repository.behavior_history(attacker_id, limit=500)
    latest = behavior_history[0] if behavior_history else {}
    engagement = await engagement_metrics(repository, attacker_id)

    ordered = sorted(events, key=lambda item: item["timestamp"])
    start = ordered[0]["timestamp"] if ordered else attacker["first_seen"]
    end = ordered[-1]["timestamp"] if ordered else attacker["last_seen"]

    usernames = sorted(
        {
            str(event["metadata"].get("username"))
            for event in events
            if event["metadata"].get("username")
        }
    )
    paths = sorted(
        {str(event["metadata"].get("path")) for event in events if event["metadata"].get("path")}
    )
    commands = [
        str(event["metadata"].get("command"))
        for event in events
        if event["metadata"].get("command")
    ][:50]
    sensors = sorted({event["sensor"] for event in events})
    event_types = sorted({event["event_type"] for event in events})

    triggered = sorted(
        name for name, value in latest.items() if isinstance(value, float) and value >= 0.5
    )

    report: dict[str, Any] = {
        "case": {
            "report_id": f"RPT-{attacker_id}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
            "title": f"HoneyMesh investigation report - {attacker_id}",
            "generated_at": datetime.now(UTC).isoformat(),
            "environment": "isolated lab (synthetic data only)",
        },
        "period": {"start": start, "end": end, "duration_events": total},
        "attacker": attacker,
        "timeline": [
            {
                "timestamp": event["timestamp"],
                "sensor": event["sensor"],
                "event_type": event["event_type"],
                "severity": event["severity"],
                "metadata": event["metadata"],
            }
            for event in ordered[:500]
        ],
        "behavioral_classification": {
            "current_stage": attacker["current_stage"],
            "latest_scores": latest,
            "triggered_behaviors": triggered,
            "history_points": len(behavior_history),
        },
        "risk": {
            "risk_score": attacker["risk_score"],
            "risk_band": attacker["risk_band"],
            "event_count": attacker["event_count"],
        },
        "deception_changes": actions,
        "decoy_interactions": [
            event
            for event in events
            if event["event_type"]
            in {"asset_access", "credential_harvest", "session_command", "authentication_success"}
        ],
        "engagement": engagement,
        "indicators": {
            "source_ip": attacker["source_ip"],
            "usernames": usernames,
            "paths": paths,
            "commands": commands,
            "sensors_touched": sensors,
            "event_types": event_types,
        },
        "summary": _summary(attacker, triggered, actions, engagement),
    }
    return report


def _summary(
    attacker: dict[str, Any],
    triggered: list[str],
    actions: list[dict[str, Any]],
    engagement: dict[str, Any],
) -> str:
    behaviors = ", ".join(triggered) if triggered else "none above threshold"
    return (
        f"Source {attacker['source_ip']} ({attacker['attacker_id']}) generated "
        f"{attacker['event_count']} events and reached stage {attacker['current_stage']} "
        f"with risk {attacker['risk_score']} ({attacker['risk_band']}). "
        f"Behaviors above threshold: {behaviors}. "
        f"HoneyMesh applied {len(actions)} deception action(s). "
        f"Engagement score: {engagement['engagement_score']}/100. "
        "All data is synthetic and confined to the isolated lab."
    )


def render_html(report: dict[str, Any]) -> str:
    def esc(value: object) -> str:
        return html.escape(str(value))

    case = report["case"]
    attacker = report["attacker"]
    risk = report["risk"]
    behavior = report["behavioral_classification"]
    engagement = report["engagement"]

    timeline_rows = "".join(
        f"<tr><td>{esc(item['timestamp'])}</td><td>{esc(item['sensor'])}</td>"
        f"<td>{esc(item['event_type'])}</td><td>{esc(item['severity'])}</td></tr>"
        for item in report["timeline"][:200]
    )
    action_rows = "".join(
        f"<tr><td>{esc(item['timestamp'])}</td><td>{esc(item['policy'])}</td>"
        f"<td>{esc(item['action'])}</td><td>{esc(item['target'])}</td>"
        f"<td>{esc(item['reason'])}</td></tr>"
        for item in report["deception_changes"]
    )
    indicator_items = "".join(
        f"<li>{esc(username)}</li>" for username in report["indicators"]["usernames"][:30]
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(case["title"])}</title>
<style>
body {{ font-family: Georgia, serif; margin: 2rem auto; max-width: 60rem; color: #1b1b1b; }}
h1, h2 {{ color: #123; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: .4rem .5rem; font-size: .9rem; text-align: left; }}
th {{ background: #eef2f7; }}
.meta {{ color: #555; }}
.badge {{ display: inline-block; padding: .15rem .5rem; border-radius: .3rem;
background: #123; color: #fff; font-size: .8rem; }}
</style></head><body>
<h1>{esc(case["title"])}</h1>
<p class="meta">Report {esc(case["report_id"])} - generated {esc(case["generated_at"])}<br>
{esc(case["environment"])}</p>

<h2>1. Case information</h2>
<table>
<tr><th>Attacker ID</th><td>{esc(attacker["attacker_id"])}</td></tr>
<tr><th>Source IP</th><td>{esc(attacker["source_ip"])}</td></tr>
<tr><th>First seen</th><td>{esc(attacker["first_seen"])}</td></tr>
<tr><th>Last seen</th><td>{esc(attacker["last_seen"])}</td></tr>
</table>

<h2>2. Start / end time</h2>
<p>{esc(report["period"]["start"])} -&gt; {esc(report["period"]["end"])}
({esc(report["period"]["duration_events"])} events)</p>

<h2>3. Behavioral classification</h2>
<p>Stage: <span class="badge">{esc(behavior["current_stage"])}</span></p>
<table><tr><th>Category</th><th>Score</th></tr>
{"".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in behavior["latest_scores"].items())}
</table>
<p>Behaviors above threshold: {esc(", ".join(behavior["triggered_behaviors"]) or "none")}</p>

<h2>4. Risk score</h2>
<p>{esc(risk["risk_score"])} ({esc(risk["risk_band"])}) from {esc(risk["event_count"])} events</p>

<h2>5. Deception changes</h2>
<table><tr><th>Time</th><th>Policy</th><th>Action</th><th>Target</th><th>Reason</th></tr>
{action_rows or "<tr><td colspan='5'>no deception actions</td></tr>"}</table>

<h2>6. Engagement</h2>
<p>Score: <strong>{esc(engagement["engagement_score"])}/100</strong></p>
<table><tr><th>Component</th><th>Value</th></tr>
{"".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in engagement["components"].items())}
</table>

<h2>7. Indicators</h2>
<p>Source IP: {esc(report["indicators"]["source_ip"])}</p>
<p>Usernames attempted:</p><ul>{indicator_items or "<li>none</li>"}</ul>

<h2>8. Timeline</h2>
<table><tr><th>Timestamp</th><th>Sensor</th><th>Event</th><th>Severity</th></tr>
{timeline_rows}</table>

<h2>9. Summary</h2>
<p>{esc(report["summary"])}</p>
</body></html>"""


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, default=str)


SEVERITY_RANK = SEVERITY_ORDER
