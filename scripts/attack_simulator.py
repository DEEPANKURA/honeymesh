#!/usr/bin/env python3
"""HoneyMesh attack simulator.

Drives a running HoneyMesh instance so the detection pipeline, profiling,
risk scoring and adaptive deception engine can be observed end to end.

Two modes:
  api   (default) post synthetic events to the ingest API
  live             generate real traffic against the honeypot sensors
                   (SSH on :2222, HTTP on :8081)

Examples:
  python scripts/attack_simulator.py --scenario brute_force --ip 10.30.0.15
  python scripts/attack_simulator.py --scenario full --mode live
  python scripts/attack_simulator.py --scenario recon --count 40 --interval 0.05

All traffic is generated from this machine only and targets lab addresses.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
INGEST_PATH = "/api/v1/ingest/events"

SCENARIOS = ("recon", "brute_force", "web", "lateral", "full")

USERNAMES = ("admin", "root", "oracle", "svc_backup", "test")


def post_events(base_url: str, events: list[dict[str, Any]], token: str = "") -> dict[str, Any]:
    payload = json.dumps({"events": events}).encode()
    request = urllib.request.Request(
        f"{base_url}{INGEST_PATH}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        request.add_header("X-Ingest-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - lab url
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:  # pragma: no cover - depends on target
        body = exc.read().decode(errors="replace")
        raise SystemExit(f"ingest failed: HTTP {exc.code} {body}") from exc
    except urllib.error.URLError as exc:  # pragma: no cover - depends on target
        raise SystemExit(f"ingest failed: {exc.reason} (is HoneyMesh running?)") from exc


def event(
    event_type: str,
    source_ip: str,
    *,
    sensor: str = "honeynet",
    severity: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "sensor": sensor,
        "event_type": event_type,
        "source_ip": source_ip,
        "metadata": metadata or {},
    }
    if severity:
        raw["severity"] = severity
    return raw


def scenario_recon(source_ip: str, count: int) -> list[dict[str, Any]]:
    events = []
    for index in range(count):
        events.append(
            event(
                "port_scan",
                source_ip,
                metadata={"port": 20 + index, "protocol": "tcp", "scanner": "syn"},
            )
        )
        events.append(
            event(
                "connection_attempt",
                source_ip,
                metadata={"destination_port": 22, "service": "ssh"},
            )
        )
    return events[:count]


def scenario_brute_force(source_ip: str, count: int) -> list[dict[str, Any]]:
    events = []
    for index in range(count):
        username = USERNAMES[index % len(USERNAMES)]
        events.append(
            event(
                "authentication_attempt",
                source_ip,
                sensor="honeyssh",
                severity="medium",
                metadata={
                    "username": username,
                    "result": "failure",
                    "surface": "ssh_password",
                    "attempt": index + 1,
                },
            )
        )
    return events


def scenario_web(source_ip: str, count: int) -> list[dict[str, Any]]:
    payloads = [
        ("/wp-login.php", "path_enumeration", "medium"),
        ("/admin", "asset_access", "high"),
        ("/api/v1/users?id=1' OR '1'='1", "http_suspicious_input", "high"),
        ("/.env", "path_enumeration", "medium"),
        ("/login", "authentication_attempt", "medium"),
    ]
    events = []
    for index in range(count):
        path, event_type, severity = payloads[index % len(payloads)]
        events.append(
            event(
                event_type,
                source_ip,
                sensor="honeyweb",
                severity=severity,
                metadata={"method": "GET" if index % 3 else "POST", "path": path},
            )
        )
    return events


def scenario_lateral(source_ip: str, count: int) -> list[dict[str, Any]]:
    chain = [
        ("discovery", "command_exec", {"command": "netstat -tulpn"}),
        ("discovery", "command_exec", {"command": "cat /etc/passwd"}),
        ("lateral", "lateral_movement", {"target_host": "honeyfile", "protocol": "smb"}),
        ("persistence", "persistence_attempt", {"mechanism": "cron"}),
    ]
    events = []
    for index in range(count):
        behavior, event_type, metadata = chain[index % len(chain)]
        events.append(
            event(
                event_type,
                source_ip,
                severity="high",
                metadata={**metadata, "behavior": behavior, "hop": index + 1},
            )
        )
    return events


def build_events(scenario: str, source_ip: str, count: int) -> list[dict[str, Any]]:
    if scenario == "recon":
        return scenario_recon(source_ip, count)
    if scenario == "brute_force":
        return scenario_brute_force(source_ip, count)
    if scenario == "web":
        return scenario_web(source_ip, count)
    if scenario == "lateral":
        return scenario_lateral(source_ip, count)
    events: list[dict[str, Any]] = []
    events += scenario_recon(source_ip, max(4, count // 5))
    events += scenario_brute_force(source_ip, max(8, count // 3))
    events += scenario_web(source_ip, max(4, count // 5))
    events += scenario_lateral(source_ip, max(4, count // 5))
    return events[: count * 2]


def run_live(base_url: str, source_ip: str, count: int) -> int:
    """Send real traffic to the honeypot sensors (requires paramiko/httpx)."""
    sent = 0

    try:
        import paramiko  # noqa: PLC0415
    except ImportError:  # pragma: no cover
        paramiko = None  # type: ignore[assignment]
    try:
        import httpx  # noqa: PLC0415
    except ImportError:  # pragma: no cover
        httpx = None  # type: ignore[assignment]

    if paramiko is not None:
        for index in range(min(count, 8)):
            username = USERNAMES[index % len(USERNAMES)]
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    "127.0.0.1",
                    port=2222,
                    username=username,
                    password=f"wrong-{index}",
                    timeout=8,
                    allow_agent=False,
                    look_for_keys=False,
                )
                client.exec_command("whoami", timeout=5)
                sent += 1
            except Exception:  # noqa: BLE001 - expected: auth rejected
                sent += 1
            finally:
                client.close()

    if httpx is not None:
        paths = ["/", "/login", "/admin", "/wp-login.php", "/.env", "/dashboard"]
        for index in range(max(1, count)):
            path = paths[index % len(paths)]
            try:
                if path == "/login":
                    httpx.post(
                        f"http://127.0.0.1:8081{path}",
                        data={"username": "admin", "password": "wrong"},
                        timeout=8,
                        follow_redirects=False,
                    )
                else:
                    httpx.get(f"http://127.0.0.1:8081{path}", timeout=8)
                sent += 1
            except Exception:  # noqa: BLE001 - lab target may be down
                sent += 1

    print(f"live mode: {sent} requests sent to sensors (source attribution: {source_ip})")
    return sent


def main() -> int:
    parser = argparse.ArgumentParser(description="HoneyMesh attack simulator")
    parser.add_argument("--scenario", choices=SCENARIOS, default="brute_force")
    parser.add_argument("--mode", choices=("api", "live"), default="api")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--ip", default="10.30.0.15", help="attacker source ip")
    parser.add_argument("--count", type=int, default=24, help="events (api) / requests (live)")
    parser.add_argument("--interval", type=float, default=0.0, help="seconds between posts")
    parser.add_argument("--batch", type=int, default=8, help="events per ingest call")
    parser.add_argument("--ingest-token", default="", help="X-Ingest-Token if configured")
    args = parser.parse_args()

    if args.mode == "live":
        run_live(args.base_url, args.ip, args.count)
        return 0

    events = build_events(args.scenario, args.ip, args.count)
    print(f"scenario={args.scenario} ip={args.ip} events={len(events)} -> {args.base_url}")

    posted = 0
    for start in range(0, len(events), args.batch):
        chunk = events[start : start + args.batch]
        result = post_events(args.base_url, chunk, args.ingest_token)
        posted += len(chunk)
        accepted = result.get("accepted", len(chunk))
        print(f"  posted {posted}/{len(events)} (accepted={accepted})")
        if args.interval > 0:
            time.sleep(args.interval)

    print("done - open the dashboard to watch risk, stage and deception adapt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
