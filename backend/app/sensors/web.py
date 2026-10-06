from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote

from app.config import WebSensorConfig
from app.deception.credentials import SyntheticCredentialStore
from app.deception.state import DeceptionState
from app.sensors.base import EmitFn, SensorBase

logger = logging.getLogger(__name__)

KNOWN_PAGES = {
    "/",
    "/login",
    "/dashboard",
    "/finance",
    "/employee",
    "/api/status",
    "/health",
}

PROBED_PATHS = {
    "/.env",
    "/.git/config",
    "/wp-admin",
    "/phpmyadmin",
    "/backup.zip",
    "/config.json",
    "/server-status",
    "/admin.php",
    "/xmlrpc.php",
    "/shell.php",
    "/actuator",
}

SUSPICIOUS_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("../", "traversal", "path traversal"),
    ("..%2f", "traversal", "encoded path traversal"),
    ("<script", "xss", "cross-site scripting payload"),
    ("onerror=", "xss", "inline event payload"),
    ("union select", "sqli", "sql union injection"),
    ("or 1=1", "sqli", "sql tautology injection"),
    ("'", "sqli", "quote injection"),
    ("etc/passwd", "disclosure", "sensitive file reference"),
    ("${jndi", "rce", "jndi injection"),
    ("%00", "misc", "null byte"),
    ("__proto__", "misc", "prototype pollution"),
)

SESSION_COOKIE = "hm_sid"
AUTH_COOKIE = "hm_auth"


@dataclass
class _SessionState:
    sid: str
    authenticated: bool = False
    requests: int = 0
    paths: set[str] = field(default_factory=set)


class HoneyWebSensor(SensorBase):
    """Fake enterprise web application with request telemetry."""

    name = "honeyweb"

    def __init__(
        self,
        config: WebSensorConfig,
        credentials: SyntheticCredentialStore,
        emit: EmitFn,
        state_provider: Callable[[], DeceptionState] | None = None,
    ) -> None:
        super().__init__(emit)
        self.config = config
        self.credentials = credentials
        self._state_provider = state_provider
        self._server: asyncio.Server | None = None
        self._sessions: dict[str, _SessionState] = {}
        self._background: set[asyncio.Task[None]] = set()

    def _deception_flags(self) -> set[str]:
        if self._state_provider is None:
            return set()
        try:
            state: DeceptionState = self._state_provider()
            return set(state.flags)
        except Exception:
            return set()

    async def start(self) -> None:
        if not self.config.enabled or self._server is not None:
            return
        self._server = await asyncio.start_server(self._handle, self.config.host, self.config.port)
        logger.info("HoneyWeb listening on %s:%s", self.config.host, self.config.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    # -- request handling --------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "0.0.0.0"
        try:
            request = await asyncio.wait_for(reader.read(65536), timeout=10)
        except (TimeoutError, ConnectionError):
            writer.close()
            return
        try:
            await self._process_request(client_ip, request, writer)
        except Exception:
            logger.exception("honeyweb request handling failed")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_request(
        self, client_ip: str, raw: bytes, writer: asyncio.StreamWriter
    ) -> None:
        text = raw.decode(errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        parts = lines[0].split() if lines else []
        method = parts[0] if parts else "GET"
        target = parts[1] if len(parts) > 1 else "/"
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        path, _, query = target.partition("?")
        path = unquote(path.split("#")[0])
        session = self._session_for(headers, client_ip)

        status, ctype, payload, extra_events = await self._route(
            method, path, query, headers, body, session, client_ip
        )
        cookies = f"{SESSION_COOKIE}={session.sid}"
        if session.authenticated:
            cookies += f"; {AUTH_COOKIE}=1"
        response = (
            f"HTTP/1.1 {status} {'OK' if status < 400 else 'Error'}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(payload.encode())}\r\n"
            "Set-Cookie: " + cookies + "; Path=/; HttpOnly\r\n"
            "Server: HoneyWeb\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + payload.encode()
        writer.write(response)

        if status == 404 and path not in KNOWN_PAGES:
            event_type = "path_enumeration"
        elif status == 404:
            event_type = "http_request"
        else:
            event_type = "http_request"
        await self.emit_event(
            event_type,
            client_ip,
            service="honeyweb",
            session_id=session.sid,
            metadata={
                "method": method,
                "path": path,
                "status": status,
                "user_agent": headers.get("user-agent", "")[:200],
                "query_keys": sorted(parse_qs(query).keys())[:10],
            },
        )
        for event in extra_events:
            await self.emit_event(
                event["event_type"],
                client_ip,
                service="honeyweb",
                session_id=session.sid,
                severity=event.get("severity"),
                username=event.get("username"),
                metadata=event.get("metadata", {}),
            )

    def _session_for(self, headers: dict[str, str], client_ip: str) -> _SessionState:
        cookie = headers.get("cookie", "")
        sid = ""
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == SESSION_COOKIE:
                sid = value
                break
        if not sid or sid not in self._sessions:
            sid = f"web-{uuid.uuid4().hex[:12]}"
            self._sessions[sid] = _SessionState(sid=sid)
            self._schedule_session_start(sid, client_ip)
        session = self._sessions[sid]
        session.requests += 1
        if f"{AUTH_COOKIE}=1" in headers.get("cookie", ""):
            session.authenticated = True
        return session

    def _schedule_session_start(self, sid: str, client_ip: str) -> None:
        task = asyncio.create_task(
            self.emit_event(
                "session_start",
                client_ip,
                service="honeyweb",
                session_id=sid,
                metadata={"transport": "http"},
            )
        )
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _route(
        self,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: str,
        session: _SessionState,
        client_ip: str,
    ) -> tuple[int, str, str, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        for pattern, category, description in SUSPICIOUS_PATTERNS:
            if pattern in unquote(path + query + body).lower() or pattern in path.lower():
                events.append(
                    {
                        "event_type": "http_suspicious_input",
                        "severity": "high",
                        "metadata": {
                            "method": method,
                            "path": path[:300],
                            "category": category,
                            "pattern": pattern,
                            "detail": description,
                        },
                    }
                )
                break

        if path in PROBED_PATHS:
            events.append(
                {
                    "event_type": "path_enumeration",
                    "severity": "medium",
                    "metadata": {"method": method, "path": path, "known_probe": True},
                }
            )
            return 404, "text/html; charset=utf-8", self._page("Not Found", "404"), events

        if method == "POST" and path == "/login":
            form = parse_qs(body)
            username = (form.get("username") or [""])[0][:64]
            password = (form.get("password") or [""])[0][:128]
            accepted = self.credentials.accept(username, password)
            events.append(
                {
                    "event_type": "authentication_attempt",
                    "severity": "medium",
                    "username": username,
                    "metadata": {
                        "username": username,
                        "result": "success" if accepted else "failure",
                        "surface": "web_login",
                    },
                }
            )
            if accepted:
                session.authenticated = True
                events.append(
                    {
                        "event_type": "authentication_success",
                        "severity": "high",
                        "username": username,
                        "metadata": {"username": username, "surface": "web_login"},
                    }
                )
                events.append(
                    {
                        "event_type": "credential_harvest",
                        "severity": "high",
                        "username": username,
                        "metadata": {
                            "username": username,
                            "synthetic": True,
                            "surface": "web_login",
                        },
                    }
                )
                return 302, "text/plain", "Redirecting to /dashboard", events
            return (
                200,
                "text/html; charset=utf-8",
                self._page("Login", "<h1>Login</h1><p>Invalid username or password.</p>"),
                events,
            )

        if path == "/login":
            page = self._login_form()
            return 200, "text/html; charset=utf-8", page, events

        if path == "/admin":
            if "admin_portal" in self._deception_flags():
                events.append(
                    {
                        "event_type": "asset_access",
                        "severity": "high",
                        "metadata": {
                            "path": path,
                            "target_host": "honeyweb",
                            "asset": "admin_portal",
                        },
                    }
                )
                return (
                    200,
                    "text/html; charset=utf-8",
                    self._page(
                        "Admin Console",
                        "<h1>Decoy Admin Console</h1>"
                        "<ul><li>users: 3</li><li>jobs: nightly-sync</li>"
                        "<li>note: synthetic environment</li></ul>",
                    ),
                    events,
                )
            events.append(
                {
                    "event_type": "path_enumeration",
                    "severity": "medium",
                    "metadata": {"method": method, "path": path, "known_probe": True},
                }
            )
            return 404, "text/html; charset=utf-8", self._page("Not Found", "404"), events

        if path in {"/dashboard", "/finance", "/employee"}:
            if not session.authenticated:
                return 302, "text/plain", "Redirecting to /login", events
            events.append(
                {
                    "event_type": "asset_access",
                    "severity": "medium",
                    "metadata": {
                        "path": path,
                        "target_host": "honeyweb",
                        "asset": path.strip("/"),
                    },
                }
            )
            return (
                200,
                "text/html; charset=utf-8",
                self._page(path.strip("/").title(), self._synthetic_page(path)),
                events,
            )

        if path == "/api/status":
            payload = json.dumps(
                {
                    "service": "honeyweb",
                    "status": "ok",
                    "synthetic": True,
                    "flags": sorted(self._deception_flags()),
                }
            )
            return 200, "application/json", payload, events

        if path == "/health":
            return 200, "application/json", json.dumps({"status": "up"}), events

        if path == "/":
            return (
                200,
                "text/html; charset=utf-8",
                self._page(
                    "Northgate Systems",
                    "<h1>Northgate Systems</h1>"
                    "<p>Employee portal - <a href='/login'>staff login</a></p>"
                    "<p>This is a synthetic HoneyMesh decoy site.</p>",
                ),
                events,
            )

        events.append(
            {
                "event_type": "path_enumeration",
                "severity": "medium",
                "metadata": {"method": method, "path": path[:300]},
            }
        )
        return 404, "text/html; charset=utf-8", self._page("Not Found", "404"), events

    @staticmethod
    def _page(title: str, body: str) -> str:
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>{title}</title></head><body>{body}</body></html>"
        )

    @staticmethod
    def _login_form() -> str:
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Login</title></head>"
            "<body><h1>Staff Login</h1>"
            "<form method='post' action='/login'>"
            "<label>Username <input name='username'></label><br>"
            "<label>Password <input name='password' type='password'></label><br>"
            "<button type='submit'>Sign in</button></form>"
            "<p>Synthetic HoneyMesh decoy.</p></body></html>"
        )

    @staticmethod
    def _synthetic_page(path: str) -> str:
        content = {
            "/dashboard": (
                "<h1>Dashboard</h1><ul><li>Q4 pipeline: 1.2M (synthetic)</li>"
                "<li>open tickets: 17</li><li>last sync: 04:00 UTC</li></ul>"
            ),
            "/finance": (
                "<h1>Finance</h1><table border='1'>"
                "<tr><th>Invoice</th><th>Amount</th></tr>"
                "<tr><td>INV-0042</td><td>18250.00</td></tr>"
                "<tr><td>INV-0044</td><td>31000.00</td></tr></table>"
                "<p>All figures synthetic.</p>"
            ),
            "/employee": (
                "<h1>Employees</h1><ul>"
                "<li>Alicia Gomez - HR</li><li>Tomas Nowak - Recruiter</li>"
                "<li>Renée Duval - HR Analytics</li></ul><p>All people synthetic.</p>"
            ),
        }
        return content.get(path, "<p>No content.</p>")
