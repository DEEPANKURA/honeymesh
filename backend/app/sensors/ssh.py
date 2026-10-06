from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import logging
import socket
import threading
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import paramiko

from app.config import SSHSensorConfig
from app.deception.credentials import SyntheticCredentialStore
from app.deception.state import DeceptionState
from app.sensors.base import EmitFn, SensorBase

logger = logging.getLogger(__name__)

PROMPT = "svc_backup@honeyssh:~$ "
FAKE_UNAME = "Linux honeyssh 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
FAKE_LS = "backup-manifest.txt  deploy.sh  logs/  .ssh/  service-status.txt  tmp/"

# Files that only exist once the deception engine escalates. Maps file ->
# (minimum deception level, event severity when read).
LEVEL_GATED_FILES: dict[str, tuple[int, str]] = {
    "credentials.env": (2, "medium"),
    "finance-archive.csv": (3, "medium"),
    "hr-export.csv": (3, "medium"),
    "persistence-drop.sh": (5, "high"),
}

PERSISTENCE_MARKERS = (
    "crontab",
    "authorized_keys",
    "systemctl enable",
    "/etc/rc.local",
    "schtasks",
    "startup",
    ".bashrc",
)


def _log_future_exception(future: concurrent.futures.Future[object]) -> None:
    if future.cancelled():
        return
    exc = future.exception()
    if exc is not None:
        logger.debug("emitted sensor event failed: %s", exc)


ENUMERATION_MARKERS = ("netstat", "ss -t", "nmap", "ifconfig", "ip a", "arp -a", "ps aux")
DISCOVERY_MARKERS = ("/etc/passwd", "/etc/shadow", "cat /etc", "ls /", "find /", "whoami")


@dataclass
class _Session:
    session_id: str
    client_ip: str
    started: float = field(default_factory=time.monotonic)
    commands: int = 0
    history: list[str] = field(default_factory=list)


class _ParamikoServer(paramiko.ServerInterface):
    def __init__(self, sensor: HoneySSHSensor, session: _Session) -> None:
        self.sensor = sensor
        self.session = session

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        self.sensor.record_auth(self.session, username, password)
        if self.sensor.credentials.accept(username, password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        with contextlib.suppress(Exception):
            channel.send(PROMPT)
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        text = command.decode(errors="replace").strip()
        self.sensor.handle_command(self.session, text, respond_to=channel)
        return True


class HoneySSHSensor(SensorBase):
    """Controlled SSH interaction surface. Runs its accept loop in a worker thread."""

    name = "honeyssh"

    def __init__(
        self,
        config: SSHSensorConfig,
        credentials: SyntheticCredentialStore,
        emit: EmitFn,
        *,
        state_provider: Callable[[], DeceptionState] | None = None,
    ) -> None:
        super().__init__(emit)
        self.config = config
        self.credentials = credentials
        self._state_provider = state_provider
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sessions: dict[str, _Session] = {}
        self._host_key: paramiko.PKey | None = None

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        if not self.config.enabled or self._running:
            return
        self._loop = asyncio.get_running_loop()
        if self._host_key is None:
            self._host_key = paramiko.ECDSAKey.generate()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.host, self.config.port))
        sock.listen(32)
        sock.settimeout(1.0)
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._serve, name="honeyssh-accept", daemon=True)
        self._thread.start()
        logger.info("HoneySSH listening on %s:%s", self.config.host, self.config.port)

    async def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None
        if self._thread is not None:
            await asyncio.to_thread(self._thread.join, 3.0)
            self._thread = None

    # -- emit helpers ------------------------------------------------------
    def _schedule(self, coroutine: Coroutine[Any, Any, Any]) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            coroutine.close()
            return
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        except RuntimeError:
            coroutine.close()
            return
        future.add_done_callback(_log_future_exception)

    def _emit_nowait(self, **kwargs: Any) -> None:
        self._schedule(self.emit_event(**kwargs))

    # -- deception state ----------------------------------------------------
    def _state(self) -> DeceptionState | None:
        if self._state_provider is None:
            return None
        try:
            return self._state_provider()
        except Exception:
            return None

    def _level(self) -> int:
        state = self._state()
        return state.level if state is not None else 1

    def _telemetry_high(self) -> bool:
        state = self._state()
        return state is not None and state.telemetry_level in {"high", "maximum"}

    def record_auth(self, session: _Session, username: str, password: str) -> None:
        accepted = self.credentials.accept(username, password)
        self._emit_nowait(
            event_type="authentication_attempt",
            source_ip=session.client_ip,
            session_id=session.session_id,
            service="ssh",
            username=username,
            metadata={
                "username": username,
                "result": "success" if accepted else "failure",
                "password_length": len(password),
            },
        )
        if accepted:
            self._emit_nowait(
                event_type="authentication_success",
                source_ip=session.client_ip,
                session_id=session.session_id,
                service="ssh",
                username=username,
                severity="high",
                metadata={"username": username, "method": "password"},
            )
            self._emit_nowait(
                event_type="credential_harvest",
                source_ip=session.client_ip,
                session_id=session.session_id,
                service="ssh",
                username=username,
                severity="high",
                metadata={"username": username, "synthetic": True},
            )

    def handle_command(
        self, session: _Session, command: str, respond_to: paramiko.Channel | None = None
    ) -> None:
        session.commands += 1
        session.history.append(command[:500])
        del session.history[:-500]
        lowered = command.lower()
        metadata: dict[str, Any] = {
            "command": command[:500],
            "command_index": session.commands,
        }
        if self._telemetry_high():
            metadata["telemetry"] = "high"
            metadata["session_history"] = list(session.history)
        self._emit_nowait(
            event_type="session_command",
            source_ip=session.client_ip,
            session_id=session.session_id,
            service="ssh",
            metadata=metadata,
        )
        if any(marker in lowered for marker in PERSISTENCE_MARKERS):
            self._emit_nowait(
                event_type="persistence_attempt",
                source_ip=session.client_ip,
                session_id=session.session_id,
                service="ssh",
                severity="high",
                metadata={"command": command[:500]},
            )
        elif any(marker in lowered for marker in ENUMERATION_MARKERS):
            self._emit_nowait(
                event_type="service_enumeration",
                source_ip=session.client_ip,
                session_id=session.session_id,
                service="ssh",
                metadata={"command": command[:500]},
            )
        elif any(marker in lowered for marker in DISCOVERY_MARKERS):
            self._emit_nowait(
                event_type="asset_access",
                source_ip=session.client_ip,
                session_id=session.session_id,
                service="ssh",
                metadata={"command": command[:500], "target_host": "honeyssh"},
            )

        output = self._fake_response(session, command)
        if respond_to is not None:
            try:
                respond_to.sendall(output.encode() + b"\r\n")
                respond_to.send_exit_status(0)
                respond_to.shutdown_write()
            except Exception:
                logger.debug("failed to respond to exec channel", exc_info=True)

    def _fake_response(self, session: _Session, command: str) -> str:
        lowered = command.lower()
        level = self._level()
        if lowered.startswith("ls"):
            visible = [
                name for name, (min_level, _) in LEVEL_GATED_FILES.items() if level >= min_level
            ]
            if visible:
                return FAKE_LS + "  " + "  ".join(visible)
            return FAKE_LS
        parts = lowered.split(maxsplit=1)
        if len(parts) == 2 and parts[0] in {"cat", "head", "more", "less"}:
            target = command.split(maxsplit=1)[1].strip().lstrip("./")
            gate = LEVEL_GATED_FILES.get(target)
            if gate is not None:
                min_level, severity = gate
                if level < min_level:
                    return f"bash: cat: {target}: No such file or directory"
                self._emit_nowait(
                    event_type="asset_access",
                    source_ip=session.client_ip,
                    session_id=session.session_id,
                    service="ssh",
                    severity=severity,
                    metadata={
                        "target_host": "honeyssh",
                        "asset": target,
                        "deception_level": level,
                        "command": command[:200],
                    },
                )
                return self._gated_file_body(target)
        if lowered.startswith("whoami"):
            return "svc_backup"
        if lowered.startswith("uname"):
            return FAKE_UNAME
        if lowered.startswith("id"):
            return "uid=1001(svc_backup) gid=1001(svc_backup) groups=1001(svc_backup),27(sudo)"
        if lowered.startswith("pwd"):
            return "/home/svc_backup"
        if lowered.startswith("cat /etc/hostname"):
            return "honeyssh"
        if lowered.startswith("exit") or lowered.startswith("logout"):
            return "logout"
        return f"bash: {command.split()[0]}: command not found"

    def _gated_file_body(self, name: str) -> str:
        if name == "credentials.env":
            creds = dict(self.credentials.credentials)
            if not creds:
                creds = self.credentials.seed_credentials()
            lines = ["# nightly-sync.env - generated by automation (synthetic)"]
            lines.extend(f"{user}={password}" for user, password in creds.items())
            lines.append("# SYNTH/LabOnly - all values fabricated for the lab")
            return "\n".join(lines)
        if name == "finance-archive.csv":
            return (
                "quarter,region,revenue\n"
                "Q3,APAC,1041200.55\n"
                "Q3,EMEA,872004.10\n"
                "# SYNTH/LabOnly - fabricated ledger export"
            )
        if name == "hr-export.csv":
            return (
                "employee_id,name,role\n"
                "E-1041,R. Okafor,Contractor\n"
                "E-1088,M. Lindqvist,Analyst\n"
                "# SYNTH/LabOnly - fabricated personnel export"
            )
        return (
            "#!/bin/sh\n"
            "# SYNTH/LabOnly - fabricated persistence drop for the deception lab\n"
            '(crontab -l; echo "0 3 * * * /home/svc_backup/.update-cache") 2>/dev/null | crontab -\n'
        )

    # -- connection handling ----------------------------------------------
    def _serve(self) -> None:
        assert self._sock is not None
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()

    def _handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        client_ip = addr[0]
        session_id = f"ssh-{uuid4().hex[:12]}"
        session = _Session(session_id=session_id, client_ip=client_ip)
        self._sessions[session_id] = session
        self._emit_nowait(
            event_type="connection_attempt",
            source_ip=client_ip,
            session_id=session_id,
            service="ssh",
            metadata={"port": self.config.port, "service": "ssh", "protocol": "tcp"},
        )
        transport: paramiko.Transport | None = None
        try:
            conn.settimeout(30)
            transport = paramiko.Transport(conn)
            transport.add_server_key(self._host_key or paramiko.ECDSAKey.generate())
            transport.start_server(server=_ParamikoServer(self, session))
            self._emit_nowait(
                event_type="service_banner",
                source_ip=client_ip,
                session_id=session_id,
                service="ssh",
                metadata={"banner": self.config.banner, "port": self.config.port},
            )
            channel = transport.accept(15)
            if channel is None:
                return
            self._emit_nowait(
                event_type="session_start",
                source_ip=client_ip,
                session_id=session_id,
                service="ssh",
                metadata={"transport": "ssh", "port": self.config.port},
            )
            self._pump_shell(transport, channel, session)
        except (TimeoutError, paramiko.SSHException, OSError) as exc:
            logger.debug("ssh connection ended from %s: %s", client_ip, exc)
        finally:
            session_meta: dict[str, Any] = {
                "duration_seconds": round(time.monotonic() - session.started, 3),
                "commands": session.commands,
            }
            if self._telemetry_high():
                session_meta["telemetry"] = "high"
                session_meta["session_history"] = list(session.history)
            self._emit_nowait(
                event_type="session_end",
                source_ip=client_ip,
                session_id=session_id,
                service="ssh",
                metadata=session_meta,
            )
            self._sessions.pop(session_id, None)
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()
            with contextlib.suppress(Exception):
                conn.close()

    def _pump_shell(
        self,
        transport: paramiko.Transport,
        channel: paramiko.Channel,
        session: _Session,
    ) -> None:
        channel.settimeout(1.0)
        current: paramiko.Channel | None = channel
        buffer = b""
        deadline = time.monotonic() + 180
        while self._running and transport.is_active() and time.monotonic() < deadline:
            if current is None:
                try:
                    current = transport.accept(1.0)
                except Exception:
                    logger.debug("ssh channel accept failed", exc_info=True)
                    break
                if current is None:
                    continue
                current.settimeout(1.0)
                buffer = b""
                continue
            try:
                data = current.recv(4096)
            except TimeoutError:
                continue
            except Exception:
                logger.debug("ssh channel recv failed", exc_info=True)
                current = None
                continue
            if not data:
                current = None
                continue
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                text = line.decode(errors="replace").strip("\r").strip()
                if not text:
                    continue
                self.handle_command(session, text)
                try:
                    current.send(self._fake_response(session, text) + "\r\n" + PROMPT)
                except Exception:
                    return
