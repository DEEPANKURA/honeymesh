from __future__ import annotations

import random
import string

SYNTHETIC_MARKER = "SYNTH"

SYNTHETIC_USERS = (
    "svc_backup",
    "j.harper",
    "a.okafor",
    "m.rossi",
    "finance.readonly",
    "hr.temp",
    "svc_reporting",
    "admin.decoy",
)

SYNTHETIC_TEMPLATES = (
    "{user}-LabOnly-{token}",
    "{marker}-{user}-{token}",
    "Winter{token}Simulation",
)


class SyntheticCredentialStore:
    """Clearly synthetic bait credentials. Never real secrets."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._credentials: dict[str, str] = {}
        self.enabled = False

    @staticmethod
    def _token(rng: random.Random) -> str:
        return "".join(rng.choices(string.ascii_lowercase + string.digits, k=6))

    def seed_credentials(self, count: int = 4) -> dict[str, str]:
        for user in SYNTHETIC_USERS[:count]:
            token = self._token(self._rng)
            template = SYNTHETIC_TEMPLATES[len(self._credentials) % len(SYNTHETIC_TEMPLATES)]
            password = template.format(user=user, token=token, marker=SYNTHETIC_MARKER)
            self._credentials[user] = password
        self.enabled = True
        return dict(self._credentials)

    @property
    def credentials(self) -> dict[str, str]:
        return dict(self._credentials)

    def accept(self, username: str, password: str) -> bool:
        expected = self._credentials.get(username)
        return bool(expected) and expected == password

    def hint(self) -> str:
        users = ", ".join(sorted(self._credentials)) or "none"
        return f"[synthetic bait accounts seeded: {users}] all values in this lab are fabricated"
