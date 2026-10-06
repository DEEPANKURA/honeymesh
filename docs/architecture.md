# Architecture

```
 sensors (threads/async)          pipeline                         storage
┌────────────────────┐   raw   ┌──────────────────────────────┐   ┌────────────┐
│ HoneySSH  :2222     │ ──────► │ normalize  (identity,        │──►│ SQLite/    │
│ HoneyWeb  :8081     │  RawEvent│            severity, ts)    │   │ Postgres   │
│ network   :9000     │         │ features   (sliding window)  │   │ events     │
│ POST /ingest/events │         │ behavior   (6 classifiers)   │   │ attackers  │
└────────────────────┘         │ risk       (weighted +       │   │ behaviors  │
                               │            velocity)         │   │ actions    │
                               │ profile    (stage machine)   │   │ decoys     │
                               │ deception  (policies)        │   └────────────┘
                               └───────────────┬──────────────┘
                                               │ publish
                               ┌───────────────▼──────────────┐
                               │ bus (topics) -> WS clients,   │
                               │ dashboard, adaptive loop      │
                               └──────────────────────────────┘
```

## Event flow

1. **Emission** - every sensor produces a `RawEvent`
   (`sensor`, `event_type`, `source_ip`, `severity?`, `metadata`).
   API clients post the same shape to `POST /api/v1/ingest/events`
   (optional `X-Ingest-Token`, per-source rate limit).
2. **Normalization** (`events/normalizer.py`) - validates the event, assigns
   `event_id`, UTC timestamp and a canonical severity
   (`info < low < medium < high < critical`).
3. **Features** (`behavior/features.py`) - per-source sliding window (default
   300 s): event rate, distinct ports/paths, credential failures, success ratio.
4. **Behavior classification** (`behavior/scoring.py`) - six bounded scores in
   `[0, 1]`: `recon`, `credential`, `web`, `discovery`, `lateral`, `persistence`.
5. **Risk** - weighted evidence average blended with a velocity factor
   (formula in `docs/adaptive-engine.md`).
6. **Profiling** (`behavior/profiler.py`) - one profile per attacker id
   (source IP): scores, risk band, kill-chain stage, event count, timestamps.
7. **Deception** (`deception/`) - policy rules match on behavior/risk/stage and
   request actions. `DecoyOrchestrator` is the only component allowed to start
   or stop decoy services, and only for allowlisted names.
8. **Persistence + publish** - rows are written through
   `database/repository.py`; the event bus publishes `security_event`,
   `attacker_updated`, `behavior_changed` to `/ws/events`.

## Adaptive loop

`main.py` runs a background loop (every `deception.decision_interval_seconds`):
it re-reads the hottest profile, lets the engine pick a strategy/level, applies
telemetry verbosity, and enforces `deception.cooldown_seconds` so state cannot
flap.

Safety rules baked into the engine:

- unknown policy actions are skipped and logged, never executed;
- only `ALLOWED_ACTIONS` and per-level actions are applicable;
- every generated credential carries a synthetic marker (`SYNTH`/`LabOnly`/
  `Simulation`);
- admin routes require a bearer token; read routes only when
  `auth.require_read_auth` is enabled.

## API and console

- REST under `/api/v1`, OpenAPI at `/docs`.
- `/ws/events` streams the same normalized event objects the DB stores.
- `dashboard/` (React + TS) is a static build mounted at `/` by FastAPI when
  `dashboard/dist` exists; in development run `npm run dev` (proxies `/api` and
  `/ws`).

## Storage

SQLAlchemy async models (`database/models.py`) with a SQLite default
(`sqlite+aiosqlite`) and a Postgres-ready URL switch
(`HONEYMESH_DATABASE__URL`). Tables: `events`, `attackers`, `behavior_scores`,
`deception_actions`, `decoys`, `sessions`.
