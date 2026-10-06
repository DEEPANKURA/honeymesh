# HoneyMesh

Adaptive cyber deception network: sensors, behavior profiling, risk scoring and an
adaptive deception engine, with a REST/WebSocket API and an operations console.

**Lab use only.** Every credential, host, file and asset HoneyMesh exposes is
synthetic and confined to an isolated lab.

## What is in the box

| Piece | Where | What it does |
| --- | --- | --- |
| Event pipeline | `backend/app/events`, `backend/app/pipeline.py` | normalize -> features -> behavior scores -> risk -> deception decision -> persist + publish |
| Sensors | `backend/app/sensors` | HoneySSH (paramiko), HoneyWeb (decoy HTTP app), network telemetry |
| Detection & profiling | `backend/app/behavior` | feature windows, behavior classifier, kill-chain stage machine, per-attacker profiles |
| Adaptive deception | `backend/app/deception` | policy engine, decoy orchestrator, synthetic credential store, state (level/strategy/telemetry) |
| API | `backend/app/api` | REST under `/api/v1`, live stream on `/ws/events`, bearer auth |
| Dashboard | `dashboard/` | React + TypeScript operations console, served from `/` when built |
| Lab | `lab/` | Docker Compose stack (not runtime-tested in this environment) |
| Simulator | `scripts/attack_simulator.py` | drives the instance with staged attack traffic |

## Quickstart (local)

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"      # Windows; use .venv/bin/pip elsewhere

# dashboard (optional but recommended)
cd dashboard && npm install && npm run build && cd ..

.venv/Scripts/python -m uvicorn app.main:app --app-dir backend --port 8000
```

Open http://127.0.0.1:8000 - sign in with `admin` /
`HONEYMESH_AUTH__ADMIN_PASSWORD` (empty by default in dev).

Generate traffic and watch the console adapt:

```bash
python scripts/attack_simulator.py --scenario full --ip 10.30.0.44 --count 40
```

Docker lab: see [`lab/README.md`](lab/README.md).

## Configuration

Precedence: **defaults < `configs/default.yaml` < `configs/lab.yaml` < `.env` <
environment variables**.

- Env vars use the `HONEYMESH_` prefix and `__` for nesting:
  `HONEYMESH_DECEPTION__MAX_LEVEL=4`
- YAML files are selected with `HONEYMESH_CONFIG_DIR` / `HONEYMESH_CONFIG`.

## API surface (summary)

- `POST /api/v1/auth/login` -> bearer token (admin actions always require it)
- `GET /api/v1/events`, `GET /api/v1/attackers`, `GET /api/v1/attackers/{id}`
  (`/timeline`, `/behavior`, `/engagement`)
- `GET /api/v1/deception/state|actions|decoys`,
  `POST /api/v1/deception/decoys/{name}/activate|deactivate`
- `GET /api/v1/reports/{attacker_id}?format=json|html`
- `GET /api/v1/overview`, `GET /api/v1/metrics`
- `POST /api/v1/ingest/events` (optional `X-Ingest-Token`, rate limited)
- `WS /ws/events` - live `security_event` / `attacker_updated` / `behavior_changed`

## Development

```bash
ruff check backend && ruff format --check backend   # lint
mypy                                                 # types
pytest                                               # 74 tests
cd dashboard && npm run typecheck && npm run build   # console
```

CI runs all of the above (`.github/workflows/ci.yml`).

## Docs

- [`docs/architecture.md`](docs/architecture.md) - components and data flow
- [`docs/adaptive-engine.md`](docs/adaptive-engine.md) - risk model, stage
  machine, policy/action mapping, engagement metric formulas
