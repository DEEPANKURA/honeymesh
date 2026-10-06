# Adaptive engine

Behavioral scoring, risk model, attacker stage machine, deception policies and
the lab engagement metric. All thresholds live in `configs/default.yaml`.

## Behavior scores (0..1)

Produced per attacker from a sliding window (`detection.window_seconds`,
default 300):

| score | main signals |
| --- | --- |
| `recon` | port/scan events, request rate, distinct destinations |
| `credential` | authentication failures, distinct usernames, success ratio |
| `web` | suspicious input, path enumeration, 404 probes, asset access |
| `discovery` | enumeration commands (`netstat`, `ifconfig`, `cat /etc/passwd`, ...) |
| `lateral` | lateral movement / target-host events |
| `persistence` | persistence mechanisms (cron, keys, services) |

Each score saturates (no value can exceed 1.0) and decays when the window
contains no evidence.

## Risk model

Weights (`risk.weights`) sum to 1.0:

```
active       = behaviours with score > 0
base         = Σ(weight_i * score_i) / Σ(weight_i)   over active behaviours
velocity     = min(request_rate / 40, 1)
risk         = clamp(base * (1 - velocity_weight) + velocity * velocity_weight, 0, 1)
```

Averaging over *active* behaviours means a single strong behaviour still
produces a meaningful band instead of being capped by the smallest weight.
Bands (`risk.bands`): `LOW < 0.25 <= MODERATE < 0.50 <= HIGH < 0.75 <= CRITICAL`
(clamped to `[0, 1]`).

## Attacker stage machine

Order: `UNKNOWN -> RECON -> INITIAL_ACCESS -> DISCOVERY -> LATERAL_ACTIVITY ->
PERSISTENCE_LIKE`.

- A stage is reached when its own evidence threshold is met
  (`recon >= 0.5`, `credential >= 0.6`, `discovery >= 0.7`, `lateral >= 0.7`,
  `persistence >= 0.7` by default).
- Progress is monotonic: profiles never regress, and missing evidence for an
  earlier stage does not block a later stage (recon may simply be unobserved).

## Deception policies

YAML list of policies: `conditions` (comparison strings such as `">0.65"` or
`">=3"` over behaviour scores, risk band, event counts), `actions`, and
`escalate_to_level`. Evaluation order is the config order; ties on threshold
pick the strongest match.

Applicable actions are filtered through `ALLOWED_ACTIONS` in
`deception/engine.py` (unknown actions are skipped and logged), then executed
through `DecoyOrchestrator`:

- `activate_decoy` / `deactivate_decoy` - allowlisted decoy names only
- `deploy_fake_credentials` - synthetic credential bait (always marked)
- `increase_auth_telemetry` - raises `telemetry_level`
- `open_session_honeypot`, `tarpit`, `log_everything` - session/sensor posture

State (`level`, `strategy`, `telemetry_level`, `active_decoys`, `flags`) is
exposed by `GET /api/v1/deception/state` and rendered live in the dashboard.
Level escalation comes from each policy's `escalate_to_level`, capped by
`deception.max_level` and held for `deception.cooldown_seconds`; the engine
re-evaluates every `deception.decision_interval_seconds`.

## Engagement score (lab metric)

Not an industry metric - documented here so it is reproducible:

```
components = saturate(raw_i / cap_i) for:
  decoy_interactions (cap 10), assets_accessed (cap 5),
  credential_attempts (cap 40), session_duration minutes (cap 60),
  services_touched (cap 5), deception_transitions (cap 12)
engagement = 100 * Σ weight_i * component_i
```

`GET /api/v1/attackers/{id}/engagement` returns the score, components, weights,
raw values and totals.
