# HoneyMesh — Adaptive Deception Network
## Product Requirements Document (PRD) + Technical Requirements Document (TRD)

**Version:** 1.0  
**Status:** Development Specification  
**Project Type:** Cybersecurity / Software Engineering Portfolio Project  
**Primary Language:** Python  
**Target:** Isolated local cybersecurity lab / VM / Docker environment  
**Security Principle:** Defensive research only; all deception infrastructure must remain isolated from real production networks.

---

# Part I — Product Requirements Document (PRD)

## 1. Product Overview

### 1.1 Product Name

**HoneyMesh — Adaptive Deception Network**

### 1.2 Product Vision

HoneyMesh is an isolated miniature enterprise network designed to detect, profile, and study attackers by deliberately exposing realistic-looking services, credentials, hosts, and decoy assets.

Unlike a conventional honeypot that primarily records attacks, HoneyMesh uses an **adaptive deception engine**:

> Observe attacker behavior → build attacker profile → classify behavior → select deception strategy → modify the decoy environment → observe again.

The project demonstrates practical cybersecurity engineering, network monitoring, event processing, behavioral analysis, deception technology, containerization, API development, and automated testing.

### 1.3 Problem Statement

Traditional beginner honeypot projects generally follow this model:

```text
Attacker
   ↓
Honeypot
   ↓
Logs
```

This provides useful telemetry but limited adaptation.

HoneyMesh aims to implement:

```text
Attacker
   ↓
Observe
   ↓
Extract behavior
   ↓
Build attacker profile
   ↓
Select deception policy
   ↓
Change environment
   ↓
Observe new behavior
   ↓
Repeat
```

The objective is to make the deception environment responsive to the attacker's behavior while remaining safe and isolated.

---

# 2. Goals

## 2.1 Primary Goals

1. Build a reproducible miniature enterprise network in an isolated environment.
2. Expose controlled decoy services such as SSH and HTTP.
3. Collect security-relevant events.
4. Correlate events belonging to the same attacker/session.
5. Build an attacker behavior profile.
6. Detect behavioral categories such as:
   - reconnaissance
   - service enumeration
   - credential attacks
   - web probing
   - discovery
   - lateral-movement-like behavior
   - persistence-like behavior
7. Dynamically change the deception environment.
8. Deploy additional decoys when justified by observed behavior.
9. Provide a real-time monitoring dashboard.
10. Generate investigation reports.
11. Provide measurable deception/engagement metrics.
12. Keep the entire system safe for local cybersecurity experimentation.

## 2.2 Secondary Goals

- Demonstrate production-style Python architecture.
- Demonstrate REST API development.
- Demonstrate asynchronous/event-driven programming.
- Demonstrate Docker-based infrastructure.
- Demonstrate database design.
- Demonstrate automated security testing.
- Produce a high-quality GitHub portfolio project.

---

# 3. Non-Goals

HoneyMesh will **not**:

- attack real systems;
- automatically retaliate against attackers;
- perform offensive actions outside the isolated lab;
- spread malware;
- deploy real credentials;
- expose real enterprise secrets;
- provide uncontrolled internet-facing vulnerable infrastructure;
- automatically scan arbitrary external IP addresses;
- attempt destructive exploitation.

All simulated credentials, files, services, and enterprise data are synthetic.

---

# 4. Target Users

## 4.1 Primary User

A cybersecurity student, security researcher, SOC trainee, or software engineer studying:

- network security;
- deception technology;
- intrusion detection;
- digital attack behavior;
- security automation.

## 4.2 Secondary User

A recruiter or interviewer evaluating the developer's:

- Python skills;
- system design;
- networking knowledge;
- cybersecurity knowledge;
- testing discipline;
- software architecture skills.

---

# 5. Core Product Features

## 5.1 Isolated Enterprise Lab

HoneyMesh shall provide a reproducible lab containing multiple simulated enterprise components.

Example:

```text
HoneyMesh Lab
│
├── HoneyGate
│
├── HoneySSH
│
├── HoneyWeb
│
├── HoneyDB
│
├── Finance-SRV
│
├── HR-SRV
│
└── Backup-SRV
```

The actual deployment may use Docker containers, local VMs, or both.

---

## 5.2 Decoy Services

Initial supported services:

### HoneySSH

Provides a controlled SSH-like interaction surface.

Telemetry should include:

- connection attempts;
- usernames attempted;
- authentication results;
- command/session activity where safely supported;
- session duration;
- source identifier.

### HoneyWeb

Provides a fake enterprise web application.

Example pages:

```text
/login
/admin
/dashboard
/finance
/employee
/api/status
```

Telemetry should include:

- HTTP method;
- path;
- status;
- request rate;
- suspicious input patterns;
- session identifier.

### HoneyDB

A simulated database service or database-like decoy.

It should contain synthetic data only.

---

# 6. Synthetic Enterprise Environment

HoneyMesh should simulate a small enterprise.

Example:

```text
Finance
├── payroll.xlsx
├── invoices/
└── quarterly_report.pdf

HR
├── employees.csv
├── leave_policy.pdf
└── hiring_plan.xlsx

IT
├── backup-manifest.txt
├── infrastructure.txt
└── service-status.txt
```

Files must contain fabricated data.

No real:

- passwords;
- personal information;
- API keys;
- company secrets;
- cloud credentials.

---

# 7. Event Collection

HoneyMesh shall normalize security events into a common format.

Example:

```json
{
  "event_id": "evt-001",
  "timestamp": "2026-10-06T14:20:11Z",
  "source_id": "attacker-01",
  "source_ip": "LAB-ADDRESS",
  "sensor": "honeyssh",
  "event_type": "authentication_attempt",
  "severity": "medium",
  "metadata": {
    "username": "admin",
    "result": "failure"
  }
}
```

The exact IP values used during demonstrations must belong to the isolated lab.

---

# 8. Attacker Identity and Session Tracking

HoneyMesh shall group events into attacker profiles.

An attacker profile may contain:

```json
{
  "attacker_id": "A-014",
  "first_seen": "...",
  "last_seen": "...",
  "event_count": 143,
  "scan_score": 0.82,
  "credential_score": 0.91,
  "web_score": 0.37,
  "discovery_score": 0.74,
  "lateral_score": 0.62,
  "risk_score": 0.87,
  "current_stage": "discovery"
}
```

The system should avoid relying on a single indicator when possible.

---

# 9. Behavioral Classification

HoneyMesh will classify behavior into defensive categories.

## 9.1 Reconnaissance

Indicators:

- repeated connection attempts;
- many destination ports;
- service enumeration;
- rapid probing.

## 9.2 Credential Attack

Indicators:

- repeated authentication failures;
- many usernames;
- high authentication request frequency;
- repeated password attempts.

## 9.3 Web Probing

Indicators:

- repeated endpoint discovery;
- suspicious paths;
- unusual request sequences;
- abnormal request frequency.

## 9.4 Discovery

Indicators:

- enumeration of users;
- enumeration of services;
- inspection of synthetic enterprise assets.

## 9.5 Lateral-Movement-Like Behavior

Indicators:

- movement between decoy hosts;
- repeated connection attempts across internal decoys;
- attempts to access additional simulated services.

## 9.6 Persistence-Like Behavior

Indicators:

- repeated attempts to modify simulated startup/configuration surfaces;
- suspicious persistence-oriented activity in the controlled lab.

These are behavioral classifications, not claims about a real-world attacker.

---

# 10. Adaptive Deception Engine

This is the primary differentiating feature.

## 10.1 Adaptive Loop

```text
Event
  ↓
Normalization
  ↓
Feature Extraction
  ↓
Attacker Profile Update
  ↓
Behavior Classification
  ↓
Risk/Confidence Calculation
  ↓
Deception Policy Selection
  ↓
Environment Change
  ↓
New Telemetry
  ↓
Profile Update
```

## 10.2 Example Policies

### Reconnaissance detected

Deploy:

```text
Additional synthetic host
Additional decoy service
```

### Credential attack detected

Deploy:

```text
Synthetic credentials
Fake administrative account
Controlled login surface
```

### Web-focused behavior detected

Deploy:

```text
Additional synthetic web endpoint
Fake admin portal
Synthetic application data
```

### Discovery behavior detected

Deploy:

```text
Finance-SRV
HR-SRV
Backup-SRV
```

### Lateral behavior detected

Increase:

```text
Internal decoy visibility
Telemetry collection
Cross-host event correlation
```

---

# 11. Deception State

HoneyMesh shall maintain a current deception state.

Example:

```json
{
  "level": 3,
  "active_decoys": [
    "honeyssh",
    "honeyweb",
    "finance-srv"
  ],
  "strategy": "enterprise_discovery",
  "telemetry_level": "high"
}
```

Deception changes must be auditable.

Every change should record:

- previous state;
- new state;
- triggering behavior;
- policy;
- timestamp;
- reason;
- confidence.

---

# 12. Risk Scoring

HoneyMesh shall calculate a normalized risk score.

Example conceptual model:

```text
Risk =
    reconnaissance_weight
  + credential_weight
  + discovery_weight
  + lateral_weight
  + persistence_weight
  + velocity_factor
```

The implementation must normalize the result to:

```text
0.0 → 1.0
```

Example:

```text
0.00–0.24  LOW
0.25–0.49  MODERATE
0.50–0.74  HIGH
0.75–1.00  CRITICAL
```

Weights must be configurable.

---

# 13. Deception Engagement Metrics

HoneyMesh should measure whether adaptive deception is keeping the simulated attacker interacting with the environment.

Metrics:

- session duration;
- number of decoy interactions;
- number of decoy assets accessed;
- number of synthetic credentials attempted;
- number of hosts touched;
- number of services touched;
- number of suspicious events;
- deception transitions;
- attacker engagement score.

Example:

```text
Engagement Score = 87/100
```

The scoring formula must be documented rather than presented as an industry-standard metric.

---

# 14. Dashboard

The dashboard should display:

## Overview

- active attackers;
- total events;
- high-risk profiles;
- active decoys;
- deception level;
- engagement score.

## Timeline

```text
14:20  Port/service probing
14:21  SSH authentication attempts
14:22  Fake admin account interaction
14:23  Finance decoy activated
14:25  Internal service enumeration
```

## Attacker Profile

- current behavior;
- risk score;
- attack-stage estimate;
- event history;
- active deception strategy.

## Network View

Show:

```text
Attacker
   ↓
HoneyGate
 ├── HoneySSH
 ├── HoneyWeb
 ├── Finance-SRV
 └── Backup-SRV
```

---

# 15. Reporting

HoneyMesh shall generate a machine-readable and human-readable incident report.

Report sections:

1. Case information.
2. Start/end time.
3. Attacker/session identifier.
4. Timeline.
5. Behavioral classification.
6. Risk score.
7. Deception changes.
8. Decoy interactions.
9. Indicators.
10. Summary.

Output formats:

- JSON;
- HTML;
- optional PDF.

---

# 16. Search and Investigation

The dashboard should allow filtering by:

- attacker;
- event type;
- severity;
- sensor;
- time range;
- deception policy;
- session.

---

# 17. Configuration

Configuration should be externalized.

Example:

```yaml
environment:
  mode: lab

deception:
  max_level: 5
  adaptive_mode: true

detection:
  brute_force_threshold: 10
  scan_threshold: 20

telemetry:
  level: normal
```

No secrets should be hardcoded.

---

# 18. User Stories

### US-01

As a researcher, I want to start the entire HoneyMesh lab with one command so that I can reproduce the environment.

### US-02

As a researcher, I want to see incoming security events in real time so that I can understand attacker behavior.

### US-03

As a researcher, I want events correlated into attacker profiles so that individual behavior can be analyzed.

### US-04

As a researcher, I want HoneyMesh to adapt decoys according to behavior so that the environment is not static.

### US-05

As a researcher, I want to see why a deception change occurred so that adaptive decisions are explainable.

### US-06

As a researcher, I want to export an investigation report so that I can document an experiment.

### US-07

As a developer, I want automated tests so that changes do not break security logic.

---

# 19. Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | Start isolated HoneyMesh environment | Must |
| FR-02 | Collect normalized events | Must |
| FR-03 | Track sessions/attackers | Must |
| FR-04 | Detect reconnaissance behavior | Must |
| FR-05 | Detect credential attacks | Must |
| FR-06 | Detect web probing | Must |
| FR-07 | Maintain attacker profiles | Must |
| FR-08 | Calculate risk score | Must |
| FR-09 | Select adaptive deception policies | Must |
| FR-10 | Dynamically activate safe decoys | Must |
| FR-11 | Record deception decisions | Must |
| FR-12 | Provide dashboard | Must |
| FR-13 | Export reports | Should |
| FR-14 | Provide API | Must |
| FR-15 | Automated tests | Must |
| FR-16 | Docker deployment | Must |
| FR-17 | CI pipeline | Should |
| FR-18 | ML-based classification | Future |

---

# 20. Non-Functional Requirements

## Performance

- Event ingestion should remain responsive under the expected lab workload.
- Dashboard updates should normally appear within a few seconds.
- Adaptive decisions should be asynchronous where practical.

## Reliability

- Events should not silently disappear.
- Sensor failure should be visible.
- Deception changes should be recoverable.

## Security

- Lab must remain isolated.
- Synthetic data only.
- No real credentials.
- No uncontrolled offensive automation.
- Administrative actions require authentication.
- API validation is mandatory.
- Secrets must come from environment/configuration mechanisms.

## Maintainability

- Modular Python code.
- Type hints.
- Clear interfaces.
- Automated tests.
- Documentation.

---

# 21. Success Criteria

HoneyMesh V1 is successful when:

1. The entire environment starts reproducibly.
2. At least two decoy services collect events.
3. Events are normalized and persisted.
4. Behavior categories can be detected.
5. An attacker profile is created.
6. Risk is calculated.
7. At least three adaptive deception policies work.
8. Deception changes appear in the dashboard.
9. Every adaptive decision has an explanation.
10. A complete investigation report can be generated.
11. Automated tests cover the core detection/deception logic.

---

# 22. Roadmap

## V1 — Detection Foundation

- Docker lab.
- HoneySSH.
- HoneyWeb.
- Event collector.
- SQLite/PostgreSQL storage.
- FastAPI.
- Basic dashboard.
- Rule-based detection.
- Attacker profiles.

## V2 — Adaptive Deception

- Dynamic decoy activation.
- Adaptive credentials.
- Dynamic synthetic hosts.
- Deception state machine.
- Risk scoring.
- Engagement scoring.
- Real-time dashboard.
- Investigation reports.

## V3 — Advanced Intelligence

- Behavioral sequence modeling.
- ML-assisted classification.
- Attack-stage inference.
- Deception strategy evaluation.
- Experiment framework.
- A/B testing of deception policies.
- Optional graph-based attacker modeling.

---

# Part II — Technical Requirements Document (TRD)

# 23. Technical Architecture

## 23.1 High-Level Architecture

```text
                     ┌───────────────────────┐
                     │     LAB ACTOR         │
                     │  controlled simulator │
                     └───────────┬───────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │      HoneyGate        │
                     │ traffic/event intake  │
                     └───────────┬───────────┘
                                 │
                ┌────────────────┼────────────────┐
                ▼                ▼                ▼
          HoneySSH          HoneyWeb          HoneyDB
                │                │                │
                └────────────────┼────────────────┘
                                 ▼
                     ┌───────────────────────┐
                     │   Event Collector     │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ Event Normalizer      │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ Feature Extractor     │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ Behavior Engine       │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ Attacker Profiler     │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ Adaptive Deception    │
                     │ Engine                │
                     └───────────┬───────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  ▼              ▼              ▼
             New service     New host       New assets
                  │              │              │
                  └──────────────┼──────────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ PostgreSQL / SQLite   │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ FastAPI               │
                     └───────────┬───────────┘
                                 ▼
                     ┌───────────────────────┐
                     │ React Dashboard       │
                     └───────────────────────┘
```

---

# 24. Technology Stack

## Backend

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- Uvicorn

## Security / Networking

- Scapy
- psutil
- standard Python networking libraries
- carefully isolated protocol simulators

## Database

### Development

SQLite

### Full deployment

PostgreSQL

## Frontend

- React
- TypeScript
- WebSocket client
- charting library

## Infrastructure

- Docker
- Docker Compose

## Testing

- pytest
- pytest-asyncio
- HTTPX

## Code Quality

- Ruff
- mypy
- pre-commit

## CI

- GitHub Actions

---

# 25. Repository Structure

```text
honeymesh/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes_events.py
│   │   │   ├── routes_attackers.py
│   │   │   ├── routes_deception.py
│   │   │   └── routes_reports.py
│   │   │
│   │   ├── behavior/
│   │   │   ├── classifier.py
│   │   │   ├── features.py
│   │   │   ├── profiler.py
│   │   │   └── scoring.py
│   │   │
│   │   ├── deception/
│   │   │   ├── engine.py
│   │   │   ├── policies.py
│   │   │   ├── state.py
│   │   │   └── orchestrator.py
│   │   │
│   │   ├── sensors/
│   │   │   ├── base.py
│   │   │   ├── ssh.py
│   │   │   ├── web.py
│   │   │   └── network.py
│   │   │
│   │   ├── database/
│   │   │   ├── models.py
│   │   │   ├── repository.py
│   │   │   └── session.py
│   │   │
│   │   ├── events/
│   │   │   ├── schema.py
│   │   │   ├── normalizer.py
│   │   │   └── bus.py
│   │   │
│   │   ├── reports/
│   │   │   └── generator.py
│   │   │
│   │   ├── config.py
│   │   └── main.py
│   │
│   └── tests/
│
├── dashboard/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── types/
│   └── package.json
│
├── lab/
│   ├── docker-compose.yml
│   ├── honeyssh/
│   ├── honeyweb/
│   ├── honeydb/
│   └── decoys/
│
├── configs/
│   ├── default.yaml
│   └── lab.yaml
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── adaptive-engine.md
│   ├── api.md
│   └── experiments.md
│
├── scripts/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── README.md
└── LICENSE
```

---

# 26. Core Components

## 26.1 Event Collector

Responsibilities:

- receive sensor events;
- timestamp events;
- attach sensor identity;
- pass events to normalizer;
- handle temporary sensor failures.

Interface:

```python
class EventCollector:
    async def collect(self) -> None:
        ...
```

---

# 27. Event Schema

Use a strongly typed model.

```python
class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source_id: str
    sensor: str
    event_type: str
    severity: str
    metadata: dict
```

Additional optional fields may include:

```text
session_id
destination
service
username
host_id
```

---

# 28. Event Processing Pipeline

```text
Raw Event
   ↓
Validation
   ↓
Normalization
   ↓
Persistence
   ↓
Feature Extraction
   ↓
Behavior Detection
   ↓
Profile Update
   ↓
Risk Update
   ↓
Policy Evaluation
   ↓
Deception Action
```

The pipeline should be asynchronous where useful.

---

# 29. Feature Extraction

Potential features:

```text
connection_count
unique_ports
unique_services
authentication_failures
authentication_successes
unique_usernames
request_rate
unique_http_paths
unique_hosts
session_duration
asset_interactions
```

Features should be normalized before scoring.

---

# 30. Behavioral Engine

The initial implementation will be rule-based.

Example conceptual logic:

```python
if failed_authentication_count >= threshold:
    behavior = "credential_attack"
```

Multiple rules may contribute to a behavior score.

Do not classify an attacker from one event alone when the behavior requires a sequence.

---

# 31. Sequence Detection

Example:

```text
service_scan
     ↓
authentication_attempts
     ↓
successful_decoy_login
     ↓
internal_asset_discovery
```

The behavior engine should be capable of recognizing sequences rather than only individual events.

Represent sequences as state transitions.

---

# 32. Attacker State Machine

Example:

```text
UNKNOWN
   ↓
RECON
   ↓
INITIAL_ACCESS
   ↓
DISCOVERY
   ↓
LATERAL_ACTIVITY
   ↓
PERSISTENCE_LIKE
```

The state machine is an **experimental behavioral model**, not an authoritative implementation of any particular threat framework.

Transitions should require configurable evidence.

---

# 33. Adaptive Deception Engine

The engine receives:

```text
AttackerProfile
CurrentDeceptionState
AvailableDecoys
PolicyConfiguration
```

and returns:

```text
DeceptionDecision
```

Example:

```python
@dataclass
class DeceptionDecision:
    action: str
    target: str
    reason: str
    confidence: float
```

Example decision:

```json
{
  "action": "activate_decoy_host",
  "target": "finance-srv",
  "reason": "discovery behavior exceeded configured threshold",
  "confidence": 0.89
}
```

---

# 34. Deception Policy Engine

Policies should be declarative where practical.

Example:

```yaml
policies:
  - name: credential_attack
    conditions:
      credential_score: ">0.70"
    actions:
      - activate_fake_credentials
      - increase_auth_telemetry

  - name: discovery
    conditions:
      discovery_score: ">0.65"
    actions:
      - activate_finance_decoy
      - activate_backup_decoy
```

---

# 35. Deception State Machine

Possible levels:

```text
LEVEL 0
Minimal deception

LEVEL 1
Basic services

LEVEL 2
Additional credentials/assets

LEVEL 3
Additional enterprise hosts

LEVEL 4
High telemetry + expanded decoys

LEVEL 5
Maximum controlled deception
```

The engine must enforce a maximum configured level.

---

# 36. Decoy Orchestration

Docker Compose should be used to start/stop approved decoy containers.

Only predefined safe images/actions should be available to the engine.

The adaptive engine must **not** construct arbitrary commands from attacker-controlled input.

Example safe abstraction:

```python
await orchestrator.activate("finance-server")
```

rather than:

```python
subprocess.run(attacker_supplied_command)
```

---

# 37. Database Design

## attackers

```text
id
first_seen
last_seen
risk_score
current_stage
status
```

## events

```text
id
timestamp
attacker_id
sensor
event_type
severity
metadata
```

## behavior_scores

```text
id
attacker_id
timestamp
recon_score
credential_score
web_score
discovery_score
lateral_score
persistence_score
```

## deception_actions

```text
id
attacker_id
timestamp
action
target
reason
confidence
previous_state
new_state
```

## sessions

```text
id
attacker_id
start_time
end_time
sensor
status
```

## decoys

```text
id
name
type
status
deception_level
```

---

# 38. API Design

Base URL:

```text
/api/v1
```

## Events

```http
GET /events
GET /events/{event_id}
```

## Attackers

```http
GET /attackers
GET /attackers/{attacker_id}
GET /attackers/{attacker_id}/timeline
```

## Behavior

```http
GET /attackers/{attacker_id}/behavior
```

## Deception

```http
GET /deception/state
GET /deception/actions
GET /deception/decoys
```

Adaptive actions should be generated by the engine rather than exposed as arbitrary shell-command endpoints.

## Reports

```http
GET /reports/{attacker_id}
```

---

# 39. WebSocket

Endpoint:

```text
/ws/events
```

Events:

```json
{
  "type": "security_event",
  "data": {}
}
```

Possible message types:

```text
security_event
attacker_updated
behavior_changed
deception_changed
risk_changed
```

---

# 40. Authentication

The dashboard/API must have authentication for administrative operations.

Recommended:

- local lab administrator account;
- strong password hashing;
- session/token-based authentication;
- secure configuration;
- no default production-like password.

The lab may use a simple local authentication system rather than an external identity provider.

---

# 41. Logging

Application logs should contain:

- timestamp;
- component;
- log level;
- event;
- correlation ID.

Sensitive data must not be unnecessarily logged.

Passwords and secrets must never be written to logs.

---

# 42. Threat Model

HoneyMesh itself must be treated as a security-sensitive application.

Threats include:

### T1 — Lab Escape

An intentionally vulnerable decoy could become a route into the host.

**Mitigation:**

- isolated Docker network;
- non-privileged containers;
- no host filesystem mounts unless strictly required;
- no host networking;
- resource limits;
- no unnecessary Linux capabilities.

### T2 — Malicious Input

Attacker-controlled data may reach the backend.

**Mitigation:**

- validation;
- parameterized queries;
- output encoding;
- strict schemas;
- no shell interpolation.

### T3 — Container Abuse

A compromised decoy could attempt lateral access.

**Mitigation:**

- isolated network;
- minimal container permissions;
- separate decoy network;
- restricted egress.

### T4 — Credential Leakage

Synthetic credentials might accidentally resemble real credentials.

**Mitigation:**

- generate clearly synthetic values;
- never use real secrets;
- scan repository for secrets.

### T5 — Denial of Service

A simulated attacker may generate excessive events.

**Mitigation:**

- rate limits;
- bounded queues;
- event retention policy;
- resource limits.

---

# 43. Security Requirements

The following are mandatory:

1. No real credentials.
2. No real customer/company data.
3. No unrestricted internet exposure.
4. No automatic counterattack.
5. No arbitrary command execution from attacker input.
6. Containers run with least privilege.
7. Database queries use parameterization/ORM.
8. API inputs are validated.
9. Dependencies are pinned or constrained.
10. CI performs security checks.

---

# 44. Testing Strategy

## Unit Tests

Test:

- event validation;
- feature extraction;
- behavior rules;
- risk scoring;
- state transitions;
- policy selection.

Example:

```text
10 failed authentication events
        ↓
credential_score increases
        ↓
credential policy selected
```

## Integration Tests

Test:

```text
sensor
 ↓
collector
 ↓
database
 ↓
behavior engine
 ↓
deception engine
```

## API Tests

Test:

- authentication;
- validation;
- event queries;
- attacker queries;
- report generation.

## Deception Tests

Verify:

- correct policy is selected;
- only approved decoys are activated;
- attacker input cannot become an executable command;
- repeated events do not cause uncontrolled deployment.

---

# 45. Experiment Framework

A major portfolio feature should be an experiment runner.

Example:

```text
Experiment A
Static deception

Experiment B
Rule-based adaptive deception

Experiment C
More aggressive adaptive deception
```

Measure:

```text
time_to_first_decoy
session_duration
decoy_interactions
assets_accessed
number_of_deception_changes
events_collected
```

The project should present results as experimental measurements, not universal claims about real attackers.

---

# 46. Performance Requirements

Target lab conditions:

- 1–10 simultaneous simulated attacker sessions.
- Event ingestion without blocking sensor processing.
- Dashboard update latency target: < 2 seconds under normal lab load.
- Adaptive decision target: < 2 seconds after sufficient evidence is available.
- Database writes must be asynchronous or buffered when necessary.

These are development targets and should be benchmarked rather than assumed.

---

# 47. Observability

HoneyMesh should expose internal metrics:

```text
events_received_total
events_processed_total
events_failed_total
active_attackers
active_decoys
deception_actions_total
average_decision_latency
database_write_latency
```

---

# 48. Configuration Management

Configuration sources, in order:

```text
Environment variables
        ↓
Configuration file
        ↓
Safe defaults
```

Secrets should come from environment variables or local secret storage.

Never commit secrets to Git.

---

# 49. Docker Requirements

Containers should:

- run as non-root where possible;
- use minimal base images;
- have explicit resource limits;
- expose only required ports;
- use dedicated Docker networks;
- avoid privileged mode;
- avoid host networking;
- avoid unnecessary volume mounts.

---

# 50. CI/CD Requirements

GitHub Actions should run:

```text
Install dependencies
       ↓
Lint
       ↓
Type check
       ↓
Unit tests
       ↓
Integration tests
       ↓
Dependency/security checks
       ↓
Build
```

Pull requests should fail if mandatory tests fail.

---

# 51. Documentation Requirements

The repository must contain:

```text
README.md
architecture.md
threat-model.md
adaptive-engine.md
api.md
experiments.md
setup.md
```

README should contain:

1. Project overview.
2. Architecture diagram.
3. Demo screenshot/GIF.
4. Quick start.
5. Technology stack.
6. Security limitations.
7. Experiment results.
8. Testing.
9. Roadmap.

---

# 52. Development Phases

## Phase 1 — Project Foundation

Deliver:

- repository;
- Python project;
- configuration;
- database;
- logging;
- Docker Compose;
- CI.

## Phase 2 — Sensors

Deliver:

- HoneySSH;
- HoneyWeb;
- event schema;
- event collector.

## Phase 3 — Detection

Deliver:

- feature extraction;
- reconnaissance detector;
- credential detector;
- web behavior detector;
- attacker profile.

## Phase 4 — Adaptive Engine

Deliver:

- risk scoring;
- policy engine;
- deception state;
- safe decoy orchestrator.

## Phase 5 — Dashboard

Deliver:

- live events;
- attacker profile;
- timeline;
- network map;
- deception state.

## Phase 6 — Reporting

Deliver:

- JSON report;
- HTML report;
- investigation timeline.

## Phase 7 — Hardening

Deliver:

- security testing;
- dependency scanning;
- container hardening;
- threat model;
- documentation.

## Phase 8 — Advanced Research

Optional:

- ML classifier;
- sequence modeling;
- deception strategy comparison;
- graph-based attacker modeling.

---

# 53. Definition of Done

HoneyMesh V2 is considered complete when:

- [ ] Docker-based lab starts successfully.
- [ ] At least three decoy services/hosts can operate.
- [ ] Events are normalized.
- [ ] Events are persisted.
- [ ] Attacker sessions are correlated.
- [ ] Behavioral scores are calculated.
- [ ] Risk scores are calculated.
- [ ] Adaptive policies operate automatically.
- [ ] At least three different deception responses work.
- [ ] Deception decisions are explainable.
- [ ] Dashboard displays real-time events.
- [ ] Investigation timeline works.
- [ ] Reports can be exported.
- [ ] Unit tests cover core logic.
- [ ] Integration tests cover the event-to-deception pipeline.
- [ ] Containers are hardened.
- [ ] No real credentials/data are used.
- [ ] No unrestricted offensive functionality exists.
- [ ] CI passes.
- [ ] Documentation is complete.

---

# 54. Resume Positioning

## Project Title

**HoneyMesh — Adaptive Cyber Deception Network**

## Resume Description

> Built an isolated Python-based adaptive deception platform that profiles attacker behavior and dynamically deploys controlled decoy services, synthetic credentials, hosts, and assets. Implemented event-driven telemetry, behavioral classification, risk scoring, adaptive deception policies, REST/WebSocket APIs, Docker-based infrastructure, automated testing, and a real-time security dashboard.

## Technologies

```text
Python • FastAPI • Scapy • Docker • PostgreSQL/SQLite
React • WebSockets • SQLAlchemy • pytest • GitHub Actions
```

---

# 55. Interview Topics This Project Should Prepare You For

A candidate should be able to explain:

### Python

- async/await;
- classes/interfaces;
- type hints;
- exception handling;
- testing;
- dependency management.

### Networking

- TCP/IP;
- ports;
- TCP connections;
- HTTP;
- DNS;
- SSH;
- packet/event monitoring.

### Cybersecurity

- honeypots;
- deception;
- reconnaissance;
- credential attacks;
- behavioral detection;
- lateral movement concepts;
- attack lifecycle;
- threat modeling.

### Software Engineering

- event-driven architecture;
- REST APIs;
- WebSockets;
- database design;
- Docker;
- CI/CD;
- observability.

### Security Engineering

- least privilege;
- network isolation;
- container hardening;
- secure input handling;
- secrets management;
- attack-surface reduction.

---

# 56. Final Architecture Principle

The central engineering principle of HoneyMesh is:

```text
             ┌─────────────────────┐
             │      ATTACKER       │
             └──────────┬──────────┘
                        │
                        ▼
                ┌───────────────┐
                │   TELEMETRY   │
                └───────┬───────┘
                        ▼
                ┌───────────────┐
                │   BEHAVIOR    │
                │   ANALYSIS    │
                └───────┬───────┘
                        ▼
                ┌───────────────┐
                │    PROFILE    │
                └───────┬───────┘
                        ▼
                ┌───────────────┐
                │   DECEPTION   │
                │    POLICY     │
                └───────┬───────┘
                        ▼
                ┌───────────────┐
                │   ENVIRONMENT │
                │    CHANGES    │
                └───────┬───────┘
                        │
                        └───────────────┐
                                        │
                                        ▼
                                  NEW TELEMETRY
                                        │
                                        └──────► LOOP
```

HoneyMesh should therefore be evaluated not simply as a honeypot, but as an **adaptive cyber-deception control loop**.

The project is successful when the system can demonstrate:

> **“The attacker changed their behavior, so HoneyMesh changed its deception.”**
