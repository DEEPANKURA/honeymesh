# HoneyMesh lab (Docker)

Isolated lab stack for the adaptive deception network. **Lab use only** - every
credential, host and asset in this stack is synthetic.

## Run

```bash
cd lab
docker compose up --build -d
```

- dashboard + API: http://127.0.0.1:8000  (sign in: `admin` / `lab-admin-pass`)
- HoneySSH decoy:   `ssh -p 2222 svc_backup@127.0.0.1`
- HoneyWeb decoy:   http://127.0.0.1:8081

Drive traffic (either from the host or with the compose attacker profile):

```bash
python scripts/attack_simulator.py --scenario full --ip 10.30.0.44 --count 40 \
  --base-url http://127.0.0.1:8000
```

```bash
docker compose --profile attack run --rm attacker
```

## Stop

```bash
docker compose down -v   # -v also drops the event database
```

## Notes

- `HONEYMESH_ADMIN_PASSWORD` and `HONEYMESH_INGEST_TOKEN` can be overridden in a
  `.env` file next to `docker-compose.yml`.
- SQLite lives in the `honeymesh-data` volume (`/app/data/honeymesh.db`); the app
  is configured for Postgres via `HONEYMESH_DATABASE__URL` if you swap it in.
- The Dockerfile builds the dashboard with Node and ships it inside the runtime
  image, so the console is served from `/` by the API process.
