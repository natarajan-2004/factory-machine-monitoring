# Factory Machine Monitoring Platform

A runnable educational full-stack industrial monitoring demo based on the uploaded *Industrial Engineering Project Training Roadmap*. It includes a React + TypeScript dashboard, FastAPI REST API, PostgreSQL persistence, Redis live-state cache, WebSocket updates, role-aware actions, alarm acknowledgement, audit events, a telemetry simulator, Docker deployment, and tests.

> **Safety note:** This is a demo and simulator. It is not a certified SCADA/control system and must not be connected to real machinery or used for safety-critical control.

## Quick start (Docker recommended)

Requirements: Docker Desktop (or Docker Engine + Compose) running.

1. Extract the ZIP and open a terminal in `factory-machine-monitoring`.
2. Start everything:
   ```bash
   docker compose up --build
   ```
3. Open the dashboard at **http://localhost:5173**.
4. API docs are at **http://localhost:8000/docs** and health at **http://localhost:8000/health**.

Demo accounts (change these before any shared deployment):

| Role | Email | Password |
|---|---|---|
| Admin | admin@factory.local | Admin123! |
| Operator | operator@factory.local | Operator123! |
| Maintenance | maintenance@factory.local | Maint123! |

The demo seeds three simulated machines and sample telemetry/alarms on first startup. The simulator updates machine readings every 3 seconds. Alarm acknowledge actions are recorded in the audit log.

## Local development without Docker

### Backend
Python 3.11+ recommended.

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
# SQLite fallback is used if DATABASE_URL is not set.
uvicorn app.main:app --reload --port 8000
```

### Frontend
Node.js 20+ recommended.

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api`, `/auth`, `/ws`, and `/health` to `http://localhost:8000`. For local development without Docker, the backend defaults to SQLite and a local in-memory fallback when Redis is not available.

## Main features

- Overview cards for total, running, stopped, and faulted machines.
- Machine list with status, temperature, vibration, RPM, and last update.
- Machine detail with recent telemetry history.
- Live updates via WebSocket, with periodic REST refresh fallback.
- Alarm severity and lifecycle (active / acknowledged / cleared).
- Role-aware access: admin manages users, operator acknowledges alarms, maintenance can acknowledge alarms.
- Audit trail for sign-ins and alarm acknowledgement.
- Health endpoint, structured application logging, simulator, API validation, and automated tests.

## API outline

- `POST /auth/login` — obtain bearer token.
- `GET /auth/me` — current user and role.
- `GET /api/dashboard` — dashboard counts.
- `GET /api/machines` — machine list.
- `GET /api/machines/{id}` — machine details and recent telemetry.
- `GET /api/alarms` — alarm list.
- `POST /api/alarms/{id}/acknowledge` — acknowledge an active alarm.
- `GET /api/audit` — recent audit events (admin/maintenance).
- `GET /api/users` and `POST /api/users` — admin-only user management.
- `WS /ws/live?token=...` — live machine/alarm snapshots.

## Project layout

```text
backend/
  app/main.py          API, models, auth, simulator, websocket
  requirements.txt
  Dockerfile
  tests/test_api.py
frontend/
  src/App.tsx          Dashboard UI
  src/main.tsx
  src/styles.css
  Dockerfile
  nginx.conf
compose.yaml
```

## Notes before production

This repository is an educational starting point, not a production-certified system. Before real deployment: use a strong secret manager, HTTPS/TLS, secure cookies or a reviewed token strategy, migrations, backups, rate limits, hardened CORS, monitoring, threat modelling, dependency scanning, and independent security/safety reviews. Do not use the included demo passwords or secret in production. Redis is used for a best-effort live-state cache; PostgreSQL remains the persistent record. The simulator intentionally generates synthetic values, not real sensor data.
