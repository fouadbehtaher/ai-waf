# AI-Based WAF Project

This project implements a hybrid web application firewall that combines:

- request capture
- behavioral feature extraction
- deterministic rules
- anomaly-aware scoring
- persistent telemetry
- blacklist management
- reporting and dataset export
- reverse proxy forwarding to a backend service

## Project layout

```text
waf_project/
|-- core/
|   |-- __init__.py
|   |-- data_ingestion.py
|   |-- feature_engineering.py
|   |-- mitigation.py
|   |-- ml_models.py
|   |-- rate_limiter.py
|   |-- rule_engine.py
|   |-- storage.py
|-- docs/
|   |-- academic_framework.md
|   |-- deployment.md
|   |-- final_report_template.md
|   |-- final_submission_checklist.md
|   |-- literature_review.md
|   |-- presentation_outline.md
|   |-- system_architecture.md
|-- deploy/
|   |-- Dockerfile.api
|   |-- Dockerfile.frontend
|   |-- Dockerfile.sample_backend
|   |-- nginx/
|-- frontend/
|   |-- src/
|   |-- package.json
|   |-- vite.config.js
|-- scripts/
|   |-- benchmark_proxy.py
|   |-- evaluate_model.py
|   |-- export_labeled_dataset.py
|   |-- generate_academic_results.py
|   |-- migrate_sqlite_to_postgres.py
|   |-- prepare_public_dataset.py
|   |-- train_model.py
|-- tests/
|   |-- test_pipeline.py
|-- .env.production.example
|-- config.py
|-- api_server.py
|-- docker-compose.production.yml
|-- main.py
|-- sample_backend.py
|-- serve_api.py
|-- serve.py
|-- requirements.txt
|-- utils.py
```

## Core capabilities

1. Request capture with normalized metadata, payload hashing, and session hints.
2. Reverse proxy forwarding to a backend service through `/proxy/<path>`.
3. Persistent telemetry using SQLite locally and PostgreSQL in production-style deployments.
4. Token-bucket rate limiting with storage fallback and optional Redis-backed distributed state.
5. Real blacklist APIs for manual and adaptive blocking.
6. Behavioral features based on IP history, session history, fingerprint reuse, and burst pressure.
7. Hybrid scoring that blends heuristic features with an optional Isolation Forest artifact.
8. Monitoring dashboard with top attack types, top sources, latency, and recent requests.
9. CSV export and labeled-dataset export for research workflows.
10. Public-dataset normalization, training, evaluation, and latency benchmarking scripts.
11. React command center for request review, blacklist management, labeling, deletion, and runtime administration.
12. Authenticated admin API with seeded roles, session tokens, audit logs, and runtime settings management.
13. API-only deployment mode for a fully separated `Flask API + React SPA` architecture.
14. PostgreSQL-ready storage support while keeping SQLite as the default local fallback.
15. Docker, Nginx, and production env files for end-to-end deployment.

## Run locally

1. Install dependencies:

```powershell
cd waf_project
python -m pip install -r requirements.txt
```

2. Start the sample backend:

```powershell
python sample_backend.py
```

3. Build the React dashboard:

```powershell
cd frontend
npm install
npm run build
cd ..
```

4. Start the WAF:

```powershell
python main.py
```

By default, the local WAF now listens on `0.0.0.0:5000` and transparent proxy mode is enabled, so other devices on the same LAN can reach it through your machine IP.

Important:

- from the same machine you can use `http://127.0.0.1:5000/`
- from another device on the same network you must use your host IP, for example `http://192.168.69.7:5000/`
- the dashboard remains available at `http://192.168.69.7:5000/dashboard/`

For a production-style local run:

```powershell
python serve.py
```

## Run as separated API + React SPA

Backend only:

```powershell
python api_server.py
```

Or with Waitress:

```powershell
python serve_api.py
```

Frontend SPA:

```powershell
cd frontend
copy .env.example .env
npm install
npm run dev
```

If you build the SPA separately, point `VITE_API_BASE_URL` to the Flask backend.

## Admin login

The React dashboard now requires authentication. Seeded demo accounts are created automatically on a fresh database:

- `admin / Admin123!`
- `analyst / Analyst123!`
- `viewer / Viewer123!`

Role behavior:

- `viewer`: read-only dashboard access
- `analyst`: review, label, targeted block, and blacklist operations
- `admin`: full access including deletion, runtime settings, user management, and audit logs

## React development mode

You can run React separately with Vite while proxying API calls to Flask:

```powershell
cd frontend
npm install
npm run dev
```

Vite proxies `/api`, `/reports`, and `/health` to `http://127.0.0.1:5000`.

## PostgreSQL mode

SQLite remains the default. To switch to PostgreSQL, set:

```powershell
$env:WAF_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/waf_project"
python serve_api.py
```

The same variable is also honored by the export and training scripts.

## SQLite to PostgreSQL migration

Create the PostgreSQL schema and migrate data from the local SQLite database:

```powershell
python scripts/migrate_sqlite_to_postgres.py --sqlite-db data/waf.sqlite3 --postgres-url "postgresql://postgres:postgres@127.0.0.1:5432/waf_project" --truncate
```

Create only the schema:

```powershell
python scripts/migrate_sqlite_to_postgres.py --postgres-url "postgresql://postgres:postgres@127.0.0.1:5432/waf_project" --schema-only
```

## Redis-backed rate limiting

To use Redis for distributed token buckets:

```powershell
$env:WAF_REDIS_URL="redis://127.0.0.1:6379/0"
$env:WAF_RATE_LIMIT_BACKEND="redis"
python serve_api.py
```

If Redis is unavailable, the project can still run with the storage-backed fallback by setting:

```powershell
$env:WAF_RATE_LIMIT_BACKEND="storage"
```

## Production deployment files

The repository now includes:

- `docker-compose.production.yml`
- `deploy/Dockerfile.api`
- `deploy/Dockerfile.frontend`
- `deploy/Dockerfile.sample_backend`
- `deploy/nginx/frontend.conf`
- `deploy/nginx/waf-edge.conf`
- `.env.production.example`

Start the full production-style stack with Docker Compose:

```powershell
copy .env.production.example .env
# If 8080 is already occupied, change WAF_FRONTEND_PORT in .env to 8081 or any free port.
docker compose -f docker-compose.production.yml up --build
```

In the Compose deployment:

- the Flask API binds to `0.0.0.0` inside Docker for cross-container access
- the sample backend binds to `0.0.0.0` inside Docker for real proxy forwarding
- Nginx serves the React SPA and forwards `/api`, `/reports`, `/health`, `/proxy`, `/protected`, and `/inspect`

## Try it

Inspect without proxying:

```powershell
curl "http://127.0.0.1:5000/protected?message=hello"
curl "http://127.0.0.1:5000/protected?message=bad_keyword"
```

Proxy traffic to the backend:

```powershell
curl "http://127.0.0.1:5000/proxy/api/hello?name=world"
curl -X POST "http://127.0.0.1:5000/proxy/login" -H "Content-Type: application/json" -d "{\"query\":\"SELECT * FROM users\"}"
```

Open:

- `http://127.0.0.1:5000/dashboard`
- `http://127.0.0.1:5000/dashboard/`
- `http://127.0.0.1:5000/api/requests?page=1&page_size=20`
- `http://127.0.0.1:5000/reports/summary`
- `http://127.0.0.1:5000/reports/events.csv`

## Labeling and blacklist APIs

Authenticate first:

```powershell
curl -X POST "http://127.0.0.1:5000/api/auth/login" -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"Admin123!\"}"
```

Add an IP to the blacklist:

```powershell
curl -X POST "http://127.0.0.1:5000/api/blacklist" -H "Content-Type: application/json" -d "{\"ip_address\":\"127.0.0.1\",\"reason\":\"manual test\",\"ttl_seconds\":300}"
```

Label a captured request:

```powershell
curl -X POST "http://127.0.0.1:5000/api/labels/<request_id>" -H "Content-Type: application/json" -d "{\"label\":\"malicious\",\"notes\":\"validated SQLi\"}"
```

Open full request details:

```powershell
curl "http://127.0.0.1:5000/api/requests/<request_id>"
```

Delete a stored request:

```powershell
curl -X DELETE "http://127.0.0.1:5000/api/requests/<request_id>"
```

Blacklist the source IP of a specific request:

```powershell
curl -X POST "http://127.0.0.1:5000/api/requests/<request_id>/blacklist" -H "Content-Type: application/json" -d "{\"scope\":\"ip\",\"reason\":\"analyst block\",\"ttl_seconds\":900}"
```

Create a targeted block based on the selected request signature instead of blocking the whole IP:

```powershell
curl -X POST "http://127.0.0.1:5000/api/requests/<request_id>/blacklist" -H "Content-Type: application/json" -d "{\"scope\":\"signature\",\"reason\":\"block this exact request pattern\",\"ttl_seconds\":900}"
```

List active targeted block rules:

```powershell
curl "http://127.0.0.1:5000/api/manual-blocks"
```

## Research workflow

Export labeled traffic:

```powershell
python scripts/export_labeled_dataset.py
```

Normalize a public dataset into the same training schema:

```powershell
python scripts/prepare_public_dataset.py --input data/csic_raw.csv --output data/public_dataset_prepared.csv
```

Train the Isolation Forest artifact:

```powershell
python scripts/train_model.py --dataset data/labeled_requests.csv --version iforest-v1
python scripts/train_model.py --dataset data/public_dataset_prepared.csv --version iforest-public-v1
```

Evaluate the artifact:

```powershell
python scripts/evaluate_model.py --dataset data/labeled_requests.csv --artifact models/active_model.joblib
```

Benchmark latency and throughput:

```powershell
python scripts/benchmark_proxy.py --url http://127.0.0.1:5000/proxy/api/hello --requests 100 --concurrency 10
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Academic package

The following files raise the project from a prototype to a research-ready package:

- `docs/academic_framework.md`
- `docs/literature_review.md`
- `docs/deployment.md`
- `docs/system_architecture.md`
- `docs/final_report.md`
- `docs/chapters/`
- `docs/presentation_deck.md`
- `docs/references.md`
- `docs/final_submission_checklist.md`
- `reports/academic_results.json`
- `reports/academic_results.md`

They define the research questions, threat model, public dataset plan, preprocessing methodology, evaluation metrics, baseline comparison, privacy limits, and deployment plan.

Generate the consolidated academic metrics package:

```powershell
python scripts/generate_academic_results.py
```

## LAN access

The local server now binds to `0.0.0.0:5000` by default, so it can serve other devices on the same local network.

Use:

- same machine: `http://127.0.0.1:5000/`
- another device on the LAN: `http://192.168.69.7:5000/`
- dashboard from another device: `http://192.168.69.7:5000/dashboard/`

Quick start for LAN mode:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_lan.ps1
```

If Windows Firewall is blocking inbound access, run this once from an elevated PowerShell window:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\enable_windows_firewall_lan.ps1
```
