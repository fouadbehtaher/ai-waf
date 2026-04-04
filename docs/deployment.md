# Deployment Notes

## Local development

1. Start the sample backend:

```powershell
python sample_backend.py
```

2. Start the WAF:

```powershell
python main.py
```

3. Optional React development server:

```powershell
cd frontend
npm run dev
```

The Vite server proxies `/api`, `/reports`, and `/health` back to Flask.

## Separated deployment

Backend API only:

```powershell
python serve_api.py
```

Frontend SPA:

```powershell
cd frontend
copy .env.example .env
npm install
npm run build
```

Serve the resulting `frontend/dist` folder from Nginx or any static host, and point `VITE_API_BASE_URL` to the Flask backend origin.

## PostgreSQL configuration

```powershell
$env:WAF_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:5432/waf_project"
python serve_api.py
```

If `WAF_DATABASE_URL` is not set, the application uses the local SQLite database file.

## Redis-backed rate limiting

```powershell
$env:WAF_REDIS_URL="redis://127.0.0.1:6379/0"
$env:WAF_RATE_LIMIT_BACKEND="redis"
python serve_api.py
```

If Redis is not available, use:

```powershell
$env:WAF_RATE_LIMIT_BACKEND="storage"
```

## Data migration

```powershell
python scripts/migrate_sqlite_to_postgres.py --sqlite-db data/waf.sqlite3 --postgres-url "postgresql://postgres:postgres@127.0.0.1:5432/waf_project" --truncate
```

## Docker Compose stack

```powershell
copy .env.production.example .env
# If port 8080 is already used on your machine:
# set WAF_FRONTEND_PORT=8081 inside .env
docker compose -f docker-compose.production.yml up --build
```

This stack includes:

- PostgreSQL
- Redis
- Flask WAF API
- sample backend
- React frontend served by Nginx

The frontend host port is configurable through `WAF_FRONTEND_PORT`, which avoids local conflicts with tools already using `8080`.
Inside Docker, both the WAF API and the sample backend bind to `0.0.0.0` so the containers can communicate reliably.
The frontend Nginx layer forwards `/api`, `/reports`, `/health`, `/proxy`, `/protected`, and `/inspect` to the WAF API.

## Production-style local run

Use Waitress instead of the Flask development server:

```powershell
python serve.py
```

## Suggested Nginx fronting pattern

```nginx
server {
    listen 80;
    server_name localhost;

    location /dashboard {
        proxy_pass http://127.0.0.1:5000/dashboard;
    }

    location /reports/ {
        proxy_pass http://127.0.0.1:5000/reports/;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:5000/api/;
    }

    location / {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Recommended production upgrades

- move SQLite to PostgreSQL or Elasticsearch for larger workloads
- replace the local token bucket store with Redis for distributed rate limiting
- run multiple WAF instances behind Nginx
- replace demo seeded users with environment-managed secrets or SSO
- add centralized logging and alerting
