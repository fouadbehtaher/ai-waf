# Appendices

## A. Reproducibility commands

### Local embedded mode

```powershell
cd C:\Users\tamat\OneDrive\Desktop\wafai\waf_project
python -m pip install -r requirements.txt
python sample_backend.py
python main.py
```

### Production-style Docker mode

```powershell
cd C:\Users\tamat\OneDrive\Desktop\wafai\waf_project
copy .env.production.example .env
# Optional: change WAF_FRONTEND_PORT if 8080 is occupied
docker compose -f docker-compose.production.yml up --build
```

### Frontend development mode

```powershell
cd C:\Users\tamat\OneDrive\Desktop\wafai\waf_project\frontend
copy .env.example .env
npm install
npm run dev
```

## B. Accounts

### Local embedded mode

- `admin / Admin123!`
- `analyst / Analyst123!`
- `viewer / Viewer123!`

### Docker production-style mode

- `admin / ChangeMeAdmin123!`
- `analyst / ChangeMeAnalyst123!`
- `viewer / ChangeMeViewer123!`

## C. Generated evidence files

- [academic_results.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/academic_results.json)
- [academic_results.md](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/academic_results.md)
- [benchmark_summary_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_summary_local.json)
- [benchmark_summary.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_summary.json)
- [benchmark_inspect_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_inspect_local.json)
- [benchmark_inspect_docker.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/benchmark_inspect_docker.json)
- [rate_limit_stress.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/rate_limit_stress.json)
- [test_results.txt](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/test_results.txt)
- [health_local.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_local.json)
- [health_docker.json](C:/Users/tamat/OneDrive/Desktop/wafai/waf_project/reports/health_docker.json)

## D. Core endpoints

- `/dashboard/`
- `/health`
- `/inspect`
- `/protected`
- `/proxy/<path>`
- `/api/auth/login`
- `/api/requests`
- `/api/blacklist`
- `/api/manual-blocks`
- `/api/admin/settings`
- `/api/admin/users`
- `/api/admin/audit`

## E. Regenerating the academic package

```powershell
cd C:\Users\tamat\OneDrive\Desktop\wafai\waf_project
python scripts\generate_academic_results.py
```

## F. Stopping background services

### Local embedded mode

```powershell
Stop-Process -Id (Get-Content C:\Users\tamat\OneDrive\Desktop\wafai\waf_project\.server.pid)
```

### Local sample backend

```powershell
Stop-Process -Id (Get-Content C:\Users\tamat\OneDrive\Desktop\wafai\waf_project\.sample_backend.pid)
```

### Docker mode

```powershell
cd C:\Users\tamat\OneDrive\Desktop\wafai\waf_project
docker compose -f docker-compose.production.yml down
```
