# Phalanx XDR — Setup & Run Guide

## Architecture

```
sentinel.py (victim VM)
    ↓ HTTP POST — every new process
Phalanx.Ingestion (port 5038)
    ↓ pushes to Redis queue: "telemetry_stream"
Phalanx.Correlator (background service)
    ↓ detection rules → saves Alert to PostgreSQL
    ↓ pushes via SignalR
Phalanx.Console (port 5100)
    ↓ dashboard — real-time alerts via SignalR WebSocket
```

---

## Step 1 — Start infrastructure (Ubuntu/Wazuh VM)

```bash
cd infrastructure/
docker compose up -d
# Verify: Redis on :6379, Postgres on :5432, Adminer on :8080
```

---

## Step 2 — Start Phalanx.Ingestion

```bash
cd backend/Phalanx.Ingestion
dotnet run
# Listening on http://localhost:5038
# Test: curl http://localhost:5038/api/v1/ingest/health
```

---

## Step 3 — Start Phalanx.Correlator

```bash
cd backend/Phalanx.Correlator
dotnet run
# Will auto-create DB tables and start watching Redis
```

---

## Step 4 — Start Phalanx.Console

```bash
cd backend/Phalanx.Console
dotnet run --urls "http://localhost:5100"
# Open http://localhost:5100 in browser
```

---

## Step 5 — Deploy Sentinel agent (on victim VM)

```bash
cd agents/sentinel-py
pip install -r requirements.txt   # psutil, requests
python3 sentinel.py --api http://<MANAGER_IP>:5038/api/v1/ingest
```

To point at a remote manager:
```bash
python3 sentinel.py --api http://192.168.245.129:5038/api/v1/ingest
```

---

## Step 6 — Trigger alerts from Kali (attacker VM)

SSH into the victim or run these directly on the victim to generate alerts:

```bash
# Reconnaissance — fires Medium alert (T1046)
nmap -sV localhost

# Discovery — fires Low alert (T1033)
whoami && id && hostname

# Download tool — fires Medium alert (T1105)
wget http://example.com -O /tmp/test

# High-severity: credential tool simulation
# (just running the binary name is enough to trigger)
```

All alerts appear in the Console dashboard in real time.

---

## Detection rules

| Process | Severity | MITRE |
|---------|----------|-------|
| mimikatz | Critical | T1003 - Credential Dumping |
| msfconsole | Critical | T1190 - Exploitation |
| psexec | High | T1035 - Lateral Movement |
| hydra | High | T1110 - Brute Force |
| nmap | Medium | T1046 - Network Scanning |
| wget/curl | Medium | T1105 - Ingress Tool Transfer |
| powershell | Medium | T1059.001 - Scripting |
| whoami/id | Low | T1033 - Discovery |

---

## Database — view alerts directly

Open Adminer at http://localhost:8080
- Server: `db`
- User: `phalanx_admin`
- Password: `password123`
- Database: `phalanx_db`

---

## Bugs fixed in this version

1. **Queue name mismatch** — Ingestion pushed to `telemetry_queue`, Correlator read from `telemetry_stream`. Now unified to `telemetry_stream`.
2. **Redis connection-per-request** — Ingestion was opening a new Redis connection on every HTTP request. Now uses DI singleton.
3. **SignalR hub was empty** — `AlertHub` had no methods. Correlator could not push real-time alerts. Fixed.
4. **Correlator never pushed to SignalR** — Alerts were saved to DB but never broadcast to the browser. Fixed.
5. **Alert model mismatch** — Correlator `Alert` had more fields than Console `Alert`, causing silent data loss. Fixed.
6. **Ingestion controller registration missing** — `Program.cs` didn't call `AddControllers()`, so the API returned 404 on all routes. Fixed.
7. **Agent ID regenerated on restart** — `sentinel.py` used `uuid4()` every run, so each restart appeared as a new agent. Now persisted to disk.
8. **No retry logic in sentinel** — Any network hiccup dropped events permanently. Now retries twice.
9. **Docker Redis had no persistence** — Data lost on container restart. Added AOF persistence.
10. **Detection rule set too small** — Only 5 processes covered. Expanded to 30+ with severity and MITRE mapping.
