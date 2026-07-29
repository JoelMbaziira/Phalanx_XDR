"""
test_pipeline_smoke.py
─────────────────────────────────────────────────────────────────────────────
End-to-end smoke test for the Phalanx telemetry pipeline:
    phalanx-client  →  POST /api/v1/ingest  →  Redis  →  Correlator  →  DB

Safety
------
• No real dangerous tools are executed.  Every event is a fabricated JSON
  payload posted to the Ingestion API over HTTP.
• A unique TEST_AGENT_ID is used so test alerts can be distinguished from
  real operational alerts.
• Cleanup removes all alerts generated with the test agent ID at teardown.
• All tests are automatically skipped if the Ingestion API is not reachable,
  so this file is safe to run in CI environments where services are down.

Prerequisites (run on the manager host or phalanx-client)
------
  pip install requests psycopg2-binary
  # Services must be running:  Phalanx.Ingestion (:5038), Redis, Postgres

Run:  pytest tests/python/test_pipeline_smoke.py -v -s
─────────────────────────────────────────────────────────────────────────────
"""
import time
import uuid
import datetime
from typing import Optional

import pytest
import requests

# ── Configuration ─────────────────────────────────────────────────────────────

INGEST_URL  = "http://localhost:5038/api/v1/ingest"
HEALTH_URL  = "http://localhost:5038/api/v1/ingest/health"
PG_DSN      = "host=localhost dbname=phalanx_db user=phalanx_admin password=password123"

# All events injected by this test suite carry this agent ID so they can be
# identified and cleaned up without touching real operational data.
TEST_AGENT_ID = "00000000-dead-beef-0000-000000000099"

# How long (seconds) to wait for the Correlator to process an event and
# write an alert to the database.
ALERT_TIMEOUT = 10


# ── Session-scoped fixtures ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def api_up():
    """Skip the entire module if the Ingestion API is not reachable."""
    try:
        r = requests.get(HEALTH_URL, timeout=3)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    pytest.skip(
        f"Ingestion API not reachable at {HEALTH_URL} — "
        "start Phalanx.Ingestion before running smoke tests"
    )


@pytest.fixture(scope="session")
def db_conn():
    """
    Optional Postgres connection for alert verification.
    Yields None if psycopg2 is not installed or Postgres is not reachable —
    individual tests that need DB call _require_db() to skip themselves.
    Must NOT call pytest.skip() here because cleanup_test_alerts is autouse=True
    and depends on this fixture; a skip here would cascade to every test.
    """
    try:
        import psycopg2
        conn = psycopg2.connect(PG_DSN, connect_timeout=4)
        conn.autocommit = True
        yield conn
        conn.close()
    except Exception:
        yield None  # let individual tests decide to skip


def _require_db(db_conn):
    """Call at the top of any test that needs Postgres. Skips the test if DB is None."""
    if db_conn is None:
        pytest.skip("Postgres not reachable or psycopg2 not installed — "
                    "run on the manager host with docker compose up")


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_alerts(db_conn):
    """Delete all alerts created by this test session at teardown."""
    yield
    if db_conn is None:
        return
    try:
        with db_conn.cursor() as cur:
            cur.execute(
                'DELETE FROM "Alerts" WHERE "AgentId" = %s::uuid',
                (TEST_AGENT_ID,)
            )
    except Exception:
        pass  # best-effort cleanup


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def _event(dataset: str, action: str, **extra) -> dict:
    """Build a minimal valid Phalanx telemetry event envelope."""
    ev: dict = {
        "@timestamp": _ts(),
        "event": {
            "id":      str(uuid.uuid4()),
            "dataset": dataset,
            "action":  action,
        },
        "agent": {"id": TEST_AGENT_ID, "version": "test", "type": "phalanx-sentinel"},
        "host":  {"hostname": "phalanx-smoke-test"},
    }
    # Merge extra fields (e.g. "process", "file", "destination", "email")
    for key, val in extra.items():
        if key in ev and isinstance(ev[key], dict) and isinstance(val, dict):
            ev[key].update(val)
        else:
            ev[key] = val
    return ev


def post(ev: dict) -> requests.Response:
    return requests.post(INGEST_URL, json=ev, timeout=5)


def wait_for_alert(conn, rule_id: str, start: float,
                   timeout: float = ALERT_TIMEOUT,
                   agent_id: str = TEST_AGENT_ID) -> bool:
    """
    Poll Postgres until an alert for `rule_id` from `agent_id` appears,
    or `timeout` seconds elapse.  Returns True on success.
    """
    deadline = start + timeout
    while time.monotonic() < deadline:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT "Id" FROM "Alerts" '
                    'WHERE "RuleId" = %s AND "AgentId" = %s::uuid '
                    'ORDER BY "Id" DESC LIMIT 1',
                    (rule_id, agent_id),
                )
                if cur.fetchone():
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


# ── 1. API health ─────────────────────────────────────────────────────────────

def test_ingestion_health_endpoint(api_up):
    r = requests.get(HEALTH_URL, timeout=3)
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"


# ── 2. Ingestion accepts every dataset type (HTTP-level check) ────────────────

class TestIngestionAcceptsAllDatasets:
    """Verify the Ingestion controller returns 202 for every known dataset."""

    def test_process_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.process", "process_start",
                    process={"name": "ls", "pid": 9999, "entity_id": str(uuid.uuid4()),
                             "command_line": "ls -la"})
        assert post(ev).status_code == 202

    def test_file_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.file", "file_open",
                    file={"path": "/tmp/smoke-test.txt", "name": "smoke-test.txt",
                          "directory": "/tmp", "size": 12})
        assert post(ev).status_code == 202

    def test_network_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.network", "network_connection",
                    network={"transport": "tcp"},
                    source={"ip": "10.0.0.2", "port": 54321},
                    destination={"ip": "10.0.0.1", "port": 443})
        assert post(ev).status_code == 202

    def test_dns_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.dns", "dns_query",
                    dns={"type": "query", "question": {"name": "example.com", "type": "A"}})
        assert post(ev).status_code == 202

    def test_login_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.login", "login_failed",
                    **{"event": {"outcome": "failure"}},
                    user={"name": "testuser"})
        assert post(ev).status_code == 202

    def test_memory_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.memory", "memory_anonymous_rwx_region",
                    process={"name": "python3", "pid": 8888},
                    memory={"indicator": "anonymous_rwx_region", "address": "0x7f0000"})
        assert post(ev).status_code == 202

    def test_email_event_accepted(self, api_up):
        ev = _event("phalanx.sentinel.email", "email_client_shell",
                    email={"indicator_type": "phishing",
                           "detail": "smoke test"},
                    process={"name": "thunderbird", "child_name": "bash"})
        assert post(ev).status_code == 202

    def test_sensor_scan_event_accepted(self, api_up):
        ev = _event("phalanx.sensor.scan", "port_scan_detected",
                    source={"ip": "192.168.1.50"})
        assert post(ev).status_code == 202

    def test_sensor_beacon_event_accepted(self, api_up):
        ev = _event("phalanx.sensor.beacon", "beacon_detected",
                    source={"ip": "192.168.1.51"},
                    destination={"ip": "203.0.113.10"})
        assert post(ev).status_code == 202

    def test_sensor_dns_event_accepted(self, api_up):
        ev = _event("phalanx.sensor.dns", "dns_query",
                    dns={"dga_score": 0.9, "question": {"name": "xn--qxam.example.com"}})
        assert post(ev).status_code == 202


# ── 3. End-to-end alert creation (requires Correlator + DB) ──────────────────

class TestAlertCreation:
    """
    Inject a triggering event and verify the Correlator produces an Alert
    in the database.  Tests skip if DB is unavailable.
    """

    def test_phx001_credential_dump_alert_created(self, api_up, db_conn):
        _require_db(db_conn)
        t0 = time.monotonic()
        ev = _event("phalanx.sentinel.process", "process_start",
                    process={"name": "mimikatz", "pid": 1001,
                             "entity_id": str(uuid.uuid4()),
                             "command_line": "mimikatz.exe"})
        assert post(ev).status_code == 202
        assert wait_for_alert(db_conn, "PHX-001", t0), \
            f"No PHX-001 alert found in DB within {ALERT_TIMEOUT}s after injecting mimikatz event"

    def test_phx002_exploitation_framework_alert_created(self, api_up, db_conn):
        _require_db(db_conn)
        t0 = time.monotonic()
        ev = _event("phalanx.sentinel.process", "process_start",
                    process={"name": "msfconsole", "pid": 1002,
                             "entity_id": str(uuid.uuid4()),
                             "command_line": "msfconsole -q"})
        assert post(ev).status_code == 202
        assert wait_for_alert(db_conn, "PHX-002", t0), \
            f"No PHX-002 alert found within {ALERT_TIMEOUT}s"

    def test_phx200_email_client_shell_alert_created(self, api_up, db_conn):
        _require_db(db_conn)
        t0 = time.monotonic()
        ev = _event("phalanx.sentinel.email", "email_client_shell",
                    email={"indicator_type": "phishing",
                           "detail": "thunderbird spawned bash",
                           "attachment": {"name": "invoice.ps1", "hash": ""}},
                    process={"name": "thunderbird", "child_name": "bash",
                             "pid": 1003, "child_pid": 1004})
        assert post(ev).status_code == 202
        assert wait_for_alert(db_conn, "PHX-200", t0), \
            f"No PHX-200 alert found within {ALERT_TIMEOUT}s"

    def test_phx202_suspicious_attachment_alert_created(self, api_up, db_conn):
        _require_db(db_conn)
        t0 = time.monotonic()
        ev = _event("phalanx.sentinel.email", "suspicious_attachment",
                    email={"indicator_type": "malware_attachment",
                           "detail": "Suspicious file in /tmp: backdoor.exe",
                           "attachment": {"name": "backdoor.exe", "hash": ""}})
        assert post(ev).status_code == 202
        assert wait_for_alert(db_conn, "PHX-202", t0), \
            f"No PHX-202 alert found within {ALERT_TIMEOUT}s"

    def test_phx300_port_scan_alert_created(self, api_up, db_conn):
        _require_db(db_conn)
        t0 = time.monotonic()
        ev = _event("phalanx.sensor.scan", "port_scan_detected",
                    source={"ip": "192.168.1.99"},
                    destination={"ip": "192.168.1.0/24"})
        assert post(ev).status_code == 202
        assert wait_for_alert(db_conn, "PHX-300", t0), \
            f"No PHX-300 alert found within {ALERT_TIMEOUT}s"


# ── 4. Correlate rule smoke test (PHX-100: discovery burst) ───────────────────

class TestCorrelateRuleSmoke:
    """Inject the minimum required event count to fire a correlate rule."""

    def test_phx100_discovery_burst_fires_on_third_event(self, api_up, db_conn):
        """
        PHX-100 requires 3 discovery commands from the same agent within 60s.
        We inject 3 events and verify an alert appears.
        """
        _require_db(db_conn)
        t0 = time.monotonic()
        agent_id_override = str(uuid.uuid4())  # unique per test run to avoid interference
        for i, proc_name in enumerate(["whoami", "id", "hostname"]):
            ev = _event("phalanx.sentinel.process", "process_start",
                        process={"name": proc_name, "pid": 2000 + i,
                                 "entity_id": str(uuid.uuid4()),
                                 "command_line": proc_name})
            # Override agent.id for this specific correlate test
            ev["agent"]["id"] = agent_id_override
            ev["host"]["hostname"] = f"smoke-{agent_id_override[:8]}"
            resp = post(ev)
            assert resp.status_code == 202, f"Event {i+1} rejected: {resp.text}"
            time.sleep(0.1)  # slight gap so timestamps differ

        assert wait_for_alert(db_conn, "PHX-100", t0, timeout=15,
                              agent_id=agent_id_override), \
            f"PHX-100 alert not found within 15s after 3-event discovery burst"


# ── 5. Policy dispatch smoke test (POL-002: kill_process, live fire) ──────────

class TestPolicyDispatch:
    """
    Verify that POL-002 (kill_process, dry_run=false) creates a PolicyDispatch
    row for a PHX-002 alert. We do NOT verify actual process termination here
    since the sentinel agent is not running during these tests.
    """

    def test_pol002_dispatch_recorded_for_phx002(self, api_up, db_conn):
        _require_db(db_conn)
        t0 = time.monotonic()
        entity_id = str(uuid.uuid4())
        ev = _event("phalanx.sentinel.process", "process_start",
                    process={"name": "sliver", "pid": 3001,
                             "entity_id": entity_id,
                             "command_line": "sliver"})
        assert post(ev).status_code == 202

        # Wait for alert first
        assert wait_for_alert(db_conn, "PHX-002", t0, timeout=ALERT_TIMEOUT), \
            "PHX-002 alert not created — can't check policy dispatch"

        # Then wait for PolicyDispatch row (PolicyEngine needs one more cycle)
        deadline = time.monotonic() + ALERT_TIMEOUT
        found = False
        while time.monotonic() < deadline:
            try:
                with db_conn.cursor() as cur:
                    cur.execute(
                        'SELECT "Outcome" FROM "PolicyDispatches" '
                        'WHERE "PolicyId" = %s ORDER BY "Id" DESC LIMIT 1',
                        ("POL-002",),
                    )
                    row = cur.fetchone()
                    if row:
                        outcome = row[0]
                        assert outcome in ("dispatched", "rate_limited", "error"), \
                            f"Unexpected dispatch outcome: {outcome}"
                        found = True
                        break
            except Exception:
                pass
            time.sleep(0.5)

        assert found, \
            f"No PolicyDispatch row for POL-002 found within {ALERT_TIMEOUT}s"
