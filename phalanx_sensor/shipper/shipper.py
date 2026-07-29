"""
Phalanx Shipper — buffers events locally and ships to the remote server.

Design:
  - Every event written to SQLite first (local buffer)
  - Background thread reads unsent events and POSTs to server
  - On network failure: keeps buffering, retries with exponential backoff
  - On reconnect: drains buffer in order (no events lost)
  - Batches events for efficiency (up to 50 per HTTP request)
  - Gzip compression to save bandwidth (critical for MiFi deployments)
"""

from __future__ import annotations
import gzip
import json
import logging
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("shipper")


class EventBuffer:
    """SQLite-backed event queue. Survives process restarts."""

    def __init__(self, db_path: str = "/var/lib/phalanx/buffer.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload   TEXT    NOT NULL,
                    dataset   TEXT    NOT NULL DEFAULT '',
                    queued_at REAL    NOT NULL,
                    shipped   INTEGER NOT NULL DEFAULT 0,
                    attempts  INTEGER NOT NULL DEFAULT 0
                )
            """)
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_unshipped ON events (shipped, id)"
            )
            self._conn.commit()

    def push(self, event: dict):
        payload = json.dumps(event, separators=(",", ":"))
        dataset = event.get("event", {}).get("dataset", "")
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (payload, dataset, queued_at) VALUES (?, ?, ?)",
                (payload, dataset, time.time())
            )
            self._conn.commit()

    def peek(self, limit: int = 50) -> list[tuple[int, str]]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, payload FROM events WHERE shipped=0 ORDER BY id LIMIT ?",
                (limit,)
            ).fetchall()

    def mark_shipped(self, ids: list[int]):
        with self._lock:
            self._conn.execute(
                f"UPDATE events SET shipped=1 WHERE id IN ({','.join('?'*len(ids))})",
                ids
            )
            self._conn.commit()

    def mark_failed(self, ids: list[int]):
        with self._lock:
            self._conn.execute(
                f"UPDATE events SET attempts=attempts+1 WHERE id IN ({','.join('?'*len(ids))})",
                ids
            )
            self._conn.commit()

    def pending_count(self) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE shipped=0"
            ).fetchone()[0]

    def prune(self, keep_last: int = 50_000):
        with self._lock:
            self._conn.execute(f"""
                DELETE FROM events WHERE shipped=1 AND id NOT IN (
                    SELECT id FROM events WHERE shipped=1 ORDER BY id DESC LIMIT {keep_last}
                )
            """)
            self._conn.commit()

    def close(self):
        self._conn.close()


class Shipper:
    """
    Drains the EventBuffer to the Phalanx ingestion API.

    Usage:
        shipper = Shipper(endpoint="http://host:5038/api/v1/ingest/batch", node_id="uuid")
        shipper.start()
        shipper.enqueue(event_dict)   # from any thread, never blocks
    """

    def __init__(self,
                 endpoint:        str,
                 node_id:         str,
                 buffer_path:     str   = "/var/lib/phalanx/buffer.db",
                 batch_size:      int   = 50,
                 flush_interval:  float = 2.0,
                 max_backoff:     float = 60.0,
                 compress:        bool  = True):

        self._endpoint       = endpoint
        self._node_id        = node_id
        self._batch_size     = batch_size
        self._flush_interval = flush_interval
        self._max_backoff    = max_backoff
        self._compress       = compress

        self._buffer   = EventBuffer(buffer_path)
        self._running  = False
        self._thread:  threading.Thread | None = None

        # Stats — guarded by _stats_lock for cross-thread safety
        self._stats_lock = threading.Lock()
        self.shipped   = 0
        self.failed    = 0
        self.buffered  = self._buffer.pending_count()

        self._backoff   = 1.0
        self._reachable = True

    def enqueue(self, event: dict):
        """Add an event to the local buffer. Thread-safe. Never blocks."""
        try:
            self._buffer.push(event)
            with self._stats_lock:
                self.buffered += 1
        except Exception as e:
            log.error(f"Buffer write: {e}")

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True, name="shipper")
        self._thread.start()
        log.info(f"Shipper → {self._endpoint}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        try:
            self._flush_once()
        except Exception:
            pass
        self._buffer.close()

    def pending(self) -> int:
        return self._buffer.pending_count()

    def stats(self) -> dict:
        with self._stats_lock:
            return {
                "shipped":   self.shipped,
                "failed":    self.failed,
                "buffered":  self.buffered,
                "pending":   self.pending(),
                "reachable": self._reachable,
            }

    def _loop(self):
        while self._running:
            try:
                self._flush_once()
            except Exception as e:
                log.error(f"Flush: {e}")

            pending = self._buffer.pending_count()
            if pending == 0:
                time.sleep(self._flush_interval)
            elif self._reachable:
                time.sleep(0.5 if pending > 10 else self._flush_interval)
            else:
                time.sleep(min(self._backoff, self._max_backoff))

    def _flush_once(self):
        rows = self._buffer.peek(self._batch_size)
        if not rows:
            return
        ids    = [r[0] for r in rows]
        events = [json.loads(r[1]) for r in rows]
        if self._ship(events):
            self._buffer.mark_shipped(ids)
            with self._stats_lock:
                self.shipped += len(ids)
                self.buffered = max(0, self.buffered - len(ids))
                do_prune = (self.shipped % 10_000 == 0)
            self._backoff  = 1.0
            self._reachable = True
            if do_prune:
                self._buffer.prune()
        else:
            self._buffer.mark_failed(ids)
            with self._stats_lock:
                self.failed += len(ids)
            self._reachable = False
            self._backoff = min(self._backoff * 2, self._max_backoff)

    def _ship(self, events: list[dict]) -> bool:
        body = json.dumps(
            {"node_id": self._node_id, "count": len(events), "events": events},
            separators=(",", ":")
        ).encode()

        headers = {
            "Content-Type": "application/json",
            "X-Node-Id":    self._node_id,
        }
        if self._compress:
            body = gzip.compress(body, compresslevel=6)
            headers["Content-Encoding"] = "gzip"

        req = urllib.request.Request(
            self._endpoint, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                ok = r.status in (200, 202)
                if ok:
                    log.debug(f"Shipped {len(events)} events")
                return ok
        except urllib.error.URLError as e:
            log.debug(f"Unreachable ({e.reason}) — buffering")
            return False
        except Exception as e:
            log.warning(f"Ship error: {e}")
            return False
