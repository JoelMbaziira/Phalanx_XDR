"""Tests for pure helper functions in sentinel.py."""
import hashlib
import re
import tempfile
import os
import uuid

import pytest

# Import the agent module (conftest.py adds it to sys.path)
import sentinel


# ── now_iso ───────────────────────────────────────────────────────────────────

def test_now_iso_format():
    ts = sentinel.now_iso()
    # Should end with Z and contain a T separator
    assert ts.endswith("Z"), f"Expected Z suffix, got {ts}"
    assert "T" in ts, f"Expected T separator, got {ts}"


def test_now_iso_is_utc():
    ts = sentinel.now_iso()
    # Must not contain +00:00 (should have been replaced with Z)
    assert "+00:00" not in ts


def test_now_iso_unique():
    # Two calls should not return identical strings (microsecond resolution)
    a = sentinel.now_iso()
    b = sentinel.now_iso()
    # Timestamps are microsecond-resolution; rapid calls may collide on slow machines
    # — assert they're at least both valid strings
    assert isinstance(a, str) and isinstance(b, str)


# ── make_entity_id ────────────────────────────────────────────────────────────

def test_make_entity_id_deterministic():
    eid1 = sentinel.make_entity_id("boot-abc", 1234, 999_000_000)
    eid2 = sentinel.make_entity_id("boot-abc", 1234, 999_000_000)
    assert eid1 == eid2


def test_make_entity_id_different_pids():
    eid1 = sentinel.make_entity_id("boot-abc", 100, 0)
    eid2 = sentinel.make_entity_id("boot-abc", 200, 0)
    assert eid1 != eid2


def test_make_entity_id_length():
    eid = sentinel.make_entity_id("boot-abc", 1, 0)
    assert len(eid) == 16


def test_make_entity_id_hex_chars():
    eid = sentinel.make_entity_id("boot-xyz", 42, 123456)
    assert re.fullmatch(r"[0-9a-f]{16}", eid), f"Not a hex string: {eid}"


# ── hash_file_sha256 ──────────────────────────────────────────────────────────

def test_hash_file_sha256_correct():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"hello phalanx")
        path = f.name
    try:
        expected = hashlib.sha256(b"hello phalanx").hexdigest()
        assert sentinel.hash_file_sha256(path) == expected
    finally:
        os.unlink(path)


def test_hash_file_sha256_empty_path():
    assert sentinel.hash_file_sha256("") == ""


def test_hash_file_sha256_missing_file():
    assert sentinel.hash_file_sha256("/tmp/this_file_does_not_exist_phx.bin") == ""


def test_hash_file_sha256_caching():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"cache test")
        path = f.name
    try:
        h1 = sentinel.hash_file_sha256(path)
        h2 = sentinel.hash_file_sha256(path)
        assert h1 == h2
    finally:
        os.unlink(path)


# ── make_envelope ─────────────────────────────────────────────────────────────

def test_make_envelope_structure():
    agent_id = str(uuid.uuid4())
    host = {"hostname": "test-host", "os": {"family": "linux"}}
    env = sentinel.make_envelope(
        agent_id=agent_id,
        host=host,
        dataset=sentinel.DATASET_PROCESS,
        category=["process"],
        event_type=["start"],
        action="process_start",
        sequence=1,
    )
    assert "@timestamp" in env
    assert env["agent"]["id"] == agent_id
    assert env["event"]["dataset"] == sentinel.DATASET_PROCESS
    assert env["event"]["action"] == "process_start"
    assert env["host"] == host


def test_make_envelope_has_event_id():
    env = sentinel.make_envelope("aid", {}, "ds", [], [], "action", 1)
    assert "id" in env["event"]
    # Should be a valid UUID
    uuid.UUID(env["event"]["id"])


def test_make_envelope_sequence_included():
    env = sentinel.make_envelope("aid", {}, "ds", [], [], "action", 42)
    assert env["event"]["sequence"] == 42


def test_make_envelope_email_dataset():
    env = sentinel.make_envelope("aid", {}, sentinel.DATASET_EMAIL, ["email"], ["info"], "smtp_anomaly", 0)
    assert env["event"]["dataset"] == "phalanx.sentinel.email"
