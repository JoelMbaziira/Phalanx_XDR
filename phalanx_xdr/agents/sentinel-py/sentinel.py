"""
Phalanx XDR — Sentinel Agent v0.3
Multi-domain telemetry: process, file, network, DNS, login, memory.
Polls a command channel for response actions (kill, isolate, quarantine).

Run: python3 sentinel.py --api http://<MANAGER>:5038/api/v1/ingest
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import psutil
import requests

# Process names that are shells or interpreters. When a process has one of
# these names the *script* being run is more meaningful than the interpreter.
_INTERPRETERS = {
    "bash", "sh", "dash", "zsh", "ksh", "fish",
    "python", "python2", "python3",
    "perl", "ruby", "node", "nodejs", "php",
}

def effective_process_name(proc) -> str:
    """Return a meaningful name even when the process is an interpreter."""
    name = proc.name()
    if name.lower() in _INTERPRETERS:
        cmdline = safe_attr(proc, "cmdline") or []
        # Skip the interpreter itself (index 0) and any flags (start with -)
        for arg in cmdline[1:]:
            if not arg.startswith("-"):
                return Path(arg).stem or name   # stem strips .py/.sh/.pl etc.
    return name

SENTINEL_VERSION = "0.4.0"
DATASET_PROCESS = "phalanx.sentinel.process"
DATASET_FILE    = "phalanx.sentinel.file"
DATASET_NETWORK = "phalanx.sentinel.network"
DATASET_DNS     = "phalanx.sentinel.dns"
DATASET_LOGIN   = "phalanx.sentinel.login"
DATASET_MEMORY  = "phalanx.sentinel.memory"
DATASET_EMAIL   = "phalanx.sentinel.email"

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Phalanx Sentinel Agent")
    p.add_argument("--api",          default="http://localhost:5038/api/v1/ingest")
    p.add_argument("--interval",     type=float, default=0.5,
                   help="Process poll interval (seconds)")
    p.add_argument("--net-interval", type=float, default=2.0,
                   help="File/network/DNS/login/memory poll interval (seconds)")
    p.add_argument("--cmd-poll",     type=float, default=5.0,
                   help="Response command poll interval (seconds)")
    p.add_argument("--agent-id",     default=None)
    p.add_argument("--state-dir",    default="/var/lib/phalanx")
    return p.parse_args()

# ── State ─────────────────────────────────────────────────────────────────────

def state_dir(preferred: str) -> Path:
    for candidate in (preferred, os.path.expanduser("~/.phalanx"), "/tmp/.phalanx"):
        try:
            p = Path(candidate)
            p.mkdir(parents=True, exist_ok=True)
            t = p / ".write_test"
            t.write_text("ok")
            t.unlink()
            return p
        except Exception:
            continue
    raise RuntimeError("No writable state directory")

def get_or_create_agent_id(state: Path) -> str:
    f = state / "agent_id"
    if f.exists():
        return f.read_text().strip()
    aid = str(uuid.uuid4())
    f.write_text(aid)
    return aid

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def read_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except Exception:
        return str(uuid.uuid4())

def read_os_release() -> dict:
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k.strip()] = v.strip().strip('"')
    except Exception:
        pass
    return info

def get_host_ips() -> list:
    try:
        return [
            a.address
            for iface in psutil.net_if_addrs().values()
            for a in iface
            if a.family == socket.AF_INET and not a.address.startswith("127.")
        ]
    except Exception:
        return []

def build_host_context() -> dict:
    osr = read_os_release()
    return {
        "hostname": socket.gethostname(),
        "os": {
            "family":   platform.system().lower(),
            "kernel":   platform.release(),
            "platform": osr.get("ID", platform.system().lower()),
            "version":  osr.get("VERSION_ID", platform.version()),
        },
        "architecture": platform.machine(),
        "ip":      get_host_ips(),
        "boot_id": read_boot_id(),
    }

@lru_cache(maxsize=4096)
def detect_package(exe_path: str) -> dict:
    if not exe_path:
        return {}
    try:
        r = subprocess.run(["dpkg", "-S", exe_path],
                           capture_output=True, text=True, timeout=2)
        if r.returncode == 0 and ":" in r.stdout:
            pkg = r.stdout.split(":", 1)[0].strip()
            v = subprocess.run(["dpkg-query", "-W", "-f=${Version}", pkg],
                               capture_output=True, text=True, timeout=2)
            if v.returncode == 0:
                return {"name": pkg, "version": v.stdout.strip()}
    except Exception:
        pass
    try:
        r = subprocess.run(["rpm", "-qf", "--qf=%{NAME}|%{VERSION}", exe_path],
                           capture_output=True, text=True, timeout=2)
        if r.returncode == 0 and "|" in r.stdout:
            n, v = r.stdout.split("|", 1)
            return {"name": n, "version": v}
    except Exception:
        pass
    return {}

_hash_cache: dict = {}

def hash_file_sha256(path: str) -> str:
    if not path:
        return ""
    try:
        st = os.stat(path)
        key = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
        if key in _hash_cache:
            return _hash_cache[key]
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        d = h.hexdigest()
        _hash_cache[key] = d
        if len(_hash_cache) > 8192:
            _hash_cache.pop(next(iter(_hash_cache)))
        return d
    except Exception:
        return ""

def make_entity_id(boot_id: str, pid: int, start_ns: int) -> str:
    raw = f"{boot_id}:{pid}:{start_ns}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]

def safe_attr(proc, attr, default=None):
    try:
        return getattr(proc, attr)()
    except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
        return default

def proc_summary(proc, boot_id: str) -> dict | None:
    try:
        with proc.oneshot():
            start_ns = int(proc.create_time() * 1_000_000_000)
            return {
                "pid":        proc.pid,
                "entity_id":  make_entity_id(boot_id, proc.pid, start_ns),
                "name":       proc.name(),
                "executable": safe_attr(proc, "exe") or "",
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def build_ancestry(proc, boot_id: str, limit: int = 16) -> list:
    chain = []
    try:
        cur = proc.parent()
        while cur is not None and len(chain) < limit:
            s = proc_summary(cur, boot_id)
            if s is None:
                break
            chain.append(s)
            if cur.pid == 1:
                break
            cur = cur.parent()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return chain

def build_user(proc) -> dict:
    user = {}
    try:
        with proc.oneshot():
            uname = safe_attr(proc, "username", "")
            uids  = safe_attr(proc, "uids")
            gids  = safe_attr(proc, "gids")
        if uname:
            user["name"] = uname
        if uids:
            user["id"] = str(uids.real)
            user["effective"] = {"id": str(uids.effective)}
            try:
                import pwd
                user["effective"]["name"] = pwd.getpwuid(uids.effective).pw_name
            except Exception:
                pass
        if gids:
            user["group"] = {"id": str(gids.real)}
            try:
                import grp
                user["group"]["name"] = grp.getgrgid(gids.real).gr_name
            except Exception:
                pass
    except Exception:
        pass
    return user

def make_envelope(agent_id: str, host: dict, dataset: str,
                  category: list, event_type: list, action: str,
                  sequence: int) -> dict:
    return {
        "@timestamp": now_iso(),
        "event": {
            "id":       str(uuid.uuid4()),
            "kind":     "event",
            "category": category,
            "type":     event_type,
            "action":   action,
            "dataset":  dataset,
            "sequence": sequence,
        },
        "agent": {
            "id":      agent_id,
            "version": SENTINEL_VERSION,
            "type":    "phalanx-sentinel",
        },
        "host": host,
    }

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 1 — Process events
# ─────────────────────────────────────────────────────────────────────────────

def build_process_event(proc, host: dict, agent_id: str, sequence: int) -> dict | None:
    boot_id = host.get("boot_id", "")
    try:
        with proc.oneshot():
            start_time = proc.create_time()
            start_ns   = int(start_time * 1_000_000_000)
            start_iso  = datetime.fromtimestamp(start_time, tz=timezone.utc) \
                .isoformat(timespec="microseconds").replace("+00:00", "Z")
            exe  = safe_attr(proc, "exe") or ""
            args = safe_attr(proc, "cmdline") or [proc.name()]
            cwd  = safe_attr(proc, "cwd") or ""
            name = effective_process_name(proc)
            pid  = proc.pid

            entity_id = make_entity_id(boot_id, pid, start_ns)
            ancestry  = build_ancestry(proc, boot_id)
            parent    = ancestry[0] if ancestry else None
            if parent:
                try:
                    pp   = psutil.Process(parent["pid"])
                    pcmd = safe_attr(pp, "cmdline")
                    if pcmd:
                        parent = {**parent, "command_line": " ".join(pcmd)}
                except Exception:
                    pass

            file_hash = hash_file_sha256(exe) if exe else ""
            pkg       = detect_package(exe) if exe else {}

            process = {
                "entity_id":    entity_id,
                "pid":          pid,
                "name":         name,
                "executable":   exe,
                "command_line": " ".join(args),
                "args":         args,
                "start":        start_iso,
            }
            if cwd:
                process["working_directory"] = cwd
            if parent:
                process["parent"] = parent
            if ancestry:
                process["ancestry"] = ancestry
            if file_hash:
                process["hash"] = {"sha256": file_hash}
            if pkg:
                process["package"]        = pkg
                process["code_signature"] = {"signed": True, "valid": True,
                                              "subject": f"package:{pkg['name']}"}
            else:
                process["code_signature"] = {"signed": False, "valid": False}

            ev = make_envelope(agent_id, host, DATASET_PROCESS,
                               ["process"], ["start"], "process_start", sequence)
            ev["process"] = process
            ev["user"]    = build_user(proc)
            return ev
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 2 — File events
# Watches /proc/<pid>/fd symlinks for sensitive path opens and mtime changes.
# Also flags newly-created executables.
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PREFIXES = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/",
    "/root/.ssh/", "/.ssh/authorized_keys", "/etc/cron",
    "/etc/systemd/", "/etc/ld.so", "/proc/sys/kernel",
    "/dev/mem", "/dev/kmem",
)

def _is_sensitive(path: str) -> bool:
    return any(path.startswith(p) or p in path for p in SENSITIVE_PREFIXES)

def _fstat_key(path: str):
    try:
        s = os.stat(path)
        return (s.st_mtime_ns, s.st_size, s.st_mode)
    except Exception:
        return None

class FileMonitor:
    def __init__(self):
        self._seen:         dict[str, tuple] = {}   # path → stat key
        self._pid_fds:      dict[int, set]   = defaultdict(set)
        self._open_emitted: set              = set()

    def scan(self, agent_id: str, host: dict, seq_counter) -> list[dict]:
        events = []
        current_pids = set()

        for proc in psutil.process_iter(["pid", "name"]):
            pid    = proc.pid
            current_pids.add(pid)
            fd_dir = Path(f"/proc/{pid}/fd")
            if not fd_dir.exists():
                continue
            try:
                for fd_path in fd_dir.iterdir():
                    try:
                        target = os.readlink(str(fd_path))
                    except Exception:
                        continue
                    if not target.startswith("/"):
                        continue

                    # Sensitive open (emit once per path)
                    if _is_sensitive(target) and target not in self._open_emitted:
                        self._open_emitted.add(target)
                        ev = self._make(agent_id, host, next(seq_counter),
                                        target, "file_open", "open", proc)
                        if ev:
                            events.append(ev)

                    # Modification
                    key = _fstat_key(target)
                    if key and target in self._seen and self._seen[target] != key:
                        ev = self._make(agent_id, host, next(seq_counter),
                                        target, "file_modified", "change", proc)
                        if ev:
                            events.append(ev)
                    if key:
                        self._seen[target] = key

                    # New executable
                    try:
                        fst = os.stat(target)
                        x_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                        if (fst.st_mode & x_bits) and target not in self._seen:
                            ev = self._make(agent_id, host, next(seq_counter),
                                            target, "file_create_exec", "creation", proc)
                            if ev:
                                events.append(ev)
                    except Exception:
                        pass

            except PermissionError:
                pass

        for dead in set(self._pid_fds) - current_pids:
            del self._pid_fds[dead]
        return events

    def _make(self, agent_id, host, seq, path, action, ftype, proc) -> dict | None:
        try:
            fst  = os.stat(path)
            size = fst.st_size
            mode = oct(fst.st_mode)
        except Exception:
            size, mode = None, None

        sha = hash_file_sha256(path) if size and size < 50 * 1024 * 1024 else ""
        ev  = make_envelope(agent_id, host, DATASET_FILE,
                            ["file"], [ftype], action, seq)
        ev["file"] = {
            "path":      path,
            "name":      Path(path).name,
            "directory": str(Path(path).parent),
            "size":      size,
            "mode":      mode,
        }
        if sha:
            ev["file"]["hash"] = {"sha256": sha}
        try:
            ev["process"] = {"pid": proc.pid, "name": proc.name()}
        except Exception:
            pass
        return ev

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 3 — Network connection events
# ─────────────────────────────────────────────────────────────────────────────

def _conn_key(c) -> tuple:
    la = c.laddr if c.laddr else ("", 0)
    ra = c.raddr if c.raddr else ("", 0)
    return (c.pid, c.status, la[0], la[1], ra[0], ra[1])

class NetworkMonitor:
    def __init__(self):
        self._seen: set[tuple] = set()

    def scan(self, agent_id: str, host: dict, seq_counter) -> list[dict]:
        events = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return []

        current = set()
        for c in conns:
            k = _conn_key(c)
            current.add(k)
            if k not in self._seen and c.raddr:
                ev = self._make(agent_id, host, next(seq_counter), c)
                if ev:
                    events.append(ev)
        self._seen = current
        return events

    def _make(self, agent_id, host, seq, c) -> dict | None:
        if not c.raddr:
            return None
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        ev = make_envelope(agent_id, host, DATASET_NETWORK,
                           ["network"], ["connection"], "network_connection", seq)
        ev["network"]     = {
            "transport": proto,
            "direction": "egress" if (c.laddr and c.laddr.port > 1024) else "ingress",
            "type":      "ipv4" if ":" not in str(c.raddr.ip) else "ipv6",
        }
        ev["source"]      = {"ip": c.laddr.ip, "port": c.laddr.port} if c.laddr else {}
        ev["destination"] = {"ip": c.raddr.ip, "port": c.raddr.port}
        ev["connection"]  = {"status": c.status}
        try:
            ev["destination"]["domain"] = socket.gethostbyaddr(c.raddr.ip)[0]
        except Exception:
            pass
        if c.pid:
            try:
                proc = psutil.Process(c.pid)
                ev["process"] = {
                    "pid":        proc.pid,
                    "name":       proc.name(),
                    "executable": safe_attr(proc, "exe") or "",
                }
            except Exception:
                pass
        return ev

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 4 — DNS events
# UDP/53 connections + syslog tailing for dnsmasq/named/systemd-resolved
# ─────────────────────────────────────────────────────────────────────────────

_DNS_LOG_RE = re.compile(
    r"query\[(?P<type>\w+)\]\s+(?P<name>[^\s]+)\s+from\s+(?P<src>[^\s]+)", re.I
)

class DnsMonitor:
    def __init__(self):
        self._seen_udp: set[tuple] = set()
        self._syslog_path, self._syslog_pos = self._find_syslog()

    @staticmethod
    def _find_syslog():
        for p in ("/var/log/syslog", "/var/log/messages"):
            try:
                return p, Path(p).stat().st_size
            except Exception:
                pass
        return None, 0

    def scan(self, agent_id: str, host: dict, seq_counter) -> list[dict]:
        events = []
        # UDP/53
        try:
            for c in psutil.net_connections(kind="udp"):
                if not c.raddr or c.raddr.port != 53:
                    continue
                k = (c.pid, c.raddr.ip, c.laddr.port if c.laddr else 0)
                if k in self._seen_udp:
                    continue
                self._seen_udp.add(k)
                ev = make_envelope(agent_id, host, DATASET_DNS,
                                   ["network"], ["connection"], "dns_query", next(seq_counter))
                ev["dns"]         = {"type": "query",
                                     "question": {"class": "IN"},
                                     "resolved_ip": [c.raddr.ip]}
                ev["destination"] = {"ip": c.raddr.ip, "port": 53}
                if c.pid:
                    try:
                        proc = psutil.Process(c.pid)
                        ev["process"] = {"pid": proc.pid, "name": proc.name()}
                    except Exception:
                        pass
                events.append(ev)
        except Exception:
            pass

        # Syslog
        if self._syslog_path:
            try:
                with open(self._syslog_path, "r", errors="replace") as f:
                    f.seek(self._syslog_pos)
                    for line in f:
                        m = _DNS_LOG_RE.search(line)
                        if m:
                            ev = make_envelope(agent_id, host, DATASET_DNS,
                                               ["network"], ["connection"], "dns_query",
                                               next(seq_counter))
                            ev["dns"]    = {"type": "query",
                                            "question": {"name": m.group("name"),
                                                         "type": m.group("type")}}
                            ev["source"] = {"ip": m.group("src")}
                            events.append(ev)
                    self._syslog_pos = f.tell()
            except Exception:
                pass
        return events

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 5 — Login / auth events  (wtmp + auth.log)
# ─────────────────────────────────────────────────────────────────────────────

_UTMP_SIZE = 384
_UTMP_FMT  = "=hi4s32s4s32s256s2ih8s16s20s"

_SSH_RE  = re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)")
_FAIL_RE = re.compile(r"(Failed password|authentication failure).*?user=?\s*(?P<user>\S+)")
_SUDO_RE = re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)")

class LoginMonitor:
    def __init__(self):
        self._wtmp_pos  = self._size("/var/log/wtmp")
        self._btmp_pos  = self._size("/var/log/btmp")
        self._auth_path = "/var/log/auth.log" if Path("/var/log/auth.log").exists() \
                          else "/var/log/secure"
        self._auth_pos  = self._size(self._auth_path)

    @staticmethod
    def _size(path: str) -> int:
        try:
            return Path(path).stat().st_size
        except Exception:
            return 0

    def scan(self, agent_id: str, host: dict, seq_counter) -> list[dict]:
        events = []
        events += self._wtmp("/var/log/wtmp",  "_wtmp_pos", agent_id, host, seq_counter, "login")
        events += self._wtmp("/var/log/btmp",  "_btmp_pos", agent_id, host, seq_counter, "login_failed")
        events += self._authlog(agent_id, host, seq_counter)
        return events

    def _wtmp(self, path, attr, agent_id, host, seq_counter, action) -> list[dict]:
        events = []
        pos = getattr(self, attr)
        try:
            with open(path, "rb") as f:
                f.seek(pos)
                while True:
                    chunk = f.read(_UTMP_SIZE)
                    if len(chunk) < _UTMP_SIZE:
                        break
                    try:
                        fields  = struct.unpack(_UTMP_FMT, chunk)
                        ut_type = fields[0]
                        if ut_type not in (7, 8):   # USER_PROCESS / DEAD_PROCESS
                            continue
                        username = fields[5].rstrip(b"\x00").decode("utf-8", errors="replace")
                        terminal = fields[3].rstrip(b"\x00").decode("utf-8", errors="replace")
                        remote   = fields[6].rstrip(b"\x00").decode("utf-8", errors="replace")
                        if not username:
                            continue
                        ev = make_envelope(agent_id, host, DATASET_LOGIN,
                                           ["authentication"], ["start"], action,
                                           next(seq_counter))
                        ev["user"]              = {"name": username}
                        ev["session"]           = {"terminal": terminal}
                        ev["event"]["outcome"]  = "success" if ut_type == 7 else "failure"
                        if remote:
                            ev["source"] = {"ip": remote}
                        events.append(ev)
                    except Exception:
                        continue
                setattr(self, attr, f.tell())
        except Exception:
            pass
        return events

    def _authlog(self, agent_id, host, seq_counter) -> list[dict]:
        events = []
        try:
            with open(self._auth_path, "r", errors="replace") as f:
                f.seek(self._auth_pos)
                for line in f:
                    m = _SSH_RE.search(line)
                    if m:
                        ev = make_envelope(agent_id, host, DATASET_LOGIN,
                                           ["authentication"], ["start"], "ssh_login",
                                           next(seq_counter))
                        ev["user"]             = {"name": m.group("user")}
                        ev["source"]           = {"ip": m.group("ip")}
                        ev["auth"]             = {"method": m.group("method")}
                        ev["event"]["outcome"] = "success"
                        events.append(ev)
                        continue

                    m = _FAIL_RE.search(line)
                    if m:
                        ev = make_envelope(agent_id, host, DATASET_LOGIN,
                                           ["authentication"], ["start"], "login_failed",
                                           next(seq_counter))
                        ev["user"]             = {"name": m.group("user")}
                        ev["event"]["outcome"] = "failure"
                        events.append(ev)
                        continue

                    m = _SUDO_RE.search(line)
                    if m:
                        ev = make_envelope(agent_id, host, DATASET_LOGIN,
                                           ["authentication", "process"], ["change"],
                                           "privilege_escalation", next(seq_counter))
                        ev["user"]             = {"name": m.group("user")}
                        ev["process"]          = {"command_line": m.group("cmd").strip()}
                        ev["event"]["outcome"] = "success"
                        events.append(ev)

                self._auth_pos = f.tell()
        except Exception:
            pass
        return events

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 6 — Memory / injection indicators  (/proc/<pid>/maps)
# Flags: anonymous rwx regions (shellcode), executable heap/stack
# ─────────────────────────────────────────────────────────────────────────────

_ANON_RWX  = re.compile(r"^[0-9a-f]+-[0-9a-f]+\s+rwxp\s+\S+\s+\S+\s+\S+\s*$")
_HEAP_EXEC = re.compile(r"rwxp.*\[heap\]")
_STCK_EXEC = re.compile(r"rwxp.*\[stack\]")

class MemoryMonitor:
    def __init__(self):
        self._seen_rwx: dict[int, frozenset] = {}

    def scan(self, agent_id: str, host: dict, seq_counter) -> list[dict]:
        events = []
        for proc in psutil.process_iter(["pid", "name"]):
            maps = Path(f"/proc/{proc.pid}/maps")
            if not maps.exists():
                continue
            try:
                text = maps.read_text(errors="replace")
            except Exception:
                continue

            rwx_addrs = set()
            for line in text.splitlines():
                parts = line.split()
                if len(parts) < 2 or "x" not in parts[1]:
                    continue
                addr = parts[0].split("-")[0]

                if _HEAP_EXEC.search(line):
                    events.append(self._make(agent_id, host, next(seq_counter),
                                             proc, "executable_heap", addr))
                elif _STCK_EXEC.search(line):
                    events.append(self._make(agent_id, host, next(seq_counter),
                                             proc, "executable_stack", addr))
                elif _ANON_RWX.match(line) and len(parts) <= 5:
                    rwx_addrs.add(addr)

            prev    = self._seen_rwx.get(proc.pid, frozenset())
            new_rwx = rwx_addrs - prev
            for addr in new_rwx:
                events.append(self._make(agent_id, host, next(seq_counter),
                                         proc, "anonymous_rwx_region", addr))
            if rwx_addrs:
                self._seen_rwx[proc.pid] = frozenset(rwx_addrs)
            else:
                self._seen_rwx.pop(proc.pid, None)

        return events

    def _make(self, agent_id, host, seq, proc, indicator, address) -> dict:
        ev = make_envelope(agent_id, host, DATASET_MEMORY,
                           ["process"], ["info"], f"memory_{indicator}", seq)
        try:
            ev["process"] = {
                "pid":        proc.pid,
                "name":       proc.name(),
                "executable": safe_attr(proc, "exe") or "",
            }
        except Exception:
            ev["process"] = {"pid": proc.pid}
        ev["memory"] = {"indicator": indicator, "address": address}
        return ev

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 7 — Email / Phishing indicators
# Watches email client child processes, suspicious files in landing directories,
# and local mail server logs to surface phishing payload delivery & execution.
# ─────────────────────────────────────────────────────────────────────────────

_EMAIL_CLIENTS = frozenset({
    "thunderbird", "betterbird", "evolution", "mutt", "alpine",
    "sylpheed", "claws-mail", "kmail", "geary", "mailspring",
})

_SUSPICIOUS_CHILD = frozenset({
    "bash", "sh", "dash", "zsh", "ash",
    "python3", "python", "perl", "ruby",
    "curl", "wget", "nc", "ncat", "netcat",
    "chmod", "base64", "xterm", "gnome-terminal",
})

_MALICIOUS_EXTENSIONS = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1",
    ".hta", ".scr", ".pif", ".com", ".jar", ".msi", ".lnk",
})

_MAIL_LOG_RE = re.compile(
    r"(reject:|dsn=5\.|spam|phish|blocked|malware|virus|trojan|credential)", re.I
)


class EmailMonitor:
    def __init__(self):
        self._client_children: dict[int, set[int]] = {}
        self._seen_files: set[str] = set()
        self._mail_log_path = self._find_mail_log()
        self._mail_log_pos  = 0   # seek to end on first run

    @staticmethod
    def _find_mail_log() -> str | None:
        for p in ("/var/log/mail.log", "/var/log/maillog", "/var/log/mail/mail.log"):
            if Path(p).exists():
                return p
        return None

    def scan(self, agent_id: str, host: dict, seq_counter) -> list[dict]:
        events: list[dict] = []
        events += self._scan_email_clients(agent_id, host, seq_counter)
        events += self._scan_attachment_dirs(agent_id, host, seq_counter)
        events += self._scan_mail_log(agent_id, host, seq_counter)
        return events

    def _scan_email_clients(self, agent_id, host, seq_counter) -> list[dict]:
        events: list[dict] = []
        live_clients: dict[int, psutil.Process] = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.name().lower() in _EMAIL_CLIENTS:
                    live_clients[proc.pid] = proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        for epid, eproc in live_clients.items():
            known = self._client_children.setdefault(epid, set())
            try:
                for child in eproc.children(recursive=False):
                    if child.pid in known:
                        continue
                    known.add(child.pid)
                    cname = ""
                    try:
                        cname = child.name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                    if cname not in _SUSPICIOUS_CHILD:
                        continue
                    ev = make_envelope(agent_id, host, DATASET_EMAIL,
                                       ["email", "process"], ["start"],
                                       "email_client_shell", next(seq_counter))
                    ev["email"] = {
                        "indicator_type": "phishing",
                        "detail": f"Email client '{eproc.name()}' spawned '{child.name()}'",
                    }
                    ev["process"] = {
                        "pid":       eproc.pid,
                        "name":      eproc.name(),
                        "child_name": child.name(),
                        "child_pid": child.pid,
                    }
                    events.append(ev)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        dead = set(self._client_children) - set(live_clients)
        for pid in dead:
            del self._client_children[pid]

        return events

    def _scan_attachment_dirs(self, agent_id, host, seq_counter) -> list[dict]:
        events: list[dict] = []
        watch_dirs = [Path.home() / "Downloads", Path("/tmp")]
        for d in watch_dirs:
            if not d.exists():
                continue
            try:
                for f in d.iterdir():
                    if not f.is_file():
                        continue
                    key = str(f)
                    if key in self._seen_files:
                        continue
                    self._seen_files.add(key)
                    if f.suffix.lower() not in _MALICIOUS_EXTENSIONS:
                        continue
                    sha = hash_file_sha256(str(f))
                    ev = make_envelope(agent_id, host, DATASET_EMAIL,
                                       ["email", "file"], ["creation"],
                                       "suspicious_attachment", next(seq_counter))
                    ev["email"] = {
                        "indicator_type": "malware_attachment",
                        "detail": f"Suspicious file in {d}: {f.name}",
                        "attachment": {"name": f.name, "hash": sha},
                    }
                    events.append(ev)
            except Exception:
                continue
        return events

    def _scan_mail_log(self, agent_id, host, seq_counter) -> list[dict]:
        events: list[dict] = []
        if not self._mail_log_path:
            return events
        try:
            with open(self._mail_log_path, "r", errors="replace") as f:
                if self._mail_log_pos == 0:
                    self._mail_log_pos = f.seek(0, 2)
                    return events
                f.seek(self._mail_log_pos)
                for line in f:
                    if not _MAIL_LOG_RE.search(line):
                        continue
                    ev = make_envelope(agent_id, host, DATASET_EMAIL,
                                       ["email"], ["info"],
                                       "smtp_anomaly", next(seq_counter))
                    ev["email"] = {
                        "indicator_type": "smtp_anomaly",
                        "detail": line.strip()[:250],
                    }
                    events.append(ev)
                self._mail_log_pos = f.tell()
        except Exception:
            pass
        return events


# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 8 — Response: command polling + execution
# The API exposes GET /api/v1/response/commands/<agent_id> to deliver commands
# and POST /api/v1/response/ack to receive results.
#
# Supported actions:
#   kill_process    { pid: int }
#   quarantine_file { path: str }   chmod 000 + rename .quarantine
#   collect_file    { path: str }   base64-encode and return in ack
#   isolate_host    { allow_ip: str }  iptables drop-all except manager
#   run_command     { cmd: str }    shell exec (disable in prod)
# ─────────────────────────────────────────────────────────────────────────────

class CommandExecutor:
    def __init__(self, api_base: str, agent_id: str, session: requests.Session):
        self._mgr_base = api_base.rstrip("/").rsplit("/api/", 1)[0]
        self._agent_id = agent_id
        self._session  = session

    def poll_and_execute(self):
        url = f"{self._mgr_base}/api/v1/response/commands/{self._agent_id}"
        try:
            r = self._session.get(url, timeout=5)
            if r.status_code != 200:
                return
            commands = r.json()
        except Exception:
            return

        for cmd in commands:
            cmd_id = cmd.get("command_id", str(uuid.uuid4()))
            action = cmd.get("action", "")
            params = cmd.get("params", {})
            result = self._execute(action, params)
            self._ack(cmd_id, action, result)

    def _execute(self, action: str, params: dict) -> dict:
        try:
            if action == "kill_process":
                pid = int(params["pid"])
                os.kill(pid, 9)
                return {"status": "ok", "detail": f"SIGKILL → pid {pid}"}

            elif action == "quarantine_file":
                path = params["path"]
                p    = Path(path)
                if not p.exists():
                    return {"status": "error", "detail": "file not found"}
                dest = path + ".quarantine"
                p.rename(dest)
                os.chmod(dest, 0o000)
                return {"status": "ok", "detail": f"quarantined → {dest}"}

            elif action == "collect_file":
                path = params["path"]
                data = Path(path).read_bytes()
                return {"status": "ok", "path": path,
                        "size": len(data),
                        "file_b64": base64.b64encode(data).decode()}

            elif action == "isolate_host":
                allow_ip = params.get("allow_ip", "")
                rules = [
                    "iptables -P INPUT DROP",
                    "iptables -P OUTPUT DROP",
                    "iptables -P FORWARD DROP",
                    "iptables -A INPUT  -i lo -j ACCEPT",
                    "iptables -A OUTPUT -o lo -j ACCEPT",
                ]
                if allow_ip:
                    rules += [
                        f"iptables -A INPUT  -s {allow_ip} -j ACCEPT",
                        f"iptables -A OUTPUT -d {allow_ip} -j ACCEPT",
                    ]
                for rule in rules:
                    subprocess.run(rule, shell=True, timeout=5)
                return {"status": "ok", "detail": "host isolated via iptables"}

            elif action == "run_command":
                cmd = params.get("cmd", "")
                r   = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, timeout=30)
                return {"status": "ok", "returncode": r.returncode,
                        "stdout": r.stdout[:4096], "stderr": r.stderr[:1024]}

            else:
                return {"status": "error", "detail": f"unknown action: {action}"}

        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def _ack(self, cmd_id: str, action: str, result: dict):
        url = f"{self._mgr_base}/api/v1/response/ack"
        try:
            self._session.post(url, json={
                "command_id":  cmd_id,
                "agent_id":    self._agent_id,
                "action":      action,
                "result":      result,
                "executed_at": now_iso(),
            }, timeout=5)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# Thread-safe sequence counter
# ─────────────────────────────────────────────────────────────────────────────

class Counter:
    def __init__(self):
        self._n    = 0
        self._lock = threading.Lock()

    def __next__(self) -> int:
        with self._lock:
            self._n += 1
            return self._n

    def __iter__(self):
        return self

# ─────────────────────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────

def monitor(api: str, interval: float, net_interval: float, cmd_poll: float,
            agent_id: str, host: dict):
    print(f"[*] Phalanx Sentinel v{SENTINEL_VERSION}")
    print(f"    Agent    : {agent_id}")
    print(f"    Host     : {host['hostname']} ({host['os']['platform']} {host['os']['version']})")
    print(f"    API      : {api}")
    print(f"    Domains  : process({interval}s)  "
          f"file/net/dns/login/memory/email({net_interval}s)  cmd({cmd_poll}s)\n")

    session  = requests.Session()
    counter  = Counter()
    executor = CommandExecutor(api, agent_id, session)

    def ship(ev: dict | None) -> bool:
        if ev is None:
            return False
        body = json.dumps(ev, separators=(",", ":"))
        for attempt in range(3):
            try:
                r = session.post(api, data=body,
                                 headers={"Content-Type": "application/json"},
                                 timeout=5)
                if r.status_code == 202:
                    return True
                print(f"  [!] API {r.status_code}: {r.text[:80]}")
                return False
            except requests.exceptions.ConnectionError:
                time.sleep(1)
            except Exception as e:
                print(f"  [!] {e}")
                return False
        return False

    # Health check
    try:
        health_url = api.rstrip("/").rsplit("/api/", 1)[0] + "/api/v1/ingest/health"
        r = session.get(health_url, timeout=3)
        print(f"[+] API health: {'OK' if r.status_code == 200 else 'degraded'}\n")
    except Exception:
        print("[!] API not reachable yet — will retry on first ship\n")

    file_mon  = FileMonitor()
    net_mon   = NetworkMonitor()
    dns_mon   = DnsMonitor()
    login_mon = LoginMonitor()
    mem_mon   = MemoryMonitor()
    email_mon = EmailMonitor()

    seen_pids  = set(psutil.pids())
    last_slow  = 0.0
    last_cmd   = 0.0
    shipped    = 0
    failed     = 0

    try:
        while True:
            now = time.monotonic()

            # ── Process (fast) ────────────────────────────────────────────
            current = set(psutil.pids())
            for pid in current - seen_pids:
                try:
                    ev = build_process_event(psutil.Process(pid), host, agent_id,
                                             next(counter))
                    if ship(ev):
                        shipped += 1
                    else:
                        failed += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            seen_pids = current

            # ── Slow domains (file, net, dns, login, memory) ──────────────
            if now - last_slow >= net_interval:
                last_slow = now
                for generator in (file_mon, net_mon, dns_mon, login_mon, mem_mon, email_mon):
                    for ev in generator.scan(agent_id, host, counter):
                        if ship(ev):
                            shipped += 1
                        else:
                            failed += 1

            # ── Response commands ─────────────────────────────────────────
            if now - last_cmd >= cmd_poll:
                last_cmd = now
                executor.poll_and_execute()

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Stopped. shipped={shipped} failed={failed}")

# ─────────────────────────────────────────────────────────────────────────────

def main():
    args  = parse_args()
    state = state_dir(args.state_dir)
    aid   = args.agent_id or get_or_create_agent_id(state)
    host  = build_host_context()
    monitor(args.api, args.interval, args.net_interval, args.cmd_poll, aid, host)

if __name__ == "__main__":
    main()
