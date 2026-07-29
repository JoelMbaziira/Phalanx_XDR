"""
dnsmasq actuator — DNS sinkhole.

Adds `0.0.0.0  domain` entries to a Phalanx-managed hosts file, then HUPs
dnsmasq to reload. Sinkholed domains resolve to 0.0.0.0 network-wide for
every device using this resolver.

The sinkhole file lives at /etc/phalanx/dnsmasq-sinkhole.list. dnsmasq must
have a directive `addn-hosts=/etc/phalanx/dnsmasq-sinkhole.list` in its
config — install_hook() adds it if missing. Caller restarts dnsmasq once
after install_hook the first time.

This blocks the domain-to-IP resolution. Connections to an IP that was
resolved before the sinkhole was added will continue working — pair with
nftables.block_ip if you need to stop those too.
"""
from __future__ import annotations
import logging
import os
import signal
import subprocess
from pathlib import Path
from shutil import which

log = logging.getLogger("response.dnsmasq")


class DnsmasqActuator:
    DEFAULT_FILE = "/etc/phalanx/dnsmasq-sinkhole.list"

    def __init__(self, sinkhole_file: str = DEFAULT_FILE):
        self._file = Path(sinkhole_file)
        self._available = which("dnsmasq") is not None
        if not self._available:
            log.warning("dnsmasq not in PATH; sinkhole actuator disabled")
            self._sinkholed: set[str] = set()
            return
        self._file.parent.mkdir(parents=True, exist_ok=True)
        if not self._file.exists():
            self._file.write_text("# Phalanx-managed DNS sinkhole. Do not edit.\n")
        self._sinkholed = self._load_existing()

    @property
    def available(self) -> bool:
        return self._available

    def _load_existing(self) -> set[str]:
        out: set[str] = set()
        try:
            for line in self._file.read_text().splitlines():
                s = line.strip()
                if not s or s.startswith("#"): continue
                parts = s.split()
                if len(parts) >= 2:
                    out.add(parts[1].lower())
        except Exception:
            pass
        return out

    # ── public ─────────────────────────────────────────────────────────────

    def sinkhole(self, domain: str) -> bool:
        if not self._available: return False
        d = domain.lower().strip(".")
        if d in self._sinkholed:
            return True
        try:
            with self._file.open("a") as f:
                f.write(f"0.0.0.0 {d}\n")
            self._sinkholed.add(d)
            return self._reload_dnsmasq()
        except Exception as e:
            log.warning("sinkhole: %s", e)
            return False

    def unsinkhole(self, domain: str) -> bool:
        if not self._available: return False
        d = domain.lower().strip(".")
        if d not in self._sinkholed:
            return True
        try:
            lines = self._file.read_text().splitlines()
            kept  = [ln for ln in lines if not ln.endswith(f" {d}")]
            self._file.write_text("\n".join(kept) + "\n")
            self._sinkholed.discard(d)
            return self._reload_dnsmasq()
        except Exception as e:
            log.warning("unsinkhole: %s", e)
            return False

    def list_sinkholed(self) -> list[str]:
        return sorted(self._sinkholed)

    # ── reload ─────────────────────────────────────────────────────────────

    def _reload_dnsmasq(self) -> bool:
        try:
            res = subprocess.run(
                ["pidof", "dnsmasq"],
                capture_output=True, text=True, timeout=3,
            )
            if res.returncode == 0 and res.stdout.strip():
                pids = [int(p) for p in res.stdout.split()]
            else:
                pids = []
                for entry in Path("/proc").iterdir():
                    if not entry.name.isdigit(): continue
                    try:
                        cmd = (entry / "cmdline").read_text("utf-8", errors="ignore")
                        if "dnsmasq" in cmd.split("\0")[0]:
                            pids.append(int(entry.name))
                    except Exception:
                        continue
            if not pids:
                log.warning("dnsmasq not running; cannot reload")
                return False
            for pid in pids:
                try: os.kill(pid, signal.SIGHUP)
                except ProcessLookupError: pass
            return True
        except Exception as e:
            log.warning("reload: %s", e)
            return False

    @classmethod
    def install_hook(cls, dnsmasq_conf: str = "/etc/dnsmasq.conf") -> bool:
        try:
            conf = Path(dnsmasq_conf)
            if not conf.exists():
                log.warning("%s not found", conf)
                return False
            existing = conf.read_text()
            directive = f"addn-hosts={cls.DEFAULT_FILE}"
            if directive in existing:
                return True
            with conf.open("a") as f:
                f.write(f"\n# Phalanx sinkhole\n{directive}\n")
            return True
        except Exception as e:
            log.warning("install_hook: %s", e)
            return False
