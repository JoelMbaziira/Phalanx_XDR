"""
nftables actuator — block a device at the router's packet filter.

Block primitives:
    block_mac(mac, ttl?)    drop traffic from a MAC
    block_ip(ip,  ttl?)     drop traffic to/from an IP
    unblock_mac(mac), unblock_ip(ip)
    list_blocked()           inventory current blocks

Owns a dedicated nftables table "phalanx" with two sets — blocked_macs and
blocked_ips — plus a forward-chain that drops on match. install_chains()
is idempotent so re-init at startup is safe.

Requires root and `nft` binary. If `nft` isn't present, the actuator
self-disables — block_mac() etc just return False.
"""
from __future__ import annotations
import json
import logging
import shutil
import subprocess

log = logging.getLogger("response.nftables")


class NftablesActuator:
    TABLE    = "phalanx"
    SET_MACS = "blocked_macs"
    SET_IPS  = "blocked_ips"

    def __init__(self):
        self._available = shutil.which("nft") is not None
        if not self._available:
            log.warning("nft not found in PATH; nftables actuator disabled")
            return
        self._install_chains()

    @property
    def available(self) -> bool:
        return self._available

    def _install_chains(self):
        """Idempotent: create table, sets, and the drop rules if missing."""
        for cmd in [
            f"add table inet {self.TABLE}",
            f"add set inet {self.TABLE} {self.SET_MACS} {{ type ether_addr; flags interval, timeout; }}",
            f"add set inet {self.TABLE} {self.SET_IPS}  {{ type ipv4_addr;  flags interval, timeout; }}",
            f"add chain inet {self.TABLE} forward {{ type filter hook forward priority -100; policy accept; }}",
            f"add rule inet {self.TABLE} forward ether saddr @{self.SET_MACS} drop",
            f"add rule inet {self.TABLE} forward ip saddr @{self.SET_IPS} drop",
            f"add rule inet {self.TABLE} forward ip daddr @{self.SET_IPS} drop",
        ]:
            try:
                subprocess.run(["nft", *cmd.split()], check=False, capture_output=True)
            except Exception as e:
                log.warning("nft setup step failed (likely already present): %s", e)

    # ── public ─────────────────────────────────────────────────────────────

    def block_mac(self, mac: str, ttl_sec: int | None = None) -> bool:
        if not self._available: return False
        elem = f"{{ {mac.lower()}"
        if ttl_sec: elem += f" timeout {ttl_sec}s"
        elem += " }"
        return self._run(f"add element inet {self.TABLE} {self.SET_MACS} {elem}")

    def unblock_mac(self, mac: str) -> bool:
        if not self._available: return False
        return self._run(f"delete element inet {self.TABLE} {self.SET_MACS} {{ {mac.lower()} }}")

    def block_ip(self, ip: str, ttl_sec: int | None = None) -> bool:
        if not self._available: return False
        elem = f"{{ {ip}"
        if ttl_sec: elem += f" timeout {ttl_sec}s"
        elem += " }"
        return self._run(f"add element inet {self.TABLE} {self.SET_IPS} {elem}")

    def unblock_ip(self, ip: str) -> bool:
        if not self._available: return False
        return self._run(f"delete element inet {self.TABLE} {self.SET_IPS} {{ {ip} }}")

    def list_blocked(self) -> dict:
        out: dict = {"macs": [], "ips": []}
        if not self._available: return out
        try:
            res = subprocess.run(
                ["nft", "-j", "list", "table", "inet", self.TABLE],
                capture_output=True, text=True, timeout=5,
            )
            if res.returncode != 0:
                return out
            data = json.loads(res.stdout)
            for item in data.get("nftables", []):
                so = item.get("set", {})
                name = so.get("name", "")
                elems = so.get("elem", [])
                target = "macs" if name == self.SET_MACS else "ips" if name == self.SET_IPS else None
                if target is None: continue
                out[target] = [
                    e if isinstance(e, str) else e.get("elem", {}).get("val", "")
                    for e in elems
                ]
        except Exception as e:
            log.warning("list_blocked: %s", e)
        return out

    def _run(self, cmd: str) -> bool:
        try:
            res = subprocess.run(
                ["nft", *cmd.split()],
                check=False, capture_output=True, text=True, timeout=5,
            )
            if res.returncode != 0:
                log.warning("nft %s failed: %s", cmd, res.stderr.strip())
                return False
            return True
        except Exception as e:
            log.warning("nft exec error: %s", e)
            return False
