"""
Response coordinator — polls the Phalanx server for commands targeting
this sensor node, executes them via the local actuators, acks results.

Mirrors the endpoint Sentinel agent's CommandExecutor:
    1. GET  {server}/api/v1/response/commands/{node_id}
    2. Execute each command via the appropriate actuator
    3. POST {server}/api/v1/response/ack with the outcome

Actions this coordinator understands:
    block_mac         { mac, ttl_sec? }
    unblock_mac       { mac }
    block_ip          { ip,  ttl_sec? }
    unblock_ip        { ip }
    sinkhole_domain   { domain }
    unsinkhole_domain { domain }
    rate_limit_mac    { mac, kbit? }
    unlimit_mac       { mac }

Wired from sensor.py:
    coordinator = ResponseCoordinator(server_url, node_id, lan_iface)
    coordinator.start()
    ... (sensor runs) ...
    coordinator.stop()

Designed to fail-soft: any actuator that's not available (no nft, no
dnsmasq, no tc) returns False from its action. The coordinator acks
'failed' with a message rather than crashing the sensor.
"""
from __future__ import annotations
import json
import logging
import threading
import time
import urllib.error
import urllib.request

from .nftables import NftablesActuator
from .dnsmasq  import DnsmasqActuator
from .tc       import TcActuator

log = logging.getLogger("response.coordinator")


class ResponseCoordinator:

    def __init__(self,
                 server_url:    str,
                 node_id:       str,
                 lan_iface:     str,
                 poll_interval: float = 5.0):
        self._server     = server_url.rstrip("/")
        self._node_id    = node_id
        self._poll_int   = poll_interval
        self._running    = False
        self._thread:    threading.Thread | None = None

        self._nft = NftablesActuator()
        self._dns = DnsmasqActuator()
        self._tc  = TcActuator(lan_iface)

        log.info("Coordinator ready: nft=%s dnsmasq=%s tc=%s",
                 self._nft.available, self._dns.available, self._tc.available)

    def start(self):
        if self._running: return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True,
                                          name="response-coordinator")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def status(self) -> dict:
        return {
            "actuators": {
                "nftables": self._nft.available,
                "dnsmasq":  self._dns.available,
                "tc":       self._tc.available,
            },
            "blocked":   self._nft.list_blocked()    if self._nft.available else {},
            "sinkholed": self._dns.list_sinkholed()  if self._dns.available else [],
            "limited":   self._tc.list_limited()     if self._tc.available  else {},
        }

    # ── poll/execute/ack ──────────────────────────────────────────────────

    def _loop(self):
        while self._running:
            try:
                for cmd in self._poll():
                    self._handle(cmd)
            except Exception as e:
                log.warning("poll error: %s", e)
            time.sleep(self._poll_int)

    def _poll(self) -> list[dict]:
        url = f"{self._server}/api/v1/response/commands/{self._node_id}"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return []
                data = json.loads(resp.read())
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and "commands" in data:
                    return data["commands"]
        except (urllib.error.URLError, ConnectionError):
            pass
        except Exception as e:
            log.warning("poll parse: %s", e)
        return []

    def _ack(self, cmd_id: str, status: str, message: str = ""):
        url = f"{self._server}/api/v1/response/ack"
        body = json.dumps({
            "CommandId": cmd_id,
            "AgentId":   self._node_id,   # backend uses AgentId field for both kinds
            "Action":    "",              # filled by backend from stored cmd row
            "Result":    {"status": status, "message": message},
            "ExecutedAt": "",
        }).encode()
        try:
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as e:
            log.warning("ack failed: %s", e)

    def _handle(self, cmd: dict):
        cmd_id = cmd.get("command_id") or cmd.get("id", "")
        action = cmd.get("action", "")
        # Server sends params as JSON-encoded string under "params_raw";
        # accept either that or a "params" dict for flexibility.
        params_raw = cmd.get("params_raw")
        if params_raw:
            try: params = json.loads(params_raw)
            except Exception: params = {}
        else:
            params = cmd.get("params", {}) or {}

        log.info("→ %s %s", action, params)

        try:
            ok, msg = self._dispatch(action, params)
        except Exception as e:
            ok, msg = False, f"{type(e).__name__}: {e}"

        self._ack(cmd_id, "ok" if ok else "failed", msg)

    def _dispatch(self, action: str, params: dict) -> tuple[bool, str]:
        match action:
            case "block_mac":
                if not self._nft.available: return False, "nftables unavailable"
                mac = params.get("mac", "")
                ttl = params.get("ttl_sec")
                ok = self._nft.block_mac(mac, ttl)
                return ok, f"blocked {mac}" if ok else "block failed"

            case "unblock_mac":
                if not self._nft.available: return False, "nftables unavailable"
                mac = params.get("mac", "")
                return self._nft.unblock_mac(mac), f"unblocked {mac}"

            case "block_ip":
                if not self._nft.available: return False, "nftables unavailable"
                ip  = params.get("ip", "")
                ttl = params.get("ttl_sec")
                ok = self._nft.block_ip(ip, ttl)
                return ok, f"blocked {ip}" if ok else "block failed"

            case "unblock_ip":
                if not self._nft.available: return False, "nftables unavailable"
                ip = params.get("ip", "")
                return self._nft.unblock_ip(ip), f"unblocked {ip}"

            case "sinkhole_domain":
                if not self._dns.available: return False, "dnsmasq unavailable"
                d = params.get("domain", "")
                ok = self._dns.sinkhole(d)
                return ok, f"sinkholed {d}" if ok else "sinkhole failed"

            case "unsinkhole_domain":
                if not self._dns.available: return False, "dnsmasq unavailable"
                d = params.get("domain", "")
                return self._dns.unsinkhole(d), f"unsinkholed {d}"

            case "rate_limit_mac":
                if not self._tc.available: return False, "tc unavailable"
                mac  = params.get("mac", "")
                kbit = params.get("kbit")
                ok = self._tc.rate_limit(mac, kbit)
                return ok, f"limited {mac} to {kbit or 64}kbit/s" if ok else "limit failed"

            case "unlimit_mac":
                if not self._tc.available: return False, "tc unavailable"
                mac = params.get("mac", "")
                return self._tc.unlimit(mac), f"unlimited {mac}"

            case _:
                return False, f"unknown action: {action}"
