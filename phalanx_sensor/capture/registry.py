"""
Device registry — the live inventory of every device on the network.

One DeviceRecord per MAC address. Updated in real time as packets arrive.
Thread-safe. Emits 'device_new' and 'device_updated' events.
"""

from __future__ import annotations
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from fingerprint.oui import lookup as oui_lookup, device_type_hint
from fingerprint.os_detect import DeviceFingerprint, OsGuess


# ─────────────────────────────────────────────────────────────────────────────
# Device record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DeviceRecord:
    mac:          str
    device_id:    str = field(default_factory=lambda: str(uuid.uuid4()))

    # Network identity
    ip:           str  = ""
    hostname:     str  = ""
    ip_history:   list[str] = field(default_factory=list)

    # Identity
    manufacturer: str  = ""
    device_type:  str  = ""     # from OUI hint
    ap_bssid:     str  = ""     # which AP it's connected to
    ssid:         str  = ""

    # Fingerprint
    fingerprint:  DeviceFingerprint | None = None
    os_guess:     OsGuess | None = None

    # Timing
    first_seen:   float = field(default_factory=time.time)
    last_seen:    float = field(default_factory=time.time)
    last_active:  float = field(default_factory=time.time)

    # Traffic counters (reset-able)
    bytes_in:     int = 0
    bytes_out:    int = 0
    dns_count:    int = 0
    conn_count:   int = 0

    # Risk
    risk_score:   float = 0.0
    risk_reasons: list[str] = field(default_factory=list)

    # Status flags
    is_new:       bool  = True
    is_gateway:   bool  = False
    is_dns_server:bool  = False

    def summary(self) -> dict:
        os = str(self.os_guess) if self.os_guess else "Unknown"
        return {
            "device_id":    self.device_id,
            "mac":          self.mac,
            "ip":           self.ip,
            "hostname":     self.hostname,
            "manufacturer": self.manufacturer,
            "device_type":  self.device_type,
            "os":           os,
            "first_seen":   self.first_seen,
            "last_seen":    self.last_seen,
            "bytes_in":     self.bytes_in,
            "bytes_out":    self.bytes_out,
            "dns_count":    self.dns_count,
            "conn_count":   self.conn_count,
            "risk_score":   self.risk_score,
            "risk_reasons": self.risk_reasons,
            "ap_bssid":     self.ap_bssid,
        }

    def to_event(self, action: str, agent_id: str, hostname: str) -> dict:
        """Emit as a Phalanx-compatible telemetry event."""
        import datetime
        return {
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": {
                "id":       str(uuid.uuid4()),
                "kind":     "event",
                "category": ["network"],
                "type":     [action],
                "action":   f"device_{action}",
                "dataset":  "phalanx.sensor.device",
            },
            "agent": {
                "id":      agent_id,
                "version": "0.1.0",
                "type":    "phalanx-sensor-node",
            },
            "host":   {"hostname": hostname},
            "device": self.summary(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────

EventCallback = Callable[[str, DeviceRecord], None]


class DeviceRegistry:
    """
    Thread-safe registry of all devices seen on the network.

    Usage:
        registry = DeviceRegistry()
        registry.on_event(lambda action, device: ...)
        registry.see(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.5")
    """

    def __init__(self, gateway_ip: str = "", dns_ip: str = ""):
        self._devices:  dict[str, DeviceRecord] = {}   # MAC → record
        self._ip_index: dict[str, str]           = {}   # IP  → MAC
        self._lock      = threading.Lock()
        self._callbacks: list[EventCallback] = []
        self._gateway_ip  = gateway_ip
        self._dns_ip      = dns_ip

    # ── Registration ─────────────────────────────────────────────────────────

    def on_event(self, cb: EventCallback):
        """Register a callback: cb(action, device_record). Actions: new, updated, risk."""
        self._callbacks.append(cb)

    def _emit(self, action: str, device: DeviceRecord):
        for cb in self._callbacks:
            try:
                cb(action, device)
            except Exception:
                pass

    # ── Core update ──────────────────────────────────────────────────────────

    def see(self,
            mac:      str,
            ip:       str  = "",
            hostname: str  = "",
            ap_bssid: str  = "",
            ssid:     str  = "") -> DeviceRecord:
        """
        Record that a device was seen. Creates the record if new.
        Returns the (updated) DeviceRecord.
        """
        mac = mac.upper()
        now = time.time()

        with self._lock:
            is_new = mac not in self._devices

            if is_new:
                mfr   = oui_lookup(mac)
                dtype = device_type_hint(mfr)
                rec   = DeviceRecord(
                    mac          = mac,
                    ip           = ip,
                    hostname     = hostname,
                    manufacturer = mfr,
                    device_type  = dtype,
                    ap_bssid     = ap_bssid,
                    ssid         = ssid,
                    fingerprint  = DeviceFingerprint(ip=ip),
                )
                rec.is_gateway   = (ip == self._gateway_ip)
                rec.is_dns_server = (ip == self._dns_ip)
                self._devices[mac] = rec
                if ip:
                    self._ip_index[ip] = mac
            else:
                rec = self._devices[mac]
                rec.last_seen = now

                if ip and ip != rec.ip:
                    if rec.ip:
                        rec.ip_history.append(rec.ip)
                    rec.ip = ip
                    if rec.fingerprint:
                        rec.fingerprint.ip = ip
                    self._ip_index[ip] = mac

                if hostname and not rec.hostname:
                    rec.hostname = hostname
                if ap_bssid:
                    rec.ap_bssid = ap_bssid
                if ssid:
                    rec.ssid = ssid

        if is_new:
            rec.is_new = True
            self._emit("new", rec)
            rec.is_new = False
        else:
            self._emit("updated", rec)

        return rec

    def by_mac(self, mac: str) -> DeviceRecord | None:
        return self._devices.get(mac.upper())

    def by_ip(self, ip: str) -> DeviceRecord | None:
        mac = self._ip_index.get(ip)
        return self._devices.get(mac) if mac else None

    def all_devices(self) -> list[DeviceRecord]:
        with self._lock:
            return list(self._devices.values())

    def count(self) -> int:
        return len(self._devices)

    # ── Traffic accounting ────────────────────────────────────────────────────

    def add_traffic(self, mac: str, bytes_out: int = 0, bytes_in: int = 0):
        with self._lock:
            rec = self._devices.get(mac.upper())
            if rec:
                rec.bytes_out  += bytes_out
                rec.bytes_in   += bytes_in
                rec.last_active = time.time()

    def add_dns(self, mac: str):
        with self._lock:
            rec = self._devices.get(mac.upper())
            if rec:
                rec.dns_count  += 1
                rec.last_active = time.time()

    def add_connection(self, mac: str):
        with self._lock:
            rec = self._devices.get(mac.upper())
            if rec:
                rec.conn_count += 1
                rec.last_active = time.time()

    # ── Fingerprint update ────────────────────────────────────────────────────

    def update_tcp_fingerprint(self, mac: str, ttl: int, window: int, options: set[str]):
        from fingerprint.os_detect import fingerprint_tcp
        rec = self._devices.get(mac.upper())
        if not rec:
            return
        if rec.fingerprint is None:
            rec.fingerprint = DeviceFingerprint(ip=rec.ip)
        rec.fingerprint.ttl_samples.append(ttl)
        rec.fingerprint.window_sizes.append(window)
        guess = fingerprint_tcp(ttl, window, options)
        if guess.confidence > 0:
            rec.fingerprint.tcp_guess = guess
            rec.os_guess = rec.fingerprint.combined()

    def update_dns_fingerprint(self, mac: str, domain: str):
        from fingerprint.os_detect import fingerprint_dns
        rec = self._devices.get(mac.upper())
        if not rec:
            return
        if rec.fingerprint is None:
            rec.fingerprint = DeviceFingerprint(ip=rec.ip)
        rec.fingerprint.dns_queries.append(domain)
        # Re-evaluate every 5 new queries to avoid too much CPU
        if len(rec.fingerprint.dns_queries) % 5 == 0:
            guess = fingerprint_dns(rec.fingerprint.dns_queries)
            if guess.confidence > 0:
                rec.fingerprint.dns_guess = guess
                rec.os_guess = rec.fingerprint.combined()

    def update_ja3_fingerprint(self, mac: str, ja3_hash: str):
        from fingerprint.os_detect import fingerprint_ja3, is_malicious_ja3
        rec = self._devices.get(mac.upper())
        if not rec:
            return
        if rec.fingerprint is None:
            rec.fingerprint = DeviceFingerprint(ip=rec.ip)
        if ja3_hash not in rec.fingerprint.ja3_hashes:
            rec.fingerprint.ja3_hashes.append(ja3_hash)
        guess = fingerprint_ja3(ja3_hash)
        if guess.confidence > 0:
            rec.fingerprint.ja3_guess = guess
            rec.os_guess = rec.fingerprint.combined()
        if is_malicious_ja3(ja3_hash):
            self._flag_risk(mac, f"malicious JA3 fingerprint: {ja3_hash[:8]}…", 40)

    # ── Risk scoring ──────────────────────────────────────────────────────────

    def _flag_risk(self, mac: str, reason: str, delta: float):
        with self._lock:
            rec = self._devices.get(mac.upper())
            if not rec:
                return
            if reason not in rec.risk_reasons:
                rec.risk_reasons.append(reason)
                rec.risk_score = min(100.0, rec.risk_score + delta)
                # Emit outside the lock to avoid holding it during callback execution
                emit = True
            else:
                emit = False
        if emit:
            self._emit("risk", rec)

    def flag_risk(self, mac: str, reason: str, delta: float = 10.0):
        self._flag_risk(mac, reason, delta)

    # ── Stale cleanup ─────────────────────────────────────────────────────────

    def evict_stale(self, max_age_seconds: float = 3600.0):
        """Remove devices not seen in max_age_seconds. Call periodically."""
        cutoff = time.time() - max_age_seconds
        with self._lock:
            stale = [mac for mac, rec in self._devices.items()
                     if rec.last_seen < cutoff and not rec.is_gateway]
            for mac in stale:
                rec = self._devices.pop(mac)
                if rec.ip in self._ip_index:
                    del self._ip_index[rec.ip]
