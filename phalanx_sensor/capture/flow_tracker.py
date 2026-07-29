"""
Flow tracker — tracks every network connection seen on the network.

A "flow" is a 5-tuple: src_ip, src_port, dst_ip, dst_port, protocol.
For each flow we track: bytes, packets, start time, last seen.

Additionally runs:
  - Beacon detector: finds devices calling home on a fixed interval (malware C2)
  - Port scan detector: finds devices hitting many IPs/ports rapidly
  - Lateral movement detector: internal → internal connections that are new

Operates on AF_PACKET raw socket, same as DnsSniffer.
"""

from __future__ import annotations
import datetime
import socket
import struct
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable


# ─────────────────────────────────────────────────────────────────────────────
# Flow record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Flow:
    src_ip:    str
    src_port:  int
    dst_ip:    str
    dst_port:  int
    protocol:  str       # tcp | udp | icmp
    src_mac:   str = ""

    # Timing
    started:   float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    # Volume
    packets:   int = 0
    bytes_out: int = 0
    bytes_in:  int = 0

    # State
    is_new:    bool = True
    closed:    bool = False

    # Geo (filled in by enricher if available)
    dst_country: str = ""
    dst_asn:     str = ""

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    @property
    def duration(self) -> float:
        return self.last_seen - self.started

    def to_event(self, action: str, agent_id: str, sensor_host: str) -> dict:
        ts = datetime.datetime.utcfromtimestamp(self.started).isoformat() + "Z"
        return {
            "@timestamp": ts,
            "event": {
                "id":       str(uuid.uuid4()),
                "kind":     "event",
                "category": ["network"],
                "type":     [action],
                "action":   f"flow_{action}",
                "dataset":  "phalanx.sensor.network",
                "duration": int(self.duration * 1e9),   # nanoseconds (ECS)
            },
            "agent": {"id": agent_id, "type": "phalanx-sensor-node"},
            "host":  {"hostname": sensor_host},
            "source": {
                "ip":    self.src_ip,
                "port":  self.src_port,
                "mac":   self.src_mac,
                "bytes": self.bytes_out,
                "packets": self.packets,
            },
            "destination": {
                "ip":      self.dst_ip,
                "port":    self.dst_port,
                "bytes":   self.bytes_in,
                "country": self.dst_country,
                "as":      {"number": self.dst_asn},
            },
            "network": {
                "transport": self.protocol,
                "bytes":     self.bytes_out + self.bytes_in,
                "packets":   self.packets,
                "direction": self._direction(),
            },
        }

    def _direction(self) -> str:
        # Simple heuristic: high src_port = client (egress)
        if self.src_port > 1024 and self.dst_port <= 1024:
            return "egress"
        if self.dst_port > 1024 and self.src_port <= 1024:
            return "ingress"
        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Beacon detector
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _BeaconCandidate:
    """Tracks connection timestamps to a specific destination from one source."""
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamps: list[float] = field(default_factory=list)

    def add(self, ts: float):
        self.timestamps.append(ts)
        if len(self.timestamps) > 200:
            self.timestamps = self.timestamps[-100:]

    def beacon_interval(self) -> float | None:
        """
        Return the beacon interval in seconds if a regular pattern is detected.
        Uses inter-arrival time variance — beacons have very low variance.
        Returns None if no beacon detected.
        """
        if len(self.timestamps) < 5:
            return None

        intervals = [
            self.timestamps[i+1] - self.timestamps[i]
            for i in range(len(self.timestamps) - 1)
        ]
        if not intervals:
            return None

        mean = sum(intervals) / len(intervals)
        if mean < 5:        # ignore sub-5s intervals (keep-alives, streaming)
            return None
        if mean > 7200:     # ignore > 2 hour intervals
            return None

        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / mean    # coefficient of variation

        # Beacons have CV < 0.1 (very regular). Human traffic has CV > 0.5.
        if cv < 0.15 and len(intervals) >= 4:
            return round(mean, 1)
        return None


@dataclass
class BeaconAlert:
    src_ip:   str
    src_mac:  str
    dst_ip:   str
    dst_port: int
    interval: float     # seconds
    confidence: float

    def to_event(self, agent_id: str, sensor_host: str) -> dict:
        return {
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": {
                "id":       str(uuid.uuid4()),
                "kind":     "alert",
                "category": ["network", "intrusion_detection"],
                "type":     ["indicator"],
                "action":   "beacon_detected",
                "dataset":  "phalanx.sensor.beacon",
                "severity": 60,
            },
            "agent": {"id": agent_id, "type": "phalanx-sensor-node"},
            "host":  {"hostname": sensor_host},
            "source": {"ip": self.src_ip, "mac": self.src_mac},
            "destination": {"ip": self.dst_ip, "port": self.dst_port},
            "threat": {
                "indicator": {
                    "type":        "network-traffic",
                    "description": f"Regular beacon every {self.interval}s to {self.dst_ip}:{self.dst_port}",
                    "confidence":  self.confidence,
                },
            },
            "beacon": {
                "interval_seconds": self.interval,
                "confidence":       self.confidence,
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# Port scan detector
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _ScanTracker:
    src_ip:          str
    dst_ips:         set  = field(default_factory=set)
    dst_ports:       set  = field(default_factory=set)
    packet_count:    int  = 0
    window_start:    float = field(default_factory=time.time)
    alerted:         bool = False

    def reset_if_stale(self):
        if time.time() - self.window_start > 60:
            self.dst_ips      = set()
            self.dst_ports    = set()
            self.packet_count = 0
            self.window_start = time.time()
            self.alerted      = False


@dataclass
class ScanAlert:
    src_ip:    str
    src_mac:   str
    dst_count: int    # number of distinct IPs hit
    port_count: int   # number of distinct ports hit
    scan_type: str    # host_sweep | port_scan | syn_scan

    def to_event(self, agent_id: str, sensor_host: str) -> dict:
        return {
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": {
                "id":       str(uuid.uuid4()),
                "kind":     "alert",
                "category": ["network", "intrusion_detection"],
                "type":     ["indicator"],
                "action":   "port_scan_detected",
                "dataset":  "phalanx.sensor.scan",
                "severity": 50,
            },
            "agent": {"id": agent_id, "type": "phalanx-sensor-node"},
            "host":  {"hostname": sensor_host},
            "source": {"ip": self.src_ip, "mac": self.src_mac},
            "scan": {
                "type":              self.scan_type,
                "distinct_ips":      self.dst_count,
                "distinct_ports":    self.port_count,
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# Flow tracker (main class)
# ─────────────────────────────────────────────────────────────────────────────

class FlowTracker:
    """
    Tracks all network flows observed on an interface.

    Start with:
        tracker = FlowTracker("br0", agent_id="...", sensor_host="node-1")
        tracker.on_flow(lambda flow, action: ...)
        tracker.on_beacon(lambda alert: ...)
        tracker.on_scan(lambda alert: ...)
        tracker.start()
    """

    # Ports considered "well-known services" for scan detection
    SENSITIVE_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                       3306, 3389, 5432, 6379, 8080, 8443, 27017}

    def __init__(self, interface: str, agent_id: str, sensor_host: str,
                 local_network: str = ""):
        self._iface         = interface
        self._agent_id      = agent_id
        self._sensor_host   = sensor_host
        self._local_network = local_network   # e.g. "192.168.0.0/24"

        self._flows:    dict[tuple, Flow] = {}
        self._lock      = threading.Lock()
        self._running   = False
        self._thread:   threading.Thread | None = None

        # Detectors
        self._beacon_candidates: dict[tuple, _BeaconCandidate] = defaultdict(
            lambda: _BeaconCandidate("", "", 0)
        )
        self._scan_trackers: dict[str, _ScanTracker] = {}

        # Callbacks
        self._flow_cbs:   list[Callable[[Flow, str], None]]   = []
        self._beacon_cbs: list[Callable[[BeaconAlert], None]] = []
        self._scan_cbs:   list[Callable[[ScanAlert], None]]   = []

        # Cleanup
        self._last_cleanup = time.time()

    def on_flow(self,   cb: Callable[[Flow, str], None]):   self._flow_cbs.append(cb)
    def on_beacon(self, cb: Callable[[BeaconAlert], None]): self._beacon_cbs.append(cb)
    def on_scan(self,   cb: Callable[[ScanAlert], None]):   self._scan_cbs.append(cb)

    def _emit_flow(self,   flow: Flow,        action: str):    [cb(flow, action)   for cb in self._flow_cbs]
    def _emit_beacon(self, alert: BeaconAlert):                [cb(alert)          for cb in self._beacon_cbs]
    def _emit_scan(self,   alert: ScanAlert):                  [cb(alert)          for cb in self._scan_cbs]

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._capture_loop, daemon=True,
                                          name="flow-tracker")
        self._thread.start()

    def stop(self):
        self._running = False

    def _capture_loop(self):
        try:
            # ETH_P_ALL (0x0003) to capture all packets
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0003))
            sock.bind((self._iface, 0))
            sock.settimeout(1.0)
        except PermissionError:
            print("[flow-tracker] ERROR: root / CAP_NET_RAW required")
            return
        except OSError as e:
            print(f"[flow-tracker] ERROR binding to {self._iface}: {e}")
            return

        print(f"[flow-tracker] Listening on {self._iface}")

        while self._running:
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                self._periodic_cleanup()
                continue
            except Exception:
                continue

            self._process_packet(raw, time.time())

        sock.close()

    def _process_packet(self, raw: bytes, ts: float):
        if len(raw) < 14:
            return

        src_mac_bytes = raw[6:12]
        src_mac = ":".join(f"{b:02X}" for b in src_mac_bytes)

        ethertype = struct.unpack("!H", raw[12:14])[0]
        if ethertype != 0x0800:    # IPv4 only
            return

        ip_start = 14
        if not _is_valid_ipv4_header(raw, ip_start):
            return

        ip_ihl   = (raw[ip_start] & 0x0F) * 4
        ip_ttl   = raw[ip_start + 8]
        ip_proto = raw[ip_start + 9]
        ip_len   = struct.unpack("!H", raw[ip_start + 2:ip_start + 4])[0]
        src_ip   = socket.inet_ntoa(raw[ip_start + 12:ip_start + 16])
        dst_ip   = socket.inet_ntoa(raw[ip_start + 16:ip_start + 20])

        proto_str = {6: "tcp", 17: "udp", 1: "icmp"}.get(ip_proto)
        if proto_str is None:
            return

        transport_start = ip_start + ip_ihl

        # TCP header validation before trusting flags/options.
        if ip_proto == 6:
            if len(raw) < transport_start + 20:
                return
            tcp_data_offset = ((raw[transport_start + 12] >> 4) * 4)
            if tcp_data_offset < 20 or transport_start + tcp_data_offset > ip_start + ip_len:
                return

        src_port = dst_port = 0

        if ip_proto == 17:
            if len(raw) < transport_start + 8:
                return
            udp_len = struct.unpack("!H", raw[transport_start + 4:transport_start + 6])[0]
            if udp_len < 8 or udp_len > ip_len - ip_ihl:
                return

        if ip_proto in (6, 17) and len(raw) >= transport_start + 4:
            src_port, dst_port = struct.unpack("!HH", raw[transport_start:transport_start + 4])

        # TCP SYN flag — used for fingerprinting and scan detection
        is_syn = False
        if ip_proto == 6 and len(raw) >= transport_start + 14:
            tcp_flags = raw[transport_start + 13]
            is_syn    = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
            # Pass TTL + window for OS fingerprinting
            if is_syn:
                window = struct.unpack("!H", raw[transport_start + 14:transport_start + 16])[0] \
                         if len(raw) >= transport_start + 16 else 0
                # We'd call registry.update_tcp_fingerprint here — passed via callback
                self._on_syn(src_mac, src_ip, ip_ttl, window)

        # Flow tracking
        flow_key = (src_ip, src_port, dst_ip, dst_port, proto_str)
        rev_key  = (dst_ip, dst_port, src_ip, src_port, proto_str)

        with self._lock:
            if flow_key in self._flows:
                flow = self._flows[flow_key]
                flow.packets   += 1
                flow.bytes_out += ip_len
                flow.last_seen  = ts
            elif rev_key in self._flows:
                flow = self._flows[rev_key]
                flow.bytes_in += ip_len
                flow.last_seen = ts
            else:
                flow = Flow(
                    src_ip   = src_ip,
                    src_port = src_port,
                    dst_ip   = dst_ip,
                    dst_port = dst_port,
                    protocol = proto_str,
                    src_mac  = src_mac,
                    started  = ts,
                    packets  = 1,
                    bytes_out = ip_len,
                )
                self._flows[flow_key] = flow
                self._emit_flow(flow, "start")

        # Beacon detection
        if proto_str in ("tcp", "udp") and dst_port in self.SENSITIVE_PORTS:
            bkey = (src_ip, dst_ip, dst_port)
            if bkey not in self._beacon_candidates:
                self._beacon_candidates[bkey] = _BeaconCandidate(src_ip, dst_ip, dst_port)
            candidate = self._beacon_candidates[bkey]
            candidate.add(ts)
            interval = candidate.beacon_interval()
            if interval:
                alert = BeaconAlert(
                    src_ip    = src_ip,
                    src_mac   = src_mac,
                    dst_ip    = dst_ip,
                    dst_port  = dst_port,
                    interval  = interval,
                    confidence = 0.85,
                )
                self._emit_beacon(alert)
                # Reset so we don't spam
                self._beacon_candidates[bkey] = _BeaconCandidate(src_ip, dst_ip, dst_port)

        # Scan detection
        if is_syn:
            self._check_scan(src_ip, src_mac, dst_ip, dst_port)

    # TCP SYN callback — subclasses or callbacks can hook this
    _syn_cbs: list[Callable] = []

    def on_syn(self, cb: Callable):
        self._syn_cbs.append(cb)

    def _on_syn(self, mac: str, ip: str, ttl: int, window: int):
        for cb in self._syn_cbs:
            try:
                cb(mac, ip, ttl, window)
            except Exception:
                pass

    def _check_scan(self, src_ip: str, src_mac: str, dst_ip: str, dst_port: int):
        if src_ip not in self._scan_trackers:
            self._scan_trackers[src_ip] = _ScanTracker(src_ip)

        tracker = self._scan_trackers[src_ip]
        tracker.reset_if_stale()
        tracker.dst_ips.add(dst_ip)
        tracker.dst_ports.add(dst_port)
        tracker.packet_count += 1

        if tracker.alerted:
            return

        # Host sweep: one device hitting many IPs
        if len(tracker.dst_ips) > 20:
            tracker.alerted = True
            self._emit_scan(ScanAlert(
                src_ip    = src_ip,
                src_mac   = src_mac,
                dst_count  = len(tracker.dst_ips),
                port_count = len(tracker.dst_ports),
                scan_type  = "host_sweep",
            ))

        # Port scan: one device hitting many ports on one IP
        elif len(tracker.dst_ports) > 15 and len(tracker.dst_ips) <= 3:
            tracker.alerted = True
            self._emit_scan(ScanAlert(
                src_ip    = src_ip,
                src_mac   = src_mac,
                dst_count  = len(tracker.dst_ips),
                port_count = len(tracker.dst_ports),
                scan_type  = "port_scan",
            ))

    def _periodic_cleanup(self):
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now

        with self._lock:
            # Emit 'end' for flows idle > 5 minutes
            stale = [k for k, f in self._flows.items()
                     if now - f.last_seen > 300]
            for k in stale:
                flow = self._flows.pop(k)
                self._emit_flow(flow, "end")

        # Clean up old beacon candidates
        stale_beacons = [k for k, c in self._beacon_candidates.items()
                         if (c.timestamps and now - c.timestamps[-1] > 3600)]
        for k in stale_beacons:
            del self._beacon_candidates[k]

    def active_flows(self) -> list[Flow]:
        with self._lock:
            return list(self._flows.values())

    def flow_count(self) -> int:
        with self._lock:
            return len(self._flows)


def _is_valid_ipv4_header(raw: bytes, offset: int) -> bool:
    """Validate the IPv4 header before trusting offsets from it."""
    if len(raw) < offset + 20:
        return False
    if (raw[offset] >> 4) != 4:
        return False

    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20:
        return False
    if len(raw) < offset + ihl:
        return False

    try:
        ip_len = struct.unpack("!H", raw[offset + 2:offset + 4])[0]
    except struct.error:
        return False

    return ip_len >= ihl and len(raw) >= offset + ip_len
