"""
Phalanx Sensor Node — main daemon

Orchestrates:
  DhcpWatcher   → new device detection
  DnsSniffer    → DNS query capture + DGA/tunnel detection
  FlowTracker   → connection tracking + beacon/scan detection
  DeviceRegistry → live device inventory + OS fingerprinting
  Shipper        → buffer → Phalanx server

Run:
  sudo python3 sensor.py --interface br0 --server http://10.0.0.1:5038
  sudo python3 sensor.py --interface eth0 --server https://phalanx.yourdomain.com
  sudo python3 sensor.py --demo              # auto-detects interface, prints to console
"""

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

# ── local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from capture.registry    import DeviceRegistry, DeviceRecord
from capture.dns_sniffer import DnsSniffer, DnsEvent
from capture.flow_tracker import FlowTracker, Flow, BeaconAlert, ScanAlert
from capture.dhcp_watcher import DhcpWatcher, DhcpEvent
from shipper.shipper      import Shipper
from response.coordinator import ResponseCoordinator

# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt = "%H:%M:%S",
)
log = logging.getLogger("sensor")

SENSOR_VERSION = "0.1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Node identity
# ─────────────────────────────────────────────────────────────────────────────

def get_or_create_node_id(state_dir: str) -> str:
    path = Path(state_dir) / "node_id"
    try:
        Path(state_dir).mkdir(parents=True, exist_ok=True)
        if path.exists():
            return path.read_text().strip()
        nid = str(uuid.uuid4())
        path.write_text(nid)
        return nid
    except Exception:
        return str(uuid.uuid4())


def detect_interface() -> str:
    """Pick the best interface to listen on (first non-loopback with an IP)."""
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            if iface.startswith("lo"):
                continue
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    return iface
    except ImportError:
        pass
    # Fallback: parse /proc/net/if_inet6 or just return eth0
    for candidate in ("br0", "eth0", "enp3s0", "wlan0"):
        if Path(f"/sys/class/net/{candidate}").exists():
            return candidate
    return "eth0"


# ─────────────────────────────────────────────────────────────────────────────
# Console printer (for --demo mode)
# ─────────────────────────────────────────────────────────────────────────────

COLOURS = {
    "reset": "\033[0m",  "bold": "\033[1m",
    "red":   "\033[31m", "green":  "\033[32m",
    "yellow":"\033[33m", "blue":   "\033[34m",
    "cyan":  "\033[36m", "grey":   "\033[90m",
}

def c(colour: str, text: str) -> str:
    return f"{COLOURS.get(colour,'')}{text}{COLOURS['reset']}"


class ConsolePrinter:
    """Prints live telemetry to the terminal in demo mode."""

    def __init__(self):
        self._lock = threading.Lock()

    def device_event(self, action: str, device: DeviceRecord):
        with self._lock:
            os_str  = str(device.os_guess) if device.os_guess else "Unknown OS"
            icon    = "🆕" if action == "new" else ("⚠️ " if action == "risk" else "📡")
            risk    = f"  {c('red', f'RISK {device.risk_score:.0f}')} {device.risk_reasons[-1]}" \
                      if action == "risk" else ""
            print(
                f"{icon} {c('cyan', device.mac)}"
                f"  {c('bold', device.ip or '?'):<16}"
                f"  {c('yellow', device.manufacturer):<20}"
                f"  {os_str:<30}"
                f"  {device.hostname or ''}"
                f"{risk}"
            )

    def dns_event(self, ev: DnsEvent):
        with self._lock:
            flags = []
            if ev.dga_score > 0.6:
                flags.append(c("red", f"DGA:{ev.dga_score:.2f}"))
            if ev.is_tunnel:
                flags.append(c("red", "TUNNEL"))
            flag_str = "  " + " ".join(flags) if flags else ""
            if ev.qr == 0:    # only print queries, not responses
                print(
                    f"   {c('grey','DNS')} "
                    f"{c('cyan', ev.src_ip):<18}"
                    f"→ {c('blue', ev.domain):<50}"
                    f"{ev.qtype:<6}"
                    f"{flag_str}"
                )

    def flow_event(self, flow: Flow, action: str):
        if action != "start":
            return
        with self._lock:
            print(
                f"   {c('grey', 'NET')} "
                f"{c('cyan', ev_fmt(flow.src_ip, flow.src_port)):<24}"
                f"→ {c('blue', ev_fmt(flow.dst_ip, flow.dst_port)):<24}"
                f"{flow.protocol.upper()}"
            )

    def beacon_alert(self, alert: BeaconAlert):
        with self._lock:
            print(
                f"\n{c('red', '⚠  BEACON')} "
                f"{c('cyan', alert.src_ip)} → {alert.dst_ip}:{alert.dst_port} "
                f"every {alert.interval}s  "
                f"[confidence {alert.confidence:.0%}]\n"
            )

    def scan_alert(self, alert: ScanAlert):
        with self._lock:
            print(
                f"\n{c('red', '⚠  SCAN')} "
                f"{c('cyan', alert.src_ip)} "
                f"{alert.scan_type.replace('_',' ')} — "
                f"{alert.dst_count} IPs / {alert.port_count} ports\n"
            )

    def dhcp_event(self, ev: DhcpEvent):
        if ev.msg_type not in ("DISCOVER", "ACK"):
            return
        with self._lock:
            print(
                f"   {c('grey','DHCP')} "
                f"{c('cyan', ev.mac):<20}"
                f"  {c('green', ev.assigned_ip or ev.requested_ip or '?'):<16}"
                f"  {ev.hostname or '':<20}"
                f"  {c('yellow', ev.os_guess or '')}"
            )

    def stats(self, registry, shipper):
        with self._lock:
            print(
                f"\r{c('grey', '●')} "
                f"Devices:{c('bold', str(registry.count())):<5} "
                f"Pending:{shipper.pending():<6} "
                f"Shipped:{shipper.shipped:<8} "
                f"{'OFFLINE' if not shipper._reachable else 'online'}",
                end="", flush=True
            )


def ev_fmt(ip: str, port: int) -> str:
    return f"{ip}:{port}"


# ─────────────────────────────────────────────────────────────────────────────
# Main sensor
# ─────────────────────────────────────────────────────────────────────────────

class SensorNode:

    def __init__(self,
                 interface:  str,
                 server_url: str,
                 node_id:    str,
                 state_dir:  str,
                 demo_mode:  bool = False,
                 gateway_ip: str  = ""):

        self._iface      = interface
        self._node_id    = node_id
        self._demo_mode  = demo_mode
        self._hostname   = socket.gethostname()
        self._running    = False

        # Shipper
        ingest_url = server_url.rstrip("/") + "/api/v1/ingest/batch"
        self._shipper = Shipper(
            endpoint    = ingest_url,
            node_id     = node_id,
            buffer_path = str(Path(state_dir) / "buffer.db"),
            compress    = True,
        )

        # Registry
        self._registry = DeviceRegistry(gateway_ip=gateway_ip)
        self._registry.on_event(self._on_device_event)

        # Capture modules
        self._dhcp   = DhcpWatcher(interface, node_id, self._hostname)
        self._dns    = DnsSniffer(interface,  node_id, self._hostname)
        self._flows  = FlowTracker(interface, node_id, self._hostname)

        # Wire up callbacks
        self._dhcp.on_event(self._on_dhcp)
        self._dns.on_event(self._on_dns)
        self._flows.on_flow(self._on_flow)
        self._flows.on_beacon(self._on_beacon)
        self._flows.on_scan(self._on_scan)
        self._flows.on_syn(self._on_syn)

        # Response coordinator — polls the server for actions to execute
        self._response = ResponseCoordinator(
            server_url    = server_url,
            node_id       = node_id,
            lan_iface     = interface,
            poll_interval = 5.0,
        )

        if demo_mode:
            self._printer = ConsolePrinter()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        self._shipper.start()
        self._dhcp.start()
        self._dns.start()
        self._flows.start()
        self._response.start()

        log.info(f"Sensor node {self._node_id[:8]} started on {self._iface}")
        log.info(f"Response actuators: {self._response.status()['actuators']}")
        if self._demo_mode:
            self._run_demo_loop()
        else:
            self._run_quiet_loop()

    def stop(self):
        self._running = False
        self._response.stop()
        self._dhcp.stop()
        self._dns.stop()
        self._flows.stop()
        self._shipper.stop()
        log.info("Sensor stopped")

    def _run_quiet_loop(self):
        while self._running:
            time.sleep(30)
            log.info(self._shipper.stats())

    def _run_demo_loop(self):
        print(f"\n{c('bold', c('blue', '⬡ PHALANX SENSOR NODE'))}"
              f"  v{SENSOR_VERSION}"
              f"  node:{self._node_id[:8]}"
              f"  iface:{self._iface}\n")
        print(f"{'TYPE':<6} {'SOURCE':<20} {'DETAIL':<50} {'FLAGS'}")
        print("─" * 90)

        last_stats = time.time()
        while self._running:
            time.sleep(0.1)
            if time.time() - last_stats > 5:
                self._printer.stats(self._registry, self._shipper)
                last_stats = time.time()

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_device_event(self, action: str, device: DeviceRecord):
        ev = device.to_event(action, self._node_id, self._hostname)
        self._ship(ev)
        if self._demo_mode:
            self._printer.device_event(action, device)

    def _on_dhcp(self, ev: DhcpEvent):
        # Register device immediately on DHCP
        self._registry.see(
            mac      = ev.mac,
            ip       = ev.assigned_ip or ev.requested_ip,
            hostname = ev.hostname,
        )
        self._ship(ev.to_event())
        if self._demo_mode:
            self._printer.dhcp_event(ev)

    def _on_dns(self, ev: DnsEvent):
        # Update device registry
        device = self._registry.by_ip(ev.src_ip)
        if not device and ev.src_mac:
            device = self._registry.see(mac=ev.src_mac, ip=ev.src_ip)

        if device:
            self._registry.add_dns(device.mac)
            self._registry.update_dns_fingerprint(device.mac, ev.domain)

            if ev.dga_score > 0.7:
                self._registry.flag_risk(
                    device.mac,
                    f"DGA domain queried: {ev.domain} (score {ev.dga_score:.2f})",
                    delta=25.0,
                )
            if ev.is_tunnel:
                self._registry.flag_risk(
                    device.mac,
                    f"DNS tunnelling detected: {ev.domain}",
                    delta=35.0,
                )

        self._ship(ev.to_event())
        if self._demo_mode and ev.qr == 0:
            self._printer.dns_event(ev)

    def _on_flow(self, flow: Flow, action: str):
        device = self._registry.by_ip(flow.src_ip)
        if device:
            self._registry.add_connection(device.mac)
            self._registry.add_traffic(device.mac,
                                        bytes_out=flow.bytes_out,
                                        bytes_in=flow.bytes_in)

        self._ship(flow.to_event(action, self._node_id, self._hostname))
        if self._demo_mode:
            self._printer.flow_event(flow, action)

    def _on_beacon(self, alert: BeaconAlert):
        device = self._registry.by_ip(alert.src_ip)
        if device:
            self._registry.flag_risk(
                device.mac,
                f"Beacon every {alert.interval}s → {alert.dst_ip}:{alert.dst_port}",
                delta=40.0,
            )
        self._ship(alert.to_event(self._node_id, self._hostname))
        if self._demo_mode:
            self._printer.beacon_alert(alert)

    def _on_scan(self, alert: ScanAlert):
        device = self._registry.by_ip(alert.src_ip)
        if device:
            self._registry.flag_risk(
                device.mac,
                f"{alert.scan_type}: {alert.dst_count} IPs / {alert.port_count} ports",
                delta=50.0,
            )
        self._ship(alert.to_event(self._node_id, self._hostname))
        if self._demo_mode:
            self._printer.scan_alert(alert)

    def _on_syn(self, mac: str, ip: str, ttl: int, window: int):
        # TCP SYN seen — update OS fingerprint
        # Options parsing would require deeper packet inspection;
        # here we use TTL+window which covers 90% of cases
        self._registry.update_tcp_fingerprint(mac, ttl, window, set())

    def _ship(self, event: dict):
        self._shipper.enqueue(event)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Phalanx Sensor Node — agentless network telemetry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Demo on MiFi hotspot (auto-detects interface, prints to console)
  sudo python3 sensor.py --demo --server http://localhost:5038

  # Production — bridge interface, remote server
  sudo python3 sensor.py --interface br0 --server https://phalanx.example.com

  # Listen on a specific interface, offline buffer only
  sudo python3 sensor.py --interface eth0 --server http://127.0.0.1:5038
        """,
    )
    p.add_argument("--interface",  "-i", default="",
                   help="Network interface to capture on (default: auto-detect)")
    p.add_argument("--server",     "-s", default="http://localhost:5038",
                   help="Phalanx server URL")
    p.add_argument("--gateway",    "-g", default="",
                   help="Gateway IP (excluded from scan alerts)")
    p.add_argument("--state-dir",        default="/var/lib/phalanx",
                   help="Directory for node ID and SQLite buffer")
    p.add_argument("--demo",             action="store_true",
                   help="Print live telemetry to console (for demos)")
    p.add_argument("--debug",            action="store_true",
                   help="Verbose logging")
    return p.parse_args()


def main():
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        print("ERROR: Phalanx sensor requires root (raw socket capture).")
        print("Run with: sudo python3 sensor.py ...")
        sys.exit(1)

    iface   = args.interface or detect_interface()
    node_id = get_or_create_node_id(args.state_dir)

    print(f"[*] Phalanx Sensor Node v{SENSOR_VERSION}")
    print(f"    Node ID  : {node_id}")
    print(f"    Interface: {iface}")
    print(f"    Server   : {args.server}")
    print(f"    State dir: {args.state_dir}")
    if args.demo:
        print(f"    Mode     : DEMO (live console output)\n")

    sensor = SensorNode(
        interface  = iface,
        server_url = args.server,
        node_id    = node_id,
        state_dir  = args.state_dir,
        demo_mode  = args.demo,
        gateway_ip = args.gateway,
    )

    # Graceful shutdown
    def _shutdown(sig, frame):
        print("\n[*] Shutting down...")
        sensor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    sensor.start()


if __name__ == "__main__":
    main()
