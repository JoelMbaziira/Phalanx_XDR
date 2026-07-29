# Phalanx — Phase 1 finish: sensor response + sensor rules

Two tasks closed in this drop:

## Task 2 — Sensor response actuators

Four Python files for `phalanx_sensor/response/`:

- `nftables.py` — `block_mac`, `block_ip`, with optional TTL. Owns a
  dedicated `phalanx` nftables table with two sets and a forward chain
  that drops on match.
- `dnsmasq.py` — `sinkhole_domain` via writing 0.0.0.0 entries to a
  Phalanx-managed hosts file plus `SIGHUP` to dnsmasq. Comes with an
  `install_hook()` classmethod that adds the `addn-hosts` directive to
  `/etc/dnsmasq.conf` if it's not already there.
- `tc.py` — `rate_limit_mac` using htb + u32 filter on ether saddr.
  Default ceiling 64 kbit/s — painfully slow but not disconnected.
- `coordinator.py` — polls `{server}/api/v1/response/commands/{node_id}`,
  dispatches by action, acks results. Same protocol as the endpoint
  agent's CommandExecutor.
- `__init__.py` — re-exports for convenient imports.

Plus `sensor_py_patch.md` showing three small edits to `sensor.py` that
wire the coordinator into the sensor's start/stop lifecycle.

### Apply

1. Copy the four `response/*.py` files into your `phalanx_sensor/response/`
   directory, replacing the empty `__init__.py` that's there now.

2. Apply the three edits in `sensor_py_patch.md` to your `sensor.py`.
   They're localized and visually obvious in the file.

3. On the gateway VM where the sensor runs, install the dnsmasq hook
   one time so sinkholing works:

   ```python
   sudo python3 -c "from response import DnsmasqActuator; DnsmasqActuator.install_hook()"
   sudo systemctl restart dnsmasq
   ```

4. Run the sensor — you'll see a log line like:
   `Response actuators: {'nftables': True, 'dnsmasq': True, 'tc': True}`
   confirming all three actuators initialised. If any read False, the
   binary isn't installed or the interface name was wrong — the
   coordinator will keep working but that specific action will return
   `failed` when invoked.

### Verify

From the Phalanx Console `/response` page, pick a sensor node, issue
`block_mac` with a test MAC (use a fake one like `aa:bb:cc:dd:ee:ff` so
you don't actually block yourself). Within ~5 seconds the command status
should flip from `pending` → `delivered` → `acked`. On the sensor host:

```bash
sudo nft list table inet phalanx
```

You should see the test MAC in the `blocked_macs` set.

## Task 3 — `network_sensor.yml` detection rules

Five new rules in `network_sensor.yml`:

| ID      | Severity | Event                        |
|---------|----------|------------------------------|
| PHX-300 | High     | Port scan detected           |
| PHX-301 | Critical | C2 beacon detected           |
| PHX-302 | Medium   | DGA-suspected DNS query      |
| PHX-303 | High     | DNS tunnelling observed      |
| PHX-304 | Low      | New device joined network    |

### Apply

Drop `network_sensor.yml` into the project's `rules/` folder alongside
`behavior.yml`, `correlation.yml`, `critical_tools.yml`, `discovery.yml`.

Restart the Correlator. You should see five additional rules show up on
the `/Rules` page (total = 19). When the sensor starts producing alerts,
the corresponding rule's `FireCount` will increment.

## What's next

Three Category 1 tasks remain:

- Task 4: Decision on the Windows agent — integrate the Phase 3 .NET
  build, or scope the demo to Linux endpoints?
- Task 5: Response policy engine — the automated half of "response"
- Task 1: Gateway-VM bench setup — manual work on your machine

I'll ship Task 5 in the next turn. Task 4 is a decision for you to make.
Task 1 is yours to execute.
