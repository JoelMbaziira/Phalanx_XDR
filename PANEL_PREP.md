# Phalanx XDR — Panel Prep & Reference

---

## What the system is trying to achieve

A proof-of-concept XDR pipeline demonstrating the full loop:

    collect telemetry → normalise → correlate against rules → automated response

Every layer is transparent and built from scratch. That is the research contribution —
not feature parity with commercial tools, but a working end-to-end architecture you
can fully explain and extend.

---

## Architecture (one-liner per component)

| Component | What it does |
|---|---|
| sentinel.py | Python agent on victim VM — polls for new processes, files, network, DNS, logins, memory, email indicators |
| Phalanx.Ingestion | HTTP API (port 5038) — receives events from agents, pushes to Redis queue |
| Phalanx.Correlator | Background service — reads Redis, runs rule engine, saves alerts to PostgreSQL, pushes via SignalR |
| Phalanx.Console | Web dashboard (port 5100) — shows real-time alerts via SignalR WebSocket, runs policy engine |
| Redis | Event queue between Ingestion and Correlator |
| PostgreSQL | Persistent store for alerts, response commands, policy audit log |

---

## What the agent collects (7 domains)

| Domain | What is actually captured |
|---|---|
| Process | Every new process: name, full command line, ancestry chain, SHA-256 of binary, user/UID, parent process |
| File | Sensitive file opens (shadow, SSH keys, sudoers, cron), modifications, new executables |
| Network | New TCP/UDP connections — src/dst IP, port, protocol, direction |
| DNS | UDP/53 connections + syslog parsing (dnsmasq/resolved) |
| Login/Auth | wtmp/btmp (login success/failure), SSH logins, failed passwords, sudo escalation |
| Memory | Anonymous RWX regions (shellcode indicator), executable heap/stack |
| Email | Email client spawning suspicious children, malicious attachment extensions in Downloads/tmp |

---

## Detection — 3 rule types

### 1. Stateless — fires on a single matching event

```yaml
id: PHX-020
title: Netcat listener
severity: High
mitre:
  tactic: TA0011
  technique: T1095
match:
  process.name:
    - nc
    - ncat
  process.command_line|contains:
    - " -l"
```

### 2. Correlate — fires when N events match within a time window

```yaml
id: PHX-100
title: SSH brute force burst
severity: High
match:
  event.action: login_failed
correlate:
  group_by: host.hostname
  window_seconds: 30
  threshold: 5
```

### 3. Sequence — fires when stage A then stage B happen in order

```yaml
id: PHX-110
title: Scan then download
severity: High
sequence:
  group_by: agent.id
  window_seconds: 300
  stages:
    - id: scan
      match:
        process.name: [nmap, masscan]
    - id: download
      match:
        process.name: [wget, curl]
```

### Match operators

| Operator | Example | Meaning |
|---|---|---|
| (none / equals) | `process.name: nmap` | exact match, case-insensitive |
| contains | `process.command_line|contains: " -enc"` | substring |
| startswith | `process.executable|startswith: /tmp/` | prefix |
| endswith | `process.executable|endswith: .sh` | suffix |
| regex | `process.command_line|regex: '(?i)base64'` | full regex |
| not | `user.id|not: "0"` | negation (wraps any operator) |
| gt / lt | `process.pid|gt: 1000` | numeric comparison |

Multiple values in a list = OR within that field.
Multiple fields in the same match block = AND across fields.

### Field paths (from the ECS-based schema)

- process.name, process.executable, process.command_line, process.args
- process.parent.name, process.parent.command_line
- process.code_signature.signed
- user.name, user.id, user.effective.id
- host.hostname, host.os.family
- event.action, event.category
- agent.id

### To add a new rule

1. Create a .yml file in phalanx_xdr/rules/
2. Give it a unique id (use your own prefix, e.g. DEMO-001)
3. Restart the Correlator — it loads all rules at startup
4. Trigger the condition and watch the Correlator log for: ALERT [...] {ruleId}

---

## Response — what it actually does

Important: response is REACTIVE not PREVENTIVE.
The agent polls for commands every 5 seconds. Damage done before the kill/quarantine stands.

| Action | What actually happens | Honest limitation |
|---|---|---|
| kill_process | SIGKILL sent to PID | Process already ran. PID reuse risk between detection and kill. |
| quarantine_file | chmod 000 + rename to .quarantine | File was already written. No rollback. |
| collect_file | Returns file base64-encoded | Forensics only — not a prevention action. |
| isolate_host | iptables DROP ALL except manager IP | Blunt instrument. No undo command — manual intervention needed. |
| run_command | Arbitrary shell execution | Research/test use only. Not for production. |

Policy engine features:
- dry_run mode — logs what would happen without acting
- Kill switch — disables all automated response globally
- Per-host rate limiting — e.g. "max 1 isolation per host per 10 minutes"
- Full audit trail of every dispatch in the database

---

## What it CANNOT do — and how to say it

### Visibility

"Does it work on Windows?"
  The agent is Linux-only — it uses /proc, iptables, wtmp/btmp.
  A Windows agent would use ETW or Sysmon feeding the same Ingestion API.
  The schema is OS-agnostic, so it's an integration task, not a redesign.

"Can it see network traffic / packet contents?"
  No — only connection metadata (IP, port, status). No DPI, no payload inspection.
  A Zeek or Suricata sensor could feed the same Ingestion API as an additional source.

"What about cloud logs — O365, AWS CloudTrail?"
  Not currently. The Ingestion API is generic — cloud logs normalised to the schema
  would be another input source. Out of scope for this prototype.

### Detection

"Is there machine learning / anomaly detection?"
  No — all detection is rule-based. Deliberate choice: rules are auditable, explainable,
  and have no training data dependency. ML/UEBA is a natural extension but requires a
  baseline dataset this prototype doesn't have.

"Can it detect lateral movement across hosts?"
  Correlation is per-host (grouped by agent.id). Cross-host campaign linking is not
  implemented. The sequence rule infrastructure could support it with a shared group key.

"What if the attacker uses a renamed tool or a novel technique?"
  No detection fires — this is rule-based, not behavioural. Coverage depends on the
  rule set. This is a known, honest limitation.

"Can it miss short-lived processes?"
  Yes. The agent polls at 0.5s intervals (userland psutil). A process that starts and
  exits in under 500ms may be missed. Kernel-level hooks (eBPF, auditd) would fix this
  but are outside the current scope.

### Architecture

"What happens if the Correlator restarts mid-investigation?"
  Correlation windows and sequence state are in-memory only — lost on restart.
  Production fix: persist state to Redis sorted sets or a stream processor like Flink.

"Is communication authenticated / encrypted?"
  No — plain HTTP, no mTLS, no API keys in the prototype.
  This is a deployment concern, not a schema concern — TLS and auth are middleware.

---

## The answer formula for any gap

  "That's outside the current scope — this prototype demonstrates [X].
   The architecture supports extending it via [specific mechanism].
   The decision not to include it was [reason: complexity / data dependency / scope]."

---

## Built-in detection rule set (from README)

| Process | Severity | MITRE |
|---|---|---|
| mimikatz | Critical | T1003 - Credential Dumping |
| msfconsole | Critical | T1190 - Exploitation |
| psexec | High | T1035 - Lateral Movement |
| hydra | High | T1110 - Brute Force |
| nmap | Medium | T1046 - Network Scanning |
| wget / curl | Medium | T1105 - Ingress Tool Transfer |
| powershell | Medium | T1059.001 - Scripting |
| whoami / id | Low | T1033 - Discovery |

Plus 22+ more in the full rule set covering memory injection, file access, privilege
escalation, and email-based phishing indicators.
