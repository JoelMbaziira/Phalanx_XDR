# Phalanx XDR — How to Trigger Rules and Policies

Run these commands ON THE VICTIM VM (where sentinel.py is running).

---

## Rule → Policy map (what actually fires what)

| Command | Rule fired | Policy fired | Policy effect |
|---|---|---|---|
| `nmap -sV localhost` | PHX-009 Medium | none | alert only |
| `whoami` | PHX-008 Low | none | alert only |
| `wget http://example.com` | PHX-013 Medium | none | alert only |
| `mimikatz` (fake binary) | PHX-001 Critical | POL-001 | DRY RUN — logs but does NOT isolate |
| `msfconsole` (fake binary) | PHX-002 Critical | POL-002 | LIVE — actually kills the process |
| `hydra` (fake binary) | PHX-004 High | POL-002 | LIVE — actually kills the process |

---

## 1. Simple alert (stateless rule) — most reliable demo

On victim VM:

    nmap -sV localhost

What happens:
- Sentinel detects new process named "nmap"
- Correlator matches PHX-009 (Network Scanning, Medium)
- Alert appears in Console dashboard within 1-2 seconds
- No policy fires for this one

Also works with:
    whoami
    wget http://example.com -O /tmp/test

---

## 2. Correlate rule — needs 3 discovery commands in 60 seconds

On victim VM, run these quickly one after another:

    whoami
    id
    hostname

What happens:
- Each individually fires PHX-008 (Low)
- After the 3rd, PHX-100 "Discovery burst" also fires (Medium)
- The correlate rule resets its window after firing

To make it even clearer, run all three in one line:

    whoami && id && hostname

---

## 3. Sequence rule — nmap then wget within 5 minutes

    nmap -sV localhost
    wget http://example.com -O /tmp/test

What happens:
- nmap fires PHX-009 (Medium) — also starts the sequence timer
- wget with http:// fires PHX-013 (Medium) — completes the sequence
- PHX-110 "Recon then download" fires (High)
- You get three alerts for one attack chain

The wget must contain http:// or https:// in the command line or the sequence won't complete.

---

## 4. Live policy response — the most impressive demo

This is where a policy ACTUALLY does something (not dry run).

POL-002 (kill_process) fires on PHX-002 (msfconsole), PHX-003 (psexec), PHX-004 (hydra).
It is NOT dry_run — it will actually send a kill command to the agent.

Step 1 — create a fake "msfconsole" that stays alive long enough to be killed:

    echo '#!/bin/bash
    echo "running..."
    sleep 60' > /tmp/msfconsole
    chmod +x /tmp/msfconsole

Step 2 — run it in the background:

    /tmp/msfconsole &

Step 3 — watch what happens (within ~5 seconds):
- Sentinel sees new process named "msfconsole"
- Correlator fires PHX-002 (Critical — Exploitation framework)
- PolicyEngine matches POL-002
- kill_process command queued in database
- Agent polls (every 5s), receives command, sends SIGKILL to the process
- Agent acks result back to manager
- Dashboard shows alert + "[POL-002] ... → kill_process" notification

You can verify it was killed:

    jobs
    # or
    ps aux | grep msfconsole

The process should be gone.

---

## 5. Dry-run policy — shows the audit trail without real action

mimikatz fires POL-001, but POL-001 has dry_run: true, so it logs but doesn't isolate.

    echo '#!/bin/bash
    sleep 30' > /tmp/mimikatz
    chmod +x /tmp/mimikatz
    /tmp/mimikatz &

What you see in the dashboard:
- PHX-001 Critical alert (Credential Dumping)
- POL-001 appears as "policy_fired" but Outcome=dry_run in the database

This is useful to explain the dry_run safety mechanism to the panel.

---

## Common reasons a rule doesn't fire

| Problem | Fix |
|---|---|
| Sentinel not running | Check: `python3 sentinel.py` is running on victim VM |
| Sentinel pointed at wrong IP | Check --api flag matches your manager IP:5038 |
| Correlator not running | Check: `dotnet run` in Phalanx.Correlator is running |
| Console not running | Check: `dotnet run --urls http://localhost:5100` in Phalanx.Console |
| Redis not running | Check: `docker compose up -d` in infrastructure/ |
| Rule not loaded | Correlator loads rules at startup — restart it after adding new rules |
| Process exits too fast | Sentinel polls at 0.5s — if a process starts and exits faster, it may be missed |
| Wrong process name | Rule matches on basename only (e.g. "nmap" not "/usr/bin/nmap") |

---

## To confirm a rule loaded correctly

Watch the Correlator terminal when it starts. It logs every rule it loads.
If a rule has an error (bad YAML, missing fields), it logs a warning and skips it.

To test a specific rule fired, watch the Correlator terminal for:

    ALERT [PHX-009] Network scanning — proc=nmap host=yourhost user=youruser

---

## Policy dry_run status at a glance

| Policy | dry_run | Effect |
|---|---|---|
| POL-001 (isolate on credential dumping) | TRUE | Logs only — safe to demo |
| POL-002 (kill exploitation/lateral/brute tools) | FALSE | Actually kills the process |
| POL-003 (quarantine suspicious downloads) | TRUE | Logs only — safe to demo |

To activate a dry-run policy for a live demo, edit the yml and set dry_run: false,
then wait ~60 seconds for the policy engine to reload (it reloads every 60s automatically).
No Console restart needed.
