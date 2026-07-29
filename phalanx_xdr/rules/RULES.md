# Phalanx Rule Format

Rules are YAML files in `rules/`. The Correlator loads every `*.yml` and `*.yaml`
file from this directory at startup. To reload, restart the Correlator (hot reload
will come in a later phase).

## Minimal stateless rule

```yaml
id: PHX-005
title: Network scanning
description: A network scanner was executed.
severity: Medium
mitre:
  tactic: TA0007
  technique: T1046
match:
  process.name:
    - nmap
    - masscan
    - rustscan
    - zmap
```

`match` is a map of field paths to expected values. Multiple values mean OR
within the field. Multiple fields in the same `match` block mean AND across fields.

## Field paths

Use the same dotted paths as the event schema:

- `process.name`, `process.executable`, `process.command_line`, `process.args`
- `process.parent.name`, `process.parent.command_line`
- `process.code_signature.signed`
- `user.name`, `user.id`, `user.effective.id`
- `host.hostname`, `host.os.family`
- `event.action`, `event.category`

## Match operators

Plain values mean equality (case-insensitive for strings). For everything else,
suffix the field with an operator:

```yaml
match:
  process.name:
    - powershell
    - pwsh
  process.command_line|contains:        # substring match
    - " -enc"
    - " -EncodedCommand"
  process.command_line|regex:           # regex match
    - '(?i)from\s+base64'
  process.command_line|startswith:
    - "/tmp/"
  user.id|not:
    - "0"                               # NOT root
  process.code_signature.signed|equals:
    - false
```

Supported operators: `equals` (default), `contains`, `startswith`, `endswith`,
`regex`, `not`, `gt`, `lt`. The `|not` operator can wrap any other operator:
`process.name|not|contains: ["systemd"]`.

## Stateful rules — `correlate` block

A rule with a `correlate` block fires only when the current event PLUS related
events in a time window satisfy the condition.

```yaml
id: PHX-100
title: Discovery burst
description: Multiple discovery commands within a short window.
severity: Medium
mitre:
  tactic: TA0007
  technique: T1033
match:
  event.action: process_start
  process.name:
    - whoami
    - id
    - hostname
    - uname
    - netstat
    - ss
correlate:
  group_by: agent.id          # window is per-host
  window_seconds: 60
  threshold: 3                # must see 3 matching events in window
```

`group_by` is required. Common groupings: `agent.id` (per host),
`process.entity_id` (per process), `user.name` (per user).

## Multi-stage rules — `sequence` block

For "A then B" patterns:

```yaml
id: PHX-110
title: Recon then download
description: Network scan followed by tool download from the same host.
severity: High
mitre:
  tactic: TA0011
  technique: T1105
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
        process.command_line|contains:
          - " http://"
          - " https://"
```

Stages must occur in order. The rule fires when the final stage matches and all
prior stages have matched within the window for the same `group_by` key.

## Sigma rule import

Place Sigma YAML rules in `rules/sigma/`. The loader translates a useful subset
of Sigma's `detection` block into Phalanx native rules at load time. Unsupported
Sigma features (some `condition` expressions, aggregations) are skipped with
a warning. The Sigma `level` field maps to `severity`, `tags` containing
`attack.tNNNN` map to `mitre.technique`.

## Tips

- Rule IDs in the `PHX-` namespace are reserved for built-in rules. Use your
  own prefix for custom rules (e.g. `ACME-001`).
- Test a rule by triggering its match and watching the Correlator log for
  `ALERT [...] {ruleId}`.
- A rule that never fires probably has an over-specified field path or a bad
  operator. Set the Correlator log level to Debug to see per-event evaluation.
