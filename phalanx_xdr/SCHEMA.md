# Phalanx Event Schema v1

Based on a subset of Elastic Common Schema (ECS) 8.x. All fields use snake_case.
Every field marked **required** must be present in every event. Optional fields
should be omitted (not sent as null) when unavailable.

## Top-level envelope

```
{
  "@timestamp": "2026-05-05T09:48:57.802538Z",   // required, RFC3339 UTC
  "event": { ... },                              // required
  "agent": { ... },                              // required
  "host": { ... },                               // required
  "process": { ... },                            // required for process events
  "user": { ... },                               // optional
  "file": { ... },                               // optional
  "network": { ... },                            // optional, for network events
  "raw": { ... }                                 // optional, original sensor payload
}
```

## event

| field          | required | description                                                    |
|----------------|----------|----------------------------------------------------------------|
| id             | yes      | UUID, unique per event                                         |
| kind           | yes      | "event"                                                        |
| category       | yes      | array, e.g. ["process"], ["network"], ["file"]                 |
| type           | yes      | array, e.g. ["start"], ["end"], ["connection"], ["creation"]   |
| action         | yes      | short verb: "process_start", "process_end", "file_create"      |
| dataset        | yes      | "phalanx.sentinel.linux" / "phalanx.sentinel.windows" etc.     |
| ingested       | no       | set by Ingestion service on receipt                            |
| sequence       | no       | monotonic counter per agent, for ordering                      |

## agent

| field          | required | description                                                    |
|----------------|----------|----------------------------------------------------------------|
| id             | yes      | persistent UUID per install                                    |
| version        | yes      | sentinel version string                                        |
| type           | yes      | "phalanx-sentinel"                                             |

## host

| field          | required | description                                                    |
|----------------|----------|----------------------------------------------------------------|
| hostname       | yes      |                                                                |
| os.family      | yes      | "linux" / "windows" / "macos"                                  |
| os.kernel      | yes      | uname -r equivalent                                            |
| os.platform    | yes      | distro id, e.g. "ubuntu"                                       |
| os.version     | yes      |                                                                |
| architecture   | yes      | "x86_64", "arm64", etc.                                        |
| ip             | no       | array of host IPs                                              |
| boot_id        | no       | /proc/sys/kernel/random/boot_id on Linux — survives reboots    |

## process

| field             | required | description                                                 |
|-------------------|----------|-------------------------------------------------------------|
| entity_id         | yes      | stable per-process ID — see below                           |
| pid               | yes      |                                                             |
| name              | yes      | basename of executable                                      |
| executable        | yes      | full path                                                   |
| command_line      | yes      | full argv joined                                            |
| args              | yes      | array of argv                                               |
| start             | yes      | RFC3339 UTC                                                 |
| working_directory | no       |                                                             |
| parent            | no       | nested {pid, entity_id, name, executable, command_line}     |
| ancestry          | yes      | array of ancestors from parent to PID 1, see below          |
| hash.sha256       | no       | of the executable file                                      |
| hash.md5          | no       |                                                             |
| code_signature    | no       | nested {signed: bool, valid: bool, subject: string}         |
| package           | no       | nested {name, version} if installed via dpkg/rpm/etc        |

### entity_id

A stable per-process identifier that does NOT collide on PID reuse. Computed as:
`sha256(boot_id + ":" + pid + ":" + start_time_ns)[:16]`

This is critical — PIDs are reused within hours on a busy host, so PID alone is
useless for correlation. entity_id lets us reliably link events to a single
process across its lifetime.

### ancestry

Array, ordered child-most to ancestor-most. Each element:

```
{ "pid": 1234, "entity_id": "abc...", "name": "bash", "executable": "/bin/bash" }
```

Limit to 16 entries to bound payload size. Always includes the immediate parent
as element [0] and PID 1 as the last element if reachable.

## user

| field           | required | description                                                |
|-----------------|----------|------------------------------------------------------------|
| name            | yes      | username                                                   |
| id              | yes      | UID (Linux/macOS) or SID (Windows)                         |
| group.name      | no       |                                                            |
| group.id        | no       |                                                            |
| effective.id    | no       | EUID — different from id when running suid                 |
| effective.name  | no       |                                                            |

## file

| field           | required | description                                                |
|-----------------|----------|------------------------------------------------------------|
| path            | yes      |                                                            |
| size            | no       | bytes                                                      |
| mtime           | no       | RFC3339                                                    |
| hash.sha256     | no       |                                                            |
| hash.md5        | no       |                                                            |

## Examples

A `process_start` event from Linux looks like:

```json
{
  "@timestamp": "2026-05-05T09:48:57.802538Z",
  "event": {
    "id": "ee511d54-a15a-499a-a6f1-52ba67f1478b",
    "kind": "event",
    "category": ["process"],
    "type": ["start"],
    "action": "process_start",
    "dataset": "phalanx.sentinel.linux",
    "sequence": 14723
  },
  "agent": {
    "id": "07393bb5-e8e1-4e07-b9c6-d8076f4715f5",
    "version": "0.2.0",
    "type": "phalanx-sentinel"
  },
  "host": {
    "hostname": "hypernikao",
    "os": { "family": "linux", "kernel": "6.5.0-21-generic",
            "platform": "ubuntu", "version": "22.04" },
    "architecture": "x86_64",
    "boot_id": "9c2e6d44-7a13-4e8f-b9c1-2f5e3a8b1c0d"
  },
  "process": {
    "entity_id": "a3f5d8c9b2e1f4a6",
    "pid": 14569,
    "name": "nmap",
    "executable": "/usr/bin/nmap",
    "command_line": "nmap -sV localhost",
    "args": ["nmap", "-sV", "localhost"],
    "start": "2026-05-05T09:48:57.800000Z",
    "working_directory": "/home/j-j",
    "parent": {
      "pid": 8116,
      "entity_id": "f1e2d3c4b5a69788",
      "name": "bash",
      "executable": "/bin/bash",
      "command_line": "-bash"
    },
    "ancestry": [
      { "pid": 8116, "entity_id": "f1e2d3c4b5a69788", "name": "bash", "executable": "/bin/bash" },
      { "pid": 8113, "entity_id": "1234567890abcdef", "name": "Relay", "executable": "/usr/lib/wsl/wslrelay" },
      { "pid": 1, "entity_id": "0000000000000001", "name": "init", "executable": "/sbin/init" }
    ],
    "hash": { "sha256": "857d5570735d576a1c6f2618aca35bdaf62f41407e733edc1f89ab115507a816" },
    "code_signature": { "signed": false, "valid": false },
    "package": { "name": "nmap", "version": "7.94+dfsg-3" }
  },
  "user": {
    "name": "j-j",
    "id": "1000",
    "group": { "name": "j-j", "id": "1000" },
    "effective": { "id": "1000", "name": "j-j" }
  }
}
```
