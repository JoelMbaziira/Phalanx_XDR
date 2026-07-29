using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Shared.Data;
using StackExchange.Redis;
using System.IO.Compression;
using System.Text.Json;

namespace Phalanx.Ingestion.Controllers;

/// <summary>
/// Batch ingestion endpoint — receives compressed batches from Phalanx Sensor Nodes.
/// POST /api/v1/ingest/batch
///
/// Body (gzip-compressed JSON):
/// {
///   "node_id": "uuid",
///   "count":   50,
///   "events":  [ { ...event... }, ... ]
/// }
///
/// Also handles sensor node registration and device inventory upserts.
/// </summary>
[ApiController]
[Route("api/v1/ingest")]
public class BatchIngestionController : ControllerBase
{
    private readonly PhalanxContext _db;
    private readonly IConnectionMultiplexer _redis;
    private static long _seq;

    public BatchIngestionController(PhalanxContext db, IConnectionMultiplexer redis)
    {
        _db    = db;
        _redis = redis;
    }

    // ── Batch endpoint (sensor nodes) ─────────────────────────────────────────

    [HttpPost("batch")]
    public async Task<IActionResult> IngestBatch()
    {
        // Decompress gzip Content-Encoding (the shipper always gzips)
        JsonElement root;
        try
        {
            Stream body = Request.Body;
            if (Request.Headers.ContentEncoding.Contains("gzip"))
                body = new GZipStream(body, CompressionMode.Decompress, leaveOpen: true);

            using var reader = new StreamReader(body, System.Text.Encoding.UTF8, leaveOpen: true);
            var raw = await reader.ReadToEndAsync();
            root    = JsonSerializer.Deserialize<JsonElement>(raw);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = $"parse failed: {ex.Message}" });
        }

        var nodeId = root.TryGetProperty("node_id", out var nid)
                     ? nid.GetString() ?? "" : "";

        if (!root.TryGetProperty("events", out var eventsEl) ||
            eventsEl.ValueKind != JsonValueKind.Array)
            return BadRequest(new { error = "missing events array" });

        // Update / register the sensor node
        await UpsertSensorNode(nodeId, eventsEl.GetArrayLength());

        var now       = DateTime.UtcNow;
        var redisDb   = _redis.GetDatabase();
        int processed = 0;
        int errors    = 0;

        // Process each event
        foreach (var ev in eventsEl.EnumerateArray())
        {
            var raw     = ev.GetRawText();
            var dataset = GetStr(ev, "event", "dataset");
            var action  = GetStr(ev, "event", "action");

            try
            {
                var ok = dataset switch
                {
                    var d when d == "phalanx.sensor.device"  => await IngestDevice(ev, nodeId, now),
                    var d when d == "phalanx.sensor.dns"     => await IngestSensorDns(ev, nodeId, now),
                    var d when d == "phalanx.sensor.network" => await IngestSensorFlow(ev, nodeId, now),
                    var d when d == "phalanx.sensor.dhcp"    => await IngestDevice(ev, nodeId, now),
                    var d when d == "phalanx.sensor.beacon"  => await IngestSensorAlert(ev, nodeId, now, "beacon"),
                    var d when d == "phalanx.sensor.scan"    => await IngestSensorAlert(ev, nodeId, now, action),

                    // Sentinel agent events (existing datasets)
                    var d when d.StartsWith("phalanx.sentinel.process") => await IngestLegacy(ev, raw, now),
                    var d when d.StartsWith("phalanx.sentinel.file")    => await IngestLegacy(ev, raw, now),
                    var d when d.StartsWith("phalanx.sentinel.network") => await IngestLegacy(ev, raw, now),
                    var d when d.StartsWith("phalanx.sentinel.dns")     => await IngestLegacy(ev, raw, now),
                    var d when d.StartsWith("phalanx.sentinel.login")   => await IngestLegacy(ev, raw, now),
                    var d when d.StartsWith("phalanx.sentinel.memory")  => await IngestLegacy(ev, raw, now),

                    _ => true   // unknown dataset — push to Redis for correlator anyway
                };

                if (ok) processed++;
                else    errors++;
            }
            catch
            {
                errors++;
            }

            // Always push to Redis correlator stream
            await redisDb.ListRightPushAsync("telemetry_stream", raw);
        }

        return Accepted(new { processed, errors, node_id = nodeId });
    }

    // ── Sensor node upsert ────────────────────────────────────────────────────

    private async Task UpsertSensorNode(string nodeId, int batchCount)
    {
        if (string.IsNullOrEmpty(nodeId)) return;
        try
        {
            var existing = await _db.SensorNodes.FirstOrDefaultAsync(n => n.NodeId == nodeId);
            if (existing is null)
            {
                _db.SensorNodes.Add(new SensorNode
                {
                    NodeId      = nodeId,
                    FirstSeen   = DateTime.UtcNow,
                    LastSeen    = DateTime.UtcNow,
                    Status      = "active",
                    EventsTotal = batchCount,
                });
            }
            else
            {
                existing.LastSeen    = DateTime.UtcNow;
                existing.Status      = "active";
                existing.EventsTotal += batchCount;
            }
            await _db.SaveChangesAsync();
        }
        catch { /* non-fatal */ }
    }

    // ── Device inventory upsert ───────────────────────────────────────────────

    private async Task<bool> IngestDevice(JsonElement ev, string nodeId, DateTime now)
    {
        try
        {
            var devEl      = ev.TryGetProperty("device", out var d) ? d : ev;
            var dhcpEl     = ev.TryGetProperty("dhcp",   out var dh) ? dh : default;
            var mac        = GetStr(devEl, "mac");
            if (string.IsNullOrEmpty(mac)) return false;

            var existing = await _db.NetworkDevices.FirstOrDefaultAsync(n => n.Mac == mac && n.NodeId == nodeId);

            if (existing is null)
            {
                var nd = new NetworkDevice
                {
                    DeviceId     = GetStr(devEl, "device_id"),
                    NodeId       = nodeId,
                    Mac          = mac,
                    Ip           = GetStr(devEl, "ip"),
                    Hostname     = GetStr(devEl, "hostname"),
                    Manufacturer = GetStr(devEl, "manufacturer"),
                    DeviceType   = GetStr(devEl, "device_type"),
                    FirstSeen    = now,
                    LastSeen     = now,
                    BytesIn      = GetLong(devEl, "bytes_in") ?? 0,
                    BytesOut     = GetLong(devEl, "bytes_out") ?? 0,
                    DnsCount     = GetInt(devEl,  "dns_count") ?? 0,
                    ConnCount    = GetInt(devEl,  "conn_count") ?? 0,
                    RiskScore    = (float)(GetDouble(devEl, "risk_score") ?? 0.0),
                    ApBssid      = GetStr(devEl, "ap_bssid"),
                };

                // OS from fingerprint
                var osStr = GetStr(devEl, "os");
                ParseOsString(osStr, nd);

                // Override with DHCP OS guess if available
                if (dhcpEl.ValueKind == JsonValueKind.Object)
                {
                    var dhcpOs = GetStr(dhcpEl, "os_guess");
                    if (!string.IsNullOrEmpty(dhcpOs))
                    {
                        nd.OsFamily    = dhcpOs;
                        nd.OsConfidence = (float)(GetDouble(dhcpEl, "os_confidence") ?? 0.5);
                    }
                    if (string.IsNullOrEmpty(nd.Hostname))
                        nd.Hostname = GetStr(dhcpEl, "hostname");
                }

                _db.NetworkDevices.Add(nd);
            }
            else
            {
                existing.LastSeen  = now;
                existing.Ip        = GetStr(devEl, "ip").NullIfEmpty() ?? existing.Ip;
                existing.Hostname  = GetStr(devEl, "hostname").NullIfEmpty() ?? existing.Hostname;
                existing.BytesIn  += GetLong(devEl, "bytes_in") ?? 0;
                existing.BytesOut += GetLong(devEl, "bytes_out") ?? 0;
                existing.DnsCount += GetInt(devEl,  "dns_count") ?? 0;
                existing.ConnCount += GetInt(devEl, "conn_count") ?? 0;
                existing.RiskScore = (float)(GetDouble(devEl, "risk_score") ?? existing.RiskScore);

                var risks = GetStr(devEl, "risk_reasons");
                if (!string.IsNullOrEmpty(risks))
                    existing.RiskReasons = risks;

                var osStr = GetStr(devEl, "os");
                if (!string.IsNullOrEmpty(osStr))
                    ParseOsString(osStr, existing);
            }

            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Sensor DNS ────────────────────────────────────────────────────────────

    private async Task<bool> IngestSensorDns(JsonElement ev, string nodeId, DateTime now)
    {
        try
        {
            var dnsEl    = ev.TryGetProperty("dns", out var d) ? d : default;
            var sourceEl = ev.TryGetProperty("source", out var s) ? s : default;

            bool isDga    = false;
            float dgaScore = 0f;
            if (dnsEl.ValueKind == JsonValueKind.Object)
            {
                dgaScore = (float)(GetDouble(dnsEl, "dga_score") ?? 0.0);
                isDga    = dnsEl.TryGetProperty("is_tunnel", out var it) && it.GetBoolean();
            }

            var record = new SensorDnsEvent
            {
                EventId    = ParseGuid(ev, "event", "id"),
                Timestamp  = ParseTimestamp(ev),
                IngestedAt = now,
                NodeId     = nodeId,
                SrcMac     = sourceEl.ValueKind == JsonValueKind.Object ? GetStr(sourceEl, "mac") : "",
                SrcIp      = sourceEl.ValueKind == JsonValueKind.Object ? GetStr(sourceEl, "ip")  : "",
                Domain     = dnsEl.ValueKind == JsonValueKind.Object ? GetStr(dnsEl, "question", "name") : "",
                QueryType  = dnsEl.ValueKind == JsonValueKind.Object ? GetStr(dnsEl, "question", "type") : "",
                DgaScore   = dgaScore,
                IsTunnel   = isDga,
                RawJson    = ev.GetRawText(),
            };

            _db.SensorDnsEvents.Add(record);
            await _db.SaveChangesAsync();

            // High DGA score → create a sensor alert
            if (dgaScore > 0.7)
                await IngestSensorAlert(ev, nodeId, now, "dga");

            return true;
        }
        catch { return false; }
    }

    // ── Sensor flow ───────────────────────────────────────────────────────────

    private async Task<bool> IngestSensorFlow(JsonElement ev, string nodeId, DateTime now)
    {
        try
        {
            var src = ev.TryGetProperty("source",      out var s) ? s : default;
            var dst = ev.TryGetProperty("destination", out var d) ? d : default;
            var net = ev.TryGetProperty("network",     out var n) ? n : default;

            var record = new SensorFlowEvent
            {
                EventId    = ParseGuid(ev, "event", "id"),
                Timestamp  = ParseTimestamp(ev),
                IngestedAt = now,
                NodeId     = nodeId,
                Action     = GetStr(ev, "event", "action"),
                SrcIp      = src.ValueKind == JsonValueKind.Object ? GetStr(src, "ip")   : "",
                SrcMac     = src.ValueKind == JsonValueKind.Object ? GetStr(src, "mac")  : "",
                SrcPort    = src.ValueKind == JsonValueKind.Object ? (GetInt(src, "port") ?? 0) : 0,
                DstIp      = dst.ValueKind == JsonValueKind.Object ? GetStr(dst, "ip")   : "",
                DstPort    = dst.ValueKind == JsonValueKind.Object ? (GetInt(dst, "port") ?? 0) : 0,
                Transport  = net.ValueKind == JsonValueKind.Object ? GetStr(net, "transport") : "",
                BytesOut   = src.ValueKind == JsonValueKind.Object ? (GetLong(src, "bytes") ?? 0) : 0,
                BytesIn    = dst.ValueKind == JsonValueKind.Object ? (GetLong(dst, "bytes") ?? 0) : 0,
                Packets    = src.ValueKind == JsonValueKind.Object ? (GetInt(src, "packets") ?? 0) : 0,
                RawJson    = ev.GetRawText(),
            };
            _db.SensorFlowEvents.Add(record);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Sensor alert (beacon, scan, dga) ──────────────────────────────────────

    private async Task<bool> IngestSensorAlert(JsonElement ev, string nodeId, DateTime now, string alertType)
    {
        try
        {
            var src     = ev.TryGetProperty("source",      out var s)  ? s  : default;
            var dst     = ev.TryGetProperty("destination", out var d)  ? d  : default;
            var beacon  = ev.TryGetProperty("beacon",      out var b)  ? b  : default;
            var scan    = ev.TryGetProperty("scan",        out var sc) ? sc : default;
            var threat  = ev.TryGetProperty("threat",      out var t)  ? t  : default;

            float conf = 0.8f;
            string detail = "";

            if (beacon.ValueKind == JsonValueKind.Object)
            {
                conf   = (float)(GetDouble(beacon, "confidence") ?? 0.8);
                var iv = GetDouble(beacon, "interval_seconds");
                detail = iv.HasValue ? $"Beacon interval: {iv.Value:F1}s" : "Beacon detected";
            }
            else if (scan.ValueKind == JsonValueKind.Object)
            {
                detail = $"{GetStr(scan, "type")} — {GetStr(scan, "distinct_ips")} IPs / {GetStr(scan, "distinct_ports")} ports";
            }
            else if (alertType == "dga")
            {
                var dns = ev.TryGetProperty("dns", out var dn) ? dn : default;
                var domain = dns.ValueKind == JsonValueKind.Object ? GetStr(dns, "question", "name") : "";
                var score  = dns.ValueKind == JsonValueKind.Object ? GetDouble(dns, "dga_score") ?? 0 : 0;
                detail = $"DGA domain: {domain} (score: {score:F2})";
                conf   = (float)Math.Min(score * 1.2, 1.0);
            }

            var record = new SensorAlert
            {
                EventId    = Guid.NewGuid(),
                Timestamp  = ParseTimestamp(ev),
                IngestedAt = now,
                NodeId     = nodeId,
                AlertType  = alertType,
                SrcIp      = src.ValueKind == JsonValueKind.Object ? GetStr(src, "ip")  : "",
                SrcMac     = src.ValueKind == JsonValueKind.Object ? GetStr(src, "mac") : "",
                DstIp      = dst.ValueKind == JsonValueKind.Object ? GetStr(dst, "ip")  : "",
                DstPort    = dst.ValueKind == JsonValueKind.Object ? (GetInt(dst, "port") ?? 0) : 0,
                Confidence = conf,
                Detail     = detail,
                RawJson    = ev.GetRawText(),
            };
            _db.SensorAlerts.Add(record);
            await _db.SaveChangesAsync();

            // Also create a top-level Alert for the dashboard
            await CreateDashboardAlert(record, nodeId);

            return true;
        }
        catch { return false; }
    }

    // ── Forward to legacy single-event handler ────────────────────────────────

    private async Task<bool> IngestLegacy(JsonElement ev, string raw, DateTime now)
    {
        var seq     = Interlocked.Increment(ref _seq);
        var dataset = GetStr(ev, "event", "dataset");
        return dataset switch
        {
            var d when d.StartsWith("phalanx.sentinel.process") => await IngestProcess(ev, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.file")    => await IngestFile(ev, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.network") => await IngestNetwork(ev, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.dns")     => await IngestDns(ev, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.login")   => await IngestLogin(ev, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.memory")  => await IngestMemory(ev, raw, now, seq),
            _ => true
        };
    }

    // Full-fidelity legacy handlers — field-for-field identical to IngestionController
    private async Task<bool> IngestProcess(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            _db.Events.Add(new TelemetryEvent
            {
                EventId            = ParseGuid(body, "event", "id"),
                Timestamp          = ParseTimestamp(body),
                IngestedAt         = now,
                Sequence           = seq,
                Action             = GetStr(body, "event", "action"),
                Category           = GetStrArr(body, "event", "category"),
                Dataset            = GetStr(body, "event", "dataset"),
                AgentId            = ParseGuid(body, "agent", "id"),
                Hostname           = GetStr(body, "host", "hostname"),
                ProcessEntityId    = GetStr(body, "process", "entity_id"),
                ProcessPid         = GetInt(body, "process", "pid"),
                ProcessName        = GetStr(body, "process", "name"),
                ProcessExecutable  = GetStr(body, "process", "executable"),
                ProcessCommandLine = GetStr(body, "process", "command_line"),
                ProcessHashSha256  = GetStr(body, "process", "hash", "sha256"),
                ParentEntityId     = GetStr(body, "process", "parent", "entity_id"),
                ParentName         = GetStr(body, "process", "parent", "name"),
                ParentCommandLine  = GetStr(body, "process", "parent", "command_line"),
                UserName           = GetStr(body, "user", "name"),
                UserId             = GetStr(body, "user", "id"),
                RawJson            = raw,
            });
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    private async Task<bool> IngestFile(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            _db.FileEvents.Add(new FileEvent
            {
                EventId         = ParseGuid(body, "event", "id"),
                Timestamp       = ParseTimestamp(body),
                IngestedAt      = now,
                Action          = GetStr(body, "event", "action"),
                Dataset         = GetStr(body, "event", "dataset"),
                AgentId         = ParseGuid(body, "agent", "id"),
                Hostname        = GetStr(body, "host", "hostname"),
                FilePath        = GetStr(body, "file", "path"),
                FileName        = GetStr(body, "file", "name"),
                FileDirectory   = GetStr(body, "file", "directory"),
                FileSize        = GetLong(body, "file", "size"),
                FileMode        = GetStr(body, "file", "mode"),
                FileHashSha256  = GetStr(body, "file", "hash", "sha256"),
                ProcessPid      = GetInt(body, "process", "pid"),
                ProcessName     = GetStr(body, "process", "name"),
                RawJson         = raw,
            });
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    private async Task<bool> IngestNetwork(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            _db.NetworkEvents.Add(new NetworkEvent
            {
                EventId           = ParseGuid(body, "event", "id"),
                Timestamp         = ParseTimestamp(body),
                IngestedAt        = now,
                Action            = GetStr(body, "event", "action"),
                Dataset           = GetStr(body, "event", "dataset"),
                AgentId           = ParseGuid(body, "agent", "id"),
                Hostname          = GetStr(body, "host", "hostname"),
                Transport         = GetStr(body, "network", "transport"),
                Direction         = GetStr(body, "network", "direction"),
                NetworkType       = GetStr(body, "network", "type"),
                SourceIp          = GetStr(body, "source", "ip"),
                SourcePort        = GetInt(body, "source", "port"),
                DestinationIp     = GetStr(body, "destination", "ip"),
                DestinationPort   = GetInt(body, "destination", "port"),
                DestinationDomain = GetStr(body, "destination", "domain"),
                ConnectionStatus  = GetStr(body, "connection", "status"),
                ProcessPid        = GetInt(body, "process", "pid"),
                ProcessName       = GetStr(body, "process", "name"),
                ProcessExecutable = GetStr(body, "process", "executable"),
                RawJson           = raw,
            });
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    private async Task<bool> IngestDns(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            _db.DnsEvents.Add(new DnsEvent
            {
                EventId     = ParseGuid(body, "event", "id"),
                Timestamp   = ParseTimestamp(body),
                IngestedAt  = now,
                Action      = GetStr(body, "event", "action"),
                Dataset     = GetStr(body, "event", "dataset"),
                AgentId     = ParseGuid(body, "agent", "id"),
                Hostname    = GetStr(body, "host", "hostname"),
                QueryName   = GetStr(body, "dns", "question", "name"),
                QueryType   = GetStr(body, "dns", "question", "type"),
                ResolvedIp  = GetStr(body, "dns", "resolved_ip"),
                SourceIp    = GetStr(body, "source", "ip"),
                ProcessPid  = GetInt(body, "process", "pid"),
                ProcessName = GetStr(body, "process", "name"),
                RawJson     = raw,
            });
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    private async Task<bool> IngestLogin(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var outcome = "";
            if (body.TryGetProperty("event", out var evNode) &&
                evNode.TryGetProperty("outcome", out var oc))
                outcome = oc.GetString() ?? "";

            _db.LoginEvents.Add(new LoginEvent
            {
                EventId     = ParseGuid(body, "event", "id"),
                Timestamp   = ParseTimestamp(body),
                IngestedAt  = now,
                Action      = GetStr(body, "event", "action"),
                Dataset     = GetStr(body, "event", "dataset"),
                Outcome     = outcome,
                AgentId     = ParseGuid(body, "agent", "id"),
                Hostname    = GetStr(body, "host", "hostname"),
                UserName    = GetStr(body, "user", "name"),
                SourceIp    = GetStr(body, "source", "ip"),
                Terminal    = GetStr(body, "session", "terminal"),
                AuthMethod  = GetStr(body, "auth", "method"),
                CommandLine = GetStr(body, "process", "command_line"),
                RawJson     = raw,
            });
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    private async Task<bool> IngestMemory(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            _db.MemoryEvents.Add(new MemoryEvent
            {
                EventId           = ParseGuid(body, "event", "id"),
                Timestamp         = ParseTimestamp(body),
                IngestedAt        = now,
                Action            = GetStr(body, "event", "action"),
                Dataset           = GetStr(body, "event", "dataset"),
                AgentId           = ParseGuid(body, "agent", "id"),
                Hostname          = GetStr(body, "host", "hostname"),
                MemoryIndicator   = GetStr(body, "memory", "indicator"),
                MemoryAddress     = GetStr(body, "memory", "address"),
                ProcessPid        = GetInt(body, "process", "pid"),
                ProcessName       = GetStr(body, "process", "name"),
                ProcessExecutable = GetStr(body, "process", "executable"),
                RawJson           = raw,
            });
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Dashboard alert creation ───────────────────────────────────────────────

    private async Task CreateDashboardAlert(SensorAlert sensor, string nodeId)
    {
        try
        {
            var severity = sensor.AlertType switch
            {
                "beacon"     => "High",
                "port_scan"  => "Medium",
                "host_sweep" => "High",
                "dga"        => "High",
                "tunnel"     => "Critical",
                _ => "Medium"
            };
            var (tactic, technique) = sensor.AlertType switch
            {
                "beacon"     => ("Command and Control", "T1071"),
                "port_scan"  => ("Discovery",           "T1046"),
                "host_sweep" => ("Discovery",           "T1018"),
                "dga"        => ("Command and Control", "T1568"),
                "tunnel"     => ("Exfiltration",        "T1048"),
                _ => ("", "")
            };

            _db.Alerts.Add(new Alert
            {
                DetectedAt      = sensor.Timestamp,
                Severity        = severity,
                RuleId          = $"SENSOR-{sensor.AlertType.ToUpper()}",
                RuleName        = $"Sensor: {sensor.AlertType.Replace("_", " ")}",
                Description     = sensor.Detail,
                MitreTactic     = tactic,
                MitreTechnique  = technique,
                Hostname        = nodeId,
                UserName        = sensor.SrcMac,
                Status          = "new",
                TriggeringEventJson = sensor.RawJson,
            });
            await _db.SaveChangesAsync();
        }
        catch { /* non-fatal */ }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void ParseOsString(string osStr, NetworkDevice nd)
    {
        // Format: "Windows 10/11 (88%)" or "macOS 12+ (91%)"
        if (string.IsNullOrEmpty(osStr)) return;
        var confMatch = System.Text.RegularExpressions.Regex.Match(osStr, @"\((\d+)%\)");
        if (confMatch.Success)
        {
            nd.OsConfidence = float.Parse(confMatch.Groups[1].Value) / 100f;
            osStr = osStr[..confMatch.Index].Trim();
        }
        var parts = osStr.Split(' ', 2);
        nd.OsFamily  = parts[0];
        nd.OsVersion = parts.Length > 1 ? parts[1] : "";
    }

    private static string GetStrArr(JsonElement root, params string[] path)
    {
        try
        {
            var node = root;
            foreach (var key in path)
                if (!node.TryGetProperty(key, out node)) return "";
            if (node.ValueKind == JsonValueKind.Array)
                return string.Join(",", node.EnumerateArray().Select(x => x.GetString() ?? ""));
            return node.GetString() ?? "";
        }
        catch { return ""; }
    }

    private static string GetStr(JsonElement root, params string[] path)    {
        try
        {
            var node = root;
            foreach (var key in path)
                if (!node.TryGetProperty(key, out node)) return "";
            return node.ValueKind == JsonValueKind.String ? node.GetString() ?? "" : node.ToString();
        }
        catch { return ""; }
    }

    private static int? GetInt(JsonElement root, params string[] path)
    {
        try
        {
            var node = root;
            foreach (var key in path)
                if (!node.TryGetProperty(key, out node)) return null;
            return node.TryGetInt32(out var v) ? v : null;
        }
        catch { return null; }
    }

    private static long? GetLong(JsonElement root, params string[] path)
    {
        try
        {
            var node = root;
            foreach (var key in path)
                if (!node.TryGetProperty(key, out node)) return null;
            return node.TryGetInt64(out var v) ? v : null;
        }
        catch { return null; }
    }

    private static double? GetDouble(JsonElement root, params string[] path)
    {
        try
        {
            var node = root;
            foreach (var key in path)
                if (!node.TryGetProperty(key, out node)) return null;
            return node.TryGetDouble(out var v) ? v : null;
        }
        catch { return null; }
    }

    private static Guid ParseGuid(JsonElement root, params string[] path)
    {
        var s = GetStr(root, path);
        return Guid.TryParse(s, out var g) ? g : Guid.NewGuid();
    }

    private static DateTime ParseTimestamp(JsonElement body)
    {
        var s = GetStr(body, "@timestamp");
        return DateTime.TryParse(s, out var dt) ? dt.ToUniversalTime() : DateTime.UtcNow;
    }
}

internal static class StringExt
{
    public static string? NullIfEmpty(this string s)
        => string.IsNullOrEmpty(s) ? null : s;
}
