using Microsoft.AspNetCore.Mvc;
using Phalanx.Shared.Data;
using StackExchange.Redis;
using System.Text.Json;

namespace Phalanx.Ingestion.Controllers;

[ApiController]
[Route("api/v1/ingest")]
public class IngestionController : ControllerBase
{
    private readonly PhalanxContext _db;
    private readonly IConnectionMultiplexer _redis;
    private static long _seq;

    public IngestionController(PhalanxContext db, IConnectionMultiplexer redis)
    {
        _db    = db;
        _redis = redis;
    }

    [HttpGet("health")]
    public IActionResult Health() => Ok(new { status = "ok", ts = DateTime.UtcNow });

    [HttpPost]
    public async Task<IActionResult> Ingest([FromBody] JsonElement body)
    {
        var raw     = body.GetRawText();
        var dataset = body.TryGetProperty("event", out var evt)
                      && evt.TryGetProperty("dataset", out var ds)
                      ? ds.GetString() ?? "" : "";

        var now = DateTime.UtcNow;
        var seq = Interlocked.Increment(ref _seq);

        // Route to appropriate handler
        var routed = dataset switch
        {
            var d when d.StartsWith("phalanx.sentinel.process") => await IngestProcess(body, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.file")    => await IngestFile(body, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.network") => await IngestNetwork(body, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.dns")     => await IngestDns(body, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.login")   => await IngestLogin(body, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.memory")  => await IngestMemory(body, raw, now, seq),
            var d when d.StartsWith("phalanx.sentinel.email")   => await IngestEmail(body, raw, now, seq),
            _ => await IngestProcess(body, raw, now, seq)   // fallback
        };

        if (!routed) return BadRequest(new { error = "ingestion failed" });

        // Push to correlator queue
        var db = _redis.GetDatabase();
        await db.ListRightPushAsync("telemetry_stream", raw);

        return Accepted();
    }

    // ── Process ──────────────────────────────────────────────────────────────

    private async Task<bool> IngestProcess(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var te = new TelemetryEvent
            {
                EventId    = ParseGuid(body, "event", "id"),
                Timestamp  = ParseTimestamp(body),
                IngestedAt = now,
                Sequence   = seq,
                Action     = GetStr(body, "event", "action"),
                Category   = GetStrArr(body, "event", "category"),
                Dataset    = GetStr(body, "event", "dataset"),
                AgentId    = ParseGuid(body, "agent", "id"),
                Hostname   = GetStr(body, "host", "hostname"),
                ProcessEntityId    = GetStr(body, "process", "entity_id"),
                ProcessPid         = GetInt(body, "process", "pid"),
                ProcessName        = GetStr(body, "process", "name"),
                ProcessExecutable  = GetStr(body, "process", "executable"),
                ProcessCommandLine = GetStr(body, "process", "command_line"),
                ProcessHashSha256  = GetStr(body, "process", "hash", "sha256"),
                ParentEntityId     = GetStr(body, "process", "parent", "entity_id"),
                ParentName         = GetStr(body, "process", "parent", "name"),
                ParentCommandLine  = GetStr(body, "process", "parent", "command_line"),
                UserName = GetStr(body, "user", "name"),
                UserId   = GetStr(body, "user", "id"),
                RawJson  = raw,
            };
            _db.Events.Add(te);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── File ─────────────────────────────────────────────────────────────────

    private async Task<bool> IngestFile(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var fe = new FileEvent
            {
                EventId    = ParseGuid(body, "event", "id"),
                Timestamp  = ParseTimestamp(body),
                IngestedAt = now,
                Action     = GetStr(body, "event", "action"),
                Dataset    = GetStr(body, "event", "dataset"),
                AgentId    = ParseGuid(body, "agent", "id"),
                Hostname   = GetStr(body, "host", "hostname"),
                FilePath        = GetStr(body, "file", "path"),
                FileName        = GetStr(body, "file", "name"),
                FileDirectory   = GetStr(body, "file", "directory"),
                FileSize        = GetLong(body, "file", "size"),
                FileMode        = GetStr(body, "file", "mode"),
                FileHashSha256  = GetStr(body, "file", "hash", "sha256"),
                ProcessPid  = GetInt(body, "process", "pid"),
                ProcessName = GetStr(body, "process", "name"),
                RawJson     = raw,
            };
            _db.FileEvents.Add(fe);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Network ───────────────────────────────────────────────────────────────

    private async Task<bool> IngestNetwork(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var ne = new NetworkEvent
            {
                EventId    = ParseGuid(body, "event", "id"),
                Timestamp  = ParseTimestamp(body),
                IngestedAt = now,
                Action     = GetStr(body, "event", "action"),
                Dataset    = GetStr(body, "event", "dataset"),
                AgentId    = ParseGuid(body, "agent", "id"),
                Hostname   = GetStr(body, "host", "hostname"),
                Transport        = GetStr(body, "network", "transport"),
                Direction        = GetStr(body, "network", "direction"),
                NetworkType      = GetStr(body, "network", "type"),
                SourceIp         = GetStr(body, "source", "ip"),
                SourcePort       = GetInt(body, "source", "port"),
                DestinationIp    = GetStr(body, "destination", "ip"),
                DestinationPort  = GetInt(body, "destination", "port"),
                DestinationDomain = GetStr(body, "destination", "domain"),
                ConnectionStatus = GetStr(body, "connection", "status"),
                ProcessPid        = GetInt(body, "process", "pid"),
                ProcessName       = GetStr(body, "process", "name"),
                ProcessExecutable = GetStr(body, "process", "executable"),
                RawJson = raw,
            };
            _db.NetworkEvents.Add(ne);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── DNS ───────────────────────────────────────────────────────────────────

    private async Task<bool> IngestDns(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var de = new DnsEvent
            {
                EventId    = ParseGuid(body, "event", "id"),
                Timestamp  = ParseTimestamp(body),
                IngestedAt = now,
                Action     = GetStr(body, "event", "action"),
                Dataset    = GetStr(body, "event", "dataset"),
                AgentId    = ParseGuid(body, "agent", "id"),
                Hostname   = GetStr(body, "host", "hostname"),
                QueryName   = GetStr(body, "dns", "question", "name"),
                QueryType   = GetStr(body, "dns", "question", "type"),
                ResolvedIp  = GetStr(body, "dns", "resolved_ip"),
                SourceIp    = GetStr(body, "source", "ip"),
                ProcessPid  = GetInt(body, "process", "pid"),
                ProcessName = GetStr(body, "process", "name"),
                RawJson     = raw,
            };
            _db.DnsEvents.Add(de);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    private async Task<bool> IngestLogin(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var outcome = "";
            if (body.TryGetProperty("event", out var evNode) &&
                evNode.TryGetProperty("outcome", out var oc))
                outcome = oc.GetString() ?? "";

            var le = new LoginEvent
            {
                EventId    = ParseGuid(body, "event", "id"),
                Timestamp  = ParseTimestamp(body),
                IngestedAt = now,
                Action     = GetStr(body, "event", "action"),
                Dataset    = GetStr(body, "event", "dataset"),
                Outcome    = outcome,
                AgentId    = ParseGuid(body, "agent", "id"),
                Hostname   = GetStr(body, "host", "hostname"),
                UserName    = GetStr(body, "user", "name"),
                SourceIp    = GetStr(body, "source", "ip"),
                Terminal    = GetStr(body, "session", "terminal"),
                AuthMethod  = GetStr(body, "auth", "method"),
                CommandLine = GetStr(body, "process", "command_line"),
                RawJson     = raw,
            };
            _db.LoginEvents.Add(le);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Memory ────────────────────────────────────────────────────────────────

    private async Task<bool> IngestMemory(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var me = new MemoryEvent
            {
                EventId    = ParseGuid(body, "event", "id"),
                Timestamp  = ParseTimestamp(body),
                IngestedAt = now,
                Action     = GetStr(body, "event", "action"),
                Dataset    = GetStr(body, "event", "dataset"),
                AgentId    = ParseGuid(body, "agent", "id"),
                Hostname   = GetStr(body, "host", "hostname"),
                MemoryIndicator   = GetStr(body, "memory", "indicator"),
                MemoryAddress     = GetStr(body, "memory", "address"),
                ProcessPid        = GetInt(body, "process", "pid"),
                ProcessName       = GetStr(body, "process", "name"),
                ProcessExecutable = GetStr(body, "process", "executable"),
                RawJson = raw,
            };
            _db.MemoryEvents.Add(me);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── Email / Phishing ──────────────────────────────────────────────────────

    private async Task<bool> IngestEmail(JsonElement body, string raw, DateTime now, long seq)
    {
        try
        {
            var ee = new EmailEvent
            {
                EventId        = ParseGuid(body, "event", "id"),
                Timestamp      = ParseTimestamp(body),
                IngestedAt     = now,
                Action         = GetStr(body, "event", "action"),
                Dataset        = GetStr(body, "event", "dataset"),
                AgentId        = ParseGuid(body, "agent", "id"),
                Hostname       = GetStr(body, "host", "hostname"),
                Sender         = GetStr(body, "email", "sender"),
                Recipient      = GetStr(body, "email", "recipient"),
                Subject        = GetStr(body, "email", "subject"),
                AttachmentName = GetStr(body, "email", "attachment", "name"),
                AttachmentHash = GetStr(body, "email", "attachment", "hash"),
                ClientProcess  = GetStr(body, "process", "name"),
                ChildProcess   = GetStr(body, "process", "child_name"),
                IndicatorType  = GetStr(body, "email", "indicator_type"),
                Detail         = GetStr(body, "email", "detail"),
                RawJson        = raw,
            };
            _db.EmailEvents.Add(ee);
            await _db.SaveChangesAsync();
            return true;
        }
        catch { return false; }
    }

    // ── JSON helpers ──────────────────────────────────────────────────────────

    private static string GetStr(JsonElement root, params string[] path)
    {
        try
        {
            var node = root;
            foreach (var key in path)
                if (!node.TryGetProperty(key, out node)) return "";
            return node.ValueKind == JsonValueKind.String ? node.GetString() ?? "" : node.ToString();
        }
        catch { return ""; }
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

    private static Guid ParseGuid(JsonElement root, params string[] path)
    {
        var s = GetStr(root, path);
        return Guid.TryParse(s, out var g) ? g : Guid.Empty;
    }

    private static DateTime ParseTimestamp(JsonElement body)
    {
        var s = GetStr(body, "@timestamp");
        return DateTime.TryParse(s, out var dt) ? dt.ToUniversalTime() : DateTime.UtcNow;
    }
}
