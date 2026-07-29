using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.EntityFrameworkCore;
using Phalanx.Correlator.Engine;
using Phalanx.Shared.Data;
using StackExchange.Redis;
using System.Text.Json;

namespace Phalanx.Correlator;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IDatabase _redis;
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _config;
    private readonly RuleEngine _engine;

    private const string QUEUE = "telemetry_stream";

    private HubConnection? _hub;

    public Worker(ILogger<Worker> logger, IConnectionMultiplexer redis,
                  IServiceProvider serviceProvider, IConfiguration config)
    {
        _logger = logger;
        _redis = redis.GetDatabase();
        _serviceProvider = serviceProvider;
        _config = config;

        // Resolve rules directory.
        // Priority: (1) Rules:Directory config key, (2) auto-discover by walking up from content root.
        var configuredDir = _config.GetValue<string>("Rules:Directory") ?? "";
        string rulesDir;
        if (!string.IsNullOrEmpty(configuredDir))
        {
            rulesDir = Path.IsPathRooted(configuredDir)
                ? configuredDir
                : Path.GetFullPath(configuredDir,
                      serviceProvider.GetRequiredService<IHostEnvironment>().ContentRootPath);
        }
        else
        {
            // Walk up from content root (project dir when `dotnet run`, publish dir otherwise)
            // looking for a "rules" sibling directory.
            var contentRoot = serviceProvider.GetRequiredService<IHostEnvironment>().ContentRootPath;
            rulesDir = RulesDirLocator.Find(contentRoot)
                    ?? Path.Combine(contentRoot, "rules");
        }

        if (!Directory.Exists(rulesDir))
            _logger.LogWarning(
                "Rules directory not found: {Dir}. "
                + "Set Rules:Directory in appsettings.json or copy the rules folder.", rulesDir);
        else
            _logger.LogInformation("Loading rules from: {Dir}", rulesDir);

        var loader = new RuleLoader(_logger);
        var rules  = loader.LoadFromDirectory(rulesDir);
        _engine = new RuleEngine(rules, _logger);

        // Seed/refresh RuleStat rows
        SeedRuleStats(rules).GetAwaiter().GetResult();
    }

    private async Task SeedRuleStats(IReadOnlyList<Rule> rules)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();
            var existing = await db.RuleStats.ToDictionaryAsync(r => r.RuleId);
            foreach (var rule in rules)
            {
                if (existing.TryGetValue(rule.Id, out var s))
                {
                    s.RuleName = rule.Title;
                    s.Severity = rule.Severity;
                    s.Source   = rule.Source;
                    s.LoadedAt = DateTime.UtcNow;
                }
                else
                {
                    db.RuleStats.Add(new RuleStat
                    {
                        RuleId = rule.Id,
                        RuleName = rule.Title,
                        Severity = rule.Severity,
                        Source = rule.Source,
                        FireCount = 0,
                        LoadedAt = DateTime.UtcNow,
                    });
                }
            }
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to seed RuleStats: {Msg}", ex.Message);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Phalanx Correlator started. Queue: {Queue} | Rules loaded: {N}",
            QUEUE, _engine.Rules.Count);

        var consoleUrl = _config.GetValue<string>("Console:HubUrl") ?? "http://localhost:5100/alertHub";
        _hub = new HubConnectionBuilder()
            .WithUrl(consoleUrl)
            .WithAutomaticReconnect(new[] { TimeSpan.Zero, TimeSpan.FromSeconds(2),
                                            TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15) })
            .Build();

        _ = TryStartHub(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // BLPOP blocks up to 1 s in Redis; returns instantly when an item exists.
                // This eliminates the 200 ms polling gap without spinning the CPU.
                var bpop = await _redis.ExecuteAsync("BLPOP", QUEUE, "1");
                if (bpop.IsNull) continue;

                var parts = (RedisResult[])bpop;
                if (parts.Length < 2 || parts[1].IsNull) continue;

                var json = (string)parts[1]!;
                using var doc = JsonDocument.Parse(json);
                await Analyze(doc.RootElement, json, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Correlator error");
                await Task.Delay(1000, stoppingToken);
            }
        }

        if (_hub is not null) await _hub.DisposeAsync();
    }

    private async Task TryStartHub(CancellationToken ct)
    {
        // Retry indefinitely with capped backoff — the Console may not be running yet.
        // The correlator processes events normally while this runs in the background.
        var backoff = TimeSpan.FromSeconds(2);
        var maxBackoff = TimeSpan.FromSeconds(60);
        int attempt = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_hub!.State == HubConnectionState.Disconnected)
                    await _hub.StartAsync(ct);
                if (_hub.State == HubConnectionState.Connected)
                {
                    _logger.LogInformation("Connected to Console SignalR hub after {N} attempt(s)", attempt + 1);
                    return;
                }
            }
            catch (Exception ex)
            {
                // Log first failure and every 10th after that to avoid log spam
                if (attempt == 0 || attempt % 10 == 0)
                    _logger.LogWarning("Console hub not reachable (attempt {N}): {Msg}. Retrying...", attempt + 1, ex.Message);
            }
            attempt++;
            await Task.Delay(backoff, ct);
            if (backoff < maxBackoff) backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 1.5, maxBackoff.TotalSeconds));
        }
    }

    private async Task Analyze(JsonElement root, string rawJson, CancellationToken ct)
    {
        // Pull a few common fields up front
        var ts        = root.TryGetProperty("@timestamp", out var t) ? t.GetDateTime().ToUniversalTime() : DateTime.UtcNow;
        var eventIdS  = FieldMatch.ResolveField(root, "event.id") ?? Guid.NewGuid().ToString();

        var hits = _engine.Evaluate(root, ts, eventIdS);
        if (hits.Count == 0) return;

        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();

        foreach (var hit in hits)
        {
            var alert = BuildAlert(hit, root, rawJson);
            db.Alerts.Add(alert);

            // Bump the rule's fire count
            var stat = await db.RuleStats.FindAsync(new object?[] { hit.Rule.Id }, ct);
            if (stat is null)
            {
                stat = new RuleStat
                {
                    RuleId = hit.Rule.Id,
                    RuleName = hit.Rule.Title,
                    Severity = hit.Rule.Severity,
                    Source = hit.Rule.Source,
                    LoadedAt = DateTime.UtcNow,
                };
                db.RuleStats.Add(stat);
            }
            stat.FireCount++;
            stat.LastFiredAt = DateTime.UtcNow;
        }

        await db.SaveChangesAsync(ct);

        foreach (var hit in hits)
        {
            _logger.LogWarning("ALERT [{Sev}] {Id} {Title} :: {Desc}",
                hit.Rule.Severity, hit.Rule.Id, hit.Rule.Title, hit.Description);
            await PushAlert(hit, root);
        }
    }

    private static Alert BuildAlert(RuleHit hit, JsonElement root, string rawJson)
    {
        var hostname     = FieldMatch.ResolveField(root, "host.hostname") ?? "";
        var procName     = FieldMatch.ResolveField(root, "process.name");
        var procEntityId = FieldMatch.ResolveField(root, "process.entity_id");
        var cmd          = FieldMatch.ResolveField(root, "process.command_line");
        var userName     = FieldMatch.ResolveField(root, "user.name");
        var agentIdS     = FieldMatch.ResolveField(root, "agent.id") ?? Guid.Empty.ToString();
        Guid agentId     = Guid.TryParse(agentIdS, out var g) ? g : Guid.Empty;

        return new Alert
        {
            DetectedAt = DateTime.UtcNow,
            Severity = hit.Rule.Severity,
            RuleId = hit.Rule.Id,
            RuleName = hit.Rule.Title,
            Description = hit.Description,
            MitreTactic = hit.Rule.MitreTactic,
            MitreTechnique = hit.Rule.MitreTechnique,
            AgentId = agentId,
            Hostname = hostname,
            ProcessEntityId = procEntityId,
            ProcessName = procName,
            CommandLine = cmd,
            UserName = userName,
            Status = "new",
            SourceEventIds = string.Join(",", hit.ContributingEventIds),
            TriggeringEventJson = rawJson,
        };
    }

    private async Task PushAlert(RuleHit hit, JsonElement root)
    {
        if (_hub is null || _hub.State != HubConnectionState.Connected) return;
        try
        {
            await _hub.SendAsync("BroadcastAlert", new
            {
                detectedAt = DateTime.UtcNow,
                severity = hit.Rule.Severity,
                ruleId = hit.Rule.Id,
                ruleName = hit.Rule.Title,
                description = hit.Description,
                mitreTactic = hit.Rule.MitreTactic,
                mitreTechnique = hit.Rule.MitreTechnique,
                hostname = FieldMatch.ResolveField(root, "host.hostname") ?? "",
                processName = FieldMatch.ResolveField(root, "process.name") ?? "",
                commandLine = FieldMatch.ResolveField(root, "process.command_line") ?? "",
                userName = FieldMatch.ResolveField(root, "user.name") ?? "",
                status = "new",
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning("SignalR push failed: {Msg}", ex.Message);
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// <summary>
/// Walk up the directory tree from <paramref name="startDir"/> looking for a
/// sibling or ancestor directory named "rules". Returns the first match, or
/// null if none found within 5 levels.
/// </summary>
file static class RulesDirLocator
{
    public static string? Find(string startDir)
    {
        var dir = new DirectoryInfo(startDir);
        for (int i = 0; i < 5 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "rules");
            if (Directory.Exists(candidate))
                return candidate;
        }
        return null;
    }
}
