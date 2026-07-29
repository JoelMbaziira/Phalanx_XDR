using System.Collections.Concurrent;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Phalanx.Console.Policies;

// ─────────────────────────────────────────────────────────────────────────────
// In-memory shape of a policy. Mirrors the YAML schema.
// Why a separate Policy and YamlPolicy DTO? Because the YAML format uses
// snake_case and tolerates duck-typed fields; the in-memory type is strongly-
// typed C# with strict invariants.
// ─────────────────────────────────────────────────────────────────────────────

public class Policy
{
    public string Id          { get; init; } = "";
    public string Title       { get; init; } = "";
    public string Description { get; init; } = "";
    public bool   Enabled     { get; init; } = true;
    public bool   DryRun      { get; init; } = false;

    public IReadOnlyList<string> MatchRuleIds   { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> MatchSeverity  { get; init; } = Array.Empty<string>();

    public string                       ActionType   { get; init; } = "";
    public IReadOnlyDictionary<string,object?> ActionParams { get; init; } =
        new Dictionary<string,object?>();

    public int       RateLimitCount  { get; init; } = int.MaxValue;
    public TimeSpan  RateLimitWindow { get; init; } = TimeSpan.Zero;

    public string SourcePath { get; init; } = "";
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML-shaped DTO used only at deserialize time.
// ─────────────────────────────────────────────────────────────────────────────

internal class YamlPolicy
{
    public string  Id          { get; set; } = "";
    public string  Title       { get; set; } = "";
    public string  Description { get; set; } = "";
    public bool    Enabled     { get; set; } = true;
    [YamlMember(Alias = "dry_run")]
    public bool    DryRun      { get; set; } = false;

    public YamlMatch?      Match       { get; set; }
    public YamlAction?     Action      { get; set; }
    [YamlMember(Alias = "rate_limit")]
    public YamlRateLimit?  RateLimit   { get; set; }
}

internal class YamlMatch
{
    [YamlMember(Alias = "rule_ids")]
    public List<string>? RuleIds  { get; set; }
    public List<string>? Severity { get; set; }
}

internal class YamlAction
{
    public string  Type    { get; set; } = "";
    public Dictionary<string,object?>?  Params { get; set; }
}

internal class YamlRateLimit
{
    [YamlMember(Alias = "per_host")]
    public string?  PerHost { get; set; }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyLoader — reads policies/*.yml from disk, caches them in memory.
// Periodic reload so admins editing files don't need a Console restart.
// ─────────────────────────────────────────────────────────────────────────────

public class PolicyLoader
{
    private readonly string _dir;
    private readonly ILogger<PolicyLoader> _log;
    private readonly ConcurrentDictionary<string, Policy> _byId = new();
    private DateTime _lastScan = DateTime.MinValue;

    public PolicyLoader(IConfiguration cfg, ILogger<PolicyLoader> log)
    {
        // Default: ../policies relative to where Console runs. Adjustable via
        // config so deployments can point at /etc/phalanx/policies etc.
        _dir = cfg["PolicyEngine:Directory"] ?? "../policies";
        _log = log;
    }

    public IReadOnlyCollection<Policy> All => _byId.Values.ToList();

    public Policy? ById(string id) => _byId.TryGetValue(id, out var p) ? p : null;

    /// <summary>Force a reload from disk. Returns count loaded.</summary>
    public int ReloadFromDisk()
    {
        if (!Directory.Exists(_dir))
        {
            _log.LogWarning("Policy directory does not exist: {dir}", _dir);
            return 0;
        }

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var loaded = new Dictionary<string, Policy>();
        foreach (var file in Directory.EnumerateFiles(_dir, "*.yml"))
        {
            try
            {
                var raw = File.ReadAllText(file);
                var y   = deserializer.Deserialize<YamlPolicy>(raw);
                if (y == null || string.IsNullOrWhiteSpace(y.Id))
                {
                    _log.LogWarning("Skipping policy file with no id: {file}", file);
                    continue;
                }

                if (loaded.ContainsKey(y.Id))
                {
                    _log.LogWarning("Skipping duplicate policy id {PolicyId} in {File}; first definition wins", y.Id, file);
                    continue;
                }

                var rateLimitExpr = y.RateLimit?.PerHost;
                var (rlCount, rlWindow) = ParseRateLimit(rateLimitExpr);
                if (!string.IsNullOrWhiteSpace(rateLimitExpr) && rlWindow == TimeSpan.Zero)
                {
                    _log.LogWarning("Ignoring invalid rate_limit '{RateLimit}' in policy {PolicyId}", rateLimitExpr, y.Id);
                }

                loaded[y.Id] = new Policy
                {
                    Id              = y.Id,
                    Title           = y.Title,
                    Description     = y.Description,
                    Enabled         = y.Enabled,
                    DryRun          = y.DryRun,
                    MatchRuleIds    = y.Match?.RuleIds  ?? new List<string>(),
                    MatchSeverity   = y.Match?.Severity ?? new List<string>(),
                    ActionType      = y.Action?.Type    ?? "",
                    ActionParams    = y.Action?.Params  ?? new Dictionary<string,object?>(),
                    RateLimitCount  = rlCount,
                    RateLimitWindow = rlWindow,
                    SourcePath      = file,
                };
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to parse policy file: {file}", file);
            }
        }

        _byId.Clear();
        foreach (var (k, v) in loaded) _byId[k] = v;
        _lastScan = DateTime.UtcNow;
        _log.LogInformation("Loaded {n} policies from {dir}", loaded.Count, _dir);
        return loaded.Count;
    }

    /// <summary>"5 per 1m" → (5, 1 minute). "1 per 5m" → (1, 5 minutes).</summary>
    private static (int count, TimeSpan window) ParseRateLimit(string? expr)
    {
        if (string.IsNullOrWhiteSpace(expr))
            return (int.MaxValue, TimeSpan.Zero);

        var parts = expr.Split("per", StringSplitOptions.TrimEntries);
        if (parts.Length != 2) return (int.MaxValue, TimeSpan.Zero);

        if (!int.TryParse(parts[0], out var count) || count <= 0)
            return (int.MaxValue, TimeSpan.Zero);

        var w   = parts[1];
        var num = new string(w.TakeWhile(char.IsDigit).ToArray());
        var unit = w[num.Length..].Trim();

        if (!int.TryParse(num, out var n) || n <= 0)
            return (int.MaxValue, TimeSpan.Zero);

        var window = unit switch
        {
            "s" or "sec" or "second" or "seconds" => TimeSpan.FromSeconds(n),
            "m" or "min" or "minute" or "minutes" => TimeSpan.FromMinutes(n),
            "h" or "hr"  or "hour"   or "hours"   => TimeSpan.FromHours(n),
            _ => TimeSpan.Zero,
        };
        return (count, window);
    }
}
