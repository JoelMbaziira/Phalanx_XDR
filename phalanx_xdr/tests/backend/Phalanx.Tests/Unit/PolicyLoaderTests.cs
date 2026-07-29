using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Phalanx.Console.Policies;
using Xunit;

namespace Phalanx.Tests.Unit;

public class PolicyLoaderTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"phx-policies-{Guid.NewGuid():N}");
    private readonly PolicyLoader _loader;

    public PolicyLoaderTests()
    {
        Directory.CreateDirectory(_dir);

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PolicyEngine:Directory"] = _dir })
            .Build();

        _loader = new PolicyLoader(cfg, NullLogger<PolicyLoader>.Instance);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private void WritePolicy(string filename, string yaml) =>
        File.WriteAllText(Path.Combine(_dir, filename), yaml);

    // ── Basic loading ──────────────────────────────────────────────────────────

    [Fact]
    public void ValidPolicy_LoadedCorrectly()
    {
        WritePolicy("block.yml", """
            id: P-001
            title: Block on Critical
            description: Auto-block
            enabled: true
            match:
              severity:
                - Critical
            action:
              type: kill_process
            """);

        var n = _loader.ReloadFromDisk();
        n.Should().Be(1);
        _loader.All.Should().HaveCount(1);

        var p = _loader.ById("P-001")!;
        p.Should().NotBeNull();
        p.Title.Should().Be("Block on Critical");
        p.Enabled.Should().BeTrue();
        p.MatchSeverity.Should().Contain("Critical");
        p.ActionType.Should().Be("kill_process");
    }

    [Fact]
    public void PolicyWithNoId_Skipped()
    {
        WritePolicy("no_id.yml", """
            title: No ID
            enabled: true
            match:
              severity:
                - High
            action:
              type: notify
            """);

        _loader.ReloadFromDisk().Should().Be(0);
        _loader.All.Should().BeEmpty();
    }

    [Fact]
    public void DuplicatePolicyId_FirstWins()
    {
        WritePolicy("a.yml", """
            id: P-DUP
            title: First
            enabled: true
            action:
              type: notify
            """);

        WritePolicy("b.yml", """
            id: P-DUP
            title: Second
            enabled: true
            action:
              type: block
            """);

        _loader.ReloadFromDisk().Should().Be(1);
        _loader.ById("P-DUP")!.Title.Should().Be("First");
    }

    // ── Rate limit parsing ─────────────────────────────────────────────────────

    [Fact]
    public void RateLimit_MinuteSuffix_ParsedCorrectly()
    {
        WritePolicy("rl.yml", """
            id: P-RL
            title: Rate Limited
            enabled: true
            action:
              type: notify
            rate_limit:
              per_host: "3 per 5m"
            """);

        _loader.ReloadFromDisk();
        var p = _loader.ById("P-RL")!;
        p.RateLimitCount.Should().Be(3);
        p.RateLimitWindow.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Fact]
    public void RateLimit_SecondSuffix_ParsedCorrectly()
    {
        WritePolicy("rl2.yml", """
            id: P-RL2
            title: Rate Limited 2
            enabled: true
            action:
              type: notify
            rate_limit:
              per_host: "1 per 30s"
            """);

        _loader.ReloadFromDisk();
        var p = _loader.ById("P-RL2")!;
        p.RateLimitCount.Should().Be(1);
        p.RateLimitWindow.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void InvalidRateLimit_Ignored()
    {
        WritePolicy("bad_rl.yml", """
            id: P-BAD-RL
            title: Bad Rate Limit
            enabled: true
            action:
              type: notify
            rate_limit:
              per_host: "not valid"
            """);

        _loader.ReloadFromDisk();
        var p = _loader.ById("P-BAD-RL")!;
        p.RateLimitCount.Should().Be(int.MaxValue);
        p.RateLimitWindow.Should().Be(TimeSpan.Zero);
    }

    [Fact]
    public void EmptyDirectory_ReturnsZero()
    {
        _loader.ReloadFromDisk().Should().Be(0);
    }
}
