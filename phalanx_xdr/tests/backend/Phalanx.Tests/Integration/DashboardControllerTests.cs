using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Console.Controllers;
using Phalanx.Shared.Data;
using System.Text.Json;
using Xunit;

namespace Phalanx.Tests.Integration;

public class DashboardControllerTests : IAsyncDisposable
{
    private readonly PhalanxContext _db;
    private readonly DashboardController _controller;

    public DashboardControllerTests()
    {
        var opts = new DbContextOptionsBuilder<PhalanxContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new PhalanxContext(opts);
        _controller = new DashboardController(_db);
    }

    public async ValueTask DisposeAsync() => await _db.DisposeAsync();

    // ── /api/dashboard/stats ───────────────────────────────────────────────────

    [Fact]
    public async Task Stats_EmptyDb_ReturnsZeroes()
    {
        var result = await _controller.Stats();

        result.Should().BeOfType<OkObjectResult>();
        var ok = (OkObjectResult)result;
        var json = JsonSerializer.Serialize(ok.Value);
        var doc  = JsonDocument.Parse(json).RootElement;

        doc.GetProperty("openAlerts").GetInt32().Should().Be(0);
        doc.GetProperty("criticalAlerts").GetInt32().Should().Be(0);
        doc.GetProperty("eventsLast24h").GetInt32().Should().Be(0);
        doc.GetProperty("activeAgents").GetInt32().Should().Be(0);
        doc.GetProperty("activeSensors").GetInt32().Should().Be(0);
        doc.GetProperty("liveDevices").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Stats_WithOpenAlerts_CountsCorrectly()
    {
        _db.Alerts.Add(new Alert { Severity = "High",     Status = "new",          DetectedAt = DateTime.UtcNow, RuleId = "R1", RuleName = "Test" });
        _db.Alerts.Add(new Alert { Severity = "Critical", Status = "new",          DetectedAt = DateTime.UtcNow, RuleId = "R2", RuleName = "Test" });
        _db.Alerts.Add(new Alert { Severity = "High",     Status = "acknowledged", DetectedAt = DateTime.UtcNow, RuleId = "R3", RuleName = "Test" });
        await _db.SaveChangesAsync();

        var result = await _controller.Stats();
        var json   = JsonSerializer.Serialize(((OkObjectResult)result).Value);
        var doc    = JsonDocument.Parse(json).RootElement;

        doc.GetProperty("openAlerts").GetInt32().Should().Be(2);
        doc.GetProperty("criticalAlerts").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task Stats_WithRecentEvents_CountsEventsLast24h()
    {
        var agentId = Guid.NewGuid();
        _db.Events.Add(new TelemetryEvent
        {
            AgentId    = agentId,
            Hostname   = "ws1",
            IngestedAt = DateTime.UtcNow.AddHours(-1),  // recent
            Timestamp  = DateTime.UtcNow,
            Action     = "process_start",
        });
        _db.Events.Add(new TelemetryEvent
        {
            AgentId    = agentId,
            Hostname   = "ws1",
            IngestedAt = DateTime.UtcNow.AddHours(-25),  // old — outside 24h window
            Timestamp  = DateTime.UtcNow,
            Action     = "process_start",
        });
        await _db.SaveChangesAsync();

        var result = await _controller.Stats();
        var json   = JsonSerializer.Serialize(((OkObjectResult)result).Value);
        var doc    = JsonDocument.Parse(json).RootElement;

        doc.GetProperty("eventsLast24h").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task Stats_ActiveAgents_DeduplicatedByAgentId()
    {
        var agentId = Guid.NewGuid();
        // Same agent sends two events — should count as 1 active agent
        _db.Events.Add(new TelemetryEvent { AgentId = agentId, Hostname = "ws1", IngestedAt = DateTime.UtcNow, Timestamp = DateTime.UtcNow, Action = "a" });
        _db.Events.Add(new TelemetryEvent { AgentId = agentId, Hostname = "ws1", IngestedAt = DateTime.UtcNow, Timestamp = DateTime.UtcNow, Action = "b" });
        await _db.SaveChangesAsync();

        var result = await _controller.Stats();
        var json   = JsonSerializer.Serialize(((OkObjectResult)result).Value);
        var doc    = JsonDocument.Parse(json).RootElement;

        doc.GetProperty("activeAgents").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task Stats_StaleAgent_NotCountedAsActive()
    {
        var agentId = Guid.NewGuid();
        // Last event was 10 minutes ago — beyond the 5-minute staleness window
        _db.Events.Add(new TelemetryEvent
        {
            AgentId    = agentId,
            Hostname   = "ws1",
            IngestedAt = DateTime.UtcNow.AddMinutes(-10),
            Timestamp  = DateTime.UtcNow,
            Action     = "process_start",
        });
        await _db.SaveChangesAsync();

        var result = await _controller.Stats();
        var json   = JsonSerializer.Serialize(((OkObjectResult)result).Value);
        var doc    = JsonDocument.Parse(json).RootElement;

        doc.GetProperty("activeAgents").GetInt32().Should().Be(0);
    }
}
