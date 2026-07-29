using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Phalanx.Ingestion.Controllers;
using Phalanx.Shared.Data;
using StackExchange.Redis;
using Xunit;

namespace Phalanx.Tests.Integration;

/// <summary>
/// Direct controller tests — no HTTP pipeline. Each test gets an isolated
/// InMemory database. Redis is mocked; we verify the telemetry push.
/// </summary>
public class IngestionControllerTests : IAsyncDisposable
{
    private readonly PhalanxContext _db;
    private readonly Mock<IConnectionMultiplexer> _redis;
    private readonly Mock<IDatabase> _rdb;
    private readonly IngestionController _controller;

    public IngestionControllerTests()
    {
        var opts = new DbContextOptionsBuilder<PhalanxContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new PhalanxContext(opts);

        _rdb   = new Mock<IDatabase>();
        _redis = new Mock<IConnectionMultiplexer>();
        _redis.Setup(r => r.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(_rdb.Object);

        _controller = new IngestionController(_db, _redis.Object);
    }

    public async ValueTask DisposeAsync() => await _db.DisposeAsync();

    // ── Health ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Health_ReturnsOk()
    {
        var result = _controller.Health();
        result.Should().BeOfType<OkObjectResult>();
    }

    // ── Process events ─────────────────────────────────────────────────────────

    [Fact]
    public async Task IngestProcess_ValidPayload_SavedToDb()
    {
        var agentId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var body = JsonDocument.Parse($$"""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "id": "{{eventId}}", "dataset": "phalanx.sentinel.process", "action": "process_start" },
            "agent": { "id": "{{agentId}}" },
            "host":  { "hostname": "ws1" },
            "process": { "name": "bash", "pid": 1234 }
        }
        """).RootElement;

        var result = await _controller.Ingest(body);

        result.Should().BeOfType<AcceptedResult>();
        _db.Events.Should().HaveCount(1);
        _db.Events.First().AgentId.Should().Be(agentId);
        _db.Events.First().ProcessName.Should().Be("bash");
    }

    [Fact]
    public async Task IngestProcess_PushesToRedis()
    {
        var body = JsonDocument.Parse("""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "dataset": "phalanx.sentinel.process", "action": "process_start" },
            "agent": { "id": "00000000-0000-0000-0000-000000000001" },
            "host":  { "hostname": "ws1" },
            "process": { "name": "ls" }
        }
        """).RootElement;

        await _controller.Ingest(body);

        _rdb.Verify(r => r.ListRightPushAsync("telemetry_stream", It.IsAny<RedisValue>(),
                                               It.IsAny<When>(), It.IsAny<CommandFlags>()),
                    Times.Once);
    }

    // ── File events ────────────────────────────────────────────────────────────

    [Fact]
    public async Task IngestFile_ValidPayload_SavedToDb()
    {
        var body = JsonDocument.Parse("""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "dataset": "phalanx.sentinel.file", "action": "file_create_exec" },
            "agent": { "id": "00000000-0000-0000-0000-000000000001" },
            "host":  { "hostname": "ws1" },
            "file":  { "path": "/tmp/evil.sh", "name": "evil.sh" }
        }
        """).RootElement;

        await _controller.Ingest(body);
        _db.FileEvents.Should().HaveCount(1);
        _db.FileEvents.First().FilePath.Should().Be("/tmp/evil.sh");
    }

    // ── Network events ─────────────────────────────────────────────────────────

    [Fact]
    public async Task IngestNetwork_ValidPayload_SavedToDb()
    {
        var body = JsonDocument.Parse("""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "dataset": "phalanx.sentinel.network", "action": "network_connection" },
            "agent": { "id": "00000000-0000-0000-0000-000000000001" },
            "host":  { "hostname": "ws1" },
            "destination": { "ip": "1.2.3.4", "port": 443 }
        }
        """).RootElement;

        await _controller.Ingest(body);
        _db.NetworkEvents.Should().HaveCount(1);
        _db.NetworkEvents.First().DestinationIp.Should().Be("1.2.3.4");
    }

    // ── Login events ───────────────────────────────────────────────────────────

    [Fact]
    public async Task IngestLogin_ValidPayload_SavedToDb()
    {
        var body = JsonDocument.Parse("""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "dataset": "phalanx.sentinel.login", "action": "login_failed", "outcome": "failure" },
            "agent": { "id": "00000000-0000-0000-0000-000000000001" },
            "host":  { "hostname": "ws1" },
            "user":  { "name": "admin" }
        }
        """).RootElement;

        await _controller.Ingest(body);
        _db.LoginEvents.Should().HaveCount(1);
        _db.LoginEvents.First().Outcome.Should().Be("failure");
        _db.LoginEvents.First().UserName.Should().Be("admin");
    }

    // ── Email events ───────────────────────────────────────────────────────────

    [Fact]
    public async Task IngestEmail_ValidPayload_SavedToDb()
    {
        var body = JsonDocument.Parse("""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "dataset": "phalanx.sentinel.email", "action": "email_client_shell" },
            "agent": { "id": "00000000-0000-0000-0000-000000000001" },
            "host":  { "hostname": "ws1" },
            "email": { "sender": "evil@attacker.com", "indicator_type": "phishing" }
        }
        """).RootElement;

        await _controller.Ingest(body);
        _db.EmailEvents.Should().HaveCount(1);
        _db.EmailEvents.First().Sender.Should().Be("evil@attacker.com");
        _db.EmailEvents.First().IndicatorType.Should().Be("phishing");
    }

    // ── Fallback routing ───────────────────────────────────────────────────────

    [Fact]
    public async Task IngestUnknownDataset_FallsBackToProcessHandler()
    {
        var body = JsonDocument.Parse("""
        {
            "@timestamp": "2024-01-01T00:00:00Z",
            "event": { "dataset": "phalanx.sentinel.unknown", "action": "something" },
            "agent": { "id": "00000000-0000-0000-0000-000000000001" },
            "host":  { "hostname": "ws1" }
        }
        """).RootElement;

        var result = await _controller.Ingest(body);
        result.Should().BeOfType<AcceptedResult>();
        _db.Events.Should().HaveCount(1);
    }
}
