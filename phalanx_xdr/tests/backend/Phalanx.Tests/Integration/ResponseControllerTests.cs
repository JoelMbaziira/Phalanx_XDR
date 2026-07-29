using FluentAssertions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Ingestion.Controllers;
using Phalanx.Shared.Data;
using Xunit;

namespace Phalanx.Tests.Integration;

public class ResponseControllerTests : IAsyncDisposable
{
    private readonly PhalanxContext _db;
    private readonly ResponseController _controller;

    public ResponseControllerTests()
    {
        var opts = new DbContextOptionsBuilder<PhalanxContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new PhalanxContext(opts);
        _controller = new ResponseController(_db);
    }

    public async ValueTask DisposeAsync() => await _db.DisposeAsync();

    private static readonly Guid AgentId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    // ── Issue ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Issue_ValidRequest_ReturnsCmdId()
    {
        var req = new IssueCommandRequest(AgentId.ToString(), "kill_process",
                                          new Dictionary<string, object> { ["pid"] = 1234 },
                                          "tester");
        var result = await _controller.Issue(req);

        result.Should().BeOfType<OkObjectResult>();
        _db.ResponseCommands.Should().HaveCount(1);
        _db.ResponseCommands.First().Status.Should().Be("pending");
        _db.ResponseCommands.First().AgentId.Should().Be(AgentId);
    }

    [Fact]
    public async Task Issue_InvalidAgentId_ReturnsBadRequest()
    {
        var req = new IssueCommandRequest("not-a-guid", "kill_process", null, null);
        var result = await _controller.Issue(req);
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task Issue_MissingAction_ReturnsBadRequest()
    {
        var req = new IssueCommandRequest(AgentId.ToString(), "", null, null);
        var result = await _controller.Issue(req);
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    // ── Poll commands ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetCommands_ReturnsPendingCommands()
    {
        _db.ResponseCommands.Add(new ResponseCommand
        {
            CommandId = Guid.NewGuid().ToString(),
            AgentId   = AgentId,
            Action    = "kill_process",
            ParamsJson = "{}",
            IssuedBy  = "test",
            IssuedAt  = DateTime.UtcNow,
            Status    = "pending",
        });
        await _db.SaveChangesAsync();

        var result = await _controller.GetCommands(AgentId.ToString());

        result.Should().BeOfType<OkObjectResult>();
        // After poll the command should be marked delivered
        _db.ResponseCommands.First().Status.Should().Be("delivered");
    }

    [Fact]
    public async Task GetCommands_InvalidAgentId_ReturnsBadRequest()
    {
        var result = await _controller.GetCommands("bad-guid");
        result.Should().BeOfType<BadRequestResult>();
    }

    [Fact]
    public async Task GetCommands_EmptyQueue_ReturnsEmptyList()
    {
        var result = await _controller.GetCommands(AgentId.ToString());
        result.Should().BeOfType<OkObjectResult>();
        var ok = (OkObjectResult)result;
        var list = ok.Value as System.Collections.IEnumerable;
        list.Should().NotBeNull();
        list!.Cast<object>().Should().BeEmpty();
    }

    // ── Ack ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Ack_Success_MarksCommandAcked()
    {
        var cmdId = Guid.NewGuid().ToString();
        _db.ResponseCommands.Add(new ResponseCommand
        {
            CommandId  = cmdId,
            AgentId    = AgentId,
            Action     = "kill_process",
            ParamsJson = "{}",
            IssuedBy   = "test",
            IssuedAt   = DateTime.UtcNow,
            Status     = "delivered",
        });
        await _db.SaveChangesAsync();

        var ack = new AckRequest(cmdId, AgentId.ToString(), "kill_process",
                                 new Dictionary<string, object> { ["status"] = "ok" },
                                 DateTime.UtcNow.ToString("o"));
        var result = await _controller.Ack(ack);

        result.Should().BeOfType<OkObjectResult>();
        _db.ResponseCommands.First().Status.Should().Be("acked");
    }

    [Fact]
    public async Task Ack_ErrorStatus_MarksCommandFailed()
    {
        var cmdId = Guid.NewGuid().ToString();
        _db.ResponseCommands.Add(new ResponseCommand
        {
            CommandId  = cmdId,
            AgentId    = AgentId,
            Action     = "kill_process",
            ParamsJson = "{}",
            IssuedBy   = "test",
            IssuedAt   = DateTime.UtcNow,
            Status     = "delivered",
        });
        await _db.SaveChangesAsync();

        var ack = new AckRequest(cmdId, AgentId.ToString(), "kill_process",
                                 new Dictionary<string, object> { ["status"] = "error" }, null);
        await _controller.Ack(ack);
        _db.ResponseCommands.First().Status.Should().Be("failed");
    }

    [Fact]
    public async Task Ack_UnknownCommandId_ReturnsNotFound()
    {
        var ack = new AckRequest("nonexistent", AgentId.ToString(), "kill_process", null, null);
        var result = await _controller.Ack(ack);
        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ── Redelivery ────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetCommands_StaleDelivered_Requeued()
    {
        var cmdId = Guid.NewGuid().ToString();
        _db.ResponseCommands.Add(new ResponseCommand
        {
            CommandId  = cmdId,
            AgentId    = AgentId,
            Action     = "quarantine_file",
            ParamsJson = "{}",
            IssuedBy   = "test",
            IssuedAt   = DateTime.UtcNow.AddMinutes(-5),  // issued 5 min ago
            Status     = "delivered",                      // stuck at delivered
        });
        await _db.SaveChangesAsync();

        // Poll — the stale delivered command should be re-delivered
        var result = await _controller.GetCommands(AgentId.ToString());
        result.Should().BeOfType<OkObjectResult>();
        var ok = (OkObjectResult)result;
        var list = ((IEnumerable<object>)ok.Value!).ToList();
        list.Should().HaveCount(1);
    }
}
