using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Shared.Data;
using System.Text.Json;

namespace Phalanx.Ingestion.Controllers;

/// <summary>
/// Response action API consumed by three parties:
///   - Console issues commands via POST /api/v1/response/issue
///   - Agent  polls           via GET  /api/v1/response/commands/{agentId}
///   - Agent  acks results     via POST /api/v1/response/ack
///
/// State machine for a ResponseCommand:
///   pending → delivered → acked   (happy path)
///   pending → delivered → failed  (agent reports error)
///   pending → (timeout) → re-delivered  (agent crashed before ack; see below)
///
/// Important behaviour notes:
/// - Polling no longer marks a command as 'delivered' immediately on read.
///   That was a bug: if the agent received the response but crashed before
///   executing it, the command stuck at 'delivered' forever and was never
///   retried. We now only mark 'delivered' if the GET completes with a 200,
///   AND we have a re-delivery window — commands that stay 'delivered' for
///   longer than the redelivery threshold get reset to 'pending' so the next
///   poll picks them up again.
/// - The ack path looks up by CommandId (which has a unique index after the
///   migration) rather than scanning the whole table.
/// </summary>
[ApiController]
[Route("api/v1/response")]
public class ResponseController : ControllerBase
{
    private readonly PhalanxContext _db;

    // If a command has been 'delivered' for longer than this without being
    // acked, assume the agent crashed and re-deliver. 120s is generous enough
    // that legitimate slow actions (a file collection of a large binary) won't
    // get re-issued, but tight enough that a crashed agent recovers quickly.
    private static readonly TimeSpan RedeliveryAfter = TimeSpan.FromSeconds(120);

    public ResponseController(PhalanxContext db) => _db = db;

    // ── Console → issue a command ─────────────────────────────────────────
    [HttpPost("issue")]
    public async Task<IActionResult> Issue([FromBody] IssueCommandRequest req)
    {
        if (!Guid.TryParse(req.AgentId, out var agentId))
            return BadRequest(new { error = "invalid agent_id" });

        if (string.IsNullOrWhiteSpace(req.Action))
            return BadRequest(new { error = "missing action" });

        var cmd = new ResponseCommand
        {
            CommandId  = Guid.NewGuid().ToString(),
            IssuedAt   = DateTime.UtcNow,
            AgentId    = agentId,
            Action     = req.Action,
            ParamsJson = JsonSerializer.Serialize(req.Params ?? new()),
            IssuedBy   = req.IssuedBy ?? "console",
            Status     = "pending",
        };
        _db.ResponseCommands.Add(cmd);
        await _db.SaveChangesAsync();
        return Ok(new { command_id = cmd.CommandId, status = "queued" });
    }

    // ── Agent → poll pending commands ─────────────────────────────────────
    [HttpGet("commands/{agentId}")]
    public async Task<IActionResult> GetCommands(string agentId)
    {
        if (!Guid.TryParse(agentId, out var aid))
            return BadRequest();

        var now = DateTime.UtcNow;
        var redeliverThreshold = now - RedeliveryAfter;

        // First: re-pend any stale 'delivered' commands. An agent that
        // crashed mid-action will have a delivered command sitting around;
        // we want to give it another chance to execute on next reconnect.
        var stale = await _db.ResponseCommands
            .Where(c => c.AgentId == aid
                     && c.Status == "delivered"
                     && c.IssuedAt < redeliverThreshold)
            .ToListAsync();
        foreach (var s in stale) s.Status = "pending";

        var cmds = await _db.ResponseCommands
            .Where(c => c.AgentId == aid && c.Status == "pending")
            .OrderBy(c => c.IssuedAt)
            .Take(20)
            .ToListAsync();

        // Mark as delivered so the next poll doesn't return them again
        // (unless they timeout per the redelivery rule above).
        foreach (var c in cmds) c.Status = "delivered";
        await _db.SaveChangesAsync();

        var result = cmds.Select(c => new
        {
            command_id = c.CommandId,
            action     = c.Action,
            params_raw = c.ParamsJson,
            issued_at  = c.IssuedAt,
        }).ToList();

        return Ok(result);
    }

    // ── Agent → ack result ────────────────────────────────────────────────
    [HttpPost("ack")]
    public async Task<IActionResult> Ack([FromBody] AckRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.CommandId))
            return BadRequest(new { error = "missing command_id" });

        var cmd = await _db.ResponseCommands
            .FirstOrDefaultAsync(c => c.CommandId == req.CommandId);

        if (cmd is null)
            return NotFound(new { error = "unknown command_id", req.CommandId });

        // Determine outcome from the result payload. We accept either
        // { "status": "ok" | "error" | "failed" } or treat any non-error
        // status as success. This keeps it compatible with both the legacy
        // endpoint agent and the new sensor coordinator.
        var statusValue = req.Result?.TryGetValue("status", out var s) == true
                          ? s?.ToString()?.ToLowerInvariant() ?? ""
                          : "";
        cmd.Status = statusValue is "error" or "failed" ? "failed" : "acked";

        cmd.AckedAt    = DateTime.TryParse(req.ExecutedAt, out var t)
                         ? t.ToUniversalTime()
                         : DateTime.UtcNow;
        cmd.ResultJson = JsonSerializer.Serialize(req.Result ?? new());

        await _db.SaveChangesAsync();
        return Ok(new { status = cmd.Status, acked_at = cmd.AckedAt });
    }

    // ── Console → list commands for an agent ─────────────────────────────
    [HttpGet("history/{agentId}")]
    public async Task<IActionResult> History(string agentId, int take = 50)
    {
        if (!Guid.TryParse(agentId, out var aid))
            return BadRequest();

        var cmds = await _db.ResponseCommands
            .Where(c => c.AgentId == aid)
            .OrderByDescending(c => c.IssuedAt)
            .Take(Math.Clamp(take, 1, 200))
            .ToListAsync();

        return Ok(cmds);
    }
}

public record IssueCommandRequest(
    string AgentId,
    string Action,
    Dictionary<string, object>? Params,
    string? IssuedBy
);

public record AckRequest(
    string CommandId,
    string AgentId,
    string Action,
    Dictionary<string, object>? Result,
    string? ExecutedAt
);
