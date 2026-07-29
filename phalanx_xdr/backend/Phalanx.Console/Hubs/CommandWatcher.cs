using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Phalanx.Shared.Data;

namespace Phalanx.Console.Hubs;

/// <summary>
/// Background service that polls ResponseCommands for acked/failed transitions
/// and pushes a CommandStatusUpdate event over SignalR so the Response page
/// updates live without a browser reload.
/// </summary>
public class CommandWatcher : BackgroundService
{
    private readonly IServiceScopeFactory  _scopes;
    private readonly IHubContext<AlertHub> _hub;
    private readonly ILogger<CommandWatcher> _log;

    // Track the highest AckedAt timestamp we have already pushed, so each
    // poll only looks at genuinely new transitions.
    private DateTime _lastPushed = DateTime.UtcNow.AddMinutes(-1);

    public CommandWatcher(
        IServiceScopeFactory scopes,
        IHubContext<AlertHub> hub,
        ILogger<CommandWatcher> log)
    {
        _scopes = scopes;
        _hub    = hub;
        _log    = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        _log.LogInformation("CommandWatcher started");

        while (!stop.IsCancellationRequested)
        {
            try
            {
                await PushTransitions(stop);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "CommandWatcher poll failed");
            }

            await Task.Delay(TimeSpan.FromSeconds(2), stop);
        }
    }

    private async Task PushTransitions(CancellationToken stop)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();

        // Find commands that have recently been acked or failed
        var since = _lastPushed;
        var transitions = await db.ResponseCommands
            .AsNoTracking()
            .Where(c => (c.Status == "acked" || c.Status == "failed")
                     && c.AckedAt != null
                     && c.AckedAt > since)
            .OrderBy(c => c.AckedAt)
            .Take(50)
            .ToListAsync(stop);

        if (transitions.Count == 0) return;

        foreach (var cmd in transitions)
        {
            await _hub.Clients.All.SendAsync("CommandStatusUpdate", new
            {
                commandId = cmd.CommandId,
                status    = cmd.Status,
                action    = cmd.Action,
                agentId   = cmd.AgentId == Guid.Empty ? null : cmd.AgentId.ToString(),
                ackedAt   = cmd.AckedAt,
                result    = cmd.ResultJson,
            }, stop);

            _log.LogInformation("Pushed CommandStatusUpdate: {CmdId} → {Status}",
                cmd.CommandId, cmd.Status);
        }

        // Advance cursor to avoid re-pushing the same transitions
        _lastPushed = transitions.Max(c => c.AckedAt)!.Value;
    }
}
