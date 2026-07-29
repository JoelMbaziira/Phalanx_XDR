using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Phalanx.Console.Hubs;
using Phalanx.Shared.Data;

namespace Phalanx.Console.Policies;

// ─────────────────────────────────────────────────────────────────────────────
// PolicyEngine
// ----------------------------------------------------------------------------
// Background hosted service. Once every PollInterval (default 2s):
//   1. Find alerts inserted since last cycle (NEW alerts only)
//   2. For each alert, evaluate every enabled policy
//   3. If a policy matches:
//        - Honor global kill switch
//        - Honor per-host rate limit
//        - If dry_run, write audit row with Outcome=dry_run
//        - Otherwise POST to /api/v1/response/issue, write audit row
//          with Outcome=dispatched and the returned command_id
//
// Why a hosted service inside Console rather than a separate worker process?
// - Reads alerts and writes commands — both already accessible via PhalanxContext
// - Re-uses Console's HttpClient registration for the Ingestion call
// - One fewer service to deploy and supervise
//
// The poll cursor (last-seen Alert.Id) lives in PolicySettings under the key
// "engine_cursor", so on restart we resume from where we left off.
// ─────────────────────────────────────────────────────────────────────────────

public class PolicyEngine : BackgroundService
{
    private readonly IServiceScopeFactory    _scopes;
    private readonly IHttpClientFactory      _http;
    private readonly PolicyLoader            _policies;
    private readonly IConfiguration          _cfg;
    private readonly ILogger<PolicyEngine>   _log;
    private readonly ChannelReader<bool>     _alertSignal;
    private readonly IHubContext<AlertHub>   _hubContext;

    private readonly TimeSpan _reloadInterval;

    private DateTime _lastReload = DateTime.MinValue;

    public PolicyEngine(
        IServiceScopeFactory scopes,
        IHttpClientFactory http,
        PolicyLoader policies,
        IConfiguration cfg,
        ILogger<PolicyEngine> log,
        Channel<bool> alertChannel,
        IHubContext<AlertHub> hubContext)
    {
        _scopes      = scopes;
        _http        = http;
        _policies    = policies;
        _cfg         = cfg;
        _log         = log;
        _alertSignal = alertChannel.Reader;
        _hubContext  = hubContext;

        _reloadInterval = TimeSpan.FromSeconds(
            int.TryParse(cfg["PolicyEngine:ReloadSeconds"], out var r) ? r : 60);
    }

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        _policies.ReloadFromDisk();
        _lastReload = DateTime.UtcNow;
        _log.LogInformation("Policy engine started (signal-driven). reload={reload}s",
            _reloadInterval.TotalSeconds);

        long cursor = await LoadCursor(stop);
        _log.LogInformation("Resuming from Alert.Id > {cursor}", cursor);

        // Catch up on any alerts written while the engine was offline
        cursor = await Cycle(cursor, stop);

        while (!stop.IsCancellationRequested)
        {
            try
            {
                // Block until AlertHub signals a new alert — zero latency vs. old 2s timer
                await _alertSignal.ReadAsync(stop);
                // Drain any burst so one Cycle() handles all accumulated alerts
                while (_alertSignal.TryRead(out _)) { }

                if (DateTime.UtcNow - _lastReload > _reloadInterval)
                {
                    _policies.ReloadFromDisk();
                    _lastReload = DateTime.UtcNow;
                }

                cursor = await Cycle(cursor, stop);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "Policy engine cycle failed");
            }
        }

        _log.LogInformation("Policy engine stopped");
    }

    // ── One cycle: fetch new alerts, evaluate, dispatch ───────────────────

    private async Task<long> Cycle(long cursor, CancellationToken stop)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();

        // Pull up to 200 new alerts per cycle. At 2s intervals that's 100/s
        // throughput — far more than any realistic detector emits. Bounded
        // so a backlog after restart doesn't OOM the process.
        var batch = await db.Alerts
            .AsNoTracking()
            .Where(a => a.Id > cursor)
            .OrderBy(a => a.Id)
            .Take(200)
            .ToListAsync(stop);

        if (batch.Count == 0) return cursor;

        var killSwitchOn = await IsKillSwitchOn(db, stop);
        if (killSwitchOn)
            _log.LogWarning("Kill switch is ON. All actions will be skipped this cycle.");

        foreach (var alert in batch)
        {
            foreach (var policy in _policies.All)
            {
                if (!policy.Enabled) continue;
                if (!Matches(policy, alert)) continue;

                await Dispatch(db, policy, alert, killSwitchOn, stop);
            }
            cursor = alert.Id;
        }

        await SaveCursor(db, cursor, stop);
        return cursor;
    }

    // ── Matching logic ────────────────────────────────────────────────────

    private static bool Matches(Policy policy, Alert alert)
    {
        if (policy.MatchRuleIds.Count > 0 &&
            !policy.MatchRuleIds.Contains(alert.RuleId, StringComparer.OrdinalIgnoreCase))
            return false;

        if (policy.MatchSeverity.Count > 0 &&
            !policy.MatchSeverity.Contains(alert.Severity, StringComparer.OrdinalIgnoreCase))
            return false;

        return true;
    }

    // ── Dispatch — the actual fire ────────────────────────────────────────

    private async Task Dispatch(PhalanxContext db, Policy policy, Alert alert,
                                bool killSwitchOn, CancellationToken stop)
    {
        // ── kill switch ──
        if (killSwitchOn)
        {
            await Audit(db, policy, alert, null, "skipped_killswitch", null, stop);
            return;
        }

        // ── rate limit ──
        if (policy.RateLimitWindow > TimeSpan.Zero)
        {
            var since = DateTime.UtcNow - policy.RateLimitWindow;
            var recent = await db.PolicyDispatches
                .Where(d => d.PolicyId == policy.Id
                         && d.DispatchedAt > since
                         && d.Outcome == "dispatched"
                         && d.Hostname  == alert.Hostname)
                .CountAsync(stop);
            if (recent >= policy.RateLimitCount)
            {
                _log.LogInformation(
                    "Rate-limited: policy={pid} host={host} ({n} dispatches in {win})",
                    policy.Id, alert.Hostname, recent, policy.RateLimitWindow);
                await Audit(db, policy, alert, null, "rate_limited", null, stop);
                return;
            }
        }

        // ── build the response command payload ──
        var (action, parameters) = BuildAction(policy, alert);
        if (action == null)
        {
            await Audit(db, policy, alert, null, "error",
                        "Policy action could not be resolved (missing alert data?)", stop);
            return;
        }

        // ── dry run ──
        if (policy.DryRun)
        {
            _log.LogInformation("DRY-RUN policy={pid} alert={aid} action={action}",
                policy.Id, alert.Id, action);
            await Audit(db, policy, alert, action, "dry_run", null, stop, parameters);
            return;
        }

        // ── live fire ──
        try
        {
            var commandId = await PostIssue(alert.AgentId, action, parameters, policy.Id, stop);
            _log.LogInformation(
                "DISPATCHED policy={pid} alert={aid} action={action} cmd={cid}",
                policy.Id, alert.Id, action, commandId);
            await Audit(db, policy, alert, action, "dispatched", commandId, stop, parameters);

            // Push instant UI update — browser sees the policy response without waiting for a page reload
            await _hubContext.Clients.All.SendAsync("ReceiveAlert", new
            {
                severity    = alert.Severity,
                ruleId      = alert.RuleId,
                ruleName    = alert.RuleName,
                description = $"[{policy.Title}] {alert.Description} → {action}",
                hostname    = alert.Hostname,
                processName = alert.ProcessName,
                userName    = alert.UserName,
                detectedAt  = DateTime.UtcNow,
                status      = "policy_fired",
            }, stop);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Dispatch failed for policy={pid} alert={aid}", policy.Id, alert.Id);
            await Audit(db, policy, alert, action, "error", null, stop,
                        errorMessage: ex.Message);
        }
    }

    // ── Map alert + policy.action.params into a (action, params) tuple ────

    private static (string? action, Dictionary<string, object?> parameters) BuildAction(
        Policy policy, Alert alert)
    {
        var p = new Dictionary<string, object?>(policy.ActionParams, StringComparer.OrdinalIgnoreCase);
        var act = policy.ActionType.ToLowerInvariant();

        switch (act)
        {
            case "kill_process":
                // Send both pid (sentinel reads this) and entity_id (audit trail).
                // pid is extracted from the triggering event JSON; entity_id from
                // the alert row. If neither is available the action can't proceed.
                var pid = ExtractProcessPid(alert.TriggeringEventJson);
                if (pid.HasValue)
                    p["pid"] = pid.Value;
                if (!string.IsNullOrEmpty(alert.ProcessEntityId))
                    p["entity_id"] = alert.ProcessEntityId;
                if (!p.ContainsKey("pid") && !p.ContainsKey("entity_id"))
                    return (null, p);
                return (act, p);

            case "quarantine_file":
                // Path may come from the alert envelope (TriggeringEventJson)
                // or be statically set in policy.action.params.path
                if (!p.ContainsKey("path"))
                {
                    var pathFromAlert = ExtractFilePath(alert.TriggeringEventJson);
                    if (pathFromAlert == null) return (null, p);
                    p["path"] = pathFromAlert;
                }
                return (act, p);

            case "isolate_host":
            case "collect_file":
            case "run_command":
                return (act, p);

            default:
                return (null, p);
        }
    }

    private static int? ExtractProcessPid(string triggeringJson)
    {
        if (string.IsNullOrWhiteSpace(triggeringJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(triggeringJson);
            if (doc.RootElement.TryGetProperty("process", out var proc) &&
                proc.TryGetProperty("pid", out var pidEl) &&
                pidEl.TryGetInt32(out var pid))
                return pid;
        }
        catch { }
        return null;
    }

    private static string? ExtractFilePath(string triggeringJson)
    {
        if (string.IsNullOrWhiteSpace(triggeringJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(triggeringJson);
            if (doc.RootElement.TryGetProperty("file", out var f) &&
                f.TryGetProperty("path", out var path))
                return path.GetString();
        }
        catch { /* ignore malformed JSON; policy will Outcome=error */ }
        return null;
    }

    // ── Post to /api/v1/response/issue, return command_id ─────────────────

    private async Task<string> PostIssue(Guid agentId, string action,
                                         Dictionary<string, object?> parameters,
                                         string issuedBy, CancellationToken stop)
    {
        var ingestionBase = _cfg["Ingestion:BaseUrl"] ?? "http://localhost:5038";
        var client = _http.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(10);

        var body = new
        {
            AgentId  = agentId.ToString(),
            Action   = action,
            Params   = parameters,
            IssuedBy = $"policy-engine:{issuedBy}",
        };
        var r = await client.PostAsJsonAsync(
            $"{ingestionBase}/api/v1/response/issue", body, stop);
        if (!r.IsSuccessStatusCode)
            throw new Exception($"Ingestion returned {(int)r.StatusCode}");

        var raw = await r.Content.ReadFromJsonAsync<Dictionary<string, object?>>(
            cancellationToken: stop);
        return raw?["command_id"]?.ToString() ?? "";
    }

    // ── Audit record ──────────────────────────────────────────────────────

    private async Task Audit(PhalanxContext db, Policy policy, Alert alert,
                             string? action, string outcome, string? commandId,
                             CancellationToken stop,
                             Dictionary<string, object?>? parameters = null,
                             string? errorMessage = null)
    {
        var paramsJson = parameters != null ? JsonSerializer.Serialize(parameters) : "{}";
        db.PolicyDispatches.Add(new PolicyDispatch
        {
            DispatchedAt  = DateTime.UtcNow,
            PolicyId      = policy.Id,
            PolicyTitle   = policy.Title,
            AlertId       = alert.Id,
            RuleId        = alert.RuleId,
            Action        = action ?? policy.ActionType,
            ParamsJson    = paramsJson,
            AgentId       = alert.AgentId == Guid.Empty ? null : alert.AgentId,
            Hostname      = alert.Hostname,
            CommandId     = commandId,
            Outcome       = outcome,
            ErrorMessage  = errorMessage,
        });
        await db.SaveChangesAsync(stop);
    }

    // ── Cursor + kill-switch persistence ──────────────────────────────────

    private static async Task<long> LoadCursor(PhalanxContext db, CancellationToken stop)
    {
        var row = await db.PolicySettings.FirstOrDefaultAsync(s => s.Key == "engine_cursor", stop);
        return row != null && long.TryParse(row.Value, out var v) ? v : 0L;
    }

    private async Task<long> LoadCursor(CancellationToken stop)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();
        return await LoadCursor(db, stop);
    }

    private static async Task SaveCursor(PhalanxContext db, long cursor, CancellationToken stop)
    {
        var row = await db.PolicySettings.FirstOrDefaultAsync(s => s.Key == "engine_cursor", stop);
        if (row == null)
        {
            db.PolicySettings.Add(new PolicySetting
                { Key = "engine_cursor", Value = cursor.ToString(), UpdatedAt = DateTime.UtcNow });
        }
        else
        {
            row.Value = cursor.ToString();
            row.UpdatedAt = DateTime.UtcNow;
        }
        await db.SaveChangesAsync(stop);
    }

    private static async Task<bool> IsKillSwitchOn(PhalanxContext db, CancellationToken stop)
    {
        var row = await db.PolicySettings.FirstOrDefaultAsync(s => s.Key == "kill_switch", stop);
        return row?.Value?.ToLowerInvariant() == "on";
    }
}
