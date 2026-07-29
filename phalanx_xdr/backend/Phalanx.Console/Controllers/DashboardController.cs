using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Shared.Data;

namespace Phalanx.Console.Controllers;

public class DashboardController : Controller
{
    private readonly PhalanxContext _db;
    public DashboardController(PhalanxContext db) => _db = db;

    // ── Main alert dashboard ──────────────────────────────────────────────

    [Route("/")]
[Route("/Dashboard")]
public async Task<IActionResult> Index()
{
    // Staleness window. Anything that hasn't reported within this counts as
    // "not currently active." 5 minutes is generous for poll-based agents
    // (Sentinel polls every 5s, ships frequently) and OK for sensor nodes
    // (they ship batches every few seconds when active).
    var staleAfter = TimeSpan.FromMinutes(5);
    var liveCutoff = DateTime.UtcNow.Subtract(staleAfter);

    var alerts = await _db.Alerts
        .OrderByDescending(a => a.DetectedAt)
        .Take(50)
        .ToListAsync();

    var eventsCutoff = DateTime.UtcNow.AddHours(-24);
    ViewBag.EventsLast24h = await _db.Events.Where(e => e.IngestedAt > eventsCutoff).CountAsync()
                          + await _db.FileEvents.Where(e => e.IngestedAt > eventsCutoff).CountAsync()
                          + await _db.NetworkEvents.Where(e => e.IngestedAt > eventsCutoff).CountAsync()
                          + await _db.LoginEvents.Where(e => e.IngestedAt > eventsCutoff).CountAsync();

    // Sentinel agents (process-level telemetry from installed agents)
    ViewBag.ActiveAgents = await _db.Events
        .Where(e => e.IngestedAt > liveCutoff)
        .Select(e => e.AgentId)
        .Distinct()
        .CountAsync();

    // Sensor nodes (passive network observers on the gateway)
    ViewBag.ActiveSensors = await _db.SensorNodes
        .CountAsync(n => n.LastSeen > liveCutoff);

    // Devices the sensors are currently seeing
    ViewBag.LiveDevices = await _db.NetworkDevices
        .CountAsync(d => d.LastSeen > liveCutoff);

    ViewBag.OpenAlerts     = await _db.Alerts.CountAsync(a => a.Status == "new");
    ViewBag.CriticalAlerts = await _db.Alerts.CountAsync(a =>
                              a.Severity == "Critical" && a.Status == "new");

    // Surface the staleness window so the view can show "active in last 5m"
    ViewBag.StaleMinutes = (int)staleAfter.TotalMinutes;

    return View(alerts);
}


    // ── Live KPI stats (polled by dashboard JS to avoid full page reload) ────

    [Route("/api/dashboard/stats")]
    public async Task<IActionResult> Stats()
    {
        var staleAfter   = TimeSpan.FromMinutes(5);
        var liveCutoff   = DateTime.UtcNow.Subtract(staleAfter);
        var eventsCutoff = DateTime.UtcNow.AddHours(-24);

        var eventsLast24h =
            await _db.Events.Where(e => e.IngestedAt > eventsCutoff).CountAsync()
          + await _db.FileEvents.Where(e => e.IngestedAt > eventsCutoff).CountAsync()
          + await _db.NetworkEvents.Where(e => e.IngestedAt > eventsCutoff).CountAsync()
          + await _db.LoginEvents.Where(e => e.IngestedAt > eventsCutoff).CountAsync();

        return Ok(new
        {
            openAlerts     = await _db.Alerts.CountAsync(a => a.Status == "new"),
            criticalAlerts = await _db.Alerts.CountAsync(a => a.Severity == "Critical" && a.Status == "new"),
            eventsLast24h,
            activeAgents   = await _db.Events.Where(e => e.IngestedAt > liveCutoff)
                                              .Select(e => e.AgentId).Distinct().CountAsync(),
            activeSensors  = await _db.SensorNodes.CountAsync(n => n.LastSeen > liveCutoff),
            liveDevices    = await _db.NetworkDevices.CountAsync(d => d.LastSeen > liveCutoff),
        });
    }

    // ── Email / Phishing events ───────────────────────────────────────────────

    [Route("/email")]
    public async Task<IActionResult> Email(string? q, int take = 100)
    {
        var query = _db.EmailEvents.AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(e =>
                EF.Functions.ILike(e.Sender ?? "", like) ||
                EF.Functions.ILike(e.Subject ?? "", like) ||
                EF.Functions.ILike(e.AttachmentName ?? "", like) ||
                EF.Functions.ILike(e.Detail ?? "", like) ||
                EF.Functions.ILike(e.Hostname, like));
        }
        var rows = await query.OrderByDescending(e => e.Timestamp)
                              .Take(Math.Clamp(take, 1, 1000))
                              .ToListAsync();
        ViewBag.Query = q;
        return View(rows);
    }

    // ── Process events search ─────────────────────────────────────────────

    [Route("/events")]
    public async Task<IActionResult> Events(string? q, int take = 100)
    {
        var query = _db.Events.AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(e =>
                EF.Functions.ILike(e.ProcessName ?? "", like) ||
                EF.Functions.ILike(e.ProcessCommandLine ?? "", like) ||
                EF.Functions.ILike(e.Hostname, like) ||
                EF.Functions.ILike(e.UserName ?? "", like));
        }
        var rows = await query.OrderByDescending(e => e.Timestamp)
                              .Take(Math.Clamp(take, 1, 1000))
                              .ToListAsync();
        ViewBag.Query = q;
        return View(rows);
    }

    // ── Network events ────────────────────────────────────────────────────

    [Route("/network")]
    public async Task<IActionResult> Network(string? q, int take = 100)
    {
        var query = _db.NetworkEvents.AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(e =>
                EF.Functions.ILike(e.DestinationIp ?? "", like) ||
                EF.Functions.ILike(e.DestinationDomain ?? "", like) ||
                EF.Functions.ILike(e.ProcessName ?? "", like) ||
                EF.Functions.ILike(e.Hostname, like));
        }
        var rows = await query.OrderByDescending(e => e.Timestamp)
                              .Take(Math.Clamp(take, 1, 1000))
                              .ToListAsync();
        ViewBag.Query = q;
        return View(rows);
    }

    // ── File events ───────────────────────────────────────────────────────

    [Route("/files")]
    public async Task<IActionResult> Files(string? q, int take = 100)
    {
        var query = _db.FileEvents.AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(e =>
                EF.Functions.ILike(e.FilePath ?? "", like) ||
                EF.Functions.ILike(e.ProcessName ?? "", like) ||
                EF.Functions.ILike(e.Hostname, like));
        }
        var rows = await query.OrderByDescending(e => e.Timestamp)
                              .Take(Math.Clamp(take, 1, 1000))
                              .ToListAsync();
        ViewBag.Query = q;
        return View(rows);
    }

    // ── Login events ──────────────────────────────────────────────────────

    [Route("/logins")]
    public async Task<IActionResult> Logins(string? q, int take = 100)
    {
        var query = _db.LoginEvents.AsQueryable();
        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(e =>
                EF.Functions.ILike(e.UserName ?? "", like) ||
                EF.Functions.ILike(e.SourceIp ?? "", like) ||
                EF.Functions.ILike(e.Hostname, like));
        }
        var rows = await query.OrderByDescending(e => e.Timestamp)
                              .Take(Math.Clamp(take, 1, 1000))
                              .ToListAsync();
        ViewBag.Query = q;
        return View(rows);
    }

    // ── Memory events ─────────────────────────────────────────────────────

    [Route("/memory")]
    public async Task<IActionResult> Memory(int take = 100)
    {
        var rows = await _db.MemoryEvents
            .OrderByDescending(e => e.Timestamp)
            .Take(Math.Clamp(take, 1, 500))
            .ToListAsync();
        return View(rows);
    }

    // ── Response panel ────────────────────────────────────────────────────

    [Route("/response")]
public async Task<IActionResult> ResponsePage()
{
    // Endpoint agents — derived from telemetry. An agent that hasn't sent
    // any event is invisible here, which matches the previous behaviour.
    var endpointAgents = await _db.Events
        .GroupBy(e => e.AgentId)
        .Select(g => new
        {
            Kind     = "endpoint",
            Id       = g.Key.ToString(),
            Name     = (string?)g.Max(e => e.Hostname),
            LastSeen = g.Max(e => e.IngestedAt),
        })
        .ToListAsync();

    // Sensor nodes — every registered network sensor.
    var sensorNodes = await _db.SensorNodes
        .Select(n => new
        {
            Kind     = "sensor",
            Id       = n.NodeId,
            Name     = (string?)(string.IsNullOrEmpty(n.Hostname) ? n.NodeId : n.Hostname),
            LastSeen = n.LastSeen,
        })
        .ToListAsync();

    var targets = endpointAgents
        .Concat(sensorNodes)
        .OrderByDescending(t => t.LastSeen)
        .ToList();

    var recentCmds = await _db.ResponseCommands
        .OrderByDescending(c => c.IssuedAt)
        .Take(50)
        .ToListAsync();

    ViewBag.Targets    = targets;
    ViewBag.RecentCmds = recentCmds;
    return View("Response");   // explicit because method is no longer named after the view
}

    // ── Live device inventory (sensor node — agentless) ───────────────────────

    [Route("/devices")]
    public async Task<IActionResult> Devices(string? q, string? node, string? risk)
    {
        var query = _db.NetworkDevices.AsQueryable();

        if (!string.IsNullOrWhiteSpace(node))
            query = query.Where(d => d.NodeId == node);

        if (risk == "high")
            query = query.Where(d => d.RiskScore >= 50);
        else if (risk == "medium")
            query = query.Where(d => d.RiskScore >= 20 && d.RiskScore < 50);

        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(d =>
                EF.Functions.ILike(d.Mac,          like) ||
                EF.Functions.ILike(d.Ip,           like) ||
                EF.Functions.ILike(d.Hostname,     like) ||
                EF.Functions.ILike(d.Manufacturer, like) ||
                EF.Functions.ILike(d.OsFamily,     like));
        }

        var devices = await query
            .OrderByDescending(d => d.RiskScore)
            .ThenByDescending(d => d.LastSeen)
            .Take(500)
            .ToListAsync();

        var nodes = await _db.SensorNodes
            .OrderByDescending(n => n.LastSeen)
            .Take(20)
            .ToListAsync();

        ViewBag.Query   = q;
        ViewBag.Node    = node;
        ViewBag.Risk    = risk;
        ViewBag.Nodes   = nodes;
        ViewBag.HighRisk   = devices.Count(d => d.RiskScore >= 50);
        ViewBag.MediumRisk = devices.Count(d => d.RiskScore >= 20 && d.RiskScore < 50);
        return View(devices);
    }

    // ── Sensor DNS query log ──────────────────────────────────────────────────

    [Route("/sensor-dns")]
    public async Task<IActionResult> SensorDns(string? q, bool dgaOnly = false, int take = 200)
    {
        var query = _db.SensorDnsEvents.AsQueryable();

        if (dgaOnly)
            query = query.Where(d => d.DgaScore > 0.6f);

        if (!string.IsNullOrWhiteSpace(q))
        {
            var like = $"%{q}%";
            query = query.Where(d =>
                EF.Functions.ILike(d.Domain, like) ||
                EF.Functions.ILike(d.SrcIp,  like) ||
                EF.Functions.ILike(d.SrcMac, like));
        }

        var rows = await query
            .OrderByDescending(d => d.Timestamp)
            .Take(Math.Clamp(take, 1, 1000))
            .ToListAsync();

        ViewBag.Query   = q;
        ViewBag.DgaOnly = dgaOnly;
        return View(rows);
    }

    // ── Sensor alerts (beacon, scan, DGA) ─────────────────────────────────────

    [Route("/sensor-alerts")]
    public async Task<IActionResult> SensorAlerts()
    {
        var alerts = await _db.SensorAlerts
            .OrderByDescending(a => a.Timestamp)
            .Take(100)
            .ToListAsync();
        return View(alerts);
    }

}
