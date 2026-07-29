using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Console.Policies;
using Phalanx.Shared.Data;

namespace Phalanx.Console.Controllers;

[Route("policies")]
public class PoliciesController : Controller
{
    private readonly PhalanxContext _db;
    private readonly PolicyLoader   _loader;

    public PoliciesController(PhalanxContext db, PolicyLoader loader)
    {
        _db     = db;
        _loader = loader;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index()
    {
        var policies   = _loader.All.OrderBy(p => p.Id).ToList();
        var dispatches = await _db.PolicyDispatches
            .AsNoTracking()
            .OrderByDescending(d => d.DispatchedAt)
            .Take(100)
            .ToListAsync();

        var killSwitch = await _db.PolicySettings
            .Where(s => s.Key == "kill_switch")
            .Select(s => s.Value)
            .FirstOrDefaultAsync() ?? "off";

        // Per-policy fire/dry/error counters for the last 24h
        var since = DateTime.UtcNow.AddHours(-24);
        var counts = await _db.PolicyDispatches
            .Where(d => d.DispatchedAt > since)
            .GroupBy(d => new { d.PolicyId, d.Outcome })
            .Select(g => new { g.Key.PolicyId, g.Key.Outcome, N = g.Count() })
            .ToListAsync();

        ViewBag.Policies   = policies;
        ViewBag.Dispatches = dispatches;
        ViewBag.KillSwitch = killSwitch;
        ViewBag.Counts     = counts.GroupBy(c => c.PolicyId)
                                    .ToDictionary(g => g.Key,
                                                  g => g.ToDictionary(x => x.Outcome, x => x.N));
        return View();
    }

    /// <summary>Flip the kill switch on or off. Posted from the UI.</summary>
    [HttpPost("kill-switch")]
    public async Task<IActionResult> ToggleKillSwitch([FromForm] string state)
    {
        var v = (state ?? "").ToLowerInvariant() == "on" ? "on" : "off";
        var row = await _db.PolicySettings.FirstOrDefaultAsync(s => s.Key == "kill_switch");
        if (row == null)
            _db.PolicySettings.Add(new PolicySetting
                { Key = "kill_switch", Value = v, UpdatedAt = DateTime.UtcNow });
        else
        {
            row.Value = v;
            row.UpdatedAt = DateTime.UtcNow;
        }
        await _db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    /// <summary>Force the engine to re-read policy files from disk.</summary>
    [HttpPost("reload")]
    public IActionResult Reload()
    {
        var n = _loader.ReloadFromDisk();
        TempData["msg"] = $"Reloaded {n} policies from disk.";
        return RedirectToAction(nameof(Index));
    }
}
