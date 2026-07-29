using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Phalanx.Shared.Data;

namespace Phalanx.Console.Controllers;

public class RulesController : Controller
{
    private readonly PhalanxContext _db;
    public RulesController(PhalanxContext db) => _db = db;

    public async Task<IActionResult> Index()
    {
        var rules = await _db.RuleStats
            .OrderByDescending(r => r.FireCount)
            .ThenBy(r => r.RuleId)
            .ToListAsync();
        return View(rules);
    }
}
