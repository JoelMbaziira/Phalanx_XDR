using Microsoft.EntityFrameworkCore;
using Phalanx.Console.Hubs;
using Phalanx.Shared.Data;
using Phalanx.Console.Policies;
using System.Threading.Channels;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

var pg = builder.Configuration.GetConnectionString("Phalanx")
    ?? "Host=localhost;Database=phalanx_db;Username=phalanx_admin;Password=password123";
builder.Services.AddDbContext<PhalanxContext>(o => o.UseNpgsql(pg));

builder.Services.AddSignalR();
builder.Services.AddHttpClient();   // for ResponseProxyController
builder.Services.AddSingleton(Channel.CreateUnbounded<bool>());

builder.Services.AddSingleton<PolicyLoader>();
builder.Services.AddHostedService<PolicyEngine>();
builder.Services.AddHostedService<CommandWatcher>();

var app = builder.Build();

// Ensure any tables added after the initial schema are present
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();
    await SchemaHelper.EnsureLatestSchemaAsync(db);
}

if (!app.Environment.IsDevelopment())
    app.UseExceptionHandler("/Home/Error");

app.UseStaticFiles();
app.UseRouting();

app.MapControllerRoute(
    name:    "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

app.MapControllers();   // for [ApiController] routes like /api/response/issue
app.MapHub<AlertHub>("/alertHub");

app.Run();
