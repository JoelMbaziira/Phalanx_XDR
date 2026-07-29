using Microsoft.EntityFrameworkCore;
using Phalanx.Correlator;
using Phalanx.Shared.Data;
using StackExchange.Redis;

var builder = Host.CreateApplicationBuilder(args);

var redisConn = builder.Configuration.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
builder.Services.AddSingleton<IConnectionMultiplexer>(_ => ConnectionMultiplexer.Connect(redisConn));

var pg = builder.Configuration.GetConnectionString("Phalanx")
    ?? "Host=localhost;Database=phalanx_db;Username=phalanx_admin;Password=password123";
builder.Services.AddDbContext<PhalanxContext>(o => o.UseNpgsql(pg));

builder.Services.AddHostedService<Worker>();

var host = builder.Build();

using (var scope = host.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();
    db.Database.EnsureCreated();
}

await host.RunAsync();
