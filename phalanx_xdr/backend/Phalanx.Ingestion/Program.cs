using Microsoft.EntityFrameworkCore;
using Phalanx.Shared.Data;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Redis (singleton — reuse the connection across all requests)
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(
        builder.Configuration.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379"));

// Postgres — connection string must be provided via config or environment variable.
// For local dev: dotnet user-secrets set "ConnectionStrings:Phalanx" "Host=localhost;..."
// For production: set CONNECTIONSTRINGS__PHALANX environment variable.
var pg = builder.Configuration.GetConnectionString("Phalanx")
    ?? throw new InvalidOperationException(
        "ConnectionStrings:Phalanx is not configured. " +
        "Set it via appsettings, user-secrets, or the CONNECTIONSTRINGS__PHALANX environment variable.");
builder.Services.AddDbContext<PhalanxContext>(o => o.UseNpgsql(pg));

var app = builder.Build();

// Auto-migrate on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<PhalanxContext>();
    db.Database.EnsureCreated();                       // no-op if DB already exists
    await SchemaHelper.EnsureLatestSchemaAsync(db);    // adds any tables added after initial create
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapControllers();
app.Run();
