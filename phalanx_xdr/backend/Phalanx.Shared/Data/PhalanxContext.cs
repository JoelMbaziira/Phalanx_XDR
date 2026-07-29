using Microsoft.EntityFrameworkCore;

namespace Phalanx.Shared.Data;

// ── Core event (process start — unchanged) ────────────────────────────────

public class TelemetryEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }
    public long Sequence { get; set; }

    public string Action { get; set; } = "";
    public string Category { get; set; } = "";
    public string Dataset { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? ProcessEntityId { get; set; }
    public int? ProcessPid { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessExecutable { get; set; }
    public string? ProcessCommandLine { get; set; }
    public string? ProcessHashSha256 { get; set; }
    public string? ParentEntityId { get; set; }
    public string? ParentName { get; set; }
    public string? ParentCommandLine { get; set; }
    public string? UserName { get; set; }
    public string? UserId { get; set; }

    public string RawJson { get; set; } = "";
}

// ── File event ────────────────────────────────────────────────────────────

public class FileEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }

    public string Action { get; set; } = "";   // file_open | file_modified | file_create_exec
    public string Dataset { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? FilePath { get; set; }
    public string? FileName { get; set; }
    public string? FileDirectory { get; set; }
    public long? FileSize { get; set; }
    public string? FileMode { get; set; }
    public string? FileHashSha256 { get; set; }

    public int? ProcessPid { get; set; }
    public string? ProcessName { get; set; }

    public string RawJson { get; set; } = "";
}

// ── Network event ─────────────────────────────────────────────────────────

public class NetworkEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }

    public string Action { get; set; } = "";   // network_connection
    public string Dataset { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? Transport { get; set; }
    public string? Direction { get; set; }
    public string? NetworkType { get; set; }

    public string? SourceIp { get; set; }
    public int? SourcePort { get; set; }
    public string? DestinationIp { get; set; }
    public int? DestinationPort { get; set; }
    public string? DestinationDomain { get; set; }
    public string? ConnectionStatus { get; set; }

    public int? ProcessPid { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessExecutable { get; set; }

    public string RawJson { get; set; } = "";
}

// ── DNS event ─────────────────────────────────────────────────────────────

public class DnsEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }

    public string Action { get; set; } = "";   // dns_query
    public string Dataset { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? QueryName { get; set; }
    public string? QueryType { get; set; }
    public string? ResolvedIp { get; set; }
    public string? SourceIp { get; set; }

    public int? ProcessPid { get; set; }
    public string? ProcessName { get; set; }

    public string RawJson { get; set; } = "";
}

// ── Login event ───────────────────────────────────────────────────────────

public class LoginEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }

    public string Action { get; set; } = "";   // login | login_failed | ssh_login | privilege_escalation
    public string Dataset { get; set; } = "";
    public string Outcome { get; set; } = "";  // success | failure

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? UserName { get; set; }
    public string? SourceIp { get; set; }
    public string? Terminal { get; set; }
    public string? AuthMethod { get; set; }
    public string? CommandLine { get; set; }   // for privilege_escalation

    public string RawJson { get; set; } = "";
}

// ── Memory event ──────────────────────────────────────────────────────────

public class MemoryEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }

    public string Action { get; set; } = "";   // memory_anonymous_rwx_region | memory_executable_heap | etc.
    public string Dataset { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? MemoryIndicator { get; set; }
    public string? MemoryAddress { get; set; }

    public int? ProcessPid { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessExecutable { get; set; }

    public string RawJson { get; set; } = "";
}

// ── Email / Phishing event ────────────────────────────────────────────────────

public class EmailEvent
{
    public long Id { get; set; }
    public Guid EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public DateTime IngestedAt { get; set; }

    public string Action { get; set; } = "";   // email_client_shell | suspicious_attachment | smtp_anomaly | email_received
    public string Dataset { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";

    public string? Sender { get; set; }
    public string? Recipient { get; set; }
    public string? Subject { get; set; }
    public string? AttachmentName { get; set; }
    public string? AttachmentHash { get; set; }
    public string? ClientProcess { get; set; }
    public string? ChildProcess { get; set; }
    public string? IndicatorType { get; set; }   // phishing | malware_attachment | smtp_anomaly | credential_harvesting
    public string? Detail { get; set; }

    public string RawJson { get; set; } = "";
}

// ── Alert (extended) ──────────────────────────────────────────────────────

public class Alert
{
    public long Id { get; set; }
    public DateTime DetectedAt { get; set; }
    public string Severity { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string RuleName { get; set; } = "";
    public string Description { get; set; } = "";
    public string MitreTactic { get; set; } = "";
    public string MitreTechnique { get; set; } = "";

    public Guid AgentId { get; set; }
    public string Hostname { get; set; } = "";
    public string? ProcessEntityId { get; set; }
    public string? ProcessName { get; set; }
    public string? CommandLine { get; set; }
    public string? UserName { get; set; }

    public string Status { get; set; } = "new";       // new | acknowledged | closed
    public string? AssignedTo { get; set; }
    public string? Notes { get; set; }

    public string SourceEventIds { get; set; } = "";
    public string TriggeringEventJson { get; set; } = "";
}

// ── Response command + ack ─────────────────────────────────────────────────

public class ResponseCommand
{
    public long Id { get; set; }
    public string CommandId { get; set; } = "";
    public DateTime IssuedAt { get; set; }
    public Guid AgentId { get; set; }
    public string Action { get; set; } = "";   // kill_process | quarantine_file | isolate_host | collect_file | run_command
    public string ParamsJson { get; set; } = "";
    public string IssuedBy { get; set; } = "";
    public string Status { get; set; } = "pending";   // pending | delivered | acked | failed
    public DateTime? AckedAt { get; set; }
    public string? ResultJson { get; set; }
}

public class PolicyDispatch
{
    public long      Id            { get; set; }
    public DateTime  DispatchedAt  { get; set; }
    public string    PolicyId      { get; set; } = "";
    public string    PolicyTitle   { get; set; } = "";
    public long      AlertId       { get; set; }
    public string    RuleId        { get; set; } = "";
    public string    Action        { get; set; } = "";
    public string    ParamsJson    { get; set; } = "{}";
    public Guid?     AgentId       { get; set; }
    public string?   Hostname      { get; set; }
    public string?   CommandId     { get; set; }       // null if dry-run or skipped
    public string    Outcome       { get; set; } = ""; // dispatched | dry_run | rate_limited | skipped_killswitch | error
    public string?   ErrorMessage  { get; set; }
}

public class PolicySetting
{
    public string    Key        { get; set; } = "";
    public string    Value      { get; set; } = "";
    public DateTime  UpdatedAt  { get; set; }
}

// ── Rule statistics (unchanged) ────────────────────────────────────────────

public class RuleStat
{
    public string RuleId { get; set; } = "";
    public string RuleName { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Source { get; set; } = "";
    public long FireCount { get; set; }
    public DateTime? LastFiredAt { get; set; }
    public DateTime LoadedAt { get; set; }
}

// ── DbContext ─────────────────────────────────────────────────────────────

public class PhalanxContext : DbContext
{
    public DbSet<TelemetryEvent> Events   => Set<TelemetryEvent>();
    public DbSet<FileEvent>      FileEvents   => Set<FileEvent>();
    public DbSet<NetworkEvent>   NetworkEvents => Set<NetworkEvent>();
    public DbSet<DnsEvent>       DnsEvents    => Set<DnsEvent>();
    public DbSet<LoginEvent>     LoginEvents  => Set<LoginEvent>();
    public DbSet<MemoryEvent>    MemoryEvents => Set<MemoryEvent>();
    public DbSet<Alert>          Alerts       => Set<Alert>();
    public DbSet<RuleStat>       RuleStats    => Set<RuleStat>();
    public DbSet<ResponseCommand> ResponseCommands => Set<ResponseCommand>();
    public DbSet<SensorNode>      SensorNodes      => Set<SensorNode>();
    public DbSet<NetworkDevice>   NetworkDevices   => Set<NetworkDevice>();
    public DbSet<SensorDnsEvent>  SensorDnsEvents  => Set<SensorDnsEvent>();
    public DbSet<SensorFlowEvent> SensorFlowEvents => Set<SensorFlowEvent>();
    public DbSet<SensorAlert>     SensorAlerts     => Set<SensorAlert>();
    public DbSet<EmailEvent>       EmailEvents      => Set<EmailEvent>();
    public DbSet<PolicyDispatch>  PolicyDispatches => Set<PolicyDispatch>();
    public DbSet<PolicySetting>   PolicySettings   => Set<PolicySetting>();

    public PhalanxContext(DbContextOptions<PhalanxContext> opts) : base(opts) { }

    protected override void OnModelCreating(ModelBuilder mb)
    {
        // Process events
        var ev = mb.Entity<TelemetryEvent>();
        ev.HasIndex(e => e.Timestamp);
        ev.HasIndex(e => e.AgentId);
        ev.HasIndex(e => e.ProcessEntityId);
        ev.HasIndex(e => e.ProcessHashSha256);
        ev.HasIndex(e => new { e.AgentId, e.Action, e.Timestamp });
        ev.Property(e => e.RawJson).HasColumnType("jsonb");

        // File events
        var fe = mb.Entity<FileEvent>();
        fe.HasIndex(f => f.Timestamp);
        fe.HasIndex(f => f.AgentId);
        fe.HasIndex(f => f.FilePath);
        fe.HasIndex(f => f.FileHashSha256);
        fe.Property(f => f.RawJson).HasColumnType("jsonb");

        // Network events
        var ne = mb.Entity<NetworkEvent>();
        ne.HasIndex(n => n.Timestamp);
        ne.HasIndex(n => n.AgentId);
        ne.HasIndex(n => n.DestinationIp);
        ne.HasIndex(n => n.DestinationPort);
        ne.Property(n => n.RawJson).HasColumnType("jsonb");

        // DNS events
        var de = mb.Entity<DnsEvent>();
        de.HasIndex(d => d.Timestamp);
        de.HasIndex(d => d.AgentId);
        de.HasIndex(d => d.QueryName);
        de.Property(d => d.RawJson).HasColumnType("jsonb");

        // Login events
        var le = mb.Entity<LoginEvent>();
        le.HasIndex(l => l.Timestamp);
        le.HasIndex(l => l.AgentId);
        le.HasIndex(l => l.UserName);
        le.HasIndex(l => l.Action);
        le.Property(l => l.RawJson).HasColumnType("jsonb");

        // Memory events
        var me = mb.Entity<MemoryEvent>();
        me.HasIndex(m => m.Timestamp);
        me.HasIndex(m => m.AgentId);
        me.HasIndex(m => m.ProcessPid);
        me.Property(m => m.RawJson).HasColumnType("jsonb");

        // Alerts
        var al = mb.Entity<Alert>();
        al.HasIndex(a => a.DetectedAt);
        al.HasIndex(a => a.AgentId);
        al.HasIndex(a => a.Status);
        al.HasIndex(a => a.Severity);
        al.HasIndex(a => a.RuleId);
        al.Property(a => a.TriggeringEventJson).HasColumnType("jsonb");

        // Response commands
        var rc = mb.Entity<ResponseCommand>();
        rc.HasIndex(r => r.AgentId);
        rc.HasIndex(r => r.Status);
        rc.HasIndex(r => r.IssuedAt);
        rc.Property(r => r.ParamsJson).HasColumnType("jsonb");
        rc.Property(r => r.ResultJson).HasColumnType("jsonb");

        // Rule stats
        var rs = mb.Entity<RuleStat>();
        rs.HasKey(r => r.RuleId);
        rs.HasIndex(r => r.LastFiredAt);

        // Sensor nodes
        var sn = mb.Entity<SensorNode>();
        sn.HasIndex(s => s.NodeId).IsUnique();
        sn.HasIndex(s => s.OrgId);

        // Network devices (agentless)
        var nd = mb.Entity<NetworkDevice>();
        nd.HasIndex(n => n.Mac);
        nd.HasIndex(n => n.Ip);
        nd.HasIndex(n => n.NodeId);
        nd.HasIndex(n => n.OrgId);
        nd.HasIndex(n => n.LastSeen);
        nd.HasIndex(n => n.RiskScore);

        // Sensor DNS events
        var sd = mb.Entity<SensorDnsEvent>();
        sd.HasIndex(s => s.Timestamp);
        sd.HasIndex(s => s.NodeId);
        sd.HasIndex(s => s.Domain);
        sd.HasIndex(s => s.SrcMac);
        sd.HasIndex(s => s.DgaScore);
        sd.Property(s => s.RawJson).HasColumnType("jsonb");

        // Sensor flow events
        var sf = mb.Entity<SensorFlowEvent>();
        sf.HasIndex(s => s.Timestamp);
        sf.HasIndex(s => s.NodeId);
        sf.HasIndex(s => s.SrcIp);
        sf.HasIndex(s => s.DstIp);
        sf.Property(s => s.RawJson).HasColumnType("jsonb");

        // Sensor alerts (beacon, scan, dga)
        var sa = mb.Entity<SensorAlert>();
        sa.HasIndex(s => s.Timestamp);
        sa.HasIndex(s => s.NodeId);
        sa.HasIndex(s => s.AlertType);
        sa.HasIndex(s => s.SrcMac);
        sa.Property(s => s.RawJson).HasColumnType("jsonb");

        // Email / Phishing events
        var ee = mb.Entity<EmailEvent>();
        ee.HasIndex(e => e.Timestamp);
        ee.HasIndex(e => e.AgentId);
        ee.HasIndex(e => e.Action);
        ee.HasIndex(e => e.Sender);
        ee.Property(e => e.RawJson).HasColumnType("jsonb");

        mb.Entity<PolicyDispatch>(e =>
    {
        e.HasIndex(p => p.DispatchedAt).IsDescending();
        e.HasIndex(p => new { p.PolicyId, p.DispatchedAt });
        e.HasIndex(p => p.Outcome);
    });

    mb.Entity<PolicySetting>(e =>
    {
        e.HasKey(p => p.Key);
    });
    }
}

// ── Sensor node registry ──────────────────────────────────────────────────

public class SensorNode
{
    public long   Id          { get; set; }
    public string NodeId      { get; set; } = "";   // UUID from sensor
    public string Hostname    { get; set; } = "";
    public string Interface   { get; set; } = "";
    public string OrgId       { get; set; } = "default";
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen  { get; set; }
    public string Version     { get; set; } = "";
    public string Status      { get; set; } = "active";  // active | stale | offline
    public int    DeviceCount { get; set; }
    public long   EventsTotal { get; set; }
}

// ── Network device (from sensor node — agentless) ─────────────────────────

public class NetworkDevice
{
    public long   Id           { get; set; }
    public string DeviceId     { get; set; } = "";   // UUID from sensor
    public string NodeId       { get; set; } = "";   // which sensor saw it
    public string OrgId        { get; set; } = "default";

    public string Mac          { get; set; } = "";
    public string Ip           { get; set; } = "";
    public string Hostname     { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string DeviceType   { get; set; } = "";
    public string OsFamily     { get; set; } = "";
    public string OsVersion    { get; set; } = "";
    public float  OsConfidence { get; set; }
    public string ApBssid      { get; set; } = "";

    public DateTime FirstSeen  { get; set; }
    public DateTime LastSeen   { get; set; }

    public long  BytesIn       { get; set; }
    public long  BytesOut      { get; set; }
    public int   DnsCount      { get; set; }
    public int   ConnCount     { get; set; }

    public float  RiskScore    { get; set; }
    public string RiskReasons  { get; set; } = "";  // JSON array
}

// ── Sensor DNS event ──────────────────────────────────────────────────────

public class SensorDnsEvent
{
    public long     Id          { get; set; }
    public Guid     EventId     { get; set; }
    public DateTime Timestamp   { get; set; }
    public DateTime IngestedAt  { get; set; }

    public string NodeId        { get; set; } = "";
    public string OrgId         { get; set; } = "default";
    public string SrcMac        { get; set; } = "";
    public string SrcIp         { get; set; } = "";
    public string Domain        { get; set; } = "";
    public string QueryType     { get; set; } = "";
    public float  DgaScore      { get; set; }
    public bool   IsTunnel      { get; set; }
    public string Answers       { get; set; } = "";   // JSON
    public string RawJson       { get; set; } = "";
}

// ── Sensor flow event ─────────────────────────────────────────────────────

public class SensorFlowEvent
{
    public long     Id          { get; set; }
    public Guid     EventId     { get; set; }
    public DateTime Timestamp   { get; set; }
    public DateTime IngestedAt  { get; set; }

    public string NodeId        { get; set; } = "";
    public string OrgId         { get; set; } = "default";
    public string SrcIp         { get; set; } = "";
    public string SrcMac        { get; set; } = "";
    public int    SrcPort       { get; set; }
    public string DstIp         { get; set; } = "";
    public int    DstPort       { get; set; }
    public string Transport     { get; set; } = "";
    public string Action        { get; set; } = "";   // start | end
    public long   BytesOut      { get; set; }
    public long   BytesIn       { get; set; }
    public int    Packets       { get; set; }
    public string RawJson       { get; set; } = "";
}

// ── Sensor alert (beacon, scan) ───────────────────────────────────────────

public class SensorAlert
{
    public long     Id          { get; set; }
    public Guid     EventId     { get; set; }
    public DateTime Timestamp   { get; set; }
    public DateTime IngestedAt  { get; set; }

    public string NodeId        { get; set; } = "";
    public string OrgId         { get; set; } = "default";
    public string AlertType     { get; set; } = "";   // beacon | port_scan | host_sweep | dga | tunnel
    public string SrcIp         { get; set; } = "";
    public string SrcMac        { get; set; } = "";
    public string DstIp         { get; set; } = "";
    public int    DstPort       { get; set; }
    public float  Confidence    { get; set; }
    public string Detail        { get; set; } = "";
    public string RawJson       { get; set; } = "";
}
