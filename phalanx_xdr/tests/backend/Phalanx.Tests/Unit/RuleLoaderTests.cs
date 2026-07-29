using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Phalanx.Correlator.Engine;
using Xunit;

namespace Phalanx.Tests.Unit;

public class RuleLoaderTests : IDisposable
{
    private readonly string _rulesDir = Path.Combine(Path.GetTempPath(), $"phx-rules-{Guid.NewGuid():N}");
    private readonly RuleLoader _loader;

    public RuleLoaderTests()
    {
        Directory.CreateDirectory(_rulesDir);
        _loader = new RuleLoader(NullLogger.Instance);
    }

    public void Dispose() => Directory.Delete(_rulesDir, recursive: true);

    private void WriteRule(string filename, string yaml) =>
        File.WriteAllText(Path.Combine(_rulesDir, filename), yaml);

    // ── Basic native parsing ───────────────────────────────────────────────────

    [Fact]
    public void LoadStatelessRule_ParsesAllFields()
    {
        WriteRule("test.yml", """
            id: PHX-TEST-001
            title: Test Rule
            description: A test rule
            severity: High
            mitre:
              tactic: execution
              technique: T1059
            match:
              process.name: bash
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules.Should().HaveCount(1);

        var r = rules[0];
        r.Id.Should().Be("PHX-TEST-001");
        r.Title.Should().Be("Test Rule");
        r.Severity.Should().Be("High");
        r.MitreTactic.Should().Be("execution");
        r.MitreTechnique.Should().Be("T1059");
        r.IsStateless.Should().BeTrue();
        r.Match.Should().NotBeNull();
        r.Match!.Fields.Should().HaveCount(1);
        r.Match.Fields[0].FieldPath.Should().Be("process.name");
    }

    [Fact]
    public void LoadCorrelateRule_ParsesCorrelateBlock()
    {
        WriteRule("corr.yml", """
            id: PHX-CORR-001
            title: Brute Force
            severity: High
            match:
              event.action: login_failed
            correlate:
              group_by: user.name
              window_seconds: 300
              threshold: 5
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules.Should().HaveCount(1);

        var r = rules[0];
        r.IsCorrelate.Should().BeTrue();
        r.CorrelateGroupBy.Should().Be("user.name");
        r.CorrelateWindowSeconds.Should().Be(300);
        r.CorrelateThreshold.Should().Be(5);
    }

    [Fact]
    public void LoadSequenceRule_ParsesStages()
    {
        WriteRule("seq.yml", """
            id: PHX-SEQ-001
            title: Phishing Sequence
            severity: Critical
            sequence:
              group_by: host.hostname
              window_seconds: 300
              stages:
                - id: email_shell
                  match:
                    event.action: email_client_shell
                - id: net_conn
                  match:
                    event.action: network_connection
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules.Should().HaveCount(1);

        var r = rules[0];
        r.IsSequence.Should().BeTrue();
        r.SequenceGroupBy.Should().Be("host.hostname");
        r.SequenceStages.Should().HaveCount(2);
        r.SequenceStages[0].Id.Should().Be("email_shell");
        r.SequenceStages[1].Match.Fields[0].FieldPath.Should().Be("event.action");
    }

    [Fact]
    public void RuleWithNoId_IsSkipped()
    {
        WriteRule("bad.yml", """
            title: No ID Rule
            severity: Medium
            match:
              process.name: bash
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules.Should().BeEmpty();
    }

    [Fact]
    public void MultipleRulesInOneFile_AllLoaded()
    {
        WriteRule("multi.yml", """
            id: R001
            title: Rule One
            severity: High
            match:
              process.name: bash
            ---
            id: R002
            title: Rule Two
            severity: Medium
            match:
              process.name: sh
            """);

        _loader.LoadFromDirectory(_rulesDir).Should().HaveCount(2);
    }

    [Fact]
    public void NonExistentDirectory_ReturnsEmptyList()
    {
        _loader.LoadFromDirectory("/tmp/this/does/not/exist").Should().BeEmpty();
    }

    [Fact]
    public void SeverityNormalization_CaseInsensitive()
    {
        WriteRule("sev.yml", """
            id: R-SEV
            title: Sev Test
            severity: CRITICAL
            match:
              process.name: bash
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules[0].Severity.Should().Be("Critical");
    }

    [Fact]
    public void NegatedFieldMatch_ParsedCorrectly()
    {
        WriteRule("negate.yml", """
            id: R-NEG
            title: Not Bash
            severity: Low
            match:
              "process.name|not": bash
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules.Should().HaveCount(1);
        rules[0].Match!.Fields[0].Negate.Should().BeTrue();
    }

    [Fact]
    public void ContainsOperator_ParsedCorrectly()
    {
        WriteRule("contains.yml", """
            id: R-CTN
            title: Contains Test
            severity: Medium
            match:
              "process.command_line|contains": /tmp/
            """);

        var rules = _loader.LoadFromDirectory(_rulesDir);
        rules[0].Match!.Fields[0].Op.Should().Be(MatchOp.Contains);
    }
}
