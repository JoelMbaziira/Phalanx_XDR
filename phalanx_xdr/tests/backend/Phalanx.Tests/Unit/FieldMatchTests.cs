using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using Phalanx.Correlator.Engine;
using Xunit;

namespace Phalanx.Tests.Unit;

public class FieldMatchTests
{
    // ── helpers ──────────────────────────────────────────────────────────────

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private static FieldMatch Match(string field, MatchOp op, bool negate, params string[] values)
    {
        Regex? re = null;
        if (op == MatchOp.Regex && values.Length > 0)
            re = new Regex(string.Join("|", values), RegexOptions.Compiled);

        return new FieldMatch
        {
            FieldPath = field,
            Op = op,
            Negate = negate,
            Values = values.ToList(),
            CompiledRegex = re,
        };
    }

    // ── Equals ───────────────────────────────────────────────────────────────

    [Fact]
    public void Equals_MatchingValue_ReturnsTrue()
    {
        var evt = Json("""{"process":{"name":"bash"}}""");
        Match("process.name", MatchOp.Equals, false, "bash").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void Equals_CaseInsensitive()
    {
        var evt = Json("""{"process":{"name":"BASH"}}""");
        Match("process.name", MatchOp.Equals, false, "bash").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void Equals_NonMatchingValue_ReturnsFalse()
    {
        var evt = Json("""{"process":{"name":"python3"}}""");
        Match("process.name", MatchOp.Equals, false, "bash").Evaluate(evt).Should().BeFalse();
    }

    [Fact]
    public void Equals_MultipleValues_MatchesAny()
    {
        var evt = Json("""{"process":{"name":"sh"}}""");
        Match("process.name", MatchOp.Equals, false, "bash", "sh", "zsh").Evaluate(evt).Should().BeTrue();
    }

    // ── Contains ─────────────────────────────────────────────────────────────

    [Fact]
    public void Contains_SubstringPresent_ReturnsTrue()
    {
        var evt = Json("""{"process":{"command_line":"/tmp/evil.sh"}}""");
        Match("process.command_line", MatchOp.Contains, false, "/tmp/").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void Contains_SubstringAbsent_ReturnsFalse()
    {
        var evt = Json("""{"process":{"command_line":"/usr/bin/ls"}}""");
        Match("process.command_line", MatchOp.Contains, false, "/tmp/").Evaluate(evt).Should().BeFalse();
    }

    // ── StartsWith / EndsWith ─────────────────────────────────────────────────

    [Fact]
    public void StartsWith_Match()
    {
        var evt = Json("""{"file":{"path":"/etc/passwd"}}""");
        Match("file.path", MatchOp.StartsWith, false, "/etc/").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void EndsWith_Match()
    {
        var evt = Json("""{"file":{"name":"evil.exe"}}""");
        Match("file.name", MatchOp.EndsWith, false, ".exe").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void EndsWith_NoMatch_ReturnsFalse()
    {
        var evt = Json("""{"file":{"name":"safe.txt"}}""");
        Match("file.name", MatchOp.EndsWith, false, ".exe").Evaluate(evt).Should().BeFalse();
    }

    // ── Regex ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Regex_Matching_ReturnsTrue()
    {
        var evt = Json("""{"process":{"name":"python3"}}""");
        Match("process.name", MatchOp.Regex, false, @"python\d?").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void Regex_NotMatching_ReturnsFalse()
    {
        var evt = Json("""{"process":{"name":"ls"}}""");
        Match("process.name", MatchOp.Regex, false, @"python\d?").Evaluate(evt).Should().BeFalse();
    }

    // ── Gt / Lt ───────────────────────────────────────────────────────────────

    [Fact]
    public void Gt_AboveThreshold_ReturnsTrue()
    {
        var evt = Json("""{"event":{"risk_score":"95"}}""");
        Match("event.risk_score", MatchOp.Gt, false, "80").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void Gt_BelowThreshold_ReturnsFalse()
    {
        var evt = Json("""{"event":{"risk_score":"10"}}""");
        Match("event.risk_score", MatchOp.Gt, false, "80").Evaluate(evt).Should().BeFalse();
    }

    [Fact]
    public void Lt_BelowThreshold_ReturnsTrue()
    {
        var evt = Json("""{"source":{"port":"1024"}}""");
        Match("source.port", MatchOp.Lt, false, "1025").Evaluate(evt).Should().BeTrue();
    }

    // ── Negate ────────────────────────────────────────────────────────────────

    [Fact]
    public void Negate_MatchingValue_ReturnsFalse()
    {
        var evt = Json("""{"process":{"name":"bash"}}""");
        Match("process.name", MatchOp.Equals, negate: true, "bash").Evaluate(evt).Should().BeFalse();
    }

    [Fact]
    public void Negate_NonMatchingValue_ReturnsTrue()
    {
        var evt = Json("""{"process":{"name":"sshd"}}""");
        Match("process.name", MatchOp.Equals, negate: true, "bash", "sh").Evaluate(evt).Should().BeTrue();
    }

    // ── Missing field ─────────────────────────────────────────────────────────

    [Fact]
    public void MissingField_NormalMatch_ReturnsFalse()
    {
        var evt = Json("""{"process":{}}""");
        Match("process.name", MatchOp.Equals, false, "bash").Evaluate(evt).Should().BeFalse();
    }

    [Fact]
    public void MissingField_NegatedMatch_ReturnsTrue()
    {
        // Negating a missing field: "field|not|equals" — should return true when field absent
        var evt = Json("""{"process":{}}""");
        Match("process.name", MatchOp.Equals, negate: true, "bash").Evaluate(evt).Should().BeTrue();
    }

    [Fact]
    public void MissingNestedField_ReturnsFalse()
    {
        var evt = Json("""{"event":{"action":"start"}}""");
        Match("process.parent.name", MatchOp.Equals, false, "bash").Evaluate(evt).Should().BeFalse();
    }

    // ── Number field ──────────────────────────────────────────────────────────

    [Fact]
    public void NumericField_EqualsAsString()
    {
        var evt = Json("""{"process":{"pid":1234}}""");
        Match("process.pid", MatchOp.Equals, false, "1234").Evaluate(evt).Should().BeTrue();
    }

    // ── Boolean field ─────────────────────────────────────────────────────────

    [Fact]
    public void BooleanField_TrueMatches()
    {
        var evt = Json("""{"process":{"elevated":true}}""");
        Match("process.elevated", MatchOp.Equals, false, "true").Evaluate(evt).Should().BeTrue();
    }

    // ── ResolveField ─────────────────────────────────────────────────────────

    [Fact]
    public void ResolveField_Array_ReturnsFirstElement()
    {
        var evt = Json("""{"event":{"category":["process","network"]}}""");
        var result = FieldMatch.ResolveField(evt, "event.category");
        result.Should().Be("process");
    }

    [Fact]
    public void ResolveField_MissingKey_ReturnsNull()
    {
        var evt = Json("""{"event":{}}""");
        FieldMatch.ResolveField(evt, "event.nonexistent").Should().BeNull();
    }
}
