using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Phalanx.Correlator.Engine;
using Xunit;

namespace Phalanx.Tests.Unit;

public class RuleEngineTests
{
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    private static Rule StatelessRule(string id, string field, string value, string severity = "High") =>
        new Rule
        {
            Id = id,
            Title = id,
            Severity = severity,
            Match = new MatchBlock
            {
                Fields = new List<FieldMatch>
                {
                    new FieldMatch { FieldPath = field, Op = MatchOp.Equals, Values = new List<string> { value } }
                }
            }
        };

    // ── Stateless ─────────────────────────────────────────────────────────────

    [Fact]
    public void Stateless_MatchingEvent_ReturnsHit()
    {
        var engine = new RuleEngine(new List<Rule> { StatelessRule("R1", "process.name", "bash") },
                                    NullLogger.Instance);
        var hits = engine.Evaluate(Json("""{"process":{"name":"bash"}}"""), DateTime.UtcNow, "e1");
        hits.Should().HaveCount(1);
        hits[0].Rule.Id.Should().Be("R1");
    }

    [Fact]
    public void Stateless_NonMatchingEvent_ReturnsNoHits()
    {
        var engine = new RuleEngine(new List<Rule> { StatelessRule("R1", "process.name", "bash") },
                                    NullLogger.Instance);
        var hits = engine.Evaluate(Json("""{"process":{"name":"ls"}}"""), DateTime.UtcNow, "e1");
        hits.Should().BeEmpty();
    }

    [Fact]
    public void MultipleRules_AllMatchingRulesFire()
    {
        var rules = new List<Rule>
        {
            StatelessRule("R1", "process.name", "bash"),
            StatelessRule("R2", "event.action", "process_start"),
        };
        var engine = new RuleEngine(rules, NullLogger.Instance);
        var evt = Json("""{"process":{"name":"bash"},"event":{"action":"process_start"}}""");
        engine.Evaluate(evt, DateTime.UtcNow, "e1").Should().HaveCount(2);
    }

    [Fact]
    public void EmptyRuleList_ReturnsNoHits()
    {
        var engine = new RuleEngine(new List<Rule>(), NullLogger.Instance);
        engine.Evaluate(Json("""{"process":{"name":"bash"}}"""), DateTime.UtcNow, "e1").Should().BeEmpty();
    }

    // ── Correlate ─────────────────────────────────────────────────────────────

    private static Rule CorrelateRule(string id, string field, string value,
                                      string groupBy, int threshold, int windowSecs)
        => new Rule
        {
            Id = id, Title = id, Severity = "High",
            Match = new MatchBlock
            {
                Fields = new List<FieldMatch>
                {
                    new FieldMatch { FieldPath = field, Op = MatchOp.Equals, Values = new List<string> { value } }
                }
            },
            CorrelateGroupBy     = groupBy,
            CorrelateThreshold   = threshold,
            CorrelateWindowSeconds = windowSecs,
        };

    [Fact]
    public void Correlate_ThresholdReached_FiresOnce()
    {
        var rule = CorrelateRule("C1", "event.action", "login_failed", "user.name", 3, 60);
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);
        var now = DateTime.UtcNow;
        var evt = Json("""{"event":{"action":"login_failed"},"user":{"name":"admin"}}""");

        var hits1 = engine.Evaluate(evt, now, "e1");
        var hits2 = engine.Evaluate(evt, now, "e2");
        var hits3 = engine.Evaluate(evt, now, "e3");

        hits1.Should().BeEmpty();
        hits2.Should().BeEmpty();
        hits3.Should().HaveCount(1).And.ContainSingle(h => h.Rule.Id == "C1");
        hits3[0].ContributingEventIds.Should().HaveCount(3);
    }

    [Fact]
    public void Correlate_WindowExpired_DoesNotFire()
    {
        var rule = CorrelateRule("C1", "event.action", "login_failed", "user.name", 3, 5);
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);
        var evt = Json("""{"event":{"action":"login_failed"},"user":{"name":"admin"}}""");

        engine.Evaluate(evt, DateTime.UtcNow.AddSeconds(-100), "e1");
        engine.Evaluate(evt, DateTime.UtcNow.AddSeconds(-100), "e2");
        var hits = engine.Evaluate(evt, DateTime.UtcNow, "e3");  // old ones expire

        hits.Should().BeEmpty();
    }

    [Fact]
    public void Correlate_DifferentGroupKey_CountedSeparately()
    {
        var rule = CorrelateRule("C1", "event.action", "login_failed", "user.name", 2, 60);
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);
        var now = DateTime.UtcNow;

        var evtAdmin = Json("""{"event":{"action":"login_failed"},"user":{"name":"admin"}}""");
        var evtUser  = Json("""{"event":{"action":"login_failed"},"user":{"name":"bob"}}""");

        engine.Evaluate(evtAdmin, now, "e1").Should().BeEmpty();
        engine.Evaluate(evtUser,  now, "e2").Should().BeEmpty();  // separate group
    }

    // ── Sequence ──────────────────────────────────────────────────────────────

    private static Rule SequenceRule(string id, string groupBy, int windowSecs,
                                     params (string field, string value)[] stages)
        => new Rule
        {
            Id = id, Title = id, Severity = "Critical",
            SequenceGroupBy     = groupBy,
            SequenceWindowSeconds = windowSecs,
            SequenceStages = stages.Select((s, i) => new SequenceStage
            {
                Id = $"stage{i}",
                Match = new MatchBlock
                {
                    Fields = new List<FieldMatch>
                    {
                        new FieldMatch { FieldPath = s.field, Op = MatchOp.Equals, Values = new List<string> { s.value } }
                    }
                }
            }).ToList(),
        };

    [Fact]
    public void Sequence_StagesInOrder_Fires()
    {
        var rule = SequenceRule("S1", "host.hostname", 300,
            ("event.action", "email_client_shell"),
            ("event.action", "network_connection"));
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);
        var now = DateTime.UtcNow;

        var stage0 = Json("""{"event":{"action":"email_client_shell"},"host":{"hostname":"ws1"}}""");
        var stage1 = Json("""{"event":{"action":"network_connection"},"host":{"hostname":"ws1"}}""");

        engine.Evaluate(stage0, now, "e1").Should().BeEmpty();
        var hits = engine.Evaluate(stage1, now.AddSeconds(5), "e2");
        hits.Should().HaveCount(1);
        hits[0].ContributingEventIds.Should().Contain("e1").And.Contain("e2");
    }

    [Fact]
    public void Sequence_StagesOutOfOrder_DoesNotFire()
    {
        var rule = SequenceRule("S1", "host.hostname", 300,
            ("event.action", "email_client_shell"),
            ("event.action", "network_connection"));
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);
        var now = DateTime.UtcNow;

        var stage1 = Json("""{"event":{"action":"network_connection"},"host":{"hostname":"ws1"}}""");
        var stage0 = Json("""{"event":{"action":"email_client_shell"},"host":{"hostname":"ws1"}}""");

        engine.Evaluate(stage1, now, "e2").Should().BeEmpty();
        engine.Evaluate(stage0, now, "e1").Should().BeEmpty();  // starts new sequence but not complete
    }

    [Fact]
    public void Sequence_WindowExpired_Resets()
    {
        var rule = SequenceRule("S1", "host.hostname", 5,
            ("event.action", "email_client_shell"),
            ("event.action", "network_connection"));
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);

        var stage0 = Json("""{"event":{"action":"email_client_shell"},"host":{"hostname":"ws1"}}""");
        var stage1 = Json("""{"event":{"action":"network_connection"},"host":{"hostname":"ws1"}}""");

        engine.Evaluate(stage0, DateTime.UtcNow.AddSeconds(-100), "e1");
        var hits = engine.Evaluate(stage1, DateTime.UtcNow, "e2");
        hits.Should().BeEmpty();
    }

    // ── Hit description ───────────────────────────────────────────────────────

    [Fact]
    public void Hit_Description_ContainsProcessName()
    {
        var rule = StatelessRule("R1", "event.action", "process_start");
        var engine = new RuleEngine(new List<Rule> { rule }, NullLogger.Instance);
        var evt = Json("""{"event":{"action":"process_start"},"process":{"name":"bash"},"host":{"hostname":"box1"}}""");
        var hits = engine.Evaluate(evt, DateTime.UtcNow, "e1");
        hits[0].Description.Should().Contain("bash").And.Contain("box1");
    }
}
