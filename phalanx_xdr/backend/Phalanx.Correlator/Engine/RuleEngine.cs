using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Phalanx.Correlator.Engine;

// What the engine returns when a rule fires.
public sealed class RuleHit
{
    public required Rule Rule { get; init; }
    public required string Description { get; init; }
    public List<string> ContributingEventIds { get; init; } = new();  // event.id values
}

public sealed class RuleEngine
{
    private readonly List<Rule> _rules;
    private readonly ILogger _logger;

    // Per-(rule, group_key) sliding window of recent events.
    // Concurrent because the worker is single-threaded today but may not be tomorrow.
    private readonly ConcurrentDictionary<string, List<EventRecord>> _correlateState = new();

    // Per-(rule, group_key) progress through a sequence — index of last matched stage.
    private readonly ConcurrentDictionary<string, SequenceState> _sequenceState = new();

    private record EventRecord(DateTime At, string EventId);
    private record SequenceState(int LastMatchedStage, DateTime FirstMatchAt, List<string> EventIds);

    public RuleEngine(List<Rule> rules, ILogger logger)
    {
        _rules = rules ?? new List<Rule>();
        _logger = logger;

        foreach (var rule in _rules)
            ValidateRule(rule);
    }

    public IReadOnlyList<Rule> Rules => _rules;

    public List<RuleHit> Evaluate(JsonElement root, DateTime eventTime, string eventId)
    {
        var hits = new List<RuleHit>();
        foreach (var rule in _rules)
        {
            if (rule is null) continue;

            try
            {
                if (rule.IsStateless)
                {
                    if (rule.Match is null) continue;
                    if (rule.Match.Evaluate(root))
                        hits.Add(BuildHit(rule, root, new[] { eventId }));
                }
                else if (rule.IsCorrelate)
                {
                    var hit = EvaluateCorrelate(rule, root, eventTime, eventId);
                    if (hit is not null) hits.Add(hit);
                }
                else if (rule.IsSequence)
                {
                    var hit = EvaluateSequence(rule, root, eventTime, eventId);
                    if (hit is not null) hits.Add(hit);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Rule {Id} threw: {Msg}", rule.Id, ex.Message);
            }
        }
        return hits;
    }

    private void ValidateRule(Rule rule)
    {
        if (rule is null)
        {
            _logger.LogWarning("Ignoring null rule");
            return;
        }

        if (string.IsNullOrWhiteSpace(rule.Id))
        {
            _logger.LogWarning("Ignoring rule with empty Id");
            return;
        }

        if (rule.IsCorrelate)
        {
            if (string.IsNullOrWhiteSpace(rule.CorrelateGroupBy))
                _logger.LogWarning("Correlate rule {RuleId} has no valid group_by and will never fire", rule.Id);
            if (rule.CorrelateThreshold <= 0)
                _logger.LogWarning("Correlate rule {RuleId} has invalid threshold {Threshold}", rule.Id, rule.CorrelateThreshold);
            if (rule.CorrelateWindowSeconds <= 0)
                _logger.LogWarning("Correlate rule {RuleId} has invalid window {WindowSeconds}s", rule.Id, rule.CorrelateWindowSeconds);
            if (rule.Match is null)
                _logger.LogWarning("Correlate rule {RuleId} has no match block and will never fire", rule.Id);
        }

        if (rule.IsSequence)
        {
            if (string.IsNullOrWhiteSpace(rule.SequenceGroupBy))
                _logger.LogWarning("Sequence rule {RuleId} has no valid group_by and will never fire", rule.Id);
            if (rule.SequenceWindowSeconds <= 0)
                _logger.LogWarning("Sequence rule {RuleId} has invalid window {WindowSeconds}s", rule.Id, rule.SequenceWindowSeconds);
            if (rule.SequenceStages.Count == 0)
                _logger.LogWarning("Sequence rule {RuleId} has no stages and will never fire", rule.Id);

            for (var i = 0; i < rule.SequenceStages.Count; i++)
            {
                var stage = rule.SequenceStages[i];
                if (stage is null)
                {
                    _logger.LogWarning("Sequence rule {RuleId} has a null stage at index {Index}", rule.Id, i);
                    continue;
                }
                if (stage.Match.Fields.Count == 0)
                {
                    _logger.LogWarning("Sequence rule {RuleId} stage {Index} has an empty match block and will match every event", rule.Id, i);
                }
            }
        }

        if (rule.IsStateless && rule.Match is null)
            _logger.LogWarning("Stateless rule {RuleId} has no match block and will never fire", rule.Id);

        if (rule.Match is not null && rule.Match.Fields.Count == 0)
            _logger.LogWarning("Rule {RuleId} has an empty match block and will match every event", rule.Id);
    }

    private RuleHit BuildHit(Rule rule, JsonElement root, IEnumerable<string> contributingIds)
    {
        // Build a description that fills in {process.name} placeholders if present
        var desc = rule.Description;
        // Always include the actual process name and host in the rendered description
        var procName = FieldMatch.ResolveField(root, "process.name") ?? "";
        var host     = FieldMatch.ResolveField(root, "host.hostname") ?? "";
        var user     = FieldMatch.ResolveField(root, "user.name") ?? "";
        var rendered = string.IsNullOrWhiteSpace(desc)
            ? $"{rule.Title} [proc={procName} host={host} user={user}]"
            : $"{desc} [proc={procName} host={host} user={user}]";
        return new RuleHit
        {
            Rule = rule,
            Description = rendered,
            ContributingEventIds = contributingIds.ToList(),
        };
    }

    // ── Correlate: N events matching `match` within window for the same group ──
    private RuleHit? EvaluateCorrelate(Rule rule, JsonElement root, DateTime now, string eventId)
    {
        if (rule.Match is null || !rule.Match.Evaluate(root)) return null;
        if (rule.CorrelateThreshold <= 0)
        {
            _logger.LogWarning("Correlate rule {RuleId} skipped because threshold is invalid", rule.Id);
            return null;
        }
        if (rule.CorrelateWindowSeconds <= 0)
        {
            _logger.LogWarning("Correlate rule {RuleId} skipped because window is invalid", rule.Id);
            return null;
        }

        var groupKey = FieldMatch.ResolveField(root, rule.CorrelateGroupBy!);
        if (string.IsNullOrEmpty(groupKey)) return null;

        var key = $"{rule.Id}:{groupKey}";
        var window = TimeSpan.FromSeconds(rule.CorrelateWindowSeconds);

        var list = _correlateState.GetOrAdd(key, _ => new List<EventRecord>());
        lock (list)
        {
            list.Add(new EventRecord(now, eventId));
            // Trim out-of-window
            list.RemoveAll(r => now - r.At > window);

            if (list.Count >= rule.CorrelateThreshold)
            {
                var contributing = list.Select(r => r.EventId).ToList();
                // Reset so the rule doesn't fire on every subsequent matching event
                list.Clear();
                return BuildHit(rule, root, contributing);
            }
        }
        return null;
    }

    // ── Sequence: stages must match in order within window for the same group ─
    private RuleHit? EvaluateSequence(Rule rule, JsonElement root, DateTime now, string eventId)
    {
        if (string.IsNullOrWhiteSpace(rule.SequenceGroupBy))
        {
            _logger.LogWarning("Sequence rule {RuleId} skipped because group_by is invalid", rule.Id);
            return null;
        }
        if (rule.SequenceWindowSeconds <= 0)
        {
            _logger.LogWarning("Sequence rule {RuleId} skipped because window is invalid", rule.Id);
            return null;
        }

        var groupKey = FieldMatch.ResolveField(root, rule.SequenceGroupBy!);
        if (string.IsNullOrEmpty(groupKey)) return null;

        var key = $"{rule.Id}:{groupKey}";
        var window = TimeSpan.FromSeconds(rule.SequenceWindowSeconds);

        var stages = rule.SequenceStages;
        if (stages.Count == 0) return null;

        var current = _sequenceState.GetValueOrDefault(key);
        // Expire stale state
        if (current is not null && now - current.FirstMatchAt > window)
            current = null;

        int nextStageIdx = current?.LastMatchedStage + 1 ?? 0;

        // Does this event match stage 0 (start a new sequence)?
        // Only restart when there is no sequence in progress — a repeated stage-0
        // event must not reset progress mid-sequence.
        if (current is null && stages[0].Match.Evaluate(root))
        {
            _sequenceState[key] = new SequenceState(0, now, new List<string> { eventId });
            if (stages.Count == 1)
            {
                // Edge case: single-stage sequence behaves like stateless
                _sequenceState.TryRemove(key, out _);
                return BuildHit(rule, root, new[] { eventId });
            }
            return null;
        }

        // Does this event match the next expected stage?
        if (current is not null && nextStageIdx < stages.Count && stages[nextStageIdx].Match.Evaluate(root))
        {
            current.EventIds.Add(eventId);
            var newState = new SequenceState(nextStageIdx, current.FirstMatchAt, current.EventIds);
            _sequenceState[key] = newState;

            if (nextStageIdx == stages.Count - 1)
            {
                // Final stage — fire and clear
                var contributing = newState.EventIds.ToList();
                _sequenceState.TryRemove(key, out _);
                return BuildHit(rule, root, contributing);
            }
        }

        return null;
    }
}
