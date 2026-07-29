using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Phalanx.Correlator.Engine;

// ──────────────────────────────────────────────────────────────────────────────
// Operators a match field can use. These are evaluated against a single event.
// ──────────────────────────────────────────────────────────────────────────────
public enum MatchOp { Equals, Contains, StartsWith, EndsWith, Regex, Gt, Lt }

public sealed class FieldMatch
{
    public string FieldPath { get; init; } = "";    // dotted: "process.name"
    public MatchOp Op { get; init; }
    public bool Negate { get; init; }
    public List<string> Values { get; init; } = new();
    public Regex? CompiledRegex { get; init; }      // pre-compiled for speed

    private static readonly HashSet<string> _interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "bash","sh","dash","zsh","ksh","fish",
        "python","python2","python3","perl","ruby","node","nodejs","php"
    };

    public bool Evaluate(JsonElement root)
    {
        var actual = ResolveField(root, FieldPath);
        if (actual == null) return Negate;          // field missing
        bool any = Values.Any(v => MatchOne(actual, v));

        // If process.name matched an interpreter (bash, python3, etc.) the
        // sentinel sends the raw interpreter name. Fall back to checking the
        // basename of the first non-flag token in process.command_line so that
        // a script named /tmp/msfconsole still triggers msfconsole rules.
        if (!any && !Negate && FieldPath == "process.name" && _interpreters.Contains(actual))
        {
            var cmdline = ResolveField(root, "process.command_line");
            if (cmdline != null)
            {
                var script = cmdline.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                    .Skip(1)
                                    .FirstOrDefault(t => !t.StartsWith('-'));
                if (script != null)
                {
                    var stem = Path.GetFileNameWithoutExtension(script);
                    if (!string.IsNullOrEmpty(stem))
                        any = Values.Any(v => MatchOne(stem, v));
                }
            }
        }

        return Negate ? !any : any;
    }

    private bool MatchOne(string actual, string expected)
    {
        return Op switch
        {
            MatchOp.Equals     => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase),
            MatchOp.Contains   => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            MatchOp.StartsWith => actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase),
            MatchOp.EndsWith   => actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase),
            MatchOp.Regex      => CompiledRegex?.IsMatch(actual) ?? false,
            MatchOp.Gt         => double.TryParse(actual, out var a) && double.TryParse(expected, out var e) && a > e,
            MatchOp.Lt         => double.TryParse(actual, out var a) && double.TryParse(expected, out var e) && a < e,
            _                  => false,
        };
    }

    public static string? ResolveField(JsonElement root, string path)
    {
        var parts = path.Split('.');
        JsonElement cur = root;
        foreach (var part in parts)
        {
            if (cur.ValueKind != JsonValueKind.Object) return null;
            if (!cur.TryGetProperty(part, out var next)) return null;
            cur = next;
        }
        return cur.ValueKind switch
        {
            JsonValueKind.String  => cur.GetString(),
            JsonValueKind.Number  => cur.ToString(),
            JsonValueKind.True    => "true",
            JsonValueKind.False   => "false",
            JsonValueKind.Array   => cur.EnumerateArray()
                                        .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : e.ToString())
                                        .FirstOrDefault(),
            _ => null,
        };
    }
}

// A "match block" is the AND of multiple FieldMatches.
public sealed class MatchBlock
{
    public List<FieldMatch> Fields { get; init; } = new();

    public bool Evaluate(JsonElement root) => Fields.All(f => f.Evaluate(root));
}

// ──────────────────────────────────────────────────────────────────────────────
// A loaded rule. Three flavors:
//   - Stateless: fires immediately when Match matches.
//   - Correlate: fires when N matching events occur in a window.
//   - Sequence:  fires when stages match in order within a window.
// ──────────────────────────────────────────────────────────────────────────────
public sealed class Rule
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Severity { get; init; } = "Medium";
    public string MitreTactic { get; init; } = "";
    public string MitreTechnique { get; init; } = "";
    public string Source { get; init; } = "phalanx";

    public MatchBlock? Match { get; init; }       // primary match (stateless and correlate)

    // Stateful — correlate
    public string? CorrelateGroupBy { get; init; }
    public int CorrelateWindowSeconds { get; init; }
    public int CorrelateThreshold { get; init; }

    // Stateful — sequence
    public string? SequenceGroupBy { get; init; }
    public int SequenceWindowSeconds { get; init; }
    public List<SequenceStage> SequenceStages { get; init; } = new();

    public bool IsCorrelate => CorrelateGroupBy is not null;
    public bool IsSequence  => SequenceStages.Count > 0;
    public bool IsStateless => !IsCorrelate && !IsSequence;
}

public sealed class SequenceStage
{
    public string Id { get; init; } = "";
    public MatchBlock Match { get; init; } = new();
}
