using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;

namespace Phalanx.Correlator.Engine;

public sealed class RuleLoader
{
    private readonly ILogger _logger;

    public RuleLoader(ILogger logger) => _logger = logger;

    public List<Rule> LoadFromDirectory(string dir)
    {
        var rules = new List<Rule>();
        if (!Directory.Exists(dir))
        {
            _logger.LogWarning("Rules directory not found: {Dir}", Path.GetFullPath(dir));
            return rules;
        }

        // Native rules first
        foreach (var path in Directory.EnumerateFiles(dir, "*.yml", SearchOption.AllDirectories)
                                       .Concat(Directory.EnumerateFiles(dir, "*.yaml", SearchOption.AllDirectories)))
        {
            try
            {
                var isSigma = path.Contains($"{Path.DirectorySeparatorChar}sigma{Path.DirectorySeparatorChar}",
                                            StringComparison.OrdinalIgnoreCase);
                var loaded = isSigma ? ParseSigmaFile(path) : ParseNativeFile(path);
                rules.AddRange(loaded);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to parse {Path}: {Msg}", path, ex.Message);
            }
        }

        _logger.LogInformation("Loaded {N} rules from {Dir}", rules.Count, Path.GetFullPath(dir));
        return rules;
    }

    // ── Native Phalanx YAML (multiple docs per file via ---) ──────────────────
    private List<Rule> ParseNativeFile(string path)
    {
        var rules = new List<Rule>();
        using var reader = new StreamReader(path);
        var stream = new YamlStream();
        stream.Load(reader);

        foreach (var doc in stream.Documents)
        {
            if (doc.RootNode is YamlMappingNode root)
            {
                var rule = ParseNativeRule(root);
                if (rule is not null) rules.Add(rule);
            }
        }
        return rules;
    }

    private Rule? ParseNativeRule(YamlMappingNode root)
    {
        string id        = ScalarOr(root, "id", "");
        string title     = ScalarOr(root, "title", "");
        string desc      = ScalarOr(root, "description", "");
        string sev       = NormalizeSeverity(ScalarOr(root, "severity", "Medium"));

        string tactic = "", technique = "";
        if (root.Children.TryGetValue(new YamlScalarNode("mitre"), out var mNode) && mNode is YamlMappingNode mm)
        {
            tactic    = ScalarOr(mm, "tactic", "");
            technique = ScalarOr(mm, "technique", "");
        }

        if (string.IsNullOrEmpty(id))
        {
            _logger.LogWarning("Skipping rule with no id ({Title})", title);
            return null;
        }

        // Match block
        MatchBlock? match = null;
        if (root.Children.TryGetValue(new YamlScalarNode("match"), out var mb) && mb is YamlMappingNode mbMap)
            match = ParseMatchBlock(mbMap);

        // Correlate
        string? corrGroup = null; int corrWin = 0, corrThresh = 0;
        if (root.Children.TryGetValue(new YamlScalarNode("correlate"), out var cb) && cb is YamlMappingNode cbMap)
        {
            corrGroup  = ScalarOr(cbMap, "group_by", "");
            corrWin    = int.Parse(ScalarOr(cbMap, "window_seconds", "60"));
            corrThresh = int.Parse(ScalarOr(cbMap, "threshold", "3"));
        }

        // Sequence
        var stages = new List<SequenceStage>();
        string? seqGroup = null; int seqWin = 0;
        if (root.Children.TryGetValue(new YamlScalarNode("sequence"), out var sb) && sb is YamlMappingNode sbMap)
        {
            seqGroup = ScalarOr(sbMap, "group_by", "");
            seqWin   = int.Parse(ScalarOr(sbMap, "window_seconds", "300"));
            if (sbMap.Children.TryGetValue(new YamlScalarNode("stages"), out var stNode) && stNode is YamlSequenceNode stSeq)
            {
                foreach (var entry in stSeq.Children)
                {
                    if (entry is not YamlMappingNode stm) continue;
                    var stageId = ScalarOr(stm, "id", "");
                    if (!stm.Children.TryGetValue(new YamlScalarNode("match"), out var mxn) || mxn is not YamlMappingNode mxm)
                        continue;
                    stages.Add(new SequenceStage { Id = stageId, Match = ParseMatchBlock(mxm) });
                }
            }
        }

        return new Rule
        {
            Id = id,
            Title = title,
            Description = desc,
            Severity = sev,
            MitreTactic = tactic,
            MitreTechnique = technique,
            Source = "phalanx",
            Match = match,
            CorrelateGroupBy = string.IsNullOrEmpty(corrGroup) ? null : corrGroup,
            CorrelateWindowSeconds = corrWin,
            CorrelateThreshold = corrThresh,
            SequenceGroupBy = string.IsNullOrEmpty(seqGroup) ? null : seqGroup,
            SequenceWindowSeconds = seqWin,
            SequenceStages = stages,
        };
    }

    private MatchBlock ParseMatchBlock(YamlMappingNode node)
    {
        var block = new MatchBlock();
        foreach (var kv in node.Children)
        {
            if (kv.Key is not YamlScalarNode keyNode) continue;
            string key = keyNode.Value ?? "";
            // Parse "field|op" or "field|not|op"
            var parts = key.Split('|');
            string fieldPath = parts[0];
            bool negate = parts.Contains("not");
            string opStr = parts.LastOrDefault(p => p != "not" && p != fieldPath) ?? "equals";
            MatchOp op = ParseOp(opStr);

            var values = new List<string>();
            if (kv.Value is YamlScalarNode s) values.Add(s.Value ?? "");
            else if (kv.Value is YamlSequenceNode seq)
                values.AddRange(seq.Children.OfType<YamlScalarNode>().Select(c => c.Value ?? ""));

            Regex? compiled = null;
            if (op == MatchOp.Regex && values.Count > 0)
            {
                try { compiled = new Regex(string.Join("|", values), RegexOptions.Compiled); }
                catch (Exception ex) { _logger.LogWarning("Bad regex in {Field}: {Msg}", fieldPath, ex.Message); }
            }

            block.Fields.Add(new FieldMatch
            {
                FieldPath = fieldPath,
                Op = op,
                Negate = negate,
                Values = values,
                CompiledRegex = compiled,
            });
        }
        return block;
    }

    private static MatchOp ParseOp(string s) => s.ToLowerInvariant() switch
    {
        "equals"     => MatchOp.Equals,
        "contains"   => MatchOp.Contains,
        "startswith" => MatchOp.StartsWith,
        "endswith"   => MatchOp.EndsWith,
        "regex"      => MatchOp.Regex,
        "gt"         => MatchOp.Gt,
        "lt"         => MatchOp.Lt,
        _            => MatchOp.Equals,
    };

    // ── Sigma subset translator ────────────────────────────────────────────────
    // Supports: detection blocks with simple selection maps and a "condition: <selection>"
    // or "condition: 1 of selection*". Maps Sigma severity (level) and ATT&CK tags.
    private List<Rule> ParseSigmaFile(string path)
    {
        var rules = new List<Rule>();
        using var reader = new StreamReader(path);
        var stream = new YamlStream();
        stream.Load(reader);

        foreach (var doc in stream.Documents)
        {
            if (doc.RootNode is not YamlMappingNode root) continue;
            try
            {
                var rule = TranslateSigma(root, Path.GetFileName(path));
                if (rule is not null) rules.Add(rule);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Failed to translate Sigma rule in {File}: {Msg}", path, ex.Message);
            }
        }
        return rules;
    }

    private Rule? TranslateSigma(YamlMappingNode root, string filename)
    {
        string id    = ScalarOr(root, "id", filename);
        string title = ScalarOr(root, "title", "");
        string desc  = ScalarOr(root, "description", "");
        string level = ScalarOr(root, "level", "medium");
        string sev   = level.ToLower() switch
        {
            "critical" => "Critical",
            "high"     => "High",
            "low"      => "Low",
            "informational" => "Low",
            _          => "Medium",
        };

        string technique = "", tactic = "";
        if (root.Children.TryGetValue(new YamlScalarNode("tags"), out var tn) && tn is YamlSequenceNode ts)
        {
            foreach (var t in ts.Children.OfType<YamlScalarNode>())
            {
                var v = t.Value ?? "";
                if (v.StartsWith("attack.t", StringComparison.OrdinalIgnoreCase))
                    technique = v[7..].ToUpperInvariant().Replace("attack.", "");
                else if (v.StartsWith("attack.ta", StringComparison.OrdinalIgnoreCase))
                    tactic = v[7..].ToUpperInvariant();
            }
        }

        if (!root.Children.TryGetValue(new YamlScalarNode("detection"), out var dn) || dn is not YamlMappingNode det)
            return null;

        // Find selections — every key except "condition" and "timeframe"
        var selections = new Dictionary<string, MatchBlock>();
        foreach (var kv in det.Children)
        {
            if (kv.Key is not YamlScalarNode kn) continue;
            var name = kn.Value ?? "";
            if (name == "condition" || name == "timeframe") continue;
            if (kv.Value is YamlMappingNode selMap)
                selections[name] = SigmaSelectionToMatchBlock(selMap);
        }

        if (selections.Count == 0) return null;

        // For Phase 2 we collapse all selections into AND. Real Sigma `condition`
        // expressions are richer; we accept the loss for now.
        var combined = new MatchBlock
        {
            Fields = selections.Values.SelectMany(b => b.Fields).ToList()
        };

        return new Rule
        {
            Id = $"SIGMA-{id[..Math.Min(id.Length, 8)]}",
            Title = title,
            Description = desc,
            Severity = sev,
            MitreTactic = tactic,
            MitreTechnique = technique,
            Source = "sigma",
            Match = combined,
        };
    }

    private static MatchBlock SigmaSelectionToMatchBlock(YamlMappingNode sel)
    {
        var block = new MatchBlock();
        foreach (var kv in sel.Children)
        {
            if (kv.Key is not YamlScalarNode kn) continue;
            // Sigma uses "Field|contains" same as us. Map common Sigma fields to ECS.
            var raw = kn.Value ?? "";
            var parts = raw.Split('|');
            var sigmaField = parts[0];
            var op = parts.Length > 1 ? parts[1] : "equals";

            var ecsField = SigmaFieldMap(sigmaField);
            var values = new List<string>();
            if (kv.Value is YamlScalarNode s) values.Add(s.Value ?? "");
            else if (kv.Value is YamlSequenceNode seq)
                values.AddRange(seq.Children.OfType<YamlScalarNode>().Select(c => c.Value ?? ""));

            block.Fields.Add(new FieldMatch
            {
                FieldPath = ecsField,
                Op = op.ToLower() switch
                {
                    "contains"   => MatchOp.Contains,
                    "startswith" => MatchOp.StartsWith,
                    "endswith"   => MatchOp.EndsWith,
                    "re"         => MatchOp.Regex,
                    _            => MatchOp.Equals,
                },
                Values = values,
            });
        }
        return block;
    }

    // Common Sigma → ECS field name translations
    private static string SigmaFieldMap(string sigma) => sigma switch
    {
        "Image"                 => "process.executable",
        "ProcessName"           => "process.name",
        "CommandLine"           => "process.command_line",
        "OriginalFileName"      => "process.name",
        "ParentImage"           => "process.parent.executable",
        "ParentProcessName"     => "process.parent.name",
        "ParentCommandLine"     => "process.parent.command_line",
        "User"                  => "user.name",
        "TargetFilename"        => "file.path",
        _                       => sigma.Replace('.', '_').ToLowerInvariant(),
    };

    private static string ScalarOr(YamlMappingNode map, string key, string def)
    {
        if (map.Children.TryGetValue(new YamlScalarNode(key), out var n) && n is YamlScalarNode s)
            return s.Value ?? def;
        return def;
    }

    private static string NormalizeSeverity(string s) => s.ToLower() switch
    {
        "critical" => "Critical",
        "high"     => "High",
        "medium"   => "Medium",
        "low"      => "Low",
        _          => "Medium",
    };
}
