"""
test_policy_wiring.py
─────────────────────────────────────────────────────────────────────────────
Validates that every rule ID referenced in a policy actually exists in the
rules directory, that severity filters are consistent with those rules, and
that no structural mistakes would silently prevent an automation from firing.

These tests are purely file-based (YAML reads) — no network, no DB, no
running services required. Safe to execute in any environment.

Run with:  pytest tests/python/test_policy_wiring.py -v
─────────────────────────────────────────────────────────────────────────────
"""
from pathlib import Path
from typing import Any

import pytest
import yaml

# ── Directory discovery ───────────────────────────────────────────────────────

def _find_dir(name: str) -> Path:
    """Walk up from this file until we find a sibling directory called `name`."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / name
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        f"Could not find '{name}/' directory walking up from {here}"
    )

RULES_DIR    = _find_dir("rules")
POLICIES_DIR = _find_dir("policies")

VALID_ACTION_TYPES = {"kill_process", "quarantine_file", "isolate_host",
                      "collect_file", "run_command"}

# ── Loaders ───────────────────────────────────────────────────────────────────

def load_all_rules() -> dict[str, dict]:
    """Return {rule_id: rule_doc} for every rule in rules/."""
    rules: dict[str, dict] = {}
    for path in sorted(RULES_DIR.glob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc and "id" in doc:
                rules[doc["id"]] = doc
    return rules


def load_all_policies() -> list[dict]:
    """Return list of policy docs from policies/."""
    policies = []
    for path in sorted(POLICIES_DIR.glob("*.yml")):
        doc = yaml.safe_load(path.read_text())
        if doc and "id" in doc:
            policies.append({"_file": path.name, **doc})
    return policies


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def all_rules():
    return load_all_rules()


@pytest.fixture(scope="module")
def all_policies():
    return load_all_policies()


# ── Policy directory structure ────────────────────────────────────────────────

def test_policies_directory_exists():
    assert POLICIES_DIR.is_dir(), f"policies/ directory not found at {POLICIES_DIR}"


def test_at_least_one_policy_file_exists():
    files = list(POLICIES_DIR.glob("*.yml"))
    assert files, "No .yml files found in policies/"


def test_all_policy_files_are_valid_yaml(all_policies):
    # Loader already parses; if it succeeded we just verify we got docs
    assert len(all_policies) >= 1


# ── Per-policy structural checks ──────────────────────────────────────────────

def _policy_ids(all_policies):
    return [p["id"] for p in all_policies]


@pytest.fixture(scope="module", params=lambda: None)
def policy(request, all_policies):
    return request.param


def test_no_duplicate_policy_ids(all_policies):
    ids = [p["id"] for p in all_policies]
    duplicates = [pid for pid in set(ids) if ids.count(pid) > 1]
    assert not duplicates, f"Duplicate policy IDs: {duplicates}"


@pytest.mark.parametrize("pol", load_all_policies(), ids=lambda p: p.get("id", p.get("_file")))
def test_policy_has_required_fields(pol):
    for field in ("id", "title", "enabled", "action"):
        assert field in pol, f"Policy {pol.get('id', pol['_file'])} missing required field '{field}'"


@pytest.mark.parametrize("pol", load_all_policies(), ids=lambda p: p.get("id", p.get("_file")))
def test_policy_action_type_is_valid(pol):
    action_type = pol.get("action", {}).get("type", "")
    assert action_type in VALID_ACTION_TYPES, (
        f"Policy {pol['id']} has unknown action type '{action_type}'. "
        f"Valid types: {sorted(VALID_ACTION_TYPES)}"
    )


@pytest.mark.parametrize("pol", load_all_policies(), ids=lambda p: p.get("id", p.get("_file")))
def test_policy_enabled_field_is_boolean(pol):
    assert isinstance(pol["enabled"], bool), (
        f"Policy {pol['id']}: 'enabled' must be a boolean, got {type(pol['enabled']).__name__}"
    )


# ── Cross-reference: every rule_id in a policy must exist in rules/ ───────────

@pytest.mark.parametrize("pol", load_all_policies(), ids=lambda p: p.get("id", p.get("_file")))
def test_policy_rule_ids_exist_in_rules_dir(pol):
    rules = load_all_rules()
    rule_ids_in_policy: list[str] = pol.get("match", {}).get("rule_ids", [])
    missing = [rid for rid in rule_ids_in_policy if rid not in rules]
    assert not missing, (
        f"Policy {pol['id']} references rule IDs that don't exist in rules/: {missing}. "
        f"Known IDs: {sorted(rules)}"
    )


# ── Cross-reference: severity filters must match the rule's actual severity ───

@pytest.mark.parametrize("pol", load_all_policies(), ids=lambda p: p.get("id", p.get("_file")))
def test_policy_severity_filter_matches_referenced_rules(pol):
    rules = load_all_rules()
    rule_ids_in_policy: list[str] = pol.get("match", {}).get("rule_ids", [])
    severity_filter: list[str]    = [s.capitalize() for s in pol.get("match", {}).get("severity", [])]

    if not severity_filter:
        return  # no severity filter → matches any severity (POL-002 pattern, valid)

    mismatches = []
    for rid in rule_ids_in_policy:
        rule = rules.get(rid)
        if rule is None:
            continue  # already caught by test above
        rule_sev = (rule.get("severity") or "").capitalize()
        if rule_sev not in severity_filter:
            mismatches.append(
                f"{rid} has severity={rule_sev!r} but policy only matches {severity_filter}"
            )

    assert not mismatches, (
        f"Policy {pol['id']} severity filter would never match its own rules:\n"
        + "\n".join(f"  • {m}" for m in mismatches)
    )


# ── Specific policy wiring assertions (named policies) ────────────────────────

def _get_policy(all_policies, policy_id: str) -> dict:
    for p in all_policies:
        if p["id"] == policy_id:
            return p
    pytest.skip(f"Policy {policy_id} not found in policies/")


class TestPOL001:
    """POL-001: Isolate on credential dumping."""

    def test_references_phx001(self, all_policies):
        pol = _get_policy(all_policies, "POL-001")
        assert "PHX-001" in pol["match"]["rule_ids"]

    def test_action_is_isolate_host(self, all_policies):
        pol = _get_policy(all_policies, "POL-001")
        assert pol["action"]["type"] == "isolate_host"

    def test_severity_filter_is_critical(self, all_policies):
        pol = _get_policy(all_policies, "POL-001")
        sevs = [s.capitalize() for s in pol["match"].get("severity", [])]
        assert "Critical" in sevs

    def test_allow_ip_is_set(self, all_policies):
        pol = _get_policy(all_policies, "POL-001")
        allow_ip = pol["action"].get("params", {}).get("allow_ip", "")
        assert allow_ip, "isolate_host policy must specify allow_ip so the manager stays reachable"

    def test_rate_limit_is_configured(self, all_policies):
        pol = _get_policy(all_policies, "POL-001")
        assert pol.get("rate_limit"), "POL-001 must have a rate_limit to prevent isolation storms"


class TestPOL002:
    """POL-002: Kill exploitation and lateral-movement tools."""

    def test_references_all_three_rule_ids(self, all_policies):
        pol = _get_policy(all_policies, "POL-002")
        rule_ids = pol["match"]["rule_ids"]
        for expected in ("PHX-002", "PHX-003", "PHX-004"):
            assert expected in rule_ids, f"POL-002 should reference {expected}"

    def test_action_is_kill_process(self, all_policies):
        pol = _get_policy(all_policies, "POL-002")
        assert pol["action"]["type"] == "kill_process"

    def test_is_live_fire_not_dry_run(self, all_policies):
        pol = _get_policy(all_policies, "POL-002")
        assert pol.get("dry_run", False) is False, (
            "POL-002 must be dry_run: false — killing exploitation tools is a live action"
        )

    def test_no_severity_filter(self, all_policies):
        pol = _get_policy(all_policies, "POL-002")
        sevs = pol.get("match", {}).get("severity", [])
        assert not sevs, (
            "POL-002 intentionally has no severity filter so it matches PHX-002 (Critical) "
            "and PHX-003/004 (High) — adding a severity filter would break that"
        )


class TestPOL003:
    """POL-003: Quarantine suspicious file attachments."""

    def test_references_phx202_not_phx013(self, all_policies):
        pol = _get_policy(all_policies, "POL-003")
        rule_ids = pol["match"]["rule_ids"]
        assert "PHX-202" in rule_ids, (
            "POL-003 must reference PHX-202 (suspicious_attachment, a FILE event that has "
            "file.path). PHX-013 is a process event with no file.path — quarantine_file "
            "would always fail with outcome=error."
        )
        assert "PHX-013" not in rule_ids, (
            "PHX-013 fires on process_start events which have no file.path field. "
            "quarantine_file action would always fail for PHX-013 alerts."
        )

    def test_action_is_quarantine_file(self, all_policies):
        pol = _get_policy(all_policies, "POL-003")
        assert pol["action"]["type"] == "quarantine_file"

    def test_severity_covers_medium(self, all_policies):
        pol = _get_policy(all_policies, "POL-003")
        sevs = [s.capitalize() for s in pol["match"].get("severity", [])]
        assert "Medium" in sevs, (
            "PHX-202 is Medium severity — POL-003 must include Medium in its filter"
        )

    def test_rate_limit_is_configured(self, all_policies):
        pol = _get_policy(all_policies, "POL-003")
        assert pol.get("rate_limit"), "POL-003 should have a rate_limit"


# ── Coverage check: rules without any policy ─────────────────────────────────

def test_report_rules_without_policy_coverage(all_policies, capsys):
    """
    Informational test — always passes, but prints a coverage table showing
    which rules have no automated response policy.  Review the output before
    your project defense to understand your automation gaps.
    """
    rules = load_all_rules()
    covered: set[str] = set()
    for pol in all_policies:
        for rid in pol.get("match", {}).get("rule_ids", []):
            covered.add(rid)

    uncovered = sorted(r for r in rules if r not in covered)

    with capsys.disabled():
        print(f"\n── Policy coverage ──────────────────────────────────────────")
        print(f"   Total rules  : {len(rules)}")
        print(f"   With policy  : {len(covered)}")
        print(f"   Without policy ({len(uncovered)} rules):")
        for rid in uncovered:
            rule = rules[rid]
            print(f"     {rid:10s}  [{rule.get('severity','?'):8s}]  {rule.get('title','')}")
        print()

    # Always passes — this is a coverage report, not a gate
    assert True
