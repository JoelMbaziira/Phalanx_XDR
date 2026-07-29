"""Validates the YAML rule files for structural correctness."""
import re
from pathlib import Path

import pytest
import yaml

RULES_DIR = Path(__file__).parent.parent.parent / "rules"
RULE_FILES = list(RULES_DIR.glob("*.yml"))

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


def load_rules(path: Path) -> list[dict]:
    """Load all YAML documents from a rule file."""
    text = path.read_text()
    docs = list(yaml.safe_load_all(text))
    return [d for d in docs if d is not None]


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_rule_files_exist(rule_file):
    assert rule_file.exists()


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_rule_files_valid_yaml(rule_file):
    load_rules(rule_file)  # should not raise


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_all_rules_have_id(rule_file):
    for doc in load_rules(rule_file):
        assert "id" in doc, f"Rule missing 'id' in {rule_file.name}: {doc}"
        assert doc["id"], f"Rule has empty 'id' in {rule_file.name}"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_all_rules_have_title(rule_file):
    for doc in load_rules(rule_file):
        assert "title" in doc, f"Rule '{doc.get('id')}' missing title in {rule_file.name}"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_all_rules_have_valid_severity(rule_file):
    for doc in load_rules(rule_file):
        sev = doc.get("severity", "")
        assert sev.capitalize() in VALID_SEVERITIES, (
            f"Rule '{doc.get('id')}' has invalid severity '{sev}' in {rule_file.name}"
        )


def test_no_duplicate_rule_ids():
    all_ids = []
    for rule_file in RULE_FILES:
        for doc in load_rules(rule_file):
            rule_id = doc.get("id")
            if rule_id:
                all_ids.append(rule_id)

    duplicates = [rid for rid in set(all_ids) if all_ids.count(rid) > 1]
    assert not duplicates, f"Duplicate rule IDs found: {duplicates}"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_rule_id_format(rule_file):
    for doc in load_rules(rule_file):
        rule_id = doc.get("id", "")
        assert re.match(r"^PHX-\d{3,}", rule_id), (
            f"Rule ID '{rule_id}' in {rule_file.name} should match PHX-NNN format"
        )


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_stateless_rules_have_match_block(rule_file):
    for doc in load_rules(rule_file):
        is_correlate = "correlate" in doc
        is_sequence  = "sequence" in doc
        if not is_correlate and not is_sequence:
            assert "match" in doc, (
                f"Stateless rule '{doc.get('id')}' has no match block in {rule_file.name}"
            )


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_correlate_rules_have_required_fields(rule_file):
    for doc in load_rules(rule_file):
        if "correlate" not in doc:
            continue
        corr = doc["correlate"]
        rule_id = doc.get("id")
        assert "group_by" in corr,        f"Correlate rule '{rule_id}' missing group_by"
        assert "window_seconds" in corr,  f"Correlate rule '{rule_id}' missing window_seconds"
        assert "threshold" in corr,       f"Correlate rule '{rule_id}' missing threshold"
        assert corr["threshold"] > 0,     f"Correlate rule '{rule_id}' threshold must be > 0"
        assert corr["window_seconds"] > 0, f"Correlate rule '{rule_id}' window must be > 0"


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_sequence_rules_have_at_least_two_stages(rule_file):
    for doc in load_rules(rule_file):
        if "sequence" not in doc:
            continue
        stages = doc["sequence"].get("stages", [])
        rule_id = doc.get("id")
        assert len(stages) >= 2, (
            f"Sequence rule '{rule_id}' in {rule_file.name} should have at least 2 stages"
        )
