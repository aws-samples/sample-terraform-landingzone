"""regression: a baseline Security Hub rule suppressed a control its description did not name.

configurations/base/security-hub-automation-rules.json is loaded into every
deployment (configurations/loader.hcl, first merge source). The rule
suppress-access-analyzer-findings said "AccessAnalyzer.1" in its description
but matched IAM.1 (IAM policies with full "*" administrative privileges), so
the default configuration suppressed that control in every account, as a
terminal rule. suppress-ssm-findings matched SSM.1 (EC2 instances managed by
Systems Manager), a check on the workloads' own instances that nothing in the
landing zone makes true.

The test reads the shipped JSON: every suppressing rule must name each
control ID it matches in its description, and no baseline rule may match a
control from the never-suppress list.
"""

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "configurations/base/security-hub-automation-rules.json"

# Controls that judge the workloads' own resources, not a service the landing
# zone runs; a baseline suppression of them hides real findings in every account.
NEVER_SUPPRESSED = {"IAM.1", "SSM.1"}


def _suppressing_rules():
    rules = json.loads(RULES.read_text())
    return [
        r for r in rules
        if r["actions"]["finding_fields_update"].get("workflow", {}).get("status") == "SUPPRESSED"
    ]


def _control_ids(rule):
    return [c["value"] for c in rule["criteria"].get("compliance_security_control_id", [])]


@pytest.mark.parametrize("rule", _suppressing_rules(), ids=lambda r: r["rule_name"])
def test_regression_suppression_names_its_control(rule):
    for control in _control_ids(rule):
        assert control in rule["description"], (
            f"{rule['rule_name']} suppresses {control} but its description does not name it: "
            f"{rule['description']!r}"
        )


def test_regression_no_baseline_suppression_of_workload_controls():
    hits = {
        r["rule_name"]: sorted(set(_control_ids(r)) & NEVER_SUPPRESSED)
        for r in _suppressing_rules()
        if set(_control_ids(r)) & NEVER_SUPPRESSED
    }
    assert hits == {}, f"baseline rules suppress controls on workload resources: {hits}"


def test_access_analyzer_rule_matches_the_analyzer_control():
    rule = next(r for r in _suppressing_rules() if r["rule_name"] == "suppress-access-analyzer-findings")
    assert _control_ids(rule) == ["IAM.28"]
