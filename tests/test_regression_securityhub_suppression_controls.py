"""regression: baseline Security Hub rules suppressed controls they had no business hiding.

configurations/base/security-hub-automation-rules.json is loaded into every
deployment (configurations/loader.hcl, first merge source). The rule
suppress-access-analyzer-findings said "AccessAnalyzer.1" in its description
but matched IAM.1 (IAM policies with full "*" administrative privileges), so
the default configuration suppressed that control in every account, as a
terminal rule. suppress-ssm-findings matched SSM.1 (EC2 instances managed by
Systems Manager), a check on the workloads' own instances that nothing in the
landing zone makes true. Six further rules matched a control ID with no
account or resource criterion (Config.1, GuardDuty.1, SecurityHub.1, Macie.1,
IAM.28, EC2.7), so they hid that control's failures in every account the rules
reach; four of them report a security service that is off.

The test reads the shipped JSON: every suppressing rule must name each
control ID it matches in its description, must be scoped to a resource or an
account, and no baseline rule may match a control from the never-suppress
list.
"""

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "configurations/base/security-hub-automation-rules.json"

# Controls that judge the workloads' own resources or report a security service
# that is off; a baseline suppression of them hides real findings in every
# account.
NEVER_SUPPRESSED = {"IAM.1", "SSM.1", "Config.1", "GuardDuty.1", "SecurityHub.1", "Macie.1"}

# Criteria that limit a rule to named resources or accounts.
SCOPE_CRITERIA = ("resource_id", "resource_tags", "aws_account_id")


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
    assert hits == {}, f"baseline rules suppress controls they must not hide: {hits}"


def test_regression_no_account_wide_control_suppression():
    unscoped = [
        r["rule_name"] for r in _suppressing_rules()
        if _control_ids(r) and not any(r["criteria"].get(k) for k in SCOPE_CRITERIA)
    ]
    assert unscoped == [], f"baseline rules suppress a control in every account: {unscoped}"
