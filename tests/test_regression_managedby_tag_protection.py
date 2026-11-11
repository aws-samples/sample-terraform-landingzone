"""regression: any principal that could tag a resource could hide its Security Hub findings.

Baseline Security Hub automation rules suppress findings of resources tagged
ManagedBy=TLZ (configurations/base/security-hub-automation-rules.json), and no
SCP kept other principals from setting that tag. The base guardrail SCP now
denies any request that sets ManagedBy=TLZ to every principal except the
exempt landing-zone roles.

The test reads the shipped documents: the value the rules trust is the value
the statement protects, the statement's exemptions are the ones the other
guardrails use, and the example attaches the SCP to every top-level OU except
Suspended and Quarantine, whose own SCPs deny everything already (the
quarantine SCP exempts the same landing-zone roles); nested OUs inherit it.
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "configurations/policies/organization"
RULES = REPO / "configurations/base/security-hub-automation-rules.json"
EXAMPLE = REPO / "env/common.hcl.example"

# Example SCP name -> document the loader injects for it.
CARRYING = {
    "base-guardrails-1": "tlz-core-guardrails-1.json",
}


def _statement(doc, sid):
    statements = json.loads((POLICIES / doc).read_text())["Statement"]
    return next(s for s in statements if s["Sid"] == sid)


def _trusted_tag_values():
    values = set()
    for rule in json.loads(RULES.read_text()):
        for tag in rule["criteria"].get("resource_tags", []):
            if tag["key"] == "ManagedBy":
                values.add(tag["value"])
    return values


def test_regression_managedby_tag_set_only_by_exempt_roles():
    exempt = _statement("tlz-core-guardrails-1.json", "ProtectSNSTopics")["Condition"]["StringNotLike"]["aws:PrincipalArn"]
    assert _trusted_tag_values() == {"TLZ"}
    for doc in CARRYING.values():
        stmt = _statement(doc, "ProtectManagedByTag")
        assert stmt["Effect"] == "Deny" and stmt["Action"] == "*" and stmt["Resource"] == "*", doc
        assert stmt["Condition"]["StringEqualsIgnoreCase"] == {"aws:RequestTag/ManagedBy": "TLZ"}, doc
        assert stmt["Condition"]["StringNotLike"]["aws:PrincipalArn"] == exempt, doc


def test_regression_managedby_protection_reaches_every_ou():
    example = EXAMPLE.read_text()
    block = example[example.index("service_control_policies = ["):example.index("resource_control_policies = [")]
    targets = set()
    for name in CARRYING:
        match = re.search(r'name\s*=\s*"' + name + r'".*?targets\s*=\s*\[([^\]]*)\]', block, re.S)
        assert match, f"{name} is not in the example's service_control_policies"
        targets |= set(re.findall(r'"([^"]+)"', match.group(1)))
    top_level = set(re.findall(r'\{ name = "([^"]+)", parent_name = "__root__" \}', example))
    # Suspended and Quarantine carry deny-all SCPs of their own; the quarantine
    # SCP exempts the same roles ProtectManagedByTag exempts.
    denied_anyway = {"Suspended", "Quarantine"}
    assert top_level - denied_anyway <= targets, sorted(top_level - denied_anyway - targets)
