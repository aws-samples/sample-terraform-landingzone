"""regression: the organization module refused SCPs above 5120 characters, half the AWS limit.

AWS Organizations accepts service control policies up to 10,240 characters
(resource control policies stay at 5120). With the old limit,
tlz-core-guardrails-2 had no room for the documented step of adding a
renamed account access role to its exemption lists: the plan refused it.

The test reads the limit from the module's validation, adds one more access
role next to every AWSControlTowerExecution exemption of each shipped SCP, and
checks that the result still passes.
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "configurations/policies/organization"
VARIABLES = REPO / "modules/organization/variables.tf"
AWS_SCP_LIMIT = 10240
EXTRA_ROLE = "LandingZoneAccessRole"


def _module_scp_limit(variable):
    block = re.search(r'variable "%s" \{.*?\n\}' % variable, VARIABLES.read_text(), re.S).group(0)
    return int(re.search(r"\)\)\s*<=\s*(\d+)", block).group(1))


def _with_extra_role(node):
    if isinstance(node, dict):
        return {key: _with_extra_role(value) for key, value in node.items()}
    if isinstance(node, list):
        out = [_with_extra_role(item) for item in node]
        extra = [i.replace("AWSControlTowerExecution", EXTRA_ROLE) for i in out
                 if isinstance(i, str) and "role/AWSControlTowerExecution" in i]
        return out + extra
    if isinstance(node, str) and "role/AWSControlTowerExecution" in node:
        return [node, node.replace("AWSControlTowerExecution", EXTRA_ROLE)]
    return node


def _scp_documents():
    return [p for p in sorted(POLICIES.glob("tlz-*.json")) if "-rcp-" not in p.name]


def test_regression_module_scp_limit_is_the_aws_limit():
    assert _module_scp_limit("service_control_policies") == AWS_SCP_LIMIT
    assert _module_scp_limit("quarantine_scp_content") == AWS_SCP_LIMIT


def test_regression_guardrails_fit_with_one_more_access_role():
    limit = _module_scp_limit("service_control_policies")
    assert _scp_documents()
    for path in _scp_documents():
        doc = _with_extra_role(json.loads(path.read_text()))
        size = len(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))
        assert size <= limit, f"{path.name}: {size} characters with one more access role, limit {limit}"
