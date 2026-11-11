"""regression: the account-move function held organizations:MoveAccount on every account and never called it.

The function behind enable_account_move_automation only logs the CreateAccount
and MoveAccount events it receives. Its role could still move any account of
the organization into any OU, and the texts promised that it moves accounts.
The grant is gone and the texts say what the function does.
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICY = REPO / "configurations/policies/organization/account-move-orgs-policy.json"
HANDLER = REPO / "modules/organization/lambda/account_move.py"


def _actions():
    actions = set()
    for stmt in json.loads(POLICY.read_text())["Statement"]:
        action = stmt["Action"]
        actions |= {action} if isinstance(action, str) else set(action)
    return actions


def test_regression_account_move_policy_grants_no_write():
    granted = _actions()
    assert granted, "the policy grants nothing"
    assert all(re.match(r"organizations:(Describe|List)", a) for a in granted), sorted(granted)
    # The function makes no Organizations write call, so it needs none.
    assert not re.search(r"organizations\.\w+\(", HANDLER.read_text())


def test_regression_account_move_texts_do_not_promise_a_move():
    variables = (REPO / "modules/organization/variables.tf").read_text()
    description = re.search(r'variable "enable_account_move_automation" \{\s*description\s*=\s*"([^"]*)"', variables).group(1)
    assert "move accounts between" not in description
    assert "moves no account" in description
