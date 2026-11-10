"""regression: the account move function listened in the stack's region.

Organizations delivers CreateAccount and MoveAccount to EventBridge in
us-east-1 only, so a rule in another region received nothing. Every regional
resource of the function names the Organizations events region of the SCP
change detection, and no plan-time check warns about the region.
"""

import re
from pathlib import Path

ORG = Path(__file__).resolve().parents[1] / "modules/organization"
REGIONAL = (
    "aws_cloudwatch_log_group",
    "aws_lambda_function",
    "aws_cloudwatch_event_rule",
    "aws_cloudwatch_event_target",
    "aws_lambda_permission",
)
BLOCK = re.compile(r'^resource "(\w+)" "(\w+)" \{\n(.*?)^\}', re.S | re.M)


def test_regional_resources_name_the_events_region():
    blocks = BLOCK.findall((ORG / "account-move.tf").read_text(encoding="utf-8"))
    regional = [(t, n, b) for t, n, b in blocks if t in REGIONAL]
    assert len(regional) == len(REGIONAL)
    for kind, name, body in regional:
        assert re.search(r"^\s*region\s*=\s*local\.scp_revert_region$", body, re.M), f"{kind}.{name}"


def test_no_region_check_for_the_account_move_function():
    module = "\n".join(p.read_text(encoding="utf-8") for p in ORG.glob("*.tf"))
    assert not re.search(r'check "[^"]*account_move[^"]*"', module)
