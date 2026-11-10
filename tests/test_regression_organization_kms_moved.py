"""regression: the organization module's KMS keys changed from count to for_each.

An earlier release addressed each key as [0] in the stack's region. Without a
moved block, the next plan destroys that key (and every log group or topic
encrypted with it loses its key) and creates a new one. The moved blocks map
[0] to the instance key "stack", which the module uses for the key in the
stack's own region.
"""

import re
from pathlib import Path

KMS_TF = Path(__file__).resolve().parents[1] / "modules/organization/kms.tf"
MOVED = re.compile(r'moved\s*\{\s*from\s*=\s*(\S+)\s*to\s*=\s*(\S+)\s*\}')


def test_single_key_addresses_move_to_the_stack_key():
    text = KMS_TF.read_text(encoding="utf-8")
    moved = dict(MOVED.findall(text))
    for resource in ("aws_kms_key.cloudwatch_logs", "aws_kms_alias.cloudwatch_logs", "aws_kms_key.sns_topics"):
        assert moved.get(f"{resource}[0]") == f'{resource}["stack"]', resource


def test_stack_region_instances_use_the_stack_key():
    # Only the quarantine topic key stays in the stack's region; the account
    # move logs key follows the Organizations events region.
    text = KMS_TF.read_text(encoding="utf-8")
    assert text.count("{ stack = local.region }") == 1
