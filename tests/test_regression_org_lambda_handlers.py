"""regression: two organization-module Lambda handlers left targets bare or claimed reverts they never made.

The two defects pinned:
- policy-strategy.tf: on ``update`` the allow-list detach handler never gave
  FullAWSAccess back to a target that left the allow-list, while that
  target's allow-list attachment was destroyed in the same apply.
- scp-revert.tf: the UpdatePolicy "revert" wrote the CURRENT (tampered)
  content back and returned "Revert completed"; TLZDeploymentRole and the
  function's own role were not excluded.

What runs here is the code the module ships: each handler is read from its
heredoc in the .tf file and executed against a stub organizations client, so
a change to the module is what this test measures. The provider's lambda
invocation semantics (``tf.prev_input`` on update) and the CloudTrail event
shapes are taken from their documentation, not measured.
"""
import importlib.util
import json
import re
import sys
import textwrap
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ORG = REPO / "modules/organization"


def heredoc(tf_file, local_name):
    text = (ORG / tf_file).read_text()
    match = re.search(local_name + r" = <<-PYTHON\n(.*?)\n\s*PYTHON\n", text, re.S)
    assert match, f"{local_name} heredoc not found in {tf_file}"
    return textwrap.dedent(match.group(1))


class PolicyNotAttachedException(Exception):
    pass


class DuplicatePolicyAttachmentException(Exception):
    pass


class StubOrganizations:
    exceptions = types.SimpleNamespace(
        PolicyNotAttachedException=PolicyNotAttachedException,
        DuplicatePolicyAttachmentException=DuplicatePolicyAttachmentException,
    )

    def __init__(self, contents=None):
        self.calls = []
        self.contents = contents or {}

    def detach_policy(self, PolicyId, TargetId):
        self.calls.append(("detach", PolicyId, TargetId))

    def attach_policy(self, PolicyId, TargetId):
        self.calls.append(("attach", PolicyId, TargetId))

    def describe_policy(self, PolicyId):
        return {"Policy": {"Content": self.contents[PolicyId]}}

    def update_policy(self, PolicyId, Content):
        self.calls.append(("update", PolicyId, Content))


def load(code, stub, path, monkeypatch):
    # The handler is written to index.py next to its known_good_policies.json,
    # as the function's zip packages it, and imported from there.
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda _name: stub))
    source = path / "index.py"
    source.write_text(code)
    spec = importlib.util.spec_from_file_location("index", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_allow_list_update_reattaches_the_default_policy_to_departed_targets(tmp_path, monkeypatch):
    stub = StubOrganizations()
    handler = load(heredoc("policy-strategy.tf", "policy_strategy_detach_lambda_code"), stub, tmp_path, monkeypatch)

    handler.lambda_handler(
        {
            "policy_id": "p-FullAWSAccess",
            "target_ids": ["ou-b"],
            "tf": {"action": "update", "prev_input": {"policy_id": "p-FullAWSAccess", "target_ids": ["ou-a", "ou-b"]}},
        },
        None,
    )

    assert stub.calls == [("attach", "p-FullAWSAccess", "ou-a"), ("detach", "p-FullAWSAccess", "ou-b")]


SCP = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}'
TAMPERED = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'


def update_event(policy_id, role):
    return {
        "detail": {
            "eventName": "UpdatePolicy",
            "requestParameters": {"policyId": policy_id},
            "userIdentity": {"sessionContext": {"sessionIssuer": {"arn": f"arn:aws:iam::123456789012:role/{role}"}}},
        }
    }


@pytest.fixture
def revert(tmp_path, monkeypatch):
    (tmp_path / "known_good_policies.json").write_text(json.dumps({"p-managed": SCP}))
    stub = StubOrganizations({"p-managed": TAMPERED, "p-foreign": TAMPERED})
    return stub, load(heredoc("scp-revert.tf", "scp_auto_revert_lambda_code"), stub, tmp_path, monkeypatch)


def test_scp_revert_restores_the_deployed_content_not_the_tampered_one(revert):
    stub, handler = revert
    result = handler.lambda_handler(update_event("p-managed", "AdminRole"), None)
    assert stub.calls == [("update", "p-managed", SCP)]
    assert result["statusCode"] == 200


def test_scp_revert_reports_an_unmanaged_policy_as_not_reverted(revert):
    stub, handler = revert
    result = handler.lambda_handler(update_event("p-foreign", "AdminRole"), None)
    assert stub.calls == []
    assert result["body"].startswith("Not reverted")


@pytest.mark.parametrize("role", ["TLZDeploymentRole", "tlz-scp-auto-revert-lambda"])
def test_scp_revert_skips_the_deployment_role_and_its_own_role(revert, role):
    stub, handler = revert
    result = handler.lambda_handler(update_event("p-managed", role), None)
    assert stub.calls == []
    assert result["body"].startswith("Skipped")


def role_name(tf_file, resource):
    block = re.search(r'resource "aws_iam_role" "' + resource + r'" \{.*?\n\s*name\s*=\s*"([^"]+)"',
                      (ORG / tf_file).read_text(), re.S)
    return block.group(1)


@pytest.mark.parametrize("tf_file, resource", [
    ("policy-strategy.tf", "policy_strategy_detach_lambda"),
    ("quarantine.tf", "quarantine_auto_detach_lambda"),
])
def test_scp_revert_leaves_the_sibling_detach_functions_alone(revert, tf_file, resource):
    # regression: re-attaching after these
    # functions gave an allow-list target FullAWSAccess back.
    stub, handler = revert
    event = update_event("p-FullAWSAccess", role_name(tf_file, resource))
    event["detail"]["eventName"] = "DetachPolicy"
    event["detail"]["requestParameters"]["targetId"] = "ou-a"
    result = handler.lambda_handler(event, None)
    assert stub.calls == []
    assert result["body"].startswith("Skipped")


def test_quarantine_detach_default_names_the_tlz_pipeline():
    variables = (ORG / "variables.tf").read_text()
    default = re.search(r'variable "quarantine_detach_pipeline_names" \{.*?default\s*=\s*(\[.*?\])', variables, re.S)
    pipeline = re.search(r'resource "aws_codepipeline" "this" \{.*?name\s*=\s*"([^"]+)"',
                         (REPO / "modules/pipeline/codepipeline.tf").read_text(), re.S)
    assert json.loads(default.group(1)) == [pipeline.group(1)]
