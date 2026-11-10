"""regression: a guardrail exemption name could be claimed in a member account.

Every guardrail document under configurations/policies/organization/ exempts
principals by role name (``aws:PrincipalArn`` conditions). ``TLZDeploymentRole``
and ``OrganizationAccountAccessRole`` are exempt in every core SCP and in the
RCP; if they were missing from the resource list of ``ProtectIAMRoles`` in
tlz-core-guardrails-2.json, a member-account administrator could create a
role of such a name and act outside every guardrail.

This test reads the shipped JSON: every role name a ``tlz-*`` guardrail
document exempts must also be a resource of ``ProtectIAMRoles``, so a name
added to an exemption list without its protection fails here.
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO / "configurations/policies/organization"
ROLE_PREFIX = "arn:*:iam::*:role/"


def _exempt_role_names(node):
    """Role names in every aws:PrincipalArn condition value below ``node``."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() == "aws:principalarn":
                for arn in value if isinstance(value, list) else [value]:
                    if arn.startswith(ROLE_PREFIX):
                        yield arn[len(ROLE_PREFIX):]
            else:
                yield from _exempt_role_names(value)
    elif isinstance(node, list):
        for item in node:
            yield from _exempt_role_names(item)


def _protected_role_names():
    return {arn[len(ROLE_PREFIX):] for arn in _protect_iam_roles()["Resource"]}


def test_every_exempt_role_name_is_protected():
    protected = _protected_role_names()
    unprotected = {}
    for path in sorted(POLICY_DIR.glob("tlz-*.json")):
        names = set(_exempt_role_names(json.loads(path.read_text())))
        missing = sorted(names - protected)
        if missing:
            unprotected[path.name] = missing
    assert not unprotected, (
        "exempt role names a member-account principal could claim, missing from "
        f"ProtectIAMRoles in tlz-core-guardrails-2.json: {unprotected}"
    )


def _protect_iam_roles():
    doc = json.loads((POLICY_DIR / "tlz-core-guardrails-2.json").read_text())
    (stmt,) = [s for s in doc["Statement"] if s["Sid"] == "ProtectIAMRoles"]
    return stmt


def _pipeline_roles_that_assume_the_deployment_role():
    """Names of the modules/pipeline roles whose inline policy grants
    sts:AssumeRole on var.deployment_role_arns, read from the .tf files."""
    names, callers = {}, set()
    for tf in sorted((REPO / "modules/pipeline").glob("*.tf")):
        for block in re.split(r'\n(?=resource ")', tf.read_text()):
            role = re.match(r'resource "aws_iam_role" "(\w+)" \{.*?\n\s*name\s*=\s*"([^"]+)"', block, re.S)
            if role:
                names[role.group(1)] = role.group(2)
            if block.startswith('resource "aws_iam_role_policy" ') and "deployment_role_arns" in block:
                ref = re.search(r"\brole\s*=\s*aws_iam_role\.(\w+)", block)
                if ref:
                    callers.add(ref.group(1))
    return {names[c] for c in callers}


def test_pipeline_roles_may_assume_the_deployment_role():
    # regression: with TLZDeploymentRole a
    # protected resource, sts:AssumeRole on it is denied to every principal
    # outside the exemption, so the deployment account's pipeline roles must
    # be exempt by exact name, and protected so no one else can claim them.
    roles = _pipeline_roles_that_assume_the_deployment_role()
    assert roles == {"TLZPipelineRole", "TLZCodeBuildServiceRole", "TLZECSTaskRole", "TLZExternalCIRole"}
    stmt = _protect_iam_roles()
    assert "sts:AssumeRole" not in stmt["NotAction"]
    assert ROLE_PREFIX + "TLZDeploymentRole" in stmt["Resource"]
    exempt = set(stmt["Condition"]["ArnNotLike"]["aws:PrincipalARN"])
    for name in roles:
        assert ROLE_PREFIX + name in exempt, f"{name} cannot assume TLZDeploymentRole"
        assert ROLE_PREFIX + name in stmt["Resource"], f"{name} is exempt but not protected"


def test_service_linked_role_entries_carry_their_path():
    # regression: a service-linked role lives
    # under role/aws-service-role/<service>/, so an entry without that path
    # matches no role and protects nothing. The pathless AWSServiceRoleForConfig
    # entry was removed for that reason; a new entry must name the full path.
    stmt = _protect_iam_roles()
    entries = stmt["Resource"] + stmt["Condition"]["ArnNotLike"]["aws:PrincipalARN"]
    for arn in entries:
        path = arn[len(ROLE_PREFIX):]
        if path.rsplit("/", 1)[-1].startswith("AWSServiceRoleFor"):
            assert path.startswith("aws-service-role/"), arn


def test_exemption_lists_are_found():
    # Guards the test above against passing vacuously after a key rename.
    names = set()
    for path in POLICY_DIR.glob("tlz-*.json"):
        names |= set(_exempt_role_names(json.loads(path.read_text())))
    assert {"TLZDeploymentRole", "OrganizationAccountAccessRole"} <= names
