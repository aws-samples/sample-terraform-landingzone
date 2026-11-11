"""regression: the End-User-Policy boundary let a bounded principal grant any role more rights.

Role policy writes (attach, detach, put, delete) were allowed on every role not
tagged ManagedBy=TLZ, so a bounded principal with IAM rights could attach
AdministratorAccess to an unbounded role and use it. They are now allowed only
on roles that carry the same boundary.

The deny that enforces the boundary on role creation compared the boundary ARN
with StringNotEquals against a wildcard value. StringNotEquals does not expand
wildcards, so it denied every role creation, boundary supplied or not. It now
uses ArnNotLike.
"""

import json
from pathlib import Path

POLICY = Path(__file__).resolve().parents[1] / "configurations/policies/general/end-user-policy.json"
ROLE_POLICY_WRITES = {"iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy"}


def _statements():
    return json.loads(POLICY.read_text())["Statement"]


def _actions(stmt):
    action = stmt.get("Action", [])
    return {action} if isinstance(action, str) else set(action)


def test_regression_role_policy_writes_require_boundary():
    granting = [s for s in _statements() if s["Effect"] == "Allow" and _actions(s) & ROLE_POLICY_WRITES]
    assert granting, "no statement grants role policy writes"
    covered = set()
    for stmt in granting:
        boundary = stmt.get("Condition", {}).get("ArnLike", {}).get("iam:PermissionsBoundary", "")
        assert boundary.endswith(":policy/End-User-Policy"), stmt["Sid"]
        covered |= _actions(stmt)
    assert ROLE_POLICY_WRITES <= covered


def test_regression_boundary_deny_uses_arn_operator():
    stmt = next(s for s in _statements() if s["Sid"] == "EnforceBoundaryOnRoleCreation")
    assert stmt["Effect"] == "Deny"
    assert _actions(stmt) == {"iam:CreateRole", "iam:PutRolePermissionsBoundary"}
    assert set(stmt["Condition"]) == {"ArnNotLike"}
    assert stmt["Condition"]["ArnNotLike"]["iam:PermissionsBoundary"] == "arn:*:iam::*:policy/End-User-Policy"
