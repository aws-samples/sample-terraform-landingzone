"""regression: the deployment role granted service:* for the security services and Identity Center; the narrow policy document is pinned to the modules.

``configurations/policies/deployment/role-inline-policy.json`` grants
``guardduty:*``, ``securityhub:*``, ``macie2:*``, ``access-analyzer:*``,
``sso:*``, ``sso-directory:*`` and ``identitystore:*`` on ``*``. The second
document, ``role-inline-policy-narrow.json``, replaces those seven grants by
the actions the modules' resource types call and is selected by the module
flag ``narrow_grants`` (default false, so the first document stays the
default). The three other wildcards on the same statement -- ``budgets:*``,
``controltower:*``, ``servicecatalog:*`` -- are out of scope and stay.

What is pinned, and how:

  * NEEDS below is the table: one row per resource type (or data source) the
    modules declare for an in-scope service, with the actions the provider
    calls for it (create, read, update, delete, tag, the lookups). The
    resource types are DERIVED from ``modules/**/*.tf``, never listed by
    hand: a resource type the modules declare without a row, a row whose
    resource type the modules no longer declare, an action a row names that
    the narrow document lacks, and an in-scope action in the narrow document
    that no row explains -- each reddens the coverage test by name.
  * The narrow document carries no ``<in-scope service>:*`` and no partial
    wildcard on an in-scope service; every action in it is ``service:Action``
    with a service prefix today's document already has.
  * Stripping the in-scope actions from both documents leaves the same
    residue: the two documents differ ONLY in the in-scope grants.
  * The narrow document grants nowhere more than today's: every action in it
    is matched by an Allow on ``*`` in today's document (IAM wildcard match,
    case-insensitive), and no statement carries a NotAction, NotResource or
    Condition today's lacks.
  * The compact rendering (what ``jsonencode(jsondecode(file(...)))`` sends)
    stays under the IAM inline-policy limit of 10240 characters, so an apply
    with the flag on does not fail at PutRolePolicy.

``sso-directory`` has no row and no action on purpose: the modules call the
identitystore API only, so the narrow document grants nothing on that prefix
-- the test asserts that too.
"""

import copy
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POLICIES = REPO / "configurations/policies/deployment"
TODAY = POLICIES / "role-inline-policy.json"
NARROW = POLICIES / "role-inline-policy-narrow.json"

# IAM service prefix per resource-type prefix; sso-directory has no resource type.
IN_SCOPE = {
    "aws_guardduty_": "guardduty",
    "aws_securityhub_": "securityhub",
    "aws_macie2_": "macie2",
    "aws_accessanalyzer_": "access-analyzer",
    "aws_ssoadmin_": "sso",
    "aws_identitystore_": "identitystore",
}
IN_SCOPE_SERVICES = frozenset(IN_SCOPE.values()) | {"sso-directory"}
IAM_INLINE_POLICY_LIMIT = 10240

BLOCK_RE = re.compile(
    r'\b(resource|data)\s+"(aws_(?:guardduty|securityhub|macie2|accessanalyzer|ssoadmin|identitystore)[a-z0-9_]*)"'
)
ACTION_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*?]+$")

# The table. Key: resource type as declared (``data.`` prefix for a data
# source); value: the actions the provider calls for it.
_ORG_ADMIN = ["EnableOrganizationAdminAccount", "DisableOrganizationAdminAccount", "ListOrganizationAdminAccounts"]
_GD_ORG_CONFIG = ["guardduty:UpdateOrganizationConfiguration", "guardduty:DescribeOrganizationConfiguration"]
_GD_TAGS = ["guardduty:ListTagsForResource", "guardduty:TagResource", "guardduty:UntagResource"]
_SSO_PROVISION = ["sso:ProvisionPermissionSet", "sso:DescribePermissionSetProvisioningStatus"]
NEEDS = {
    # modules/security/guardduty.tf, modules/security-org-config/main.tf
    "aws_guardduty_detector": ["guardduty:CreateDetector", "guardduty:GetDetector", "guardduty:UpdateDetector",
                               "guardduty:DeleteDetector"] + _GD_TAGS,
    "aws_guardduty_detector_feature": ["guardduty:GetDetector", "guardduty:UpdateDetector"],
    "aws_guardduty_organization_admin_account": ["guardduty:" + a for a in _ORG_ADMIN],
    "aws_guardduty_organization_configuration": _GD_ORG_CONFIG,
    "aws_guardduty_organization_configuration_feature": _GD_ORG_CONFIG,
    "aws_guardduty_publishing_destination": ["guardduty:CreatePublishingDestination",
                                             "guardduty:DescribePublishingDestination",
                                             "guardduty:UpdatePublishingDestination",
                                             "guardduty:DeletePublishingDestination"],
    "aws_guardduty_malware_protection_plan": ["guardduty:CreateMalwareProtectionPlan",
                                              "guardduty:GetMalwareProtectionPlan",
                                              "guardduty:UpdateMalwareProtectionPlan",
                                              "guardduty:DeleteMalwareProtectionPlan"] + _GD_TAGS,
    # modules/security/securityhub.tf, modules/security-org-config/main.tf
    "aws_securityhub_account": ["securityhub:EnableSecurityHub", "securityhub:DescribeHub",
                                "securityhub:UpdateSecurityHubConfiguration", "securityhub:DisableSecurityHub"],
    "aws_securityhub_organization_admin_account": ["securityhub:" + a for a in _ORG_ADMIN],
    "aws_securityhub_organization_configuration": ["securityhub:UpdateOrganizationConfiguration",
                                                   "securityhub:DescribeOrganizationConfiguration"],
    "aws_securityhub_standards_subscription": ["securityhub:BatchEnableStandards",
                                               "securityhub:BatchDisableStandards",
                                               "securityhub:GetEnabledStandards"],
    "aws_securityhub_standards_control": ["securityhub:UpdateStandardsControl",
                                          "securityhub:DescribeStandardsControls",
                                          "securityhub:GetEnabledStandards"],
    "aws_securityhub_finding_aggregator": ["securityhub:CreateFindingAggregator", "securityhub:GetFindingAggregator",
                                           "securityhub:UpdateFindingAggregator",
                                           "securityhub:DeleteFindingAggregator"],
    "aws_securityhub_automation_rule": ["securityhub:CreateAutomationRule", "securityhub:BatchGetAutomationRules",
                                        "securityhub:BatchUpdateAutomationRules",
                                        "securityhub:BatchDeleteAutomationRules",
                                        "securityhub:ListTagsForResource", "securityhub:TagResource",
                                        "securityhub:UntagResource"],
    # modules/security-org-config/consumers.tf: the member enrolment of the
    # administrator; the provider disassociates before it deletes.
    "aws_securityhub_member": ["securityhub:CreateMembers", "securityhub:GetMembers",
                               "securityhub:DisassociateMembers", "securityhub:DeleteMembers"],
    # modules/security/macie.tf, modules/security-org-config/main.tf
    "aws_macie2_account": ["macie2:EnableMacie", "macie2:GetMacieSession", "macie2:UpdateMacieSession",
                           "macie2:DisableMacie"],
    "aws_macie2_organization_admin_account": ["macie2:" + a for a in _ORG_ADMIN],
    "aws_macie2_classification_export_configuration": ["macie2:PutClassificationExportConfiguration",
                                                       "macie2:GetClassificationExportConfiguration"],
    # modules/security/access-analyzer.tf
    "aws_accessanalyzer_analyzer": ["access-analyzer:CreateAnalyzer", "access-analyzer:GetAnalyzer",
                                    "access-analyzer:UpdateAnalyzer", "access-analyzer:DeleteAnalyzer",
                                    "access-analyzer:ListTagsForResource", "access-analyzer:TagResource",
                                    "access-analyzer:UntagResource"],
    # modules/accounts/sso.tf
    "data.aws_ssoadmin_instances": ["sso:ListInstances"],
    "data.aws_ssoadmin_permission_set": ["sso:ListPermissionSets", "sso:DescribePermissionSet",
                                         "sso:ListTagsForResource"],
    "aws_ssoadmin_permission_set": ["sso:CreatePermissionSet", "sso:DescribePermissionSet",
                                    "sso:UpdatePermissionSet", "sso:DeletePermissionSet",
                                    "sso:ListTagsForResource", "sso:TagResource", "sso:UntagResource"] + _SSO_PROVISION,
    "aws_ssoadmin_permission_set_inline_policy": ["sso:PutInlinePolicyToPermissionSet",
                                                  "sso:GetInlinePolicyForPermissionSet",
                                                  "sso:DeleteInlinePolicyFromPermissionSet"] + _SSO_PROVISION,
    "aws_ssoadmin_managed_policy_attachment": ["sso:AttachManagedPolicyToPermissionSet",
                                               "sso:ListManagedPoliciesInPermissionSet",
                                               "sso:DetachManagedPolicyFromPermissionSet"] + _SSO_PROVISION,
    "aws_ssoadmin_customer_managed_policy_attachment": ["sso:AttachCustomerManagedPolicyReferenceToPermissionSet",
                                                        "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
                                                        "sso:DetachCustomerManagedPolicyReferenceFromPermissionSet"]
                                                       + _SSO_PROVISION,
    "aws_ssoadmin_permissions_boundary_attachment": ["sso:PutPermissionsBoundaryToPermissionSet",
                                                     "sso:GetPermissionsBoundaryForPermissionSet",
                                                     "sso:DeletePermissionsBoundaryFromPermissionSet"]
                                                    + _SSO_PROVISION,
    "aws_ssoadmin_account_assignment": ["sso:CreateAccountAssignment", "sso:DescribeAccountAssignmentCreationStatus",
                                        "sso:ListAccountAssignments", "sso:DeleteAccountAssignment",
                                        "sso:DescribeAccountAssignmentDeletionStatus"],
    "aws_identitystore_user": ["identitystore:CreateUser", "identitystore:DescribeUser",
                               "identitystore:UpdateUser", "identitystore:DeleteUser"],
    "data.aws_identitystore_user": ["identitystore:GetUserId", "identitystore:DescribeUser",
                                    "identitystore:ListUsers"],
    "data.aws_identitystore_group": ["identitystore:GetGroupId", "identitystore:DescribeGroup",
                                     "identitystore:ListGroups"],
}


def _load(path):
    doc = json.loads(path.read_text())
    assert doc.get("Version") == "2012-10-17", "%s: unexpected policy Version %r" % (path.name, doc.get("Version"))
    assert isinstance(doc.get("Statement"), list) and doc["Statement"], "%s: no Statement list" % path.name
    return doc


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _actions(statement):
    return _as_list(statement.get("Action", []))


def _service(action):
    return action.split(":", 1)[0]


def _in_scope_actions(doc):
    return [a for st in doc["Statement"] for a in _actions(st) if _service(a) in IN_SCOPE_SERVICES]


def _residue(doc):
    """The document without its in-scope actions; a statement left empty is dropped."""
    out = copy.deepcopy(doc)
    kept = []
    for st in out["Statement"]:
        remaining = [a for a in _actions(st) if _service(a) not in IN_SCOPE_SERVICES]
        if remaining:
            st["Action"] = remaining
            kept.append(st)
    out["Statement"] = kept
    return out


def _iam_match(pattern, action):
    """IAM action matching: ``*`` any run, ``?`` one character, case-insensitive."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, action, re.IGNORECASE) is not None


def _declared_resource_types():
    """Resource types and data sources the modules declare for the in-scope services, with their files."""
    found = {}
    for tf in sorted((REPO / "modules").rglob("*.tf")):
        if any(part.startswith(".") for part in tf.relative_to(REPO).parts):
            continue  # provider caches, staged live-test fixtures
        for kind, rtype in BLOCK_RE.findall(tf.read_text()):
            key = ("data." if kind == "data" else "") + rtype
            found.setdefault(key, set()).add(tf.relative_to(REPO).as_posix())
    assert found, "no module declares a resource of an in-scope service: nothing to pin"
    return found


def _service_of_resource_type(key):
    rtype = key[len("data."):] if key.startswith("data.") else key
    for prefix, service in IN_SCOPE.items():
        if rtype.startswith(prefix):
            return service
    raise AssertionError("resource type %s belongs to no in-scope service" % key)


def test_narrow_document_carries_no_in_scope_wildcard():
    narrow = _load(NARROW)
    problems = []
    for st in narrow["Statement"]:
        for action in _actions(st):
            if _service(action) in IN_SCOPE_SERVICES and ("*" in action or "?" in action):
                problems.append("%s: %s" % (st.get("Sid"), action))
    assert not problems, "in-scope wildcards in the narrow document:\n" + "\n".join(problems)
    assert not [a for a in _in_scope_actions(narrow) if _service(a) == "sso-directory"], (
        "the modules call the identitystore API only; the narrow document must grant no sso-directory action")
    # the definition of "in scope" still matches today's document
    today_in_scope = sorted(_in_scope_actions(_load(TODAY)))
    assert today_in_scope == sorted(s + ":*" for s in IN_SCOPE_SERVICES), (
        "today's document no longer grants exactly the seven in-scope service:* -- re-read the scope above "
        "before trusting this pin: %s" % today_in_scope)


def test_every_action_is_service_colon_action_with_a_known_prefix():
    today, narrow = _load(TODAY), _load(NARROW)
    known = {_service(a) for st in today["Statement"] for a in _actions(st)}
    problems = []
    for st in narrow["Statement"]:
        for action in _actions(st):
            if not ACTION_RE.match(action):
                problems.append("%s: %r is not service:Action" % (st.get("Sid"), action))
            elif _service(action) not in known:
                problems.append("%s: %s names a service today's document does not grant" % (st.get("Sid"), action))
    assert not problems, "\n".join(problems)


def test_modules_resource_types_are_covered_by_the_table_and_the_document():
    narrow = _load(NARROW)
    granted = set(_in_scope_actions(narrow))
    declared = _declared_resource_types()
    problems = []
    for key in sorted(declared):
        if key not in NEEDS:
            problems.append("%s (in %s) has no row in NEEDS -- add the actions it needs to the table and to %s" % (
                key, ", ".join(sorted(declared[key])), NARROW.name))
    for key in sorted(NEEDS):
        if key not in declared:
            problems.append("NEEDS row %s names a resource type no module declares any more -- drop the row" % key)
    for key, actions in sorted(NEEDS.items()):
        service = _service_of_resource_type(key)
        for action in actions:
            if _service(action) != service:
                problems.append("NEEDS row %s names %s, which is not a %s action" % (key, action, service))
            elif action not in granted:
                problems.append("%s needs %s, which %s does not grant" % (key, action, NARROW.name))
    explained = {a for actions in NEEDS.values() for a in actions}
    for action in sorted(granted - explained):
        problems.append("%s grants %s, which no NEEDS row explains" % (NARROW.name, action))
    for key in sorted(declared):
        print("narrow grants pin: %s <- %d action(s)" % (key, len(NEEDS.get(key, []))))
    assert not problems, "\n".join(problems)


def test_documents_differ_only_in_the_in_scope_grants():
    today, narrow = _load(TODAY), _load(NARROW)
    assert _residue(today) == _residue(narrow), (
        "outside the in-scope grants the two documents differ -- role-inline-policy.json is the default and "
        "role-inline-policy-narrow.json may change nothing but the seven service:* grants")
    today_sids = [st.get("Sid") for st in today["Statement"]]
    narrow_sids = [st.get("Sid") for st in narrow["Statement"]]
    assert today_sids == narrow_sids, "statement order or Sids differ: %s vs %s" % (today_sids, narrow_sids)
    for wildcard in ("budgets:*", "controltower:*", "servicecatalog:*"):
        for name, doc in (("today's", today), ("the narrow", narrow)):
            assert any(wildcard in _actions(st) for st in doc["Statement"]), (
                "%s is out of scope for the narrowing and must stay in %s document" % (wildcard, name))


def test_narrow_document_grants_nowhere_more_than_todays():
    today, narrow = _load(TODAY), _load(NARROW)
    allows = [st for st in today["Statement"] if st.get("Effect") == "Allow" and "*" in _as_list(st.get("Resource"))
              and "Condition" not in st and "NotAction" not in st and "NotResource" not in st]
    patterns = [a for st in allows for a in _actions(st)]
    problems = []
    for st in narrow["Statement"]:
        sid = st.get("Sid")
        if st.get("Effect") != "Allow":
            problems.append("%s: Effect %r -- the document is an allow list like today's" % (sid, st.get("Effect")))
        for field in ("NotAction", "NotResource", "Condition", "Principal", "NotPrincipal"):
            if field in st:
                problems.append("%s: carries %s, which today's document does not" % (sid, field))
        for action in _actions(st):
            if not any(_iam_match(p, action) for p in patterns):
                problems.append("%s: %s is not covered by any Allow on * in today's document" % (sid, action))
    assert not problems, "the narrow document grants more than today's:\n" + "\n".join(problems)


def test_narrow_document_fits_the_iam_inline_policy_limit():
    for path in (TODAY, NARROW):
        compact = json.dumps(_load(path), separators=(",", ":"))
        print("%s: %d compact characters" % (path.name, len(compact)))
        assert len(compact) <= IAM_INLINE_POLICY_LIMIT, (
            "%s renders to %d characters, over the IAM inline-policy limit of %d -- PutRolePolicy would refuse it"
            % (path.name, len(compact), IAM_INLINE_POLICY_LIMIT))
