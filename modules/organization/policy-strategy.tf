# =============================================================================
# Policy strategy: allow-list entries detach the AWS default policy
# =============================================================================
# An SCP or RCP entry with strategy = "allow-list" only restricts anything
# once the AWS default policy (FullAWSAccess / RCPFullAWSAccess) no longer
# grants everything alongside it. Those default attachments were created by
# AWS, not by this configuration, so no aws_organizations_policy_attachment
# can manage them; a module-owned function detaches them at deployment time
# and re-attaches them on removal — the pattern of the quarantine automation
# (inline template packaged with archive_file), invoked synchronously like
# the Macie session settings. Everything hangs on enable_allow_list_detach
# (default false): without the switch nothing is created, and the variable
# validations reject allow-list entries so the strategy cannot silently stay
# without effect.

locals {
  # Detach set per policy type: the resolved targets of every allow-list
  # entry, deduplicated — two entries sharing a target detach once.
  scp_allow_list_target_ids = distinct([
    for att in local.scp_attachments :
    lookup(local.target_name_to_id, att.target, att.target)
    if contains([
      for scp in var.service_control_policies : scp.name
      if scp.strategy == "allow-list"
    ], att.policy)
  ])

  rcp_allow_list_target_ids = distinct([
    for att in local.rcp_attachments :
    lookup(local.target_name_to_id, att.target, att.target)
    if contains([
      for rcp in var.resource_control_policies : rcp.name
      if rcp.strategy == "allow-list"
    ], att.policy)
  ])

  policy_strategy_detach_enabled = var.enable_allow_list_detach && (
    length(local.scp_allow_list_target_ids) + length(local.rcp_allow_list_target_ids) > 0
  )

  # The function body: detach on create/update, re-attach on delete. Both
  # directions tolerate the state they want to reach (PolicyNotAttached /
  # Duplicate), so re-running an apply or unwinding a destroy stays clean.
  # An update also re-attaches the default policy to every target that left
  # the list since the last apply (prev_input, which the provider sends with
  # an update): that target's allow-list attachment is destroyed in the same
  # apply, and without the re-attach it would keep no Allow policy at all.
  # tests/test_regression_org_lambda_handlers.py runs this code offline.
  policy_strategy_detach_lambda_code = <<-PYTHON
    """Detaches the AWS default policy from allow-list targets.

    Invoked synchronously by Terraform (aws_lambda_invocation, lifecycle
    scope CRUD). create/update detach the named policy from every target;
    update re-attaches it to targets that left the list; delete re-attaches
    it everywhere, so removing the configuration restores the AWS default
    state.
    """
    import json
    import logging

    import boto3

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    organizations = boto3.client("organizations")


    def _detach(policy_id, target_id):
        try:
            organizations.detach_policy(PolicyId=policy_id, TargetId=target_id)
            logger.info("Detached %s from %s", policy_id, target_id)
        except organizations.exceptions.PolicyNotAttachedException:
            logger.info(
                "%s already detached from %s — skipping.", policy_id, target_id
            )


    def _attach(policy_id, target_id):
        try:
            organizations.attach_policy(PolicyId=policy_id, TargetId=target_id)
            logger.info("Re-attached %s to %s", policy_id, target_id)
        except organizations.exceptions.DuplicatePolicyAttachmentException:
            logger.info(
                "%s already attached to %s — skipping.", policy_id, target_id
            )


    def lambda_handler(event, context):
        tf = event.get("tf", {})
        action = tf.get("action", "create")
        policy_id = event["policy_id"]
        target_ids = event["target_ids"]
        if action in ("create", "update"):
            previous = []
            if action == "update":
                previous = (tf.get("prev_input") or {}).get("target_ids", [])
            # Re-attach first, so a target that left the list is never bare.
            for target_id in previous:
                if target_id not in target_ids:
                    _attach(policy_id, target_id)
            for target_id in target_ids:
                _detach(policy_id, target_id)
        else:
            for target_id in target_ids:
                _attach(policy_id, target_id)
        return {"statusCode": 200, "body": json.dumps({"action": action})}
  PYTHON
}

data "archive_file" "policy_strategy_detach" {
  count = local.policy_strategy_detach_enabled ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/.archive/policy_strategy_detach.zip"

  source {
    content  = local.policy_strategy_detach_lambda_code
    filename = "index.py"
  }
}

resource "aws_iam_role" "policy_strategy_detach_lambda" {
  count = local.policy_strategy_detach_enabled ? 1 : 0

  name = "tlz-policy-strategy-detach-lambda"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_iam_role_policy" "policy_strategy_detach_lambda" {
  count = local.policy_strategy_detach_enabled ? 1 : 0

  name = "policy-strategy-detach-permissions"
  role = aws_iam_role.policy_strategy_detach_lambda[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/organization/policy-strategy-detach-policy.json", {
    arn_prefix = local.arn_prefix
  })))
}

resource "aws_lambda_function" "policy_strategy_detach" {
  count = local.policy_strategy_detach_enabled ? 1 : 0

  function_name = "tlz-policy-strategy-detach"
  description   = "Detaches the AWS default policy from allow-list strategy targets"
  role          = aws_iam_role.policy_strategy_detach_lambda[0].arn
  handler       = "index.lambda_handler"
  runtime       = "python3.12"
  timeout       = 60

  # The function is only ever invoked synchronously by Terraform, one call
  # per policy type and apply — a single reserved execution is all it can use.
  reserved_concurrent_executions = 1

  filename         = data.archive_file.policy_strategy_detach[0].output_path
  source_code_hash = data.archive_file.policy_strategy_detach[0].output_base64sha256

  depends_on = [aws_iam_role_policy.policy_strategy_detach_lambda]
}

# The function's own execution log group. Lambda creates /aws/lambda/<function
# name> implicitly on the first invocation when nothing has declared it: the
# group then sits outside the state, carries no retention and is never
# destroyed with the stack. Same class as aws_cloudwatch_log_group.account_move
# in this module, and as the monitoring module's two functions
# (modules/monitoring/README.md, "Lambda execution log groups"). The name
# derives from the function so the two cannot drift apart. The invocations
# below depend on it — this function is invoked synchronously by Terraform
# during the apply, so without that edge the very apply that creates the group
# could invoke the function first. CreateLogGroup is create-only: an account
# where the function has already run must import the group (README, "Lambda
# execution log groups").
resource "aws_cloudwatch_log_group" "policy_strategy_detach" {
  count = local.policy_strategy_detach_enabled ? 1 : 0

  name              = "/aws/lambda/${aws_lambda_function.policy_strategy_detach[0].function_name}"
  retention_in_days = var.policy_strategy_detach_log_retention_days
  kms_key_id        = var.policy_strategy_detach_log_kms_key_arn != "" ? var.policy_strategy_detach_log_kms_key_arn : null
}

# One invocation per policy type. depends_on the attachments: the entry's own
# policy reaches the target before the default policy leaves it, and on
# destroy the re-attach runs first — no target is ever left bare.
resource "aws_lambda_invocation" "scp_allow_list_detach" {
  count = local.policy_strategy_detach_enabled && length(local.scp_allow_list_target_ids) > 0 ? 1 : 0

  function_name   = aws_lambda_function.policy_strategy_detach[0].function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    policy_id  = "p-FullAWSAccess"
    target_ids = local.scp_allow_list_target_ids
  })

  # The log group must exist before this invocation, or Lambda creates it
  # implicitly during the same apply that declares it.
  depends_on = [
    aws_organizations_policy_attachment.scp,
    aws_cloudwatch_log_group.policy_strategy_detach,
  ]
}

resource "aws_lambda_invocation" "rcp_allow_list_detach" {
  count = local.policy_strategy_detach_enabled && length(local.rcp_allow_list_target_ids) > 0 ? 1 : 0

  function_name   = aws_lambda_function.policy_strategy_detach[0].function_name
  lifecycle_scope = "CRUD"

  input = jsonencode({
    policy_id  = "rp-FullAWSAccess"
    target_ids = local.rcp_allow_list_target_ids
  })

  # Same ordering as the SCP invocation above.
  depends_on = [
    aws_organizations_policy_attachment.rcp,
    aws_cloudwatch_log_group.policy_strategy_detach,
  ]
}
