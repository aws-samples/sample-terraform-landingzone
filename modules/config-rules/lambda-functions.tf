# =============================================================================
# Configuration-supplied Lambda functions for custom rules and remediations
# =============================================================================
# custom_rules[].lambda and remediation_configs[].target_document_lambda
# describe functions the module creates behind enable_custom_rule_lambdas.
# The function code arrives as a string from the configuration layer (the
# loader resolves a source_file path to its content — a path would not
# survive the deployment cache) and is packaged with archive_file, the
# established packaging of module-owned functions. The module reads no user
# file and executes no script.

data "aws_caller_identity" "current" {}

locals {
  dns_suffix = data.aws_partition.current.dns_suffix
  account_id = data.aws_caller_identity.current.account_id

  # Entries that ask for a module-created function, gated by the switch (the
  # variable validations reject a lambda block behind a disabled switch, so
  # the gate here only keeps the derived plan consistent with the switch).
  custom_rule_lambdas = var.enable_custom_rule_lambdas ? {
    for rule in var.custom_rules : rule.name => rule.lambda
    if rule.lambda != null
  } : {}

  remediation_lambdas = var.enable_custom_rule_lambdas ? {
    for r in var.remediation_configs : r.rule_name => r.target_document_lambda
    if r.target_document_lambda != null
  } : {}

  # Both kinds share packaging, role and function mechanics; the merged map
  # keys them by their distinct function names.
  config_lambda_functions = merge(
    { for name, l in local.custom_rule_lambdas : "tlz-config-rule-${name}" => l },
    { for name, l in local.remediation_lambdas : "tlz-remediation-${name}" => l },
  )

  # The source file name inside the archive follows the handler's module part
  # and the runtime's language: handler index.handler with python3.12 becomes
  # index.py, with nodejs20.x index.js (CommonJS).
  config_lambda_source_filenames = {
    for fn_name, l in local.config_lambda_functions :
    fn_name => "${split(".", l.handler)[0]}.${startswith(l.runtime, "python") ? "py" : "js"}"
  }

  # Function ARN per rule / per remediation entry, read by main.tf.
  custom_rule_lambda_arns = {
    for name, _ in local.custom_rule_lambdas :
    name => aws_lambda_function.config["tlz-config-rule-${name}"].arn
  }
  remediation_lambda_arns = {
    for name, _ in local.remediation_lambdas :
    name => aws_lambda_function.config["tlz-remediation-${name}"].arn
  }
}

data "archive_file" "config_lambda" {
  for_each = local.config_lambda_functions

  type        = "zip"
  output_path = "${path.module}/lambda-packages/${each.key}.zip"

  source {
    content  = each.value.source_code
    filename = local.config_lambda_source_filenames[each.key]
  }
}

resource "aws_iam_role" "config_lambda" {
  for_each = local.config_lambda_functions

  name = each.key

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/general/lambda-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))
}

# The execution policy comes from the configuration layer, scoped by its
# author. It is deliberately not authored here: only the rule's author knows
# what the evaluator has to read.
resource "aws_iam_role_policy" "config_lambda" {
  for_each = local.config_lambda_functions

  name   = "function-policy"
  role   = aws_iam_role.config_lambda[each.key].id
  policy = each.value.role_policy
}

# The log statement is module-owned and limited to the function's own log
# group, so a configuration-supplied policy cannot forget it.
resource "aws_iam_role_policy" "config_lambda_logs" {
  for_each = local.config_lambda_functions

  name = "function-logs"
  role = aws_iam_role.config_lambda[each.key].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/general/lambda-logs-policy.json", {
    log_group_arn = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${each.key}:*"
  })))
}

resource "aws_lambda_function" "config" {
  for_each = local.config_lambda_functions

  function_name = each.key
  role          = aws_iam_role.config_lambda[each.key].arn
  handler       = each.value.handler
  runtime       = each.value.runtime
  timeout       = each.value.timeout

  filename         = data.archive_file.config_lambda[each.key].output_path
  source_code_hash = data.archive_file.config_lambda[each.key].output_base64sha256

  # The module convention for control-plane functions (quarantine automation,
  # log-group onboarding, Firehose processor): a bounded reservation instead
  # of an open account-pool share.
  reserved_concurrent_executions = 10

  depends_on = [
    aws_iam_role_policy.config_lambda,
    aws_iam_role_policy.config_lambda_logs,
  ]
}

# Each function's own execution log group, one per entry of the same map that
# creates the functions. Lambda creates /aws/lambda/<function name> implicitly
# on the first invocation when nothing has declared it: the group then sits
# outside the state, carries no retention and is never destroyed with the
# stack — in every deployment, not only in a test. Same class as the monitoring
# module's two functions (modules/monitoring/README.md, "Lambda execution log
# groups").
#
# The name is built from the FUNCTION, not from the map key, for the same
# reason the module derives every other per-function value that way: the key
# and the function name are equal by construction, and a group that
# rebuilt the name itself would only agree with the function by convention.
# for_each over the identical map keeps group and function in lockstep — an
# entry cannot gain a function without gaining its group.
#
# CreateLogGroup is create-only: in an account where a function has already
# been invoked, its group exists outside the state and the apply fails with
# ResourceAlreadyExistsException for that group until it is imported (README,
# "Lambda execution log groups").
resource "aws_cloudwatch_log_group" "config_lambda" {
  for_each = local.config_lambda_functions

  name              = "/aws/lambda/${aws_lambda_function.config[each.key].function_name}"
  retention_in_days = var.config_lambda_log_retention_days
  kms_key_id        = var.config_lambda_log_kms_key_arn != "" ? var.config_lambda_log_kms_key_arn : null
}

# AWS Config invokes an organization custom rule's evaluator from every
# member account; the service principal needs the resource-based permission
# before the rule is created. Remediation functions carry no such statement:
# they are invoked through the automation document's assume role, an IAM
# path that needs no resource-based policy.
resource "aws_lambda_permission" "config_invoke" {
  for_each = local.custom_rule_lambdas

  statement_id  = "AllowConfigInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.config["tlz-config-rule-${each.key}"].function_name
  principal     = "config.${local.dns_suffix}"

  # This statement is what lets Config invoke the evaluator; the function's log
  # group must exist before the first invocation can create it implicitly. The
  # remediation functions reach their group through the for_each above — their
  # invocation path (the automation document's assume role) is not gated by any
  # resource in this module, so no edge here can order it.
  depends_on = [aws_cloudwatch_log_group.config_lambda]
}
