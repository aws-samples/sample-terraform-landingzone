# =============================================================================
# VPC flow logs — S3, CloudWatch or both
# =============================================================================

# CloudWatch Log Group for Flow Logs (destination cloudwatch or both)
resource "aws_cloudwatch_log_group" "flow_logs" {
  for_each = local.flow_log_vpcs_cloudwatch

  name = "/vpc/flow-logs/${each.key}"
  # The default of 365 days matches the retention baseline the project applies
  # to its other log groups (configurations/base/base.tfvars); long-term
  # storage beyond that lives in the central S3 log bucket.
  retention_in_days = each.value.cloudwatch_retention_days
  kms_key_id        = var.cloudwatch_logs_kms_key_arn != "" ? var.cloudwatch_logs_kms_key_arn : null

  tags = {
    Name = "${each.key}-flow-logs"
  }
}

# IAM role for VPC Flow Logs (CloudWatch destination)
resource "aws_iam_role" "flow_logs" {
  count = length(local.flow_log_vpcs_cloudwatch) > 0 ? 1 : 0

  name = "tlz-vpc-flow-logs-role"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/networking/vpc-flow-logs-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))

  tags = {
    Name = "tlz-vpc-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  count = length(local.flow_log_vpcs_cloudwatch) > 0 ? 1 : 0

  name = "tlz-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode(jsondecode(file("${path.module}/../../configurations/policies/networking/vpc-flow-logs-policy.json")))
}

# Flow logs — S3 destination
# for_each uses only statically known keys (VPC name + destination type).
# central_log_bucket_name is used only in log_destination (known at apply time is fine).
resource "aws_flow_log" "s3" {
  for_each = local.flow_log_vpcs_s3

  vpc_id = aws_vpc.this[each.key].id
  # s3_log_path replaces the derived prefix; null keeps "vpc-flow-logs/<vpc>".
  log_destination          = "${local.arn_prefix}:s3:::${var.central_log_bucket_name}/${each.value.s3_log_path != null ? each.value.s3_log_path : "vpc-flow-logs/${each.key}"}"
  log_destination_type     = "s3"
  traffic_type             = each.value.traffic_type
  max_aggregation_interval = each.value.max_aggregation_interval
  log_format               = each.value.log_format

  tags = {
    Name = "${each.key}-flow-log-s3"
  }

  lifecycle {
    precondition {
      condition     = var.central_log_bucket_name != ""
      error_message = "central_log_bucket_name must not be empty when S3 flow logs are enabled."
    }
  }
}

# Flow logs — CloudWatch destination
resource "aws_flow_log" "cloudwatch" {
  for_each = local.flow_log_vpcs_cloudwatch

  vpc_id                   = aws_vpc.this[each.key].id
  iam_role_arn             = aws_iam_role.flow_logs[0].arn
  log_destination          = aws_cloudwatch_log_group.flow_logs[each.key].arn
  traffic_type             = each.value.traffic_type
  max_aggregation_interval = each.value.max_aggregation_interval
  log_format               = each.value.log_format

  tags = {
    Name = "${each.key}-flow-log-cw"
  }

  # The drain window below must be TORN DOWN AFTER this flow log, so this flow
  # log depends on it: on destroy Terraform removes the dependent first.
  depends_on = [time_sleep.flow_log_drain]
}

# =============================================================================
# Flow-Log Drain Window — the destroy-time barrier between a flow log and its
# log group
# =============================================================================

# WHY THIS EXISTS. DeleteFlowLogs does not stop
# delivery at once: the aggregation window already in flight is still
# published, and if that publish lands after the destination log group is
# gone, the VPC flow-logs service CREATES THE GROUP AGAIN under the role this
# module builds (aws_iam_role.flow_logs, whose policy grants
# logs:CreateLogGroup). The recreated group is outside Terraform's state, so
# every `terraform destroy` of a CloudWatch flow log leaves one behind, and the
# next apply of the same configuration dies with
# `CreateLogGroup ... ResourceAlreadyExistsException`.
#
# In CloudTrail this shows as DeleteLogGroup by Terraform followed about one
# second later by CreateLogGroup from the flow-logs role. The teardown itself
# reports no error — the group comes back after it.
#
# WHY A WAIT AND NOT A SECOND DELETE: deleting the group again after the flow
# log would race the same publish and could delete a group a later apply had
# already recreated legitimately. Waiting removes the cause (there is nothing
# left to deliver) instead of repairing the symptom.
#
# WHY THIS IS NOT THE STRONGEST FIX AVAILABLE: the deterministic fix is to
# drop logs:CreateLogGroup from the flow-logs role, since this module always
# declares the destination group itself and the service therefore never needs
# to create one. That permission lives in
# configurations/policies/networking/vpc-flow-logs-policy.json, outside this
# module. Until it is removed, this barrier is a timing guarantee rather than
# an impossibility proof — it is bounded by the aggregation interval AWS
# itself publishes on, not by hope.
resource "time_sleep" "flow_log_drain" {
  for_each = local.flow_log_vpcs_cloudwatch

  # No wait on the way up — only on the way down.
  destroy_duration = "${each.value.max_aggregation_interval + 60}s"

  # This barrier must be torn down BEFORE the log group, so it depends on the
  # group. Chain on destroy: aws_flow_log.cloudwatch -> this -> log group.
  depends_on = [aws_cloudwatch_log_group.flow_logs]
}
