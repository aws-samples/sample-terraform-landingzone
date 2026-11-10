# Pipeline Module — ECS variant
# Created only when pipeline_type == "ecs"
# Resources: ECS cluster, task definition, IAM task roles, EventBridge, SNS

# --- ECS Cluster ---

resource "aws_ecs_cluster" "pipeline" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  # ECS CreateCluster is idempotent (returns an existing cluster of this name)
  # — see var.ecs_cluster_name for why an apply-test must scope this.
  name = var.ecs_cluster_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# --- IAM Role: ECS task execution role ---

resource "aws_iam_role" "ecs_execution" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  name  = "TLZECSExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.${local.dns_suffix}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  count      = var.pipeline_type == "ecs" ? 1 : 0
  role       = aws_iam_role.ecs_execution[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- IAM Role: ECS task role (assumes deployment roles) ---

resource "aws_iam_role" "ecs_task" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  name  = "TLZECSTaskRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.${local.dns_suffix}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  name  = "TLZECSTaskRole-policy"
  role  = aws_iam_role.ecs_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeDeploymentRoles"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = values(var.deployment_role_arns)
      },
      {
        Sid    = "SSMAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
        ]
        Resource = "${local.arn_prefix}:ssm:${local.region}:${local.account_id}:parameter/tlz/*"
      },
      {
        Sid      = "STSGetCaller"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

# --- KMS key for the ECS log group ---
#
# count-gated on the same condition as the log group it encrypts, so an
# unchanged (codepipeline or external) deployment still creates no key and
# pays nothing for it.

resource "aws_kms_key" "ecs_logs" {
  count = var.pipeline_type == "ecs" ? 1 : 0

  description             = "KMS key for the ECS pipeline variant's CloudWatch log group"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/security/per-account-cloudwatch-kms-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = local.account_id
    region     = local.region
    dns_suffix = local.dns_suffix
  })))
}

resource "aws_kms_alias" "ecs_logs" {
  count = var.pipeline_type == "ecs" ? 1 : 0

  name          = "alias/tlz/pipeline/ecs-logs/kms"
  target_key_id = aws_kms_key.ecs_logs[0].key_id
}

# --- CloudWatch Log Group for ECS ---

resource "aws_cloudwatch_log_group" "pipeline" {
  count             = var.pipeline_type == "ecs" ? 1 : 0
  name              = "/ecs/tlz-pipeline"
  retention_in_days = var.ecs_log_retention_in_days
  kms_key_id        = aws_kms_key.ecs_logs[0].arn
}

# --- ECS Task Definition ---
#
# The image is pinned by digest through var.ecs_task_image, whose validation
# refuses a reference without one. A mutable third-party tag would be resolved
# at task start and pulled into a task whose task role can assume every
# deployment_role_arns entry, then run against the real organization by the
# command below. The codepipeline variant pins its terragrunt download the
# same way.

resource "aws_ecs_task_definition" "pipeline" {
  count                    = var.pipeline_type == "ecs" ? 1 : 0
  family                   = "tlz-pipeline"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_execution[0].arn
  task_role_arn            = aws_iam_role.ecs_task[0].arn

  container_definitions = jsonencode([
    {
      name      = "terragrunt"
      image     = var.ecs_task_image
      essential = true
      command   = ["sh", "-c", "terragrunt run --all -- plan && echo 'Plan complete'"]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.pipeline[0].name
          "awslogs-region"        = local.region
          "awslogs-stream-prefix" = "tlz"
        }
      }
    }
  ])
}

# --- SNS Topic for Approval ---

resource "aws_sns_topic" "ecs_approval" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  # SNS CreateTopic is an upsert — see var.ecs_approval_topic_name.
  name              = var.ecs_approval_topic_name
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "ecs_approval_email" {
  count     = var.pipeline_type == "ecs" && var.approval_notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.ecs_approval[0].arn
  protocol  = "email"
  endpoint  = var.approval_notification_email
}

# --- EventBridge Rule: trigger ECS task ---
#
# Source model of this variant: a CodeCommit repository in this account, named
# by repository_name. The rule listens to "CodeCommit Repository State Change"
# events for pushes to branch_name and is scoped to exactly that repository via
# the event's resources field — without it every CodeCommit repository in the
# account started the task. This is the only trigger the variant has; the
# codepipeline variant instead sources through a CodeConnections connection,
# whose repositories emit no CodeCommit event (see codepipeline.tf, Trigger).
# The two models are mutually exclusive, which the validations on
# source_connection_arn and repository_name refuse at plan time: a connection
# ARN with the ecs variant, or a repository ID of the owner/repo form, would
# describe a trigger that never fires.

locals {
  ecs_source_repository_arn = "${local.arn_prefix}:codecommit:${local.region}:${local.account_id}:${var.repository_name}"
}

resource "aws_cloudwatch_event_rule" "ecs_trigger" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  # EventBridge PutRule is an upsert — see var.ecs_trigger_rule_name.
  name        = var.ecs_trigger_rule_name
  description = "Trigger TLZ ECS pipeline task on push to ${var.branch_name} of CodeCommit repository ${var.repository_name}"

  event_pattern = jsonencode({
    source      = ["aws.codecommit"]
    detail-type = ["CodeCommit Repository State Change"]
    resources   = [local.ecs_source_repository_arn]
    detail = {
      event         = ["referenceCreated", "referenceUpdated"]
      referenceType = ["branch"]
      referenceName = [var.branch_name]
    }
  })
}

# --- The default security group: the FACT behind the caller's word ----------
#
# ecs_use_default_security_group lets an ecs variant that names no security
# group through the validation on ecs_security_group_ids (variables.tf) — a
# refusal that runs before any provider call and therefore can only read
# VARIABLES. The flag is the caller's word about the world: nothing in that
# stage can see whether the default group of the subnets' VPC really has an
# egress rule. In a VPC this landing zone manages it has none
# (modules/networking/security-groups.tf, aws_default_security_group.vpc
# strips every rule), so a caller who sets the flag there gets a pipeline that
# cannot work — EventBridge accepts the target, every triggered task fails
# late, nothing in the plan says so.
#
# So the fact is read, exactly when ECS will attach the default group to the
# task (ecs variant, no group named — for that shape the validation has already
# demanded the flag), and the EventBridge target below refuses through a
# `precondition` when, in any VPC the subnets are in, no egress rule of that
# VPC's default group covers outbound HTTPS — per VPC, not over the union of
# every group's rules.
# Two stages, one law, each catching the case the other cannot:
#   validation   — no group named, no acknowledgement: refused before any
#                  provider call, from the variables alone;
#   precondition — no group named, acknowledged, but the default group of the
#                  subnets' VPC has no egress rule for HTTPS: refused at plan
#                  time, after three describe calls and before any resource is
#                  created. A failed `precondition` stops terraform 1.16.1; a
#                  failed test-time `assert` does not.
#
# Which data source carries the truth, per the schema of the pinned provider
# (hashicorp/aws 6.62.0, `terraform providers schema -json`):
#   aws_subnet                    vpc_id of each named subnet. The module has
#                                 no VPC variable, on purpose (var.ecs_subnet_ids
#                                 names why), so the VPC is derived from the
#                                 subnets — every one of them, never assumed
#                                 from the first.
#   aws_security_group            the group named "default" of that VPC. It
#                                 exposes arn, description, id, name, vpc_id,
#                                 tags and NO rules: it cannot tell an empty
#                                 egress list from an allow-all rule and only
#                                 resolves the group id here.
#   aws_vpc_security_group_rules  the rule ids of that group
#                                 (DescribeSecurityGroupRules, filter group-id;
#                                 the API offers no is-egress filter, so ingress
#                                 and egress ids come back together).
#   aws_vpc_security_group_rule   one read per rule id: is_egress, ip_protocol,
#                                 from_port, to_port — the fields the
#                                 precondition reads. An empty `ids` list and a
#                                 list holding one 0.0.0.0/0 egress rule are
#                                 distinguishable: the first yields no rule at
#                                 all, the second a rule with is_egress = true
#                                 and ip_protocol = "-1".
# The acknowledged path therefore needs ec2:DescribeSubnets,
# ec2:DescribeSecurityGroups and ec2:DescribeSecurityGroupRules at plan time,
# and its subnet ids must be known at plan time (the for_each keys below derive
# from them) — an existing VPC, which is the shape the flag exists for. A caller
# who names a group reads none of this: the four data sources have no instance.

locals {
  # True exactly when ECS will attach the VPC's default group to the task.
  # Gated on the SHAPE (ecs variant, no group named), not on the flag, so the
  # fact is checked whatever the caller said about it.
  ecs_task_uses_default_security_group = var.pipeline_type == "ecs" && length(var.ecs_security_group_ids) == 0
}

data "aws_subnet" "ecs" {
  for_each = local.ecs_task_uses_default_security_group ? toset(var.ecs_subnet_ids) : toset([])
  id       = each.value
}

data "aws_security_group" "ecs_default" {
  for_each = toset(distinct([for s in data.aws_subnet.ecs : s.vpc_id]))
  vpc_id   = each.value
  name     = "default"
}

data "aws_vpc_security_group_rules" "ecs_default" {
  for_each = data.aws_security_group.ecs_default

  filter {
    name   = "group-id"
    values = [each.value.id]
  }
}

data "aws_vpc_security_group_rule" "ecs_default" {
  for_each               = toset(flatten([for rules in data.aws_vpc_security_group_rules.ecs_default : rules.ids]))
  security_group_rule_id = each.value
}

locals {
  # Per rule read (keyed by rule id, the for_each key above): does it let a
  # task reach an HTTPS endpoint — egress, and all traffic or TCP with 443
  # inside the port range. The destination is deliberately not constrained —
  # 0.0.0.0/0, a prefix list for gateway endpoints or another group are all
  # legitimate routes out. The ports go through coalesce because an
  # all-traffic rule carries none.
  ecs_default_security_group_rule_allows_https_egress = {
    for rule_id, rule in data.aws_vpc_security_group_rule.ecs_default : rule_id => rule.is_egress && (
      rule.ip_protocol == "-1" ||
      (contains(["tcp", "6"], lower(rule.ip_protocol)) && coalesce(rule.from_port, -1) <= 443 && 443 <= coalesce(rule.to_port, -1))
    )
  }

  # Per VPC read (keyed by vpc id): the HTTPS egress rule ids of ITS default
  # group. A map, not one list over every group: the task carries the default
  # group of the VPC its subnet is in, so each VPC must hold its own rule, and
  # a rule in one VPC says nothing about a task started in another. A
  # flattened list would let subnets spanning two VPCs, one of them with
  # HTTPS egress, pass on that one VPC's rule.
  ecs_default_security_group_https_egress_rule_ids = {
    for vpc_id, rules in data.aws_vpc_security_group_rules.ecs_default :
    vpc_id => [for rule_id in rules.ids : rule_id if local.ecs_default_security_group_rule_allows_https_egress[rule_id]]
  }

  # The VPCs whose default group has no such rule — empty exactly when the
  # precondition below holds; sorted so the error message is stable.
  ecs_default_security_group_vpcs_without_https_egress = sort([
    for vpc_id, rule_ids in local.ecs_default_security_group_https_egress_rule_ids : vpc_id if length(rule_ids) == 0
  ])
}

resource "aws_cloudwatch_event_target" "ecs_trigger" {
  count     = var.pipeline_type == "ecs" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.ecs_trigger[0].name
  target_id = "tlz-ecs-pipeline"
  arn       = aws_ecs_cluster.pipeline[0].arn
  role_arn  = aws_iam_role.eventbridge_ecs[0].arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.pipeline[0].arn
    task_count          = 1
    launch_type         = "FARGATE"

    # Mandatory for a FARGATE launch type: the task definition above is awsvpc,
    # and EventBridge refuses the target without this block ("Parameter
    # NetworkConfiguration must be specified for target tlz-ecs-pipeline when
    # launch type is FARGATE", PutTargets 400).
    # The subnets come from the caller (see var.ecs_subnet_ids for why they
    # are never derived here); an empty security-group list makes ECS use the
    # VPC's default group — whose egress the precondition below has read.
    network_configuration {
      subnets          = var.ecs_subnet_ids
      security_groups  = var.ecs_security_group_ids
      assign_public_ip = var.ecs_assign_public_ip
    }
  }

  lifecycle {
    # The fact behind ecs_use_default_security_group (see the block above the
    # data sources): when the task will carry the VPC's default group, that
    # group must have an egress rule that reaches an HTTPS endpoint — in EVERY
    # VPC the subnets are in, since the task carries the default group of the
    # VPC it is started in. Refuses at plan time, before this target — or
    # anything else — is created.
    precondition {
      condition     = !local.ecs_task_uses_default_security_group || length(local.ecs_default_security_group_vpcs_without_https_egress) == 0
      error_message = "pipeline_type is ecs, ecs_security_group_ids is empty and ecs_use_default_security_group is true — but the default security group of ${length(data.aws_security_group.ecs_default) == 1 ? "the subnets' VPC" : "${length(local.ecs_default_security_group_vpcs_without_https_egress)} of the subnets' ${length(data.aws_security_group.ecs_default)} VPCs"} has no egress rule that allows outbound HTTPS: ${join("; ", [for vpc_id in local.ecs_default_security_group_vpcs_without_https_egress : "${vpc_id} (${data.aws_security_group.ecs_default[vpc_id].id}): ${length(data.aws_vpc_security_group_rules.ecs_default[vpc_id].ids)} rule(s) read, none of them egress for all traffic or for TCP covering port 443"])}. ECS would attach exactly that group to a Fargate task started in that VPC, EventBridge would accept the target, and every triggered task would then fail to pull its image or reach an AWS API — late, on every trigger. This is the shape of every VPC this landing zone's networking module manages (aws_default_security_group.vpc strips the default group of every rule). Name a security group that allows outbound HTTPS in ecs_security_group_ids, or place the task in a VPC whose default group has one."
    }
  }
}

resource "aws_iam_role" "eventbridge_ecs" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  name  = "TLZEventBridgeECSRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.${local.dns_suffix}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_ecs" {
  count = var.pipeline_type == "ecs" ? 1 : 0
  name  = "TLZEventBridgeECSRole-policy"
  role  = aws_iam_role.eventbridge_ecs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecs:RunTask",
        ]
        Resource = aws_ecs_task_definition.pipeline[0].arn
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.ecs_execution[0].arn,
          aws_iam_role.ecs_task[0].arn,
        ]
      },
    ]
  })
}
