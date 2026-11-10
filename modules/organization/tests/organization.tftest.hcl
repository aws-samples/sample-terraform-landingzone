# =============================================================================
# Organization Module Tests (modules/organization)
# =============================================================================
# Coverage:
#   - Toggle-Off: every enable_* toggle false and every policy list empty =>
#     zero derived resources. NOTE: aws_organizations_organization.this itself
#     is unconditional (the module manages the Organization), so the scenario
#     asserts zero for all conditional resources and an empty
#     enabled_policy_types set on the Organization resource.
#   - Default configuration (OU hierarchy, SCPs, attachments)
#   - Custom configuration (5-level OU nesting, all policy types, pipeline SCP,
#     quarantine SCP + auto-detach, opt-in regions, delegated administrators)
#   - Validation failure scenarios for every validated variable
#
# Providers used by the module: aws (default only, no aliases) and archive
# (hashicorp/archive for the Lambda deployment packages).

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  # The region where Organizations events reach EventBridge: runs that enable
  # SCP change detection stay clear of the check scp_revert_detection_region,
  # which regression_scp_revert_detection_outside_us_east_1_warns proves.
  override_data {
    target = data.aws_region.current
    values = {
      region = "us-east-1"
    }
  }
}

mock_provider "archive" {}

variables {
  # Passed explicitly so root-ID resolution does not depend on unknown
  # attributes of the Organization resource during plan.
  organization_root_id = "r-abc1"

  # The module refuses an empty trusted-access list, so every run that
  # does not name its own list gets one service here.
  aws_service_access_principals = ["cloudtrail.amazonaws.com"]
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off — no OUs, no policies, all toggles off
# -----------------------------------------------------------------------------
run "all_toggles_off_no_resources" {
  command = plan

  variables {
    organizational_units           = []
    service_control_policies       = []
    tag_policies                   = []
    backup_policies                = []
    resource_control_policies      = []
    declarative_policies           = []
    chatbot_policies               = []
    service_access_principals      = []
    opt_in_regions                 = []
    quarantine_scp_targets         = []
    enable_pipeline_scp            = false
    enable_quarantine_scp          = false
    enable_quarantine_auto_detach  = false
    enable_scp_revert_detection    = false
    enable_scp_auto_revert         = false
    enable_account_move_automation = false
    enable_allow_list_detach       = false
  }

  assert {
    condition = alltrue([
      length(aws_lambda_function.policy_strategy_detach) == 0,
      length(aws_lambda_invocation.scp_allow_list_detach) == 0,
      length(aws_lambda_invocation.rcp_allow_list_detach) == 0,
    ])
    error_message = "No policy strategy detach function or invocation must be created when enable_allow_list_detach is false."
  }

  # No OUs on any level
  assert {
    condition     = length(aws_organizations_organizational_unit.level_1) == 0
    error_message = "No level-1 OUs must be created when organizational_units is empty."
  }

  assert {
    condition = alltrue([
      length(aws_organizations_organizational_unit.level_2) == 0,
      length(aws_organizations_organizational_unit.level_3) == 0,
      length(aws_organizations_organizational_unit.level_4) == 0,
      length(aws_organizations_organizational_unit.level_5) == 0,
    ])
    error_message = "No nested OUs must be created when organizational_units is empty."
  }

  # No policies of any type
  assert {
    condition = alltrue([
      length(aws_organizations_policy.scp) == 0,
      length(aws_organizations_policy.tag) == 0,
      length(aws_organizations_policy.backup) == 0,
      length(aws_organizations_policy.rcp) == 0,
      length(aws_organizations_policy.declarative) == 0,
      length(aws_organizations_policy.chatbot) == 0,
    ])
    error_message = "No Organizations policies must be created when all policy lists are empty."
  }

  assert {
    condition = alltrue([
      length(aws_organizations_policy_attachment.scp) == 0,
      length(aws_organizations_policy_attachment.tag) == 0,
      length(aws_organizations_policy_attachment.backup) == 0,
      length(aws_organizations_policy_attachment.rcp) == 0,
      length(aws_organizations_policy_attachment.declarative) == 0,
      length(aws_organizations_policy_attachment.chatbot) == 0,
    ])
    error_message = "No policy attachments must be created when all policy lists are empty."
  }

  # Pipeline SCP
  assert {
    condition = alltrue([
      length(aws_organizations_policy.pipeline_scp) == 0,
      length(aws_organizations_policy_attachment.pipeline_scp) == 0,
    ])
    error_message = "No pipeline SCP must be created when enable_pipeline_scp is false."
  }

  # Quarantine SCP + auto-detach
  assert {
    condition = alltrue([
      length(aws_organizations_policy.quarantine) == 0,
      length(aws_organizations_policy_attachment.quarantine) == 0,
    ])
    error_message = "No quarantine SCP must be created when enable_quarantine_scp is false."
  }

  assert {
    condition = alltrue([
      length(aws_sns_topic.quarantine_detach) == 0,
      length(aws_sns_topic_policy.quarantine_detach) == 0,
      length(aws_cloudwatch_event_rule.quarantine_detach) == 0,
      length(aws_cloudwatch_event_target.quarantine_detach) == 0,
      length(aws_lambda_function.quarantine_auto_detach) == 0,
      length(aws_iam_role.quarantine_auto_detach_lambda) == 0,
      length(aws_lambda_permission.quarantine_auto_detach) == 0,
      length(aws_sqs_queue.quarantine_auto_detach_dlq) == 0,
      length(aws_sqs_queue.scp_auto_revert_dlq) == 0,
    ])
    error_message = "No quarantine auto-detach resources must be created when the toggle is false."
  }

  # SCP revert detection
  assert {
    condition = alltrue([
      length(aws_sns_topic.scp_revert) == 0,
      length(aws_sns_topic_policy.scp_revert) == 0,
      length(aws_cloudwatch_event_rule.scp_revert) == 0,
      length(aws_cloudwatch_event_target.scp_revert) == 0,
    ])
    error_message = "No SCP revert detection resources must be created when the toggle is false."
  }

  # Account move automation
  assert {
    condition = alltrue([
      length(aws_lambda_function.account_move) == 0,
      length(aws_iam_role.account_move_lambda) == 0,
      length(aws_cloudwatch_log_group.account_move) == 0,
      length(aws_cloudwatch_event_rule.account_move) == 0,
      length(aws_cloudwatch_event_target.account_move) == 0,
    ])
    error_message = "No account move resources must be created when the toggle is false."
  }

  # Opt-in regions and delegated administrators
  assert {
    condition     = length(aws_account_region.this) == 0
    error_message = "No opt-in region resources must be created when the list is empty."
  }

  assert {
    condition     = length(aws_organizations_delegated_administrator.this) == 0
    error_message = "No delegated administrators must be created when the list is empty."
  }

  # The Organization itself is unconditional, but no policy type is enabled
  assert {
    condition     = length(aws_organizations_organization.this.enabled_policy_types) == 0
    error_message = "No policy types must be enabled when no policies are configured."
  }

  assert {
    condition     = aws_organizations_organization.this.feature_set == "ALL"
    error_message = "feature_set must default to ALL."
  }

  # Outputs
  assert {
    condition     = length(output.ou_name_to_id) == 0
    error_message = "ou_name_to_id output must be empty."
  }

  assert {
    condition     = length(output.scp_ids) == 0
    error_message = "scp_ids output must be empty."
  }

  assert {
    condition     = output.quarantine_scp_id == ""
    error_message = "quarantine_scp_id must be empty when the quarantine SCP is disabled."
  }

  # The policy and its attachments are asserted directly; that says more than
  # an echo of var.enable_quarantine_scp would.
  assert {
    condition     = length(aws_organizations_policy.quarantine) == 0 && length(aws_organizations_policy_attachment.quarantine) == 0
    error_message = "No quarantine SCP and no attachment must be created when the quarantine SCP is disabled."
  }

  assert {
    condition     = length(output.ignored_ou_ids) == 0
    error_message = "ignored_ou_ids output must be empty."
  }

  assert {
    condition     = output.account_move_lambda_arn == ""
    error_message = "account_move_lambda_arn must be empty when account move automation is disabled."
  }

  assert {
    condition     = output.scp_revert_sns_topic_arn == ""
    error_message = "scp_revert_sns_topic_arn must be empty when revert detection is disabled."
  }

  assert {
    condition     = output.scp_auto_revert_lambda_arn == null
    error_message = "scp_auto_revert_lambda_arn must be null when auto-revert is disabled."
  }

  assert {
    condition     = output.quarantine_auto_detach_lambda_arn == null
    error_message = "quarantine_auto_detach_lambda_arn must be null when auto-detach is disabled."
  }

  assert {
    condition     = output.partition == "aws"
    error_message = "partition output must come from the partition data source."
  }

  assert {
    condition     = output.dns_suffix == "amazonaws.com"
    error_message = "dns_suffix output must come from the partition data source."
  }

  assert {
    condition     = output.org_root_id == "r-abc1"
    error_message = "org_root_id must be the explicitly passed root ID."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — two-level OU tree with one SCP
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  variables {
    organizational_units = [
      { name = "Security" },
      { name = "Infrastructure" },
      { name = "Workloads" },
      { name = "Production", parent_name = "Workloads" },
    ]

    service_control_policies = [
      {
        name        = "DenyLeaveOrg"
        description = "Deny leaving the organization"
        content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets     = ["Root", "Workloads"]
      },
    ]
  }

  # OU hierarchy
  assert {
    condition     = length(aws_organizations_organizational_unit.level_1) == 3
    error_message = "Three level-1 OUs must be created."
  }

  assert {
    condition     = length(aws_organizations_organizational_unit.level_2) == 1
    error_message = "One level-2 OU must be created."
  }

  assert {
    condition     = aws_organizations_organizational_unit.level_1["Workloads"].parent_id == "r-abc1"
    error_message = "Level-1 OUs must be parented to the organization root."
  }

  assert {
    condition     = aws_organizations_organizational_unit.level_2["Production"].name == "Production"
    error_message = "Level-2 OU name must match the input."
  }

  # SCP and attachments
  assert {
    condition     = length(aws_organizations_policy.scp) == 1
    error_message = "One SCP must be created."
  }

  assert {
    condition     = aws_organizations_policy.scp["DenyLeaveOrg"].type == "SERVICE_CONTROL_POLICY"
    error_message = "SCP type must be SERVICE_CONTROL_POLICY."
  }

  assert {
    condition     = aws_organizations_policy.scp["DenyLeaveOrg"].description == "Deny leaving the organization"
    error_message = "SCP description must match the input."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.scp) == 2
    error_message = "Two SCP attachments must be created (one per target)."
  }

  # "Root" is resolved through target_name_to_id
  assert {
    condition     = aws_organizations_policy_attachment.scp["DenyLeaveOrg:Root"].target_id == "r-abc1"
    error_message = "The Root target must be resolved to the organization root ID."
  }

  # SERVICE_CONTROL_POLICY is enabled because SCPs are configured
  assert {
    condition     = contains(aws_organizations_organization.this.enabled_policy_types, "SERVICE_CONTROL_POLICY")
    error_message = "SERVICE_CONTROL_POLICY must be enabled when SCPs are configured."
  }

  assert {
    condition     = length(aws_organizations_organization.this.enabled_policy_types) == 1
    error_message = "Only SERVICE_CONTROL_POLICY must be enabled when only SCPs are configured."
  }

  assert {
    condition     = length(output.ou_name_to_id) == 4
    error_message = "ou_name_to_id must contain all four OUs."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — 5-level OU nesting, all policy types,
#             pipeline SCP, quarantine SCP + auto-detach, revert detection,
#             account move automation, opt-in regions, delegated admins
# -----------------------------------------------------------------------------
run "custom_configuration" {
  command = plan

  variables {
    feature_set                   = "ALL"
    aws_service_access_principals = ["cloudtrail.amazonaws.com", "guardduty.amazonaws.com"]

    organizational_units = [
      { name = "L1" },
      { name = "L2", parent_name = "L1" },
      { name = "L3", parent_name = "L2" },
      { name = "L4", parent_name = "L3" },
      { name = "L5", parent_name = "L4" },
      { name = "Ignored", ignore = true },
    ]

    service_control_policies = [
      {
        name    = "ScpA"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"iam:*\",\"Resource\":\"*\"}]}"
        targets = ["L1", "123456789012"]
      },
    ]

    tag_policies = [
      {
        name    = "TagA"
        content = "{\"tags\":{}}"
        targets = ["L1"]
      },
    ]

    backup_policies = [
      {
        name    = "BackupA"
        content = "{\"plans\":{}}"
        targets = ["L2"]
      },
    ]

    resource_control_policies = [
      {
        name    = "RcpA"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets = ["L1"]
      },
    ]

    declarative_policies = [
      {
        name    = "DeclA"
        content = "{\"ec2_attributes\":{}}"
        targets = ["L1"]
      },
    ]

    chatbot_policies = [
      {
        name    = "ChatA"
        content = "{\"chatbot\":{}}"
        targets = ["L1"]
      },
    ]

    service_access_principals = [
      {
        service_principal = "guardduty.amazonaws.com"
        account_id        = "222222222222"
      },
    ]

    enable_pipeline_scp = true
    pipeline_scp_config = {
      deployment_role_name  = "TLZDeploymentRole"
      pipeline_role_name    = "TLZPipelineRole"
      infrastructure_ou_id  = "ou-abc1-11111111"
      management_account_id = "111111111111"
    }

    enable_quarantine_scp         = true
    quarantine_scp_targets        = ["L1", "123456789012"]
    enable_quarantine_auto_detach = true

    enable_scp_revert_detection     = true
    enable_scp_auto_revert          = true
    scp_revert_notification_emails  = ["ops@example.com", "sec@example.com"]
    enable_account_move_automation  = true
    account_move_log_retention_days = 30

    opt_in_regions = ["af-south-1", "ap-east-1"]
  }

  # Five OU levels plus one ignored level-1 OU
  assert {
    condition     = length(aws_organizations_organizational_unit.level_1) == 2
    error_message = "Two level-1 OUs must be created (L1 and Ignored)."
  }

  assert {
    condition = alltrue([
      length(aws_organizations_organizational_unit.level_2) == 1,
      length(aws_organizations_organizational_unit.level_3) == 1,
      length(aws_organizations_organizational_unit.level_4) == 1,
      length(aws_organizations_organizational_unit.level_5) == 1,
    ])
    error_message = "Each nesting level must create exactly one OU."
  }

  assert {
    condition     = length(output.ignored_ou_ids) == 1
    error_message = "Exactly one OU must be reported as ignored."
  }

  # All policy types created and attached
  assert {
    condition = alltrue([
      length(aws_organizations_policy.scp) == 1,
      length(aws_organizations_policy.tag) == 1,
      length(aws_organizations_policy.backup) == 1,
      length(aws_organizations_policy.rcp) == 1,
      length(aws_organizations_policy.declarative) == 1,
      length(aws_organizations_policy.chatbot) == 1,
    ])
    error_message = "One policy of each type must be created."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.scp) == 2
    error_message = "The SCP must be attached to both targets."
  }

  # A raw account ID target passes through unchanged
  assert {
    condition     = aws_organizations_policy_attachment.scp["ScpA:123456789012"].target_id == "123456789012"
    error_message = "A 12-digit account ID target must be used verbatim."
  }

  assert {
    condition     = aws_organizations_policy.tag["TagA"].type == "TAG_POLICY"
    error_message = "Tag policy type must be TAG_POLICY."
  }

  assert {
    condition     = aws_organizations_policy.backup["BackupA"].type == "BACKUP_POLICY"
    error_message = "Backup policy type must be BACKUP_POLICY."
  }

  assert {
    condition     = aws_organizations_policy.rcp["RcpA"].type == "RESOURCE_CONTROL_POLICY"
    error_message = "RCP type must be RESOURCE_CONTROL_POLICY."
  }

  assert {
    condition     = aws_organizations_policy.declarative["DeclA"].type == "DECLARATIVE_POLICY_EC2"
    error_message = "Declarative policy type must be DECLARATIVE_POLICY_EC2."
  }

  assert {
    condition     = aws_organizations_policy.chatbot["ChatA"].type == "CHATBOT_POLICY"
    error_message = "Chatbot policy type must be CHATBOT_POLICY."
  }

  # All six policy types are enabled on the Organization
  assert {
    condition     = length(aws_organizations_organization.this.enabled_policy_types) == 6
    error_message = "All six policy types must be enabled."
  }

  assert {
    condition     = length(aws_organizations_organization.this.aws_service_access_principals) == 2
    error_message = "Both service access principals must be registered."
  }

  # Pipeline SCP
  assert {
    condition     = length(aws_organizations_policy.pipeline_scp) == 1
    error_message = "The pipeline SCP must be created when enabled."
  }

  assert {
    condition     = aws_organizations_policy.pipeline_scp[0].name == "TLZPipelineRoleProtection"
    error_message = "The pipeline SCP name must be TLZPipelineRoleProtection."
  }

  assert {
    condition     = strcontains(aws_organizations_policy.pipeline_scp[0].content, "TLZDeploymentRole")
    error_message = "The pipeline SCP must protect the configured deployment role."
  }

  assert {
    condition     = strcontains(aws_organizations_policy.pipeline_scp[0].content, "arn:aws:")
    error_message = "The pipeline SCP must build ARNs from the detected partition."
  }

  # The guardrail must DENY. A statement flipped from Deny to Allow still
  # names the protected roles and the partition, so the two strcontains
  # asserts above stay green while the SCP protects nothing. Decode the
  # document the module actually produces and read every statement's Effect;
  # the length guard keeps an emptied Statement list from passing vacuously.
  assert {
    condition = alltrue([
      length(jsondecode(aws_organizations_policy.pipeline_scp[0].content).Statement) > 0,
      alltrue([
        for statement in jsondecode(aws_organizations_policy.pipeline_scp[0].content).Statement :
        statement.Effect == "Deny"
      ]),
    ])
    error_message = "Every statement of the pipeline SCP must carry Effect Deny — an Allow here reads as a present, working guardrail that protects nothing."
  }

  assert {
    condition     = aws_organizations_policy_attachment.pipeline_scp[0].target_id == "ou-abc1-11111111"
    error_message = "The pipeline SCP must be attached to the infrastructure OU."
  }

  # Quarantine SCP
  assert {
    condition     = length(aws_organizations_policy.quarantine) == 1
    error_message = "The quarantine SCP must be created when enabled."
  }

  assert {
    condition     = aws_organizations_policy.quarantine[0].name == "TLZQuarantinePolicy"
    error_message = "The quarantine SCP name must be TLZQuarantinePolicy."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.quarantine) == 2
    error_message = "The quarantine SCP must be attached to both targets."
  }

  # The policy is already asserted above by name and attachment count; this
  # assertion states the count explicitly.
  assert {
    condition     = length(aws_organizations_policy.quarantine) == 1
    error_message = "The quarantine SCP must be created when enabled."
  }

  # Quarantine auto-detach
  assert {
    condition     = length(aws_sns_topic.quarantine_detach) == 1
    error_message = "The quarantine detach SNS topic must be created."
  }

  # The topic's key is the module's SNS key: its ARN is unknown at plan here,
  # so the link and the key policy are pinned by
  # regression_eventbridge_topics_use_the_sns_key.
  assert {
    condition     = length(aws_kms_key.sns_topics) == 1
    error_message = "The quarantine detach SNS topic must be encrypted with the module's SNS key."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.quarantine_detach) == 2
    error_message = "One subscription per notification email must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.quarantine_detach) == 1
    error_message = "The quarantine detach EventBridge rule must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.quarantine_detach) == 1
    error_message = "The SNS target of the quarantine detach rule must be created."
  }

  assert {
    condition     = length(aws_lambda_function.quarantine_auto_detach) == 1
    error_message = "The quarantine auto-detach Lambda must be created."
  }

  assert {
    condition     = aws_lambda_function.quarantine_auto_detach[0].runtime == "python3.12"
    error_message = "The quarantine auto-detach Lambda must use the python3.12 runtime."
  }

  # The asynchronously invoked guard Lambdas must keep their dead-letter queue and
  # concurrency cap — without the DLQ a failed invocation vanishes silently.
  assert {
    condition = alltrue([
      length(aws_sqs_queue.quarantine_auto_detach_dlq) == 1,
      length(aws_lambda_function.quarantine_auto_detach[0].dead_letter_config) == 1,
      length(aws_sqs_queue.scp_auto_revert_dlq) == 1,
      length(aws_lambda_function.scp_auto_revert[0].dead_letter_config) == 1,
    ])
    error_message = "Both guard Lambdas must carry a dead-letter queue (SQS) so failed asynchronous invocations stay observable."
  }

  assert {
    condition = alltrue([
      aws_sqs_queue.quarantine_auto_detach_dlq[0].sqs_managed_sse_enabled == true,
      aws_sqs_queue.scp_auto_revert_dlq[0].sqs_managed_sse_enabled == true,
    ])
    error_message = "Both dead-letter queues must be encrypted at rest (SSE-SQS)."
  }

  assert {
    condition = alltrue([
      aws_lambda_function.quarantine_auto_detach[0].reserved_concurrent_executions == 10,
      aws_lambda_function.scp_auto_revert[0].reserved_concurrent_executions == 10,
    ])
    error_message = "Both guard Lambdas must cap their concurrency (reserved_concurrent_executions)."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.quarantine_auto_detach_lambda) == 1
    error_message = "The Lambda target of the quarantine detach rule must be created."
  }

  assert {
    condition     = aws_lambda_permission.quarantine_auto_detach[0].principal == "events.amazonaws.com"
    error_message = "The Lambda invoke permission must use the partition DNS suffix."
  }

  # SCP revert detection
  assert {
    condition     = length(aws_sns_topic.scp_revert) == 1
    error_message = "The SCP revert SNS topic must be created."
  }

  assert {
    condition     = length(aws_sns_topic_subscription.scp_revert) == 2
    error_message = "One SCP revert subscription per notification email must be created."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.scp_revert) == 1
    error_message = "The SCP revert EventBridge rule must be created."
  }

  assert {
    condition     = strcontains(aws_cloudwatch_event_rule.scp_revert[0].event_pattern, "organizations.amazonaws.com")
    error_message = "The SCP revert event pattern must use the partition DNS suffix."
  }

  # Account move automation
  assert {
    condition     = length(aws_lambda_function.account_move) == 1
    error_message = "The account move Lambda must be created."
  }

  assert {
    condition     = aws_lambda_function.account_move[0].function_name == "tlz-account-move"
    error_message = "The account move Lambda name must be tlz-account-move."
  }

  assert {
    condition     = aws_cloudwatch_log_group.account_move[0].retention_in_days == 30
    error_message = "The account move log retention must match the input."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.account_move) == 1
    error_message = "The account move EventBridge rule must be created."
  }

  # Opt-in regions and delegated administrators
  assert {
    condition     = length(aws_account_region.this) == 2
    error_message = "One resource per opt-in region must be created."
  }

  assert {
    condition     = aws_account_region.this["af-south-1"].enabled == true
    error_message = "Opt-in regions must be enabled."
  }

  assert {
    condition     = length(aws_organizations_delegated_administrator.this) == 1
    error_message = "One delegated administrator must be created."
  }

  assert {
    condition     = aws_organizations_delegated_administrator.this["guardduty.amazonaws.com:222222222222"].account_id == "222222222222"
    error_message = "The delegated administrator account must match the input."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "invalid_import_organization_id_rejected" {
  command = plan

  variables {
    import_organization_id = "org-123"
  }

  expect_failures = [var.import_organization_id]
}

run "invalid_organization_root_id_rejected" {
  command = plan

  variables {
    organization_root_id = "root-1"
  }

  expect_failures = [var.organization_root_id]
}

run "invalid_feature_set_rejected" {
  command = plan

  variables {
    feature_set = "PARTIAL"
  }

  expect_failures = [var.feature_set]
}

run "invalid_scp_target_rejected" {
  command = plan

  variables {
    service_control_policies = [
      {
        name    = "ScpBadTarget"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets = ["1invalid"]
      },
    ]
  }

  expect_failures = [var.service_control_policies]
}

run "invalid_tag_policy_target_rejected" {
  command = plan

  variables {
    tag_policies = [
      {
        name    = "TagBadTarget"
        content = "{\"tags\":{}}"
        targets = ["-nope"]
      },
    ]
  }

  expect_failures = [var.tag_policies]
}

run "invalid_backup_policy_target_rejected" {
  command = plan

  variables {
    backup_policies = [
      {
        name    = "BackupBadTarget"
        content = "{\"plans\":{}}"
        targets = ["12345"]
      },
    ]
  }

  expect_failures = [var.backup_policies]
}

run "invalid_rcp_target_rejected" {
  command = plan

  variables {
    resource_control_policies = [
      {
        name    = "RcpBadTarget"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets = ["9bad"]
      },
    ]
  }

  expect_failures = [var.resource_control_policies]
}

run "invalid_declarative_policy_target_rejected" {
  command = plan

  variables {
    declarative_policies = [
      {
        name    = "DeclBadTarget"
        content = "{\"ec2_attributes\":{}}"
        targets = ["0"]
      },
    ]
  }

  expect_failures = [var.declarative_policies]
}

run "invalid_chatbot_policy_target_rejected" {
  command = plan

  variables {
    chatbot_policies = [
      {
        name    = "ChatBadTarget"
        content = "{\"chatbot\":{}}"
        targets = ["#invalid"]
      },
    ]
  }

  expect_failures = [var.chatbot_policies]
}

run "invalid_service_principal_rejected" {
  command = plan

  variables {
    service_access_principals = [
      {
        service_principal = "guardduty.example.com"
        account_id        = "222222222222"
      },
    ]
  }

  expect_failures = [var.service_access_principals]
}

run "invalid_delegated_admin_account_id_rejected" {
  command = plan

  variables {
    service_access_principals = [
      {
        service_principal = "guardduty.amazonaws.com"
        account_id        = "22222"
      },
    ]
  }

  expect_failures = [var.service_access_principals]
}

run "invalid_quarantine_scp_target_rejected" {
  command = plan

  variables {
    quarantine_scp_targets = ["_bad"]
  }

  expect_failures = [var.quarantine_scp_targets]
}

run "invalid_opt_in_region_rejected" {
  command = plan

  variables {
    opt_in_regions = ["AF-South-1"]
  }

  expect_failures = [var.opt_in_regions]
}

run "invalid_account_move_log_retention_rejected" {
  command = plan

  variables {
    account_move_log_retention_days = 42
  }

  expect_failures = [var.account_move_log_retention_days]
}

# -----------------------------------------------------------------------------
# The OU hierarchy is materialised by five level-bound resources. An OU that
# lands in none of the five filtered maps would be created by no resource at
# all, so every such shape is refused: typos in parent_name, references to OUs
# that do not exist, hierarchies beyond level five, and parent cycles.
# Same-named OUs would overwrite each other in ou_name_to_id.
# -----------------------------------------------------------------------------

# A parent_name that matches no declared OU is rejected.
run "unknown_parent_name_rejected" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
      { name = "Production", parent_name = "Wrokloads" },
    ]
  }

  expect_failures = [var.organizational_units]
}

# Duplicate OU names would collide in ou_name_to_id and in the level resources.
run "duplicate_ou_names_rejected" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
      { name = "Sandbox", parent_name = "Workloads" },
      { name = "Sandbox" },
    ]
  }

  expect_failures = [var.organizational_units]
}

# The sentinel for "directly under the root" must not double as an OU name.
run "reserved_root_sentinel_as_ou_name_rejected" {
  command = plan

  variables {
    organizational_units = [
      { name = "__root__" },
    ]
  }

  expect_failures = [var.organizational_units]
}

# A sixth nesting level is placed by no resource and must abort the plan.
run "sixth_ou_level_aborts" {
  command = plan

  variables {
    organizational_units = [
      { name = "L1" },
      { name = "L2", parent_name = "L1" },
      { name = "L3", parent_name = "L2" },
      { name = "L4", parent_name = "L3" },
      { name = "L5", parent_name = "L4" },
      { name = "L6", parent_name = "L5" },
    ]
  }

  expect_failures = [resource.aws_organizations_organization.this]
}

# A parent cycle keeps both OUs out of every level and must abort the plan.
run "ou_parent_cycle_aborts" {
  command = plan

  variables {
    organizational_units = [
      { name = "Alpha", parent_name = "Beta" },
      { name = "Beta", parent_name = "Alpha" },
    ]
  }

  expect_failures = [resource.aws_organizations_organization.this]
}

# A policy target that names neither the root, a declared OU, nor an account ID
# is refused instead of being forwarded to the Organizations API as a raw name.
run "unresolvable_policy_target_aborts" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]
    service_control_policies = [
      {
        name    = "DenyLeaveOrg"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets = ["Wrokloads"]
      },
    ]
  }

  expect_failures = [resource.aws_organizations_organization.this]
}

# -----------------------------------------------------------------------------
# Chatbot policies
#
# stacks/management/organization reads var.chatbot_policies from the loader in
# the same group as the five neighbouring policy types.
#
# The two runs hold the ends of the path: a configured policy becomes a policy
# plus its attachments, and the empty list creates nothing.
# -----------------------------------------------------------------------------
run "regression_chatbot_policy_is_created_and_attached" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]

    chatbot_policies = [
      {
        name        = "ChatbotGuardrail"
        description = "Restrict Chatbot to approved channels"
        content     = "{\"chatbot\":{\"default\":{\"@@assign\":\"deny\"}}}"
        targets     = ["Workloads", "123456789012"]
      },
    ]
  }

  assert {
    condition     = length(aws_organizations_policy.chatbot) == 1
    error_message = "A configured chatbot policy must be created."
  }

  assert {
    condition     = aws_organizations_policy.chatbot["ChatbotGuardrail"].type == "CHATBOT_POLICY"
    error_message = "The policy must be created as CHATBOT_POLICY."
  }

  assert {
    condition     = aws_organizations_policy.chatbot["ChatbotGuardrail"].content == "{\"chatbot\":{\"default\":{\"@@assign\":\"deny\"}}}"
    error_message = "The policy content must arrive unchanged — the loader resolves __LOADER_INJECT__ before this point."
  }

  assert {
    condition     = aws_organizations_policy.chatbot["ChatbotGuardrail"].description == "Restrict Chatbot to approved channels"
    error_message = "The policy description must be taken from the configuration."
  }

  # Both targets are attached: the OU by name, the account verbatim.
  assert {
    condition     = length(aws_organizations_policy_attachment.chatbot) == 2
    error_message = "The chatbot policy must be attached to both targets."
  }

  # Only the account ID has a known target at plan time; an OU ID is created in
  # this same plan and therefore unknown.
  assert {
    condition     = aws_organizations_policy_attachment.chatbot["ChatbotGuardrail:123456789012"].target_id == "123456789012"
    error_message = "A 12-digit account ID target must be used verbatim."
  }

  # The output carries the created policy.
  assert {
    condition     = length(output.chatbot_policy_ids) == 1
    error_message = "chatbot_policy_ids must report the created policy."
  }

  # CHATBOT_POLICY must be among the policy types enabled on the Organization,
  # otherwise AWS rejects the policy itself.
  assert {
    condition     = contains(aws_organizations_organization.this.enabled_policy_types, "CHATBOT_POLICY")
    error_message = "CHATBOT_POLICY must be enabled on the Organization."
  }
}

# An adopted organization with a policy type the lists do not derive
# (AISERVICES_OPT_OUT_POLICY) keeps it enabled on the next apply.
run "regression_additional_enabled_policy_types_kept" {
  command = plan

  variables {
    service_control_policies = [
      {
        name    = "base-scp"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"cloudtrail:StopLogging\",\"Resource\":\"*\"}]}"
        targets = ["111111111111"]
      }
    ]
    additional_enabled_policy_types = ["AISERVICES_OPT_OUT_POLICY", "SERVICE_CONTROL_POLICY"]
  }

  assert {
    condition     = contains(aws_organizations_organization.this.enabled_policy_types, "AISERVICES_OPT_OUT_POLICY")
    error_message = "A policy type named in additional_enabled_policy_types must stay enabled on the Organization."
  }

  assert {
    condition     = length(aws_organizations_organization.this.enabled_policy_types) == 2
    error_message = "A derived type named again must appear once: SERVICE_CONTROL_POLICY and AISERVICES_OPT_OUT_POLICY only."
  }
}

run "additional_enabled_policy_types_refuses_lower_case" {
  command = plan

  variables {
    additional_enabled_policy_types = ["aiservices_opt_out_policy"]
  }

  expect_failures = [var.additional_enabled_policy_types]
}

run "regression_chatbot_policy_list_empty_plans_nothing" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]
    chatbot_policies = []
  }

  assert {
    condition     = length(aws_organizations_policy.chatbot) == 0
    error_message = "No chatbot policy must be created from an empty list."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.chatbot) == 0
    error_message = "No attachment must be created without a policy."
  }

  assert {
    condition     = length(output.chatbot_policy_ids) == 0
    error_message = "chatbot_policy_ids must stay empty without a policy."
  }
}

# -----------------------------------------------------------------------------
# Scenario: policy strategy and AWS-managed policies
# -----------------------------------------------------------------------------
# strategy = "allow-list" detaches the AWS default policy (FullAWSAccess /
# RCPFullAWSAccess) from the entry's targets through the module-owned
# function, invoked synchronously per policy type; deny-list (the default)
# keeps the purely additive attaching. type = "aws-managed" attaches an
# AWS-managed policy by its well-known ID instead of creating one.
run "regression_policy_strategy_defaults_keep_the_plan" {
  command = plan
  variables {
    service_control_policies = [
      {
        name    = "base-scp"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"cloudtrail:StopLogging\",\"Resource\":\"*\"}]}"
        targets = ["111111111111"]
      }
    ]
    resource_control_policies = [
      {
        name    = "base-rcp"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"o-example\"}}}]}"
        targets = ["111111111111"]
      }
    ]
  }
  assert {
    condition     = length(aws_organizations_policy.scp) == 1 && length(aws_organizations_policy.rcp) == 1
    error_message = "Entries of the old form must create their policies — the form of every existing plan."
  }
  assert {
    condition     = length(aws_lambda_function.policy_strategy_detach) == 0 && length(aws_iam_role.policy_strategy_detach_lambda) == 0 && length(aws_lambda_invocation.scp_allow_list_detach) == 0 && length(aws_lambda_invocation.rcp_allow_list_detach) == 0
    error_message = "Without allow-list entries and without the switch no detach resource may exist."
  }
}

run "policy_strategy_allow_list_reaches_the_detach" {
  command = plan
  variables {
    enable_allow_list_detach = true
    service_control_policies = [
      {
        name     = "allowed-services"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\",\"ec2:*\"],\"Resource\":\"*\"}]}"
        targets  = ["111111111111", "222222222222"]
        strategy = "allow-list"
      },
      {
        name     = "allowed-logging"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"logs:*\",\"Resource\":\"*\"}]}"
        targets  = ["222222222222"]
        strategy = "allow-list"
      },
      {
        name    = "deny-extra"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"iam:*\",\"Resource\":\"*\"}]}"
        targets = ["333333333333"]
      }
    ]
    resource_control_policies = [
      {
        name     = "rcp-perimeter"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"o-example\"}}}]}"
        targets  = ["444444444444"]
        strategy = "allow-list"
      }
    ]
  }
  assert {
    condition     = length(aws_lambda_function.policy_strategy_detach) == 1 && length(aws_iam_role.policy_strategy_detach_lambda) == 1 && length(aws_iam_role_policy.policy_strategy_detach_lambda) == 1
    error_message = "Allow-list entries behind the switch must plan the shared detach function with its role and policy."
  }
  assert {
    condition     = aws_lambda_function.policy_strategy_detach[0].reserved_concurrent_executions == 1
    error_message = "The detach function is invoked synchronously by Terraform — one reserved execution."
  }
  assert {
    condition     = jsondecode(aws_lambda_invocation.scp_allow_list_detach[0].input).policy_id == "p-FullAWSAccess"
    error_message = "The SCP invocation must name FullAWSAccess by its well-known ID."
  }
  assert {
    condition     = jsondecode(aws_lambda_invocation.scp_allow_list_detach[0].input).target_ids == ["111111111111", "222222222222"]
    error_message = "The SCP detach set must union the allow-list targets and deduplicate the shared one — the deny-list target stays out."
  }
  assert {
    condition     = jsondecode(aws_lambda_invocation.rcp_allow_list_detach[0].input).policy_id == "rp-FullAWSAccess"
    error_message = "The RCP invocation must name RCPFullAWSAccess by its well-known ID."
  }
  assert {
    condition     = jsondecode(aws_lambda_invocation.rcp_allow_list_detach[0].input).target_ids == ["444444444444"]
    error_message = "The RCP detach set must carry exactly the RCP allow-list targets."
  }
}

run "aws_managed_scp_attaches_by_well_known_id" {
  command = plan
  variables {
    service_control_policies = [
      {
        name    = "FullAWSAccess"
        type    = "aws-managed"
        targets = ["111111111111"]
      },
      {
        name    = "base-scp"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"cloudtrail:StopLogging\",\"Resource\":\"*\"}]}"
        targets = ["111111111111"]
      }
    ]
  }
  assert {
    condition     = length(aws_organizations_policy.scp) == 1
    error_message = "Only the customer-managed entry may create a policy — AWS owns the managed one."
  }
  assert {
    condition     = aws_organizations_policy_attachment.scp["FullAWSAccess:111111111111"].policy_id == "p-FullAWSAccess"
    error_message = "An aws-managed entry must attach by the well-known policy ID."
  }
}

run "policy_strategy_invalid_values_rejected" {
  command = plan
  variables {
    enable_allow_list_detach = true
    service_control_policies = [
      {
        name     = "bad-strategy"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets  = ["111111111111"]
        strategy = "denylist"
      },
      {
        name    = "bad-type"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets = ["111111111111"]
        type    = "awsmanaged"
      },
      {
        name     = "no-targets"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets  = []
        strategy = "allow-list"
      }
    ]
  }
  expect_failures = [var.service_control_policies]
}

run "policy_strategy_allow_list_without_switch_rejected" {
  command = plan
  variables {
    service_control_policies = [
      {
        name     = "gated"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets  = ["111111111111"]
        strategy = "allow-list"
      }
    ]
  }
  expect_failures = [var.service_control_policies]
}

run "aws_managed_scp_form_errors_rejected" {
  command = plan
  variables {
    service_control_policies = [
      {
        name    = "NotAManagedPolicy"
        type    = "aws-managed"
        targets = ["111111111111"]
      },
      {
        name    = "FullAWSAccess"
        type    = "aws-managed"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets = ["111111111111"]
      },
      {
        name    = "no-content"
        targets = ["111111111111"]
      }
    ]
  }
  expect_failures = [var.service_control_policies]
}

run "aws_managed_allow_list_combination_rejected" {
  command = plan
  variables {
    enable_allow_list_detach = true
    service_control_policies = [
      {
        name     = "FullAWSAccess"
        type     = "aws-managed"
        targets  = ["111111111111"]
        strategy = "allow-list"
      }
    ]
  }
  expect_failures = [var.service_control_policies]
}

run "rcp_strategy_bounds_rejected" {
  command = plan
  variables {
    resource_control_policies = [
      {
        name     = "bad-strategy"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets  = ["111111111111"]
        strategy = "allow"
      },
      {
        name     = "gated"
        content  = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
        targets  = ["111111111111"]
        strategy = "allow-list"
      }
    ]
  }
  expect_failures = [var.resource_control_policies]
}

# -----------------------------------------------------------------------------
# SCP attachment quota
#
# AWS Organizations attaches at most 5 SCPs directly to one target. The module
# counts its own attachments per declared target — service_control_policies
# plus quarantine and pipeline SCP — and rejects the plan on the sixth.
# -----------------------------------------------------------------------------

run "scp_quota_five_attachments_on_one_target_pass" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]
    service_control_policies = [
      for i in range(5) : {
        name    = "quota-scp-${i}"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets = ["Workloads"]
      }
    ]
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.scp) == 5
    error_message = "Five SCPs on one target sit exactly at the AWS quota and must plan."
  }
}

run "scp_quota_sixth_attachment_aborts" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]
    service_control_policies = [
      for i in range(6) : {
        name    = "quota-scp-${i}"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets = ["Workloads"]
      }
    ]
  }

  expect_failures = [
    resource.aws_organizations_policy_attachment.scp,
  ]
}

run "scp_quota_counts_the_quarantine_scp" {
  command = plan

  variables {
    # Four list entries plus the quarantine SCP on the same OU: the merged
    # count reaches exactly 5 and the plan passes. The count assertion proves
    # the cross-source merge — the list alone contributes only 4. (The
    # pipeline SCP joins the same concat in scp-quota.tf; its target is an
    # ou- ID by contract, which the target-resolution precondition keeps out
    # of the name-based lists, so a collision scenario cannot be declared
    # here. The hard failure itself is proven by the sixth-attachment run —
    # which resource reports a shared precondition first is graph order, not
    # a stable contract.)
    organizational_units = [
      { name = "Workloads" },
    ]
    service_control_policies = [
      for i in range(4) : {
        name    = "quota-scp-${i}"
        content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets = ["Workloads"]
      }
    ]
    enable_quarantine_scp  = true
    quarantine_scp_targets = ["Workloads"]
  }

  assert {
    condition     = local.scp_attachment_count_by_target["Workloads"] == 5
    error_message = "The quota count must merge the service_control_policies entries (4) with the quarantine SCP (1) on the same target."
  }

  assert {
    condition     = length(local.scp_quota_exceeded_targets) == 0
    error_message = "Five attachments sit exactly at the quota — no target may be reported as exceeded."
  }
}
# -----------------------------------------------------------------------------
# Scenario: quarantine_scp_content — custom policy content reaches the SCP
# verbatim; empty keeps the built-in deny-all document (quarantine.tf).
# -----------------------------------------------------------------------------
run "quarantine_scp_custom_content_reaches_the_policy" {
  command = plan

  variables {
    enable_quarantine_scp  = true
    quarantine_scp_content = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"CustomQuarantine\",\"Effect\":\"Deny\",\"NotAction\":\"sts:AssumeRole\",\"Resource\":\"*\"}]}"
  }

  assert {
    condition     = aws_organizations_policy.quarantine[0].content == "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"CustomQuarantine\",\"Effect\":\"Deny\",\"NotAction\":\"sts:AssumeRole\",\"Resource\":\"*\"}]}"
    error_message = "A non-empty quarantine_scp_content must reach the SCP verbatim, replacing the built-in document."
  }

  assert {
    condition     = !strcontains(aws_organizations_policy.quarantine[0].content, "AWSControlTowerExecution")
    error_message = "With custom content the built-in tlz-quarantine-guardrails.json document must not leak into the policy."
  }
}

run "quarantine_scp_oversized_content_rejected" {
  command = plan

  variables {
    # 5200 characters, not valid JSON: the validation's try() falls back to
    # the raw length, which exceeds the 5120-character AWS SCP limit.
    quarantine_scp_content = join("", [for i in range(520) : "0123456789"])
  }

  expect_failures = [var.quarantine_scp_content]
}

# -----------------------------------------------------------------------------
# Scenario: Account-move event pattern follows the partition —
# under a mock partition the EventBridge rule filters on the partition's
# eventSource instead of a fixed one, so the automation triggers in every
# partition.
# -----------------------------------------------------------------------------
run "account_move_event_pattern_follows_the_partition" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  variables {
    enable_account_move_automation = true
  }
  assert {
    condition     = strcontains(aws_cloudwatch_event_rule.account_move[0].event_pattern, "organizations.amazonaws.eu")
    error_message = "The account-move event pattern must filter on the partition's eventSource."
  }
  assert {
    condition     = aws_lambda_permission.account_move_eventbridge[0].principal == "events.amazonaws.eu"
    error_message = "The Lambda permission principal must carry the partition's DNS suffix."
  }
}

# -----------------------------------------------------------------------------
# Scenario: check "scp_without_targets" — a created SCP with targets = []
# warns at plan time (framework SCPs ship unattached; attaching is an
# operator decision, so the module surfaces the inert policy instead of
# silently planning it).
# -----------------------------------------------------------------------------
run "scp_without_targets_check_fires" {
  command = plan

  variables {
    service_control_policies = [
      {
        name        = "UnattachedScp"
        description = "Created but attached to nothing"
        content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyLeaveOrg\",\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets     = []
      },
    ]
  }

  expect_failures = [check.scp_without_targets]
}

run "scp_with_targets_check_passes" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]
    service_control_policies = [
      {
        name        = "AttachedScp"
        description = "Attached to an OU"
        content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyLeaveOrg\",\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets     = ["Workloads"]
      },
    ]
  }

  assert {
    condition     = length(local.scps_without_targets) == 0
    error_message = "An SCP with a target must not appear in the target-less list."
  }
}

run "scp_without_targets_names_every_inert_policy" {
  command = plan

  variables {
    organizational_units = [
      { name = "Workloads" },
    ]
    service_control_policies = [
      {
        name        = "InertOne"
        description = "Created but attached to nothing"
        content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyLeaveOrg\",\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets     = []
      },
      {
        name        = "InertTwo"
        description = "Created but attached to nothing"
        content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyLeaveOrg\",\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets     = []
      },
      {
        name        = "AttachedScp"
        description = "Attached to an OU"
        content     = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyLeaveOrg\",\"Effect\":\"Deny\",\"Action\":\"organizations:LeaveOrganization\",\"Resource\":\"*\"}]}"
        targets     = ["Workloads"]
      },
    ]
  }

  assert {
    condition     = local.scps_without_targets == ["InertOne", "InertTwo"]
    error_message = "The target-less list must name exactly the SCPs without targets, in input order."
  }

  expect_failures = [check.scp_without_targets]
}

# -----------------------------------------------------------------------------
# Upsert-safe names of the SCP revert detection chain
# -----------------------------------------------------------------------------
# SNS CreateTopic and EventBridge PutRule are upserts: an apply against an
# account already carrying the name adopts the live resource and a test
# teardown deletes it. Both names are therefore overridable; the defaults are
# the module's standard names, so a production plan stays empty.

# Default: the two literals the module wrote before the variables existed.
run "scp_revert_names_default_to_the_live_literals" {
  command = plan

  variables {
    enable_scp_revert_detection = true
  }

  assert {
    condition     = aws_sns_topic.scp_revert[0].name == "tlz-scp-revert-detection"
    error_message = "scp_revert_topic_name must default to the live name tlz-scp-revert-detection so a production plan stays empty."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.scp_revert[0].name == "tlz-scp-modification-detection"
    error_message = "scp_revert_rule_name must default to the live name tlz-scp-modification-detection so a production plan stays empty."
  }
}

# Reach: an override lands on the resource, and the target still follows the
# renamed rule (the rule name is the target's join key).
run "scp_revert_names_reach_their_resources" {
  command = plan

  variables {
    enable_scp_revert_detection    = true
    scp_revert_notification_emails = ["ops@example.com"]
    scp_revert_topic_name          = "tlz-l4test-scp-revert-detection"
    scp_revert_rule_name           = "tlz-l4test-scp-modification-detection"
  }

  assert {
    condition     = aws_sns_topic.scp_revert[0].name == "tlz-l4test-scp-revert-detection"
    error_message = "scp_revert_topic_name must reach the SCP revert SNS topic."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.scp_revert[0].name == "tlz-l4test-scp-modification-detection"
    error_message = "scp_revert_rule_name must reach the SCP modification EventBridge rule."
  }

  assert {
    condition     = aws_cloudwatch_event_target.scp_revert[0].rule == "tlz-l4test-scp-modification-detection"
    error_message = "The EventBridge target must follow the renamed rule."
  }
}

# Rejection: both classes are guardrail classes — the organization SCPs
# protect only tlz-* topics and rules — so a name outside the namespace is
# refused before the plan can create an unprotected resource.
run "scp_revert_topic_name_outside_namespace_rejected" {
  command = plan

  variables {
    enable_scp_revert_detection = true
    scp_revert_topic_name       = "scp-revert-detection"
  }

  expect_failures = [var.scp_revert_topic_name]
}

run "scp_revert_rule_name_outside_namespace_rejected" {
  command = plan

  variables {
    enable_scp_revert_detection = true
    scp_revert_rule_name        = "scp-modification-detection"
  }

  expect_failures = [var.scp_revert_rule_name]
}

# Rejection: the AWS naming rule of each service still applies inside the
# namespace (a topic name with a dot, a 65-character rule name).
run "scp_revert_names_breaking_the_aws_naming_rule_rejected" {
  command = plan

  variables {
    enable_scp_revert_detection = true
    scp_revert_topic_name       = "tlz-scp.revert"
    scp_revert_rule_name        = "tlz-${join("", [for i in range(61) : "x"])}"
  }

  expect_failures = [var.scp_revert_topic_name, var.scp_revert_rule_name]
}

# -----------------------------------------------------------------------------
# Upsert-safe names of the DORMANT chains (quarantine auto-detach, SCP
# auto-revert, account move)
# -----------------------------------------------------------------------------
# Same class as the SCP revert names above — SNS CreateTopic and EventBridge
# PutRule are upserts, SQS CreateQueue is idempotent on identical attributes —
# but behind toggles that are off by default. A toggle that is off is not a
# safety property: the day a toggle is enabled in production the
# resource exists under the default, and an apply-test asserting that default
# becomes its deletion. The defaults are the module's standard names, so a
# production plan stays empty.

# Default: every name is the module's standard name.
run "dormant_upsert_names_default_to_the_literals" {
  command = plan

  variables {
    enable_quarantine_scp          = true
    enable_quarantine_auto_detach  = true
    enable_scp_revert_detection    = true
    enable_scp_auto_revert         = true
    enable_account_move_automation = true
  }

  assert {
    condition     = aws_sns_topic.quarantine_detach[0].name == "tlz-quarantine-scp-detach-notification"
    error_message = "quarantine_detach_topic_name must default to tlz-quarantine-scp-detach-notification so a production plan stays empty."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.quarantine_detach[0].name == "tlz-quarantine-scp-pipeline-completion"
    error_message = "quarantine_detach_rule_name must default to tlz-quarantine-scp-pipeline-completion so a production plan stays empty."
  }

  assert {
    condition     = aws_sqs_queue.quarantine_auto_detach_dlq[0].name == "tlz-quarantine-auto-detach-dlq"
    error_message = "quarantine_auto_detach_dlq_name must default to tlz-quarantine-auto-detach-dlq so a production plan stays empty."
  }

  assert {
    condition     = aws_sqs_queue.scp_auto_revert_dlq[0].name == "tlz-scp-auto-revert-dlq"
    error_message = "scp_auto_revert_dlq_name must default to tlz-scp-auto-revert-dlq so a production plan stays empty."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.account_move[0].name == "tlz-account-move"
    error_message = "account_move_rule_name must default to tlz-account-move so a production plan stays empty."
  }

  # The two Lambda policies grant sqs:SendMessage on the default queue names.
  assert {
    condition     = strcontains(aws_iam_role_policy.quarantine_auto_detach_lambda[0].policy, ":sqs:*:*:tlz-quarantine-auto-detach-dlq")
    error_message = "The quarantine auto-detach policy's DLQ grant must name the default queue."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.scp_auto_revert_lambda[0].policy, ":sqs:*:*:tlz-scp-auto-revert-dlq")
    error_message = "The SCP auto-revert policy's DLQ grant must name the default queue."
  }
}

# Reach: an override lands on each resource; the EventBridge targets follow
# the renamed rules (the rule name is the target's join key) and the two
# Lambda policies' sqs:SendMessage grants follow the renamed queues — a queue
# renamed without its grant would be unreachable for dead-lettering, and
# Lambda validates the grant against dead_letter_config at create.
run "dormant_upsert_names_reach_their_resources" {
  command = plan

  variables {
    enable_quarantine_scp           = true
    enable_quarantine_auto_detach   = true
    enable_scp_revert_detection     = true
    enable_scp_auto_revert          = true
    enable_account_move_automation  = true
    scp_revert_notification_emails  = ["ops@example.com"]
    quarantine_detach_topic_name    = "tlz-l4test-quarantine-scp-detach-notification"
    quarantine_detach_rule_name     = "tlz-l4test-quarantine-scp-pipeline-completion"
    quarantine_auto_detach_dlq_name = "tlz-l4test-quarantine-auto-detach-dlq"
    scp_auto_revert_dlq_name        = "tlz-l4test-scp-auto-revert-dlq"
    account_move_rule_name          = "tlz-l4test-account-move"
  }

  assert {
    condition     = aws_sns_topic.quarantine_detach[0].name == "tlz-l4test-quarantine-scp-detach-notification"
    error_message = "quarantine_detach_topic_name must reach the quarantine detach SNS topic."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.quarantine_detach[0].name == "tlz-l4test-quarantine-scp-pipeline-completion"
    error_message = "quarantine_detach_rule_name must reach the quarantine detach EventBridge rule."
  }

  assert {
    condition = alltrue([
      aws_cloudwatch_event_target.quarantine_detach[0].rule == "tlz-l4test-quarantine-scp-pipeline-completion",
      aws_cloudwatch_event_target.quarantine_auto_detach_lambda[0].rule == "tlz-l4test-quarantine-scp-pipeline-completion",
    ])
    error_message = "Both targets (SNS and Lambda) of the quarantine detach rule must follow the renamed rule."
  }

  assert {
    condition     = aws_sqs_queue.quarantine_auto_detach_dlq[0].name == "tlz-l4test-quarantine-auto-detach-dlq"
    error_message = "quarantine_auto_detach_dlq_name must reach the quarantine auto-detach DLQ."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.quarantine_auto_detach_lambda[0].policy, ":sqs:*:*:tlz-l4test-quarantine-auto-detach-dlq")
    error_message = "The quarantine auto-detach policy's sqs:SendMessage grant must follow the renamed DLQ."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.quarantine_auto_detach_lambda[0].policy, "tlz-quarantine-auto-detach-dlq\"")
    error_message = "The quarantine auto-detach policy must not keep granting on the default DLQ name once the queue is renamed."
  }

  assert {
    condition     = aws_sqs_queue.scp_auto_revert_dlq[0].name == "tlz-l4test-scp-auto-revert-dlq"
    error_message = "scp_auto_revert_dlq_name must reach the SCP auto-revert DLQ."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.scp_auto_revert_lambda[0].policy, ":sqs:*:*:tlz-l4test-scp-auto-revert-dlq")
    error_message = "The SCP auto-revert policy's sqs:SendMessage grant must follow the renamed DLQ."
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.scp_auto_revert_lambda[0].policy, "tlz-scp-auto-revert-dlq\"")
    error_message = "The SCP auto-revert policy must not keep granting on the default DLQ name once the queue is renamed."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.account_move[0].name == "tlz-l4test-account-move"
    error_message = "account_move_rule_name must reach the account-move EventBridge rule."
  }

  assert {
    condition     = aws_cloudwatch_event_target.account_move[0].rule == "tlz-l4test-account-move"
    error_message = "The account-move Lambda target must follow the renamed rule."
  }
}

# Rejection: the topic and the two rules are guardrail classes — the
# organization SCPs protect only tlz-* topics and rules — so a name outside
# the namespace is refused before the plan can create an unprotected resource.
run "quarantine_detach_topic_name_outside_namespace_rejected" {
  command = plan

  variables {
    enable_quarantine_scp         = true
    enable_quarantine_auto_detach = true
    quarantine_detach_topic_name  = "quarantine-scp-detach-notification"
  }

  expect_failures = [var.quarantine_detach_topic_name]
}

run "quarantine_detach_rule_name_outside_namespace_rejected" {
  command = plan

  variables {
    enable_quarantine_scp         = true
    enable_quarantine_auto_detach = true
    quarantine_detach_rule_name   = "quarantine-scp-pipeline-completion"
  }

  expect_failures = [var.quarantine_detach_rule_name]
}

run "account_move_rule_name_outside_namespace_rejected" {
  command = plan

  variables {
    enable_account_move_automation = true
    account_move_rule_name         = "account-move"
  }

  expect_failures = [var.account_move_rule_name]
}

# Rejection: the two queue names are deliberately NOT pinned to tlz- (no
# guardrail names an SQS queue ARN), so a name outside the namespace passes —
# and only the SQS naming rule refuses: a dot would turn a standard queue into
# an accidental .fifo name, 81 characters exceed the limit.
run "dlq_names_outside_namespace_accepted_but_aws_naming_rule_enforced" {
  command = plan

  variables {
    enable_quarantine_scp           = true
    enable_quarantine_auto_detach   = true
    enable_scp_revert_detection     = true
    enable_scp_auto_revert          = true
    quarantine_auto_detach_dlq_name = "team-quarantine-auto-detach-dlq"
    scp_auto_revert_dlq_name        = "team-scp-auto-revert-dlq"
  }

  assert {
    condition = alltrue([
      aws_sqs_queue.quarantine_auto_detach_dlq[0].name == "team-quarantine-auto-detach-dlq",
      aws_sqs_queue.scp_auto_revert_dlq[0].name == "team-scp-auto-revert-dlq",
    ])
    error_message = "The DLQ names are not confined to tlz- (no guardrail covers SQS), so a name outside the namespace must be accepted."
  }
}

run "dlq_names_breaking_the_sqs_naming_rule_rejected" {
  command = plan

  variables {
    enable_quarantine_scp           = true
    enable_quarantine_auto_detach   = true
    enable_scp_revert_detection     = true
    enable_scp_auto_revert          = true
    quarantine_auto_detach_dlq_name = "tlz-quarantine-auto-detach-dlq.fifo"
    scp_auto_revert_dlq_name        = join("", [for i in range(81) : "x"])
  }

  expect_failures = [var.quarantine_auto_detach_dlq_name, var.scp_auto_revert_dlq_name]
}

# -----------------------------------------------------------------------------
# An empty aws_service_access_principals would remove the trusted access of
# every service the organization trusts
#
# aws_organizations_organization.this owns the COMPLETE trusted-access list.
# An apply with [] disables trusted access for every enabled service (Config,
# GuardDuty, Security Hub, ...). No
# working landing zone runs without trusted access, so the module refuses the
# empty list at plan time instead of applying it.
# -----------------------------------------------------------------------------
run "d12_empty_service_access_list_refused" {
  command = plan

  variables {
    aws_service_access_principals = []
  }

  expect_failures = [var.aws_service_access_principals]
}

run "d12_non_empty_service_access_list_plans" {
  command = plan

  variables {
    aws_service_access_principals = ["config.amazonaws.com", "guardduty.amazonaws.com"]
  }

  assert {
    condition     = toset(aws_organizations_organization.this.aws_service_access_principals) == toset(["config.amazonaws.com", "guardduty.amazonaws.com"])
    error_message = "A non-empty aws_service_access_principals must reach aws_organizations_organization.this unchanged."
  }
}

# -----------------------------------------------------------------------------
# A blank aws_service_access_principals entry is refused by name, not dropped
#
# An "" or a whitespace entry an operator types in
# additional_aws_service_access_principals reaches the module (pinned by
# tests/test_regression_trusted_services_wiring.py), and the variable's blank
# validation refuses it before any apply instead of planning with the intended
# service silently absent.
#
# What this case pins is the BLANK diagnostic, not just "some validation of
# the variable failed": the shape regex explicitly passes a blank or null
# entry, the list is non-empty and carries no duplicates, so the blank
# validation is the only rule of aws_service_access_principals that can refuse
# this input. Remove that rule and this run turns red, because nothing else
# refuses ["config.amazonaws.com", "", "   ", null]. Keep the shape regex
# passing blanks: if it refused them too, this case would stay green with the
# blank rule gone.
# -----------------------------------------------------------------------------
run "d12_blank_service_access_entry_refused" {
  command = plan

  variables {
    aws_service_access_principals = ["config.amazonaws.com", "", "   ", null]
  }

  expect_failures = [var.aws_service_access_principals]
}

# -----------------------------------------------------------------------------
# A resource control policy the loader dropped is named, not silent
#
# With import_organization_id = "" the loader keeps @@organization_id@@ in
# base-rcp-guardrails-1 and drops the document. The stack passes the dropped
# names in, so the plan shows the missing data perimeter: the check block warns
# on plan and apply and the output carries them. Every other run passes the
# default [] and so pins that the check stays quiet when nothing was dropped.
# -----------------------------------------------------------------------------
run "m2_dropped_rcp_named_by_check" {
  command = plan

  variables {
    unresolved_resource_control_policies = ["base-rcp-guardrails-1"]
  }

  expect_failures = [check.rcp_documents_unresolved]

  assert {
    condition     = output.rcp_documents_unresolved == tolist(["base-rcp-guardrails-1"])
    error_message = "The output must name the dropped resource control policy."
  }
}

# -----------------------------------------------------------------------------
# EventBridge-fed topics, the quarantine detach pattern and the SCP change
# detection region
# -----------------------------------------------------------------------------
# Both topics use aws_kms_key.sns_topics: EventBridge cannot publish to a topic
# encrypted with alias/aws/sns. The key policy grants the
# EventBridge principal exactly GenerateDataKey* and Decrypt and carries no
# aws:SourceAccount / aws:SourceArn condition: AWS does not support those keys
# in a KMS policy for EventBridge-to-encrypted-topic delivery, so a condition
# there would drop every event. The quarantine detach rule matches SUCCEEDED of
# the named pipelines only, not of every pipeline in the account.
run "regression_eventbridge_topics_use_the_sns_key" {
  command = plan

  override_resource {
    target          = aws_kms_key.sns_topics
    override_during = plan
    values = {
      arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }

  variables {
    enable_quarantine_scp          = true
    quarantine_scp_targets         = ["123456789012"]
    enable_quarantine_auto_detach  = true
    enable_scp_revert_detection    = true
    scp_revert_notification_emails = ["ops@example.com"]
  }

  assert {
    condition = alltrue([
      aws_sns_topic.scp_revert[0].kms_master_key_id == "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
      aws_sns_topic.quarantine_detach[0].kms_master_key_id == "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
    ])
    error_message = "Both EventBridge-fed topics must use the module's SNS key, not alias/aws/sns (EventBridge cannot publish to the AWS managed key)."
  }

  assert {
    condition = jsondecode(aws_kms_key.sns_topics[0].policy).Statement == [
      {
        Sid       = "EnableRootAccountAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowEventBridgePublishToEncryptedTopic"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      },
    ]
    error_message = "The SNS key policy must hold exactly the account root statement and the EventBridge statement (GenerateDataKey* and Decrypt, no source condition, which AWS does not support on this path)."
  }

  assert {
    condition = jsondecode(aws_cloudwatch_event_rule.quarantine_detach[0].event_pattern).detail == {
      pipeline = ["tlz-deployment-pipeline"]
      state    = ["SUCCEEDED"]
    }
    error_message = "The quarantine detach rule must match SUCCEEDED of the TLZ deployment pipeline only; without a pipeline filter any pipeline's success detaches the quarantine SCP."
  }
}

run "regression_quarantine_detach_pipeline_names_reach_the_rule" {
  command = plan

  variables {
    enable_quarantine_scp            = true
    quarantine_scp_targets           = ["123456789012"]
    enable_quarantine_auto_detach    = true
    quarantine_detach_pipeline_names = ["tlz-l4test-pipeline"]
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.quarantine_detach[0].event_pattern).detail.pipeline == ["tlz-l4test-pipeline"]
    error_message = "quarantine_detach_pipeline_names must reach the rule's detail.pipeline filter."
  }
}

run "regression_quarantine_detach_pipeline_names_malformed_rejected" {
  command = plan

  variables {
    quarantine_detach_pipeline_names = ["tlz pipeline"]
  }

  expect_failures = [var.quarantine_detach_pipeline_names]
}

run "regression_quarantine_detach_pipeline_names_empty_rejected" {
  command = plan

  variables {
    quarantine_detach_pipeline_names = []
  }

  expect_failures = [var.quarantine_detach_pipeline_names]
}

# Organizations events reach EventBridge in us-east-1 only: detection in
# another region of the aws partition warns; us-east-1 does not.
run "regression_scp_revert_detection_outside_us_east_1_warns" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }

  variables {
    enable_scp_revert_detection = true
  }

  expect_failures = [check.scp_revert_detection_region]
}

run "regression_scp_revert_detection_in_us_east_1_passes" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = {
      region = "us-east-1"
    }
  }

  variables {
    enable_scp_revert_detection = true
  }

  assert {
    condition     = local.region == "us-east-1" && length(aws_cloudwatch_event_rule.scp_revert) == 1
    error_message = "Detection in us-east-1 must plan its rule without the region warning."
  }
}
