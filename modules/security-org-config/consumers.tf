# =============================================================================
# Finding consumers of the delegated administrator
# =============================================================================
# AWS ties these to the administrator account: an administrator's publishing
# destination also exports its members' findings, automation rules exist only
# in an administrator account and reach its members, and members inherit the
# administrator's cross-Region aggregation. Running them here — and not in the
# management account — is what makes them cover the organization.
#
# The resources keep the addresses of their counterparts in modules/security
# (same names, same count conditions), so the two modules read alike. Every
# input defaults to "create nothing": the stack switches them on with
# security_finding_consumers_in_audit. The bucket, its key and the export
# lifecycle rules stay with modules/logging in the management account; this
# module only writes into them.

# =============================================================================
# GuardDuty — Publishing Destination / Export
# =============================================================================

# Wait for the bucket and key policy grants of the logging unit to propagate
# before GuardDuty validates its permissions at CreatePublishingDestination.
resource "time_sleep" "guardduty_export_wait" {
  count = var.enable_guardduty && var.guardduty_export_frequency != null && var.central_log_bucket_name != "" ? 1 : 0

  create_duration = "30s"

  depends_on = [aws_guardduty_detector.this]
}

locals {
  guardduty_export_prefix_normalized = trim(var.guardduty_export_prefix, "/")

  guardduty_export_destination_arn = join("", [
    "${local.arn_prefix}:s3:::${var.central_log_bucket_name}",
    local.guardduty_export_prefix_normalized != "" ? "/${local.guardduty_export_prefix_normalized}" : "",
  ])
}

resource "aws_guardduty_publishing_destination" "this" {
  count = var.enable_guardduty && var.guardduty_export_frequency != null && var.central_log_bucket_name != "" ? 1 : 0

  detector_id      = aws_guardduty_detector.this[0].id
  destination_arn  = local.guardduty_export_destination_arn
  destination_type = "S3"
  kms_key_arn      = var.guardduty_export_kms_key_arn

  # Second line of defence behind the cross-variable validation of
  # guardduty_export_kms_key_arn: it keeps the requirement attached to the
  # resource even if the creation condition above ever changes.
  lifecycle {
    precondition {
      condition     = var.guardduty_export_kms_key_arn != ""
      error_message = "guardduty_export_kms_key_arn must be set when guardduty_export_frequency and central_log_bucket_name are configured. kms_key_arn is a required argument of aws_guardduty_publishing_destination and AWS rejects an empty value."
    }
  }

  depends_on = [aws_guardduty_detector.this, time_sleep.guardduty_export_wait]
}

# =============================================================================
# Macie — Classification export
# =============================================================================

resource "aws_macie2_classification_export_configuration" "this" {
  count = var.enable_macie && !local.is_eusc && var.macie_publish_sensitive_data_findings && var.central_log_bucket_name != "" ? 1 : 0

  s3_destination {
    bucket_name = var.central_log_bucket_name
    key_prefix  = "macie/classification-results/"
    kms_key_arn = var.guardduty_export_kms_key_arn != "" ? var.guardduty_export_kms_key_arn : null
  }

  # Same defence as the GuardDuty export: the Macie API requires a KMS key for
  # the S3 destination and rejects a null kms_key_arn at apply time — the
  # precondition turns that into a plan error.
  lifecycle {
    precondition {
      condition     = var.guardduty_export_kms_key_arn != ""
      error_message = "guardduty_export_kms_key_arn must be set when macie_publish_sensitive_data_findings and central_log_bucket_name are configured. The Macie classification export requires a KMS key for its S3 destination and AWS rejects an empty value."
    }
  }

  depends_on = [aws_macie2_account.this]
}

# =============================================================================
# Security Hub — Member enrolment
# =============================================================================
# auto_enable of the organization configuration enrols only accounts that join
# AFTER it is set; the accounts that already exist — and the management
# account — are enrolled here. invite = false is the organization form: no
# invitation, the member must have Security Hub enabled (the accounts' own
# security units and modules/security do that). Destroying a member ends the
# association only; Security Hub stays enabled in the account.

resource "aws_securityhub_member" "this" {
  for_each = var.enable_security_hub ? toset(var.security_hub_member_account_ids) : toset([])

  account_id = each.key
  invite     = false

  # CreateMembers from the administrator naming the administrator fails at
  # apply; the stack filters the Audit account out, this stops a plan that
  # still carries it.
  lifecycle {
    precondition {
      condition     = each.key != local.account_id
      error_message = "security_hub_member_account_ids names this account (${local.account_id}), the administrator — an administrator cannot be its own member. Remove it from the list."
    }
  }

  depends_on = [aws_securityhub_organization_configuration.this]
}

# Automation rules exist only in an administrator account and reach its
# members. Rules without a single enrolled member are a half-move: the rules
# exist, no member finding reaches them. A warning, not a failure — the first
# plan before the accounts exist legitimately has no member to name.
check "security_hub_members_enrolled" {
  assert {
    condition     = !(var.enable_security_hub && length(var.security_hub_member_account_ids) == 0 && length(var.security_hub_automation_rules) > 0)
    error_message = "security_hub_automation_rules names ${length(var.security_hub_automation_rules)} rule(s) but security_hub_member_account_ids is empty: the rules exist in this administrator account, and no member is enrolled whose findings they could reach. Pass the organization's account ids (the stack does so once the accounts unit has applied)."
  }
}

# =============================================================================
# Security Hub — Disabled controls of the administrator account
# =============================================================================

locals {
  disabled_controls_flat = flatten([
    for entry in var.security_hub_disabled_controls : [
      for control_id in entry.control_ids : {
        key                 = "${entry.standard_arn_suffix}/${control_id}"
        standard_arn_suffix = entry.standard_arn_suffix
        control_id          = control_id
      }
    ]
  ])
}

# Disables the administrator account's own controls — the same list that
# modules/security disables in the management account. Org-wide disablement
# would need Security Hub central configuration, which this module does not
# use.
resource "aws_securityhub_standards_control" "disabled" {
  for_each = var.enable_security_hub ? {
    for ctrl in local.disabled_controls_flat : ctrl.key => ctrl
  } : {}

  standards_control_arn = "${local.arn_prefix}:securityhub:${local.region}:${local.account_id}:control/${each.value.standard_arn_suffix}/${each.value.control_id}"
  control_status        = "DISABLED"
  disabled_reason       = "Disabled via Landing Zone configuration"

  # A control only exists once its standard is subscribed; the ARN is
  # string-built, so the order has to be stated. The cross-variable validation
  # of security_hub_disabled_controls refuses an unsubscribed standard.
  depends_on = [aws_securityhub_standards_subscription.this]
}

# =============================================================================
# Security Hub Finding Aggregator — Cross-Region
# =============================================================================

resource "aws_securityhub_finding_aggregator" "this" {
  count             = var.enable_security_hub && var.enable_security_hub_region_aggregation ? 1 : 0
  linking_mode      = length(var.security_hub_aggregation_regions) > 0 ? "SPECIFIED_REGIONS" : "ALL_REGIONS"
  specified_regions = length(var.security_hub_aggregation_regions) > 0 ? var.security_hub_aggregation_regions : null

  depends_on = [aws_securityhub_account.this]
}

# =============================================================================
# Security Hub Automation Rules
# =============================================================================
# The resource block below is a verbatim copy of the one in
# modules/security/securityhub.tf and is pinned to it by
# tests/test_regression_automation_rule_block_identical.py — change both.

locals {
  # Gate of the automation rules: here they are the administrator's and follow
  # the Security Hub toggle alone. The resource block reads the local so that
  # it stays identical to its copy in modules/security.
  manage_security_hub_automation_rules = var.enable_security_hub
}

resource "aws_securityhub_automation_rule" "this" {
  # A rule whose exclude_regions list names the current region is not created
  # in this deployment — the per-rule counterpart to the module-wide region
  # exclusion lists.
  for_each = local.manage_security_hub_automation_rules ? {
    for r in var.security_hub_automation_rules : r.rule_name => r
    if !contains(r.exclude_regions, local.region)
  } : {}

  rule_name   = each.value.rule_name
  rule_order  = each.value.rule_order
  description = each.value.description
  is_terminal = each.value.is_terminal
  rule_status = each.value.enabled ? "ENABLED" : "DISABLED"

  actions {
    type = each.value.actions.type

    finding_fields_update {
      dynamic "severity" {
        for_each = each.value.actions.finding_fields_update != null && each.value.actions.finding_fields_update.severity != null ? [each.value.actions.finding_fields_update.severity] : []
        content {
          label   = severity.value.label
          product = severity.value.product
        }
      }

      dynamic "note" {
        for_each = each.value.actions.finding_fields_update != null && each.value.actions.finding_fields_update.note != null ? [each.value.actions.finding_fields_update.note] : []
        content {
          text       = note.value.text
          updated_by = note.value.updated_by
        }
      }

      dynamic "workflow" {
        for_each = each.value.actions.finding_fields_update != null && each.value.actions.finding_fields_update.workflow != null ? [each.value.actions.finding_fields_update.workflow] : []
        content {
          status = workflow.value.status
        }
      }

      dynamic "related_findings" {
        for_each = each.value.actions.finding_fields_update != null ? each.value.actions.finding_fields_update.related_findings : []
        content {
          id          = related_findings.value.id
          product_arn = related_findings.value.product_arn
        }
      }

      verification_state  = each.value.actions.finding_fields_update != null ? each.value.actions.finding_fields_update.verification_state : null
      types               = each.value.actions.finding_fields_update != null ? each.value.actions.finding_fields_update.types : null
      user_defined_fields = each.value.actions.finding_fields_update != null ? each.value.actions.finding_fields_update.user_defined_fields : null
      confidence          = each.value.actions.finding_fields_update != null ? each.value.actions.finding_fields_update.confidence : null
      criticality         = each.value.actions.finding_fields_update != null ? each.value.actions.finding_fields_update.criticality : null
    }
  }

  criteria {
    dynamic "product_name" {
      for_each = each.value.criteria != null ? each.value.criteria.product_name : []
      content {
        comparison = product_name.value.comparison
        value      = product_name.value.value
      }
    }

    dynamic "severity_label" {
      for_each = each.value.criteria != null ? each.value.criteria.severity_label : []
      content {
        comparison = severity_label.value.comparison
        value      = severity_label.value.value
      }
    }

    dynamic "resource_id" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_id : []
      content {
        comparison = resource_id.value.comparison
        value      = resource_id.value.value
      }
    }

    dynamic "resource_type" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_type : []
      content {
        comparison = resource_type.value.comparison
        value      = resource_type.value.value
      }
    }

    dynamic "workflow_status" {
      for_each = each.value.criteria != null ? each.value.criteria.workflow_status : []
      content {
        comparison = workflow_status.value.comparison
        value      = workflow_status.value.value
      }
    }

    dynamic "compliance_status" {
      for_each = each.value.criteria != null ? each.value.criteria.compliance_status : []
      content {
        comparison = compliance_status.value.comparison
        value      = compliance_status.value.value
      }
    }

    dynamic "record_state" {
      for_each = each.value.criteria != null ? each.value.criteria.record_state : []
      content {
        comparison = record_state.value.comparison
        value      = record_state.value.value
      }
    }

    dynamic "title" {
      for_each = each.value.criteria != null ? each.value.criteria.title : []
      content {
        comparison = title.value.comparison
        value      = title.value.value
      }
    }

    dynamic "type" {
      for_each = each.value.criteria != null ? each.value.criteria.type : []
      content {
        comparison = type.value.comparison
        value      = type.value.value
      }
    }

    dynamic "aws_account_id" {
      for_each = each.value.criteria != null ? each.value.criteria.aws_account_id : []
      content {
        comparison = aws_account_id.value.comparison
        value      = aws_account_id.value.value
      }
    }

    dynamic "compliance_security_control_id" {
      for_each = each.value.criteria != null ? each.value.criteria.compliance_security_control_id : []
      content {
        comparison = compliance_security_control_id.value.comparison
        value      = compliance_security_control_id.value.value
      }
    }

    dynamic "resource_tags" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_tags : []
      content {
        key        = resource_tags.value.key
        value      = resource_tags.value.value
        comparison = resource_tags.value.comparison
      }
    }

    # --- string criteria beyond the original field set ---

    dynamic "aws_account_name" {
      for_each = each.value.criteria != null ? each.value.criteria.aws_account_name : []
      content {
        comparison = aws_account_name.value.comparison
        value      = aws_account_name.value.value
      }
    }

    dynamic "company_name" {
      for_each = each.value.criteria != null ? each.value.criteria.company_name : []
      content {
        comparison = company_name.value.comparison
        value      = company_name.value.value
      }
    }

    dynamic "compliance_associated_standards_id" {
      for_each = each.value.criteria != null ? each.value.criteria.compliance_associated_standards_id : []
      content {
        comparison = compliance_associated_standards_id.value.comparison
        value      = compliance_associated_standards_id.value.value
      }
    }

    dynamic "description" {
      for_each = each.value.criteria != null ? each.value.criteria.description : []
      content {
        comparison = description.value.comparison
        value      = description.value.value
      }
    }

    dynamic "generator_id" {
      for_each = each.value.criteria != null ? each.value.criteria.generator_id : []
      content {
        comparison = generator_id.value.comparison
        value      = generator_id.value.value
      }
    }

    dynamic "id" {
      for_each = each.value.criteria != null ? each.value.criteria.id : []
      content {
        comparison = id.value.comparison
        value      = id.value.value
      }
    }

    dynamic "note_text" {
      for_each = each.value.criteria != null ? each.value.criteria.note_text : []
      content {
        comparison = note_text.value.comparison
        value      = note_text.value.value
      }
    }

    dynamic "note_updated_by" {
      for_each = each.value.criteria != null ? each.value.criteria.note_updated_by : []
      content {
        comparison = note_updated_by.value.comparison
        value      = note_updated_by.value.value
      }
    }

    dynamic "product_arn" {
      for_each = each.value.criteria != null ? each.value.criteria.product_arn : []
      content {
        comparison = product_arn.value.comparison
        value      = product_arn.value.value
      }
    }

    dynamic "related_findings_id" {
      for_each = each.value.criteria != null ? each.value.criteria.related_findings_id : []
      content {
        comparison = related_findings_id.value.comparison
        value      = related_findings_id.value.value
      }
    }

    dynamic "related_findings_product_arn" {
      for_each = each.value.criteria != null ? each.value.criteria.related_findings_product_arn : []
      content {
        comparison = related_findings_product_arn.value.comparison
        value      = related_findings_product_arn.value.value
      }
    }

    dynamic "resource_application_arn" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_application_arn : []
      content {
        comparison = resource_application_arn.value.comparison
        value      = resource_application_arn.value.value
      }
    }

    dynamic "resource_application_name" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_application_name : []
      content {
        comparison = resource_application_name.value.comparison
        value      = resource_application_name.value.value
      }
    }

    dynamic "resource_partition" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_partition : []
      content {
        comparison = resource_partition.value.comparison
        value      = resource_partition.value.value
      }
    }

    dynamic "resource_region" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_region : []
      content {
        comparison = resource_region.value.comparison
        value      = resource_region.value.value
      }
    }

    dynamic "source_url" {
      for_each = each.value.criteria != null ? each.value.criteria.source_url : []
      content {
        comparison = source_url.value.comparison
        value      = source_url.value.value
      }
    }

    dynamic "verification_state" {
      for_each = each.value.criteria != null ? each.value.criteria.verification_state : []
      content {
        comparison = verification_state.value.comparison
        value      = verification_state.value.value
      }
    }

    # --- number criteria: exact value or bound combination ---

    dynamic "confidence" {
      for_each = each.value.criteria != null ? each.value.criteria.confidence : []
      content {
        eq  = confidence.value.eq
        gt  = confidence.value.gt
        gte = confidence.value.gte
        lt  = confidence.value.lt
        lte = confidence.value.lte
      }
    }

    dynamic "criticality" {
      for_each = each.value.criteria != null ? each.value.criteria.criticality : []
      content {
        eq  = criticality.value.eq
        gt  = criticality.value.gt
        gte = criticality.value.gte
        lt  = criticality.value.lt
        lte = criticality.value.lte
      }
    }

    # --- date criteria: rolling date_range or fixed start/end window ---

    dynamic "created_at" {
      for_each = each.value.criteria != null ? each.value.criteria.created_at : []
      content {
        start = created_at.value.start
        end   = created_at.value.end

        dynamic "date_range" {
          for_each = created_at.value.date_range != null ? [created_at.value.date_range] : []
          content {
            unit  = date_range.value.unit
            value = date_range.value.value
          }
        }
      }
    }

    dynamic "first_observed_at" {
      for_each = each.value.criteria != null ? each.value.criteria.first_observed_at : []
      content {
        start = first_observed_at.value.start
        end   = first_observed_at.value.end

        dynamic "date_range" {
          for_each = first_observed_at.value.date_range != null ? [first_observed_at.value.date_range] : []
          content {
            unit  = date_range.value.unit
            value = date_range.value.value
          }
        }
      }
    }

    dynamic "last_observed_at" {
      for_each = each.value.criteria != null ? each.value.criteria.last_observed_at : []
      content {
        start = last_observed_at.value.start
        end   = last_observed_at.value.end

        dynamic "date_range" {
          for_each = last_observed_at.value.date_range != null ? [last_observed_at.value.date_range] : []
          content {
            unit  = date_range.value.unit
            value = date_range.value.value
          }
        }
      }
    }

    dynamic "note_updated_at" {
      for_each = each.value.criteria != null ? each.value.criteria.note_updated_at : []
      content {
        start = note_updated_at.value.start
        end   = note_updated_at.value.end

        dynamic "date_range" {
          for_each = note_updated_at.value.date_range != null ? [note_updated_at.value.date_range] : []
          content {
            unit  = date_range.value.unit
            value = date_range.value.value
          }
        }
      }
    }

    dynamic "updated_at" {
      for_each = each.value.criteria != null ? each.value.criteria.updated_at : []
      content {
        start = updated_at.value.start
        end   = updated_at.value.end

        dynamic "date_range" {
          for_each = updated_at.value.date_range != null ? [updated_at.value.date_range] : []
          content {
            unit  = date_range.value.unit
            value = date_range.value.value
          }
        }
      }
    }

    # --- key-value criteria beyond resource_tags ---

    dynamic "resource_details_other" {
      for_each = each.value.criteria != null ? each.value.criteria.resource_details_other : []
      content {
        key        = resource_details_other.value.key
        value      = resource_details_other.value.value
        comparison = resource_details_other.value.comparison
      }
    }

    dynamic "user_defined_fields" {
      for_each = each.value.criteria != null ? each.value.criteria.user_defined_fields : []
      content {
        key        = user_defined_fields.value.key
        value      = user_defined_fields.value.value
        comparison = user_defined_fields.value.comparison
      }
    }
  }

  depends_on = [aws_securityhub_account.this]
}
