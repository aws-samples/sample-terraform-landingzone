# =============================================================================
# Security Hub — Activation in Management Account + Standards
# Org config is managed from the Audit account (modules/security-org-config)
# =============================================================================

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = false

  depends_on = [aws_organizations_delegated_administrator.securityhub]
}

# Security Hub designates its delegated administrator only through
# securityhub:EnableOrganizationAdminAccount from the management account; the
# Organizations registration in delegated-admin.tf is not read by the service
# (the GuardDuty sibling in guardduty.tf carries the reasoning). Without
# it the Audit account's aws_securityhub_organization_configuration in
# modules/security-org-config is refused. Same pairing as Macie (macie.tf),
# same audit_account_id guard. Adoption of an out-of-band designation:
#   terraform import 'aws_securityhub_organization_admin_account.this[0]' <audit-account-id>
resource "aws_securityhub_organization_admin_account" "this" {
  count = var.enable_security_hub && var.audit_account_id != "" ? 1 : 0

  admin_account_id = var.audit_account_id

  depends_on = [aws_organizations_delegated_administrator.securityhub, aws_securityhub_account.this]
}

locals {
  # var.security_hub_standards carries the structured form (arn_suffix +
  # enabled), so no shape normalization happens here. The map is keyed by
  # arn_suffix for for_each — removing or disabling one standard does not
  # shift the remaining subscriptions, as a count index would (destroy/create
  # with a coverage gap in between).
  enabled_standards = var.enable_security_hub ? {
    for s in var.security_hub_standards : s.arn_suffix => s if s.enabled
  } : {}
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each = local.enabled_standards

  standards_arn = "${local.arn_prefix}:securityhub:${local.region}::standards/${each.key}"

  depends_on = [aws_securityhub_account.this]
}

# A state written with count indices needs its addresses moved to for_each keys.
# The moved blocks map the count indices of the DEFAULT DELIVERY ORDER — all
# four standards enabled, sorted lexicographically by arn_suffix — onto the
# new keys. Deployments whose enabled-standard list orders differently (for
# example compliance_frameworks = ["nist-800-53"] without a cis-3.0 framework
# puts nist at index 2) do NOT migrate cleanly: a moved target absent from
# for_each is destroyed and recreated, exactly as it would be without the
# block, so the blocks cannot make it worse — but such deployments need
# `terraform state mv` BEFORE upgrading. See the "Migrating Security Hub
# Standards Subscriptions" section in docs/operations.md. Both modules
# subscribe the same loader-merged list, so the index order matches
# modules/security-org-config/main.tf. An index a deployment never had is
# ignored by Terraform.
moved {
  from = aws_securityhub_standards_subscription.this[0]
  to   = aws_securityhub_standards_subscription.this["aws-foundational-security-best-practices/v/1.0.0"]
}

moved {
  from = aws_securityhub_standards_subscription.this[1]
  to   = aws_securityhub_standards_subscription.this["cis-aws-foundations-benchmark/v/1.4.0"]
}

moved {
  from = aws_securityhub_standards_subscription.this[2]
  to   = aws_securityhub_standards_subscription.this["cis-aws-foundations-benchmark/v/3.0.0"]
}

moved {
  from = aws_securityhub_standards_subscription.this[3]
  to   = aws_securityhub_standards_subscription.this["nist-800-53/v/5.0.0"]
}

# =============================================================================
# Security Hub Standards per OU/Account
# =============================================================================

resource "aws_securityhub_standards_subscription" "config" {
  for_each = var.enable_security_hub ? {
    for cfg in var.security_hub_standards_config : cfg.standard_arn_suffix => cfg
  } : {}

  standards_arn = "${local.arn_prefix}:securityhub:${local.region}::standards/${each.value.standard_arn_suffix}"

  depends_on = [aws_securityhub_account.this]
}

check "security_hub_standards_deployment_targets_warning" {
  assert {
    condition     = alltrue([for cfg in var.security_hub_standards_config : length(cfg.deployment_targets) == 0])
    error_message = "security_hub_standards_config contains entries with deployment_targets. Per-OU/Account Security Hub standard activation requires cross-account providers. Standards are enabled in the management account only."
  }
}

# =============================================================================
# Security Hub Disable Controls (G3)
# =============================================================================

locals {
  # Flatten the disabled controls list into individual control entries
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

resource "aws_securityhub_standards_control" "disabled" {
  for_each = var.enable_security_hub ? {
    for ctrl in local.disabled_controls_flat : ctrl.key => ctrl
  } : {}

  standards_control_arn = "${local.arn_prefix}:securityhub:${local.region}:${local.account_id}:control/${each.value.standard_arn_suffix}/${each.value.control_id}"
  control_status        = "DISABLED"
  disabled_reason       = "Disabled via Landing Zone configuration"

  # A control only exists once its STANDARD is subscribed — UpdateStandardsControl
  # against an unsubscribed standard answers ResourceNotFoundException /
  # InvalidAccessException. standards_control_arn is string-built from the
  # variable, so nothing in the data flow links a control to the subscription
  # that makes it real and Terraform must be told the order.
  #
  # Both subscription resources belong in this list. Naming only .this left every
  # control whose standard comes from security_hub_standards_config with NO
  # ordering at all: it raced its own subscription on a fresh apply and failed
  # whenever it happened to be created first. Do not narrow this list back.
  #
  # depends_on is not sufficient on its own here: it can only order what exists.
  # A standard_arn_suffix that is never subscribed at all — absent from both
  # variables, or present in security_hub_standards with enabled = false — has no
  # resource to depend on, so the graph stays healthy and AWS rejects the call at
  # apply. The cross-variable validation on var.security_hub_disabled_controls
  # catches that case at plan time.
  depends_on = [
    aws_securityhub_standards_subscription.this,
    aws_securityhub_standards_subscription.config,
  ]
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

resource "aws_securityhub_automation_rule" "this" {
  # A rule whose exclude_regions list names the current region is not created
  # in this deployment — the per-rule counterpart to the module-wide region
  # exclusion lists.
  for_each = var.enable_security_hub ? {
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

check "security_hub_excluded_region_check" {
  assert {
    condition     = !contains(var.security_hub_excluded_regions, local.region)
    error_message = "The current region '${local.region}' is in security_hub_excluded_regions. Security Hub resources are still created in this deployment but the region should be excluded from multi-region configuration."
  }
}
