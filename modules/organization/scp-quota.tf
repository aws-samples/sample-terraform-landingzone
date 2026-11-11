# =============================================================================
# SCP attachment quota (plan-time check)
# =============================================================================
# AWS Organizations attaches at most 5 service control policies directly to a
# single target — root, OU, or account. The quota is fixed and cannot be
# raised. Every SCP attachment this module manages is known at plan time: the
# entries of var.service_control_policies, the quarantine SCP and the pipeline
# SCP. A target pushed past the quota is therefore rejected before any
# attachment is attempted, instead of failing halfway through an apply with
# part of the policy set attached.
#
# Counting boundary, stated plainly: the count groups targets by their
# declared spelling — "Root", an OU name, a 12-digit account ID, or a raw
# ou-/r- ID (the pipeline SCP names its target by ID). The same OU addressed
# once by name and once by ID counts as two targets, and attachments created
# outside this configuration — the AWS default FullAWSAccess that stays
# attached under the deny-list strategy, Control Tower guardrails, manual
# attachments — are invisible to a plan. A declarative plan cannot list the
# policies already attached to targets that do not exist yet; counting the
# declared attachments is the part the plan can guarantee.

locals {
  # AWS Organizations quota: SCPs directly attached per target. Fixed by AWS,
  # not configurable — a variable would only invite values AWS rejects.
  scp_attachments_per_target_quota = 5

  # Every SCP attachment this module manages, as declared target strings.
  # Tag, backup, RCP, declarative and chatbot policies carry their own,
  # separate quotas and stay out of this count.
  managed_scp_attachment_targets = concat(
    [for att in local.scp_attachments : att.target],
    var.enable_quarantine_scp ? local.quarantine_scp_attachment_targets : [],
    var.enable_pipeline_scp && var.pipeline_scp_config != null ? [var.pipeline_scp_config.infrastructure_ou_id] : [],
  )

  scp_attachment_count_by_target = {
    for target in distinct(local.managed_scp_attachment_targets) :
    target => length([for t in local.managed_scp_attachment_targets : t if t == target])
  }

  # Targets over quota, rendered as "target (count)" for the error message.
  scp_quota_exceeded_targets = sort([
    for target, count in local.scp_attachment_count_by_target :
    "${target} (${count})"
    if count > local.scp_attachments_per_target_quota
  ])

  scp_quota_error = join(" ", [
    "SCP quota exceeded for [${join(", ", local.scp_quota_exceeded_targets)}]:",
    "AWS Organizations attaches at most ${local.scp_attachments_per_target_quota}",
    "service control policies directly to one target, counting the",
    "service_control_policies entries plus the quarantine and pipeline SCPs.",
    "Merge policy documents or remove targets. Attachments created outside",
    "this configuration (the AWS default FullAWSAccess under the deny-list",
    "strategy, Control Tower guardrails) occupy additional slots the plan",
    "cannot see.",
  ])
}
