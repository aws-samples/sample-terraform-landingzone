# =============================================================================
# Compliance Configuration Loader — Terragrunt Merge Engine
# =============================================================================
# Reads base config + enabled framework configs, merges them using defined
# rules, and exposes merged values as locals for stack consumption.
#
# Usage in stacks:
#   compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")
#   ... local.compliance.locals.<variable> ...
# =============================================================================

locals {
  # ---------------------------------------------------------------------------
  # Inputs from calling context (env/common.hcl)
  # ---------------------------------------------------------------------------
  common                 = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts               = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance_frameworks  = local.common.locals.compliance_frameworks
  partition              = local.common.locals.partition
  apply_network_defaults = local.common.locals.apply_network_defaults

  # ---------------------------------------------------------------------------
  # Valid framework names — used for validation
  # ---------------------------------------------------------------------------
  valid_frameworks = [
    "c5-2020",
    "cmmc",
    "fedramp-high",
    "fedramp-moderate",
    "hipaa",
    "iso-27001",
    "nist-800-171",
    "nist-800-53",
  ]

  # Validation: an unknown framework name aborts the load with a message that
  # names it. Without the guard the first consumer of framework_configs would be
  # read_tfvars_file, whose error names a missing .tfvars path instead of the
  # misconfigured name. file() fails on the non-existent path; the
  # "path" carries the diagnostic text — the guard pattern of
  # configurations/ou-membership.hcl. The guard must not rely on Terragrunt
  # evaluating it: a local that nothing consumes is not evaluated, so
  # _checked_frameworks is the only list the framework files are read
  # from, and it can only be computed once the guard has passed.
  _clean_frameworks = [for f in local.compliance_frameworks : f if f != ""]
  _invalid_frameworks = [
    for name in local._clean_frameworks : name
    if !contains(local.valid_frameworks, name)
  ]
  _framework_guard = length(local._invalid_frameworks) == 0 ? "ok" : file(
    "ERROR: compliance_frameworks names the unknown framework(s) '${join("', '", local._invalid_frameworks)}'; valid names: ${join(", ", local.valid_frameworks)}"
  )
  _checked_frameworks = local._framework_guard == "ok" ? local._clean_frameworks : []

  # ---------------------------------------------------------------------------
  # Load base configuration
  # ---------------------------------------------------------------------------
  # read_tfvars_file returns a JSON *string*, not an object. Without jsondecode
  # every attribute access below is an error, and because each one sits inside a
  # try(…) it would fall back to the loader default without a word — every key
  # of base.tfvars and of the framework files would be unreachable.
  # Keep the jsondecode at every read_tfvars_file call site under
  # configurations/ and stacks/.
  base = jsondecode(read_tfvars_file("${get_repo_root()}/configurations/base/base.tfvars"))

  # ---------------------------------------------------------------------------
  # Load external policy files and SSM documents
  # ---------------------------------------------------------------------------
  _policy_dir = "${get_repo_root()}/configurations/policies"
  _ssm_dir    = "${get_repo_root()}/configurations/ssm-documents"

  # ---------------------------------------------------------------------------
  # Deployment values used inside policy documents
  # ---------------------------------------------------------------------------
  # Two policy documents scope their conditions to this organization and to the
  # Control Tower log bucket. file() returns the document unchanged and does not
  # substitute anything, so the documents carry @@…@@ markers that are replaced
  # here — the same mechanism primary-backup-plan.json already uses for
  # @@region@@.
  #
  # A marker is only replaced when its value is known. An empty organization ID
  # must never reach a resource control policy: the condition
  # StringNotEqualsIfExists aws:PrincipalOrgID "" is true for every principal
  # and would deny S3 writes organization-wide. An unreplaced marker is
  # therefore kept on purpose — the two policy lists below drop every document
  # that still carries one, and local.unresolved_policy_documents names them.
  _organization_id        = try(local.common.locals.import_organization_id, "")
  _log_archive_account_id = try(local.accounts.locals.log_archive_account_id, "")

  # The partition of the target deployment. Two policy documents name a
  # partition inside an ARN and cannot derive it from
  # data.aws_partition.current, because they are read with file() and never
  # pass through a Terraform expression: the backup policy hands its
  # iam_role_arn to AWS Organizations, and the event bus policy its Resource to
  # the EventBridge bus. Both therefore carry the @@partition@@ marker that is
  # replaced here, the same mechanism primary-backup-plan.json already uses for
  # @@region@@. The marker is always replaced — an unreplaced one
  # would strand the document, so the fallback is the commercial partition,
  # which is also the default of env/common.hcl.example.
  _partition = try(local.common.locals.partition, "aws")
  # DNS suffix of service principals, derived from the partition — the same
  # mapping stacks/management/config-recorder-members carries.
  _dns_suffix = local._partition == "aws-eusc" ? "amazonaws.eu" : "amazonaws.com"

  # SCP content from external files
  _scp_guardrails_1_content     = file("${local._policy_dir}/organization/tlz-core-guardrails-1.json")
  _scp_guardrails_2_content     = file("${local._policy_dir}/organization/tlz-core-guardrails-2.json")
  _rcp_guardrails_1_raw         = file("${local._policy_dir}/organization/tlz-core-rcp-guardrails-1.json")
  _rcp_guardrails_1_org         = local._organization_id != "" ? replace(local._rcp_guardrails_1_raw, "@@organization_id@@", local._organization_id) : local._rcp_guardrails_1_raw
  _rcp_guardrails_1_log_account = local._log_archive_account_id != "" ? replace(local._rcp_guardrails_1_org, "@@log_archive_account_id@@", local._log_archive_account_id) : local._rcp_guardrails_1_org
  _rcp_guardrails_1_region      = replace(local._rcp_guardrails_1_log_account, "@@home_region@@", local.common.locals.region)
  # The aws:CalledVia service principals carry the partition's DNS suffix as a
  # @@dns_suffix@@ mark — the same load-path convention the other
  # marks of this document use. The value is always known (derived from the
  # partition), so the substitution is unconditional.
  _rcp_guardrails_1_content        = replace(local._rcp_guardrails_1_region, "@@dns_suffix@@", local._dns_suffix)
  _scp_suspended_content           = file("${local._policy_dir}/organization/tlz-suspended-guardrails.json")
  _scp_workloads_content           = file("${local._policy_dir}/organization/tlz-workloads-guardrails-1.json")
  _scp_sandbox_content             = file("${local._policy_dir}/organization/tlz-sandbox-guardrails-1.json")
  _scp_security_content            = file("${local._policy_dir}/organization/tlz-core-security-guardrails-1.json")
  _scp_infrastructure_content      = file("${local._policy_dir}/organization/tlz-infrastructure-guardrails-1.json")
  _scp_quarantine_content          = file("${local._policy_dir}/organization/tlz-quarantine-guardrails.json")
  _vpc_block_public_access_content = file("${local._policy_dir}/organization/vpc-block-public-access.json")
  _org_tag_policy_content          = file("${local._policy_dir}/organization/org-tag-policy.json")
  _s3_tag_policy_content           = file("${local._policy_dir}/organization/s3-tag-policy.json")
  _primary_backup_plan_region      = replace(file("${local._policy_dir}/organization/primary-backup-plan.json"), "@@region@@", local.common.locals.region)
  _primary_backup_plan_content     = replace(local._primary_backup_plan_region, "@@partition@@", local._partition)

  # IAM policy and VPC endpoint policy content from external files
  _end_user_policy_content             = file("${local._policy_dir}/general/end-user-policy.json")
  _ssm_s3_policy_content               = file("${local._policy_dir}/general/ssm-s3-policy.json")
  _vpc_endpoint_default_policy_raw     = file("${local._policy_dir}/general/vpc-endpoint-default-policy.json")
  _vpc_endpoint_default_policy_content = local._organization_id != "" ? replace(local._vpc_endpoint_default_policy_raw, "@@organization_id@@", local._organization_id) : local._vpc_endpoint_default_policy_raw

  # SSM document content
  # The two remediation documents reach the security module through the
  # ssm_documents list below (content_file in env/common.hcl), not through an
  # injection key. resource-policy-enforcement.yaml has its own module variable
  # because its resource sets document_format = "YAML".
  resource_policy_enforcement_document = file("${local._ssm_dir}/resource-policy-enforcement.yaml")

  # ---------------------------------------------------------------------------
  # Inject policy content into __LOADER_INJECT__ placeholders
  # ---------------------------------------------------------------------------
  _loader_inject_map = {
    # SCP content injection (base.tfvars + common.hcl SCPs)
    "base-guardrails-1"           = local._scp_guardrails_1_content
    "base-guardrails-2"           = local._scp_guardrails_2_content
    "base-rcp-guardrails-1"       = local._rcp_guardrails_1_content
    "suspended-guardrails"        = local._scp_suspended_content
    "workloads-guardrails-1"      = local._scp_workloads_content
    "sandbox-guardrails-1"        = local._scp_sandbox_content
    "core-security-guardrails-1"  = local._scp_security_content
    "infrastructure-guardrails-1" = local._scp_infrastructure_content
    "quarantine-guardrails"       = local._scp_quarantine_content

    # IAM customer-managed policy content injection (common.hcl)
    "End-User-Policy" = local._end_user_policy_content
    "SSM-S3-Policy"   = local._ssm_s3_policy_content

    # VPC endpoint default policy content injection (common.hcl,
    # endpoint_policies entry "vpc-endpoint-default-policy")
    "vpc-endpoint-default-policy" = local._vpc_endpoint_default_policy_content

    # Tag, backup, declarative policy content injection (common.hcl)
    "org-tag-policy"          = local._org_tag_policy_content
    "s3-tag-policy"           = local._s3_tag_policy_content
    "primary-backup-plan"     = local._primary_backup_plan_content
    "vpc-block-public-access" = local._vpc_block_public_access_content
  }

  # ---------------------------------------------------------------------------
  # Load each enabled framework configuration
  # ---------------------------------------------------------------------------
  # Same as local.base above: read_tfvars_file yields a JSON string, so without
  # jsondecode every cfg.<key> access would fail silently and the choice of a
  # compliance framework would have no effect at all.
  framework_configs = {
    for name in local._checked_frameworks :
    name => jsondecode(read_tfvars_file("${get_repo_root()}/configurations/frameworks/${name}.tfvars"))
  }

  has_frameworks = length(local._clean_frameworks) > 0

  # Process common.hcl policies through inject (these bypass the base.tfvars merge)
  _common_scps = try(local.common.locals.service_control_policies, [])
  common_service_control_policies = [
    for scp in local._common_scps : merge(scp, {
      content = (
        try(scp.content, "") == "__LOADER_INJECT__"
        ? jsonencode(jsondecode(try(local._loader_inject_map[scp.name], scp.content)))
        : try(scp.content, "")
      )
    })
  ]

  # All five policy families normalize injected content the same way:
  # jsonencode(jsondecode(...)) parses the document at plan time (a syntax
  # error fails the plan, not the AWS call) and yields the compact form the
  # organization module measures against the AWS length limits.
  _common_declarative = try(local.common.locals.declarative_policies, [])
  common_declarative_policies = [
    for p in local._common_declarative : merge(p, {
      content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  # Marker of a deployment value that could not be resolved (see the comment at
  # _organization_id). A document carrying one is not deployable.
  _unresolved_marker = "@@[a-z_]+@@"

  _common_rcps = try(local.common.locals.resource_control_policies, [])
  _common_rcps_injected = [
    for rcp in local._common_rcps : merge(rcp, {
      content = try(rcp.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[rcp.name], rcp.content))) : try(rcp.content, "")
    })
  ]
  common_resource_control_policies = [
    for rcp in local._common_rcps_injected : rcp
    if !can(regex(local._unresolved_marker, rcp.content))
  ]

  _common_tag = try(local.common.locals.tag_policies, [])
  common_tag_policies = [
    for p in local._common_tag : merge(p, {
      content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  _common_backup = try(local.common.locals.backup_policies, [])
  common_backup_policies = [
    for p in local._common_backup : merge(p, {
      content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  _common_quarantine            = try(local.common.locals.quarantine_scp, {})
  common_quarantine_scp_content = try(local._common_quarantine.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[try(local._common_quarantine.name, "")], local._common_quarantine.content))) : try(local._common_quarantine.content, "")

  # ---------------------------------------------------------------------------
  # Merge: Lists by concatenation
  # ---------------------------------------------------------------------------
  # managed_rules and remediation_configs are loaded from JSON files
  # because read_tfvars_file cannot parse their nested object structures.
  _json_managed_rules       = jsondecode(file("${get_repo_root()}/configurations/base/managed-rules.json"))
  _json_management_rules    = jsondecode(file("${get_repo_root()}/configurations/base/management-only-rules.json"))
  _json_remediation_configs = jsondecode(file("${get_repo_root()}/configurations/base/remediation-configs.json"))
  _json_automation_rules    = jsondecode(file("${get_repo_root()}/configurations/base/security-hub-automation-rules.json"))

  # env/common.hcl is the fourth source: a concat in the config-rules stack
  # would bypass the EUSC filter below — a rule env/common.hcl contributes must
  # pass the same partition filter as every other rule, so the merge happens
  # here and the stack reads filtered_managed_rules alone.
  managed_rules = concat(
    local._json_managed_rules,
    try(local.base.managed_rules, []),
    try(local.common.locals.managed_rules, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.managed_rules, [])])
  )

  management_only_rules = local._json_management_rules

  service_control_policies = [
    for scp in concat(
      try(local.base.service_control_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.service_control_policies, [])])
      ) : merge(scp, {
        content = scp.content == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[scp.name], scp.content))) : scp.content
    })
  ]

  _rcps_injected = [
    for rcp in concat(
      try(local.base.resource_control_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.resource_control_policies, [])])
      ) : merge(rcp, {
        content = rcp.content == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[rcp.name], rcp.content))) : rcp.content
    })
  ]
  resource_control_policies = [
    for rcp in local._rcps_injected : rcp
    if !can(regex(local._unresolved_marker, rcp.content))
  ]

  # Resource control policies left out above. stacks/management/organization
  # hands this list to the module, whose check block names each one as a
  # warning on every plan and apply: on a new organization the ID exists only
  # after the first apply, so a refusal here would block that apply.
  unresolved_resource_control_policies = concat(
    [for rcp in local._common_rcps_injected : rcp.name if can(regex(local._unresolved_marker, rcp.content))],
    [for rcp in local._rcps_injected : rcp.name if can(regex(local._unresolved_marker, rcp.content))],
  )

  # Diagnostic: policy documents left out because a deployment value they need
  # is not configured. Read this list when an expected policy does not appear in
  # the plan.
  unresolved_policy_documents = concat(
    local.unresolved_resource_control_policies,
    [for p in local._endpoint_policies_injected : p.name if can(regex(local._unresolved_marker, p.policy))],
  )

  # custom_rules and remediation_configs entries may describe a Lambda the
  # module creates (lambda / target_document_lambda). The static configuration
  # layers cannot call file(), so a source_file / role_policy_file path is
  # resolved to its content here — the pattern of ssm_documents' content_file.
  # Inline source_code / role_policy win over the file form.
  custom_rules = [
    for rule in concat(
      try(local.base.custom_rules, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.custom_rules, [])])
      ) : merge(rule, {
        lambda = try(rule.lambda, null) == null ? null : merge(rule.lambda, {
          source_code = try(rule.lambda.source_code, "") != "" ? rule.lambda.source_code : (
            try(rule.lambda.source_file, "") != "" ? file("${get_repo_root()}/${rule.lambda.source_file}") : ""
          )
          role_policy = try(rule.lambda.role_policy, "") != "" ? rule.lambda.role_policy : (
            try(rule.lambda.role_policy_file, "") != "" ? file("${get_repo_root()}/${rule.lambda.role_policy_file}") : ""
          )
        })
    })
  ]

  conformance_packs = concat(
    try(local.base.conformance_packs, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.conformance_packs, [])])
  )

  remediation_configs = [
    for config in concat(
      local._json_remediation_configs,
      try(local.base.remediation_configs, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.remediation_configs, [])])
      ) : merge(config, {
        target_document_lambda = try(config.target_document_lambda, null) == null ? null : merge(config.target_document_lambda, {
          source_code = try(config.target_document_lambda.source_code, "") != "" ? config.target_document_lambda.source_code : (
            try(config.target_document_lambda.source_file, "") != "" ? file("${get_repo_root()}/${config.target_document_lambda.source_file}") : ""
          )
          role_policy = try(config.target_document_lambda.role_policy, "") != "" ? config.target_document_lambda.role_policy : (
            try(config.target_document_lambda.role_policy_file, "") != "" ? file("${get_repo_root()}/${config.target_document_lambda.role_policy_file}") : ""
          )
        })
    })
  ]

  # IAM customer-managed policies pass through the injection table like the
  # organization policy families (sixth family): jsonencode(jsondecode(...))
  # parses the document at plan time, so a JSON syntax error in an injected
  # file — and an unknown name, whose entry keeps the literal marker — fails
  # the plan instead of the AWS call. The loop covers the full concat list
  # (base + common + frameworks), the pattern of service_control_policies:
  # an injection marker means the same thing in every layer, so a base or
  # framework entry carrying it must not reach the IAM module as a literal.
  customer_managed_policies = [
    for p in concat(
      try(local.base.customer_managed_policies, []),
      try(local.common.locals.customer_managed_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.customer_managed_policies, [])])
      ) : merge(p, {
        policy = try(p.policy, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.policy))) : try(p.policy, "")
    })
  ]

  # env/common.hcl is the third source: customer-managed keys
  # are an installation decision, so the layer that describes the installation
  # has to be able to contribute them — base.tfvars carries no kms_keys at all
  # and only three of the eight framework files do.
  kms_keys = concat(
    try(local.base.kms_keys, []),
    try(local.common.locals.kms_keys, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.kms_keys, [])])
  )

  # env/common.hcl is the third source: which Security Hub controls an
  # installation switches off is an installation decision. Neither base.tfvars
  # nor any framework file carries the key, so this source is the only path to
  # aws_securityhub_standards_control.disabled.
  security_hub_disabled_controls = concat(
    try(local.base.security_hub_disabled_controls, []),
    try(local.common.locals.security_hub_disabled_controls, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.security_hub_disabled_controls, [])])
  )

  # Security Hub standards with per-standard deployment targets.
  # Separate from security_hub_standards above: that list says *which* standards
  # are enabled, this one says *where*.
  security_hub_standards_config = concat(
    try(local.base.security_hub_standards_config, []),
    try(local.common.locals.security_hub_standards_config, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.security_hub_standards_config, [])])
  )

  # Firewall Manager policies — same list-concatenation rule as
  # the organization policies above.
  fms_policies = concat(
    try(local.base.fms_policies, []),
    try(local.common.locals.fms_policies, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.fms_policies, [])])
  )

  # Chatbot policies, the sixth policy type beside service_control_policies,
  # resource_control_policies, declarative_policies, tag_policies and
  # backup_policies; the organization stack reads all six from here.
  chatbot_policies = [
    for p in concat(
      try(local.base.chatbot_policies, []),
      try(local.common.locals.chatbot_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.chatbot_policies, [])])
      ) : merge(p, {
        content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  # Monitoring collections: metric filters, alarms and SNS topics. Merged by
  # concatenation like the policy lists, so a framework can add alarms to the
  # baseline instead of replacing it.
  cloudwatch_metric_filters = concat(
    try(local.base.cloudwatch_metric_filters, []),
    try(local.common.locals.cloudwatch_metric_filters, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.cloudwatch_metric_filters, [])])
  )

  cloudwatch_alarms = concat(
    try(local.base.cloudwatch_alarms, []),
    try(local.common.locals.cloudwatch_alarms, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.cloudwatch_alarms, [])])
  )

  sns_topics = concat(
    try(local.base.sns_topics, []),
    try(local.common.locals.sns_topics, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.sns_topics, [])])
  )

  # CloudWatch log data protection identifiers — union, because
  # every layer may add categories of sensitive data and none may drop one.
  cloudwatch_log_data_protection_identifiers = distinct(concat(
    try(local.base.cloudwatch_log_data_protection_identifiers, []),
    try(local.common.locals.cloudwatch_log_data_protection_identifiers, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.cloudwatch_log_data_protection_identifiers, [])])
  ))

  # The 29 baseline rules from security-hub-automation-rules.json are the
  # first concat source (pattern managed_rules): a contribution from any
  # layer supplements the baseline instead of replacing it. A fallback to the
  # JSON only for an empty list would let the first contributed rule silently
  # drop every baseline suppression.
  security_hub_automation_rules = concat(
    local._json_automation_rules,
    try(local.base.security_hub_automation_rules, []),
    try(local.common.locals.security_hub_automation_rules, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.security_hub_automation_rules, [])])
  )

  # env/common.hcl is a source of its own: the two documents the auto-remediations
  # target are defined there. Without a source the list would stay empty, the
  # security module would create no document at all, and both target_id values
  # would point at nothing.
  ssm_documents = [
    for doc in concat(
      try(local.base.ssm_documents, []),
      try(local.common.locals.ssm_documents, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.ssm_documents, [])])
      ) : merge(doc, {
        content = try(doc.content, "") != "" ? doc.content : (
          try(doc.content_file, "") != "" ? file("${get_repo_root()}/${doc.content_file}") : ""
        )
    })
  ]

  # ---------------------------------------------------------------------------
  # EC2 compute (firewall appliances, workload compute): launch templates
  # ---------------------------------------------------------------------------
  # The configuration replacement template of an entry travels as a string:
  # either inline (user_data_template) or as the name of a repository file
  # (user_data_template_file) that is resolved to its content here — the same
  # name-carrying entry form the ssm_documents content_file uses. The module
  # itself reads no files; the helper key is stripped before the entry reaches
  # the module variable.
  firewall_launch_templates = {
    for name, lt in try(local.common.locals.firewall_launch_templates, {}) : name => {
      for attr, value in merge(lt, {
        user_data_template = try(lt.user_data_template, "") != "" ? lt.user_data_template : (
          try(lt.user_data_template_file, "") != "" ? file("${get_repo_root()}/${lt.user_data_template_file}") : ""
        )
      }) : attr => value if attr != "user_data_template_file"
    }
  }

  workload_launch_templates = {
    for name, lt in try(local.common.locals.workload_launch_templates, {}) : name => {
      for attr, value in merge(lt, {
        user_data_template = try(lt.user_data_template, "") != "" ? lt.user_data_template : (
          try(lt.user_data_template_file, "") != "" ? file("${get_repo_root()}/${lt.user_data_template_file}") : ""
        )
      }) : attr => value if attr != "user_data_template_file"
    }
  }

  directory_config_launch_templates = {
    for name, lt in try(local.common.locals.directory_config_launch_templates, {}) : name => {
      for attr, value in merge(lt, {
        user_data_template = try(lt.user_data_template, "") != "" ? lt.user_data_template : (
          try(lt.user_data_template_file, "") != "" ? file("${get_repo_root()}/${lt.user_data_template_file}") : ""
        )
      }) : attr => value if attr != "user_data_template_file"
    }
  }

  # Per-template IMDSv1 acknowledgement, read the same way as the launch
  # template maps above: from env/common.hcl alone. These three lists take
  # no base/framework merge (unlike _additional_aws_service_access_principals
  # further down, which concatenates base, common and frameworks), so a
  # framework cannot acknowledge IMDSv1 for an operator. A name on one of these
  # lists says that this launch template deliberately leaves IMDSv1 reachable
  # through its metadata option, and silences the module's warning for that
  # template only. Absent or empty (the default) leaves every plan as it was.
  # What it costs: on that template any process reaching the link-local
  # metadata address reads the instance role's credentials without a signed
  # token, as long as the name is listed.
  firewall_imdsv1_acknowledged_launch_templates         = try(local.common.locals.firewall_imdsv1_acknowledged_launch_templates, [])
  workload_imdsv1_acknowledged_launch_templates         = try(local.common.locals.workload_imdsv1_acknowledged_launch_templates, [])
  directory_config_imdsv1_acknowledged_launch_templates = try(local.common.locals.directory_config_imdsv1_acknowledged_launch_templates, [])

  declarative_policies = [
    for p in concat(
      try(local.base.declarative_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.declarative_policies, [])])
      ) : merge(p, {
        content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  tag_policies = [
    for p in concat(
      try(local.base.tag_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.tag_policies, [])])
      ) : merge(p, {
        content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  backup_policies = [
    for p in concat(
      try(local.base.backup_policies, []),
      flatten([for _, cfg in local.framework_configs : try(cfg.backup_policies, [])])
      ) : merge(p, {
        content = try(p.content, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.content))) : try(p.content, "")
    })
  ]

  # ---------------------------------------------------------------------------
  # Merge: Sets by union (distinct)
  # ---------------------------------------------------------------------------
  # security_hub_standards can contain mixed types (strings and objects).
  # Normalize to objects first, then deduplicate by arn_suffix.
  #
  # env/common.hcl is a merge source of its own: read_tfvars_file cannot parse
  # the mixed-type list, so the canonical standards live there. Without this
  # source the stacks would have to read common.hcl directly and bypass the
  # union merge, which silently drops every standard a framework contributes.
  # Order matters — base, then common.hcl, then the frameworks,
  # so that a framework entry wins the deduplication below.
  _raw_security_hub_standards = concat(
    try(local.base.security_hub_standards, []),
    try(local.common.locals.security_hub_standards, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.security_hub_standards, [])])
  )

  # Built unconditionally with try() instead of a conditional on can(s.arn_suffix):
  # the list holds both shapes at the same time — objects from env/common.hcl
  # and bare strings from a framework file. A conditional has to unify the types
  # of both result expressions, so `can(s.arn_suffix) ? s : { … }` would abort
  # the whole loader with "Inconsistent conditional result types". try()
  # resolves per element and per attribute and keeps the result type fixed.
  _normalized_security_hub_standards = [
    for s in local._raw_security_hub_standards : {
      arn_suffix = try(tostring(s.arn_suffix), tostring(s))
      enabled    = try(tobool(s.enabled), true)
    }
  ]

  # Deduplicate by arn_suffix — last entry wins (framework overrides base).
  # The grouping form (=> s...) is required: a plain for-object expression
  # aborts with "Duplicate object key" as soon as two sources name the same
  # standard (env/common.hcl and nist-800-53.tfvars both carry
  # nist-800-53/v/5.0.0).
  _standards_groups = { for s in local._normalized_security_hub_standards : s.arn_suffix => s... }
  _standards_map = {
    for suffix, group in local._standards_groups : suffix => group[length(group) - 1]
  }
  security_hub_standards = values(local._standards_map)

  cloudtrail_insights = distinct(concat(
    try(local.base.cloudtrail_insights, []),
    try(local.common.locals.cloudtrail_insights, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.cloudtrail_insights, [])])
  ))

  # ---------------------------------------------------------------------------
  # Merge: Scalars by most-restrictive
  # ---------------------------------------------------------------------------
  # Three sources per retention, same layering as the booleans below:
  # base.tfvars, env/common.hcl and the enabled frameworks. It is a max(): a
  # framework enforces a minimum
  # retention, and a shorter value in env/common.hcl cannot undercut it.
  _base_log_retention       = try(local.base.log_retention_days, 365)
  _common_log_retention     = try(local.common.locals.log_retention_days, 365)
  _framework_log_retentions = [for _, cfg in local.framework_configs : try(cfg.log_retention_days, 365)]
  log_retention_days = max(concat(
    [local._base_log_retention, local._common_log_retention],
    local._framework_log_retentions
  )...)

  _base_cw_retention       = try(local.base.cloudwatch_log_group_retention, 90)
  _common_cw_retention     = try(local.common.locals.cloudwatch_log_group_retention, 90)
  _framework_cw_retentions = [for _, cfg in local.framework_configs : try(cfg.cloudwatch_log_group_retention, 90)]
  cloudwatch_log_group_retention = max(concat(
    [local._base_cw_retention, local._common_cw_retention],
    local._framework_cw_retentions
  )...)

  # Control Tower keeps its own two retention periods. They follow
  # the merged log retention so that Control Tower does not hold a shorter
  # period than the rest of the landing zone, and env/common.hcl may raise them
  # further.
  control_tower_logging_retention_days = max(
    local.log_retention_days,
    try(local.common.locals.control_tower_logging_retention_days, 0)
  )
  control_tower_access_logging_retention_days = max(
    local.log_retention_days,
    try(local.common.locals.control_tower_access_logging_retention_days, 0)
  )

  # Audit Manager report bucket lifecycle. Deliberately *not*
  # coupled to log_retention_days: the module documents 0 as "no lifecycle", and
  # a max() against the merged retention would make that value unreachable.
  # base.tfvars and env/common.hcl are merged with max(), the frameworks are not
  # a source — none of them carries the key.
  audit_manager_bucket_lifecycle_days = max(
    try(local.base.audit_manager_bucket_lifecycle_days, 365),
    try(local.common.locals.audit_manager_bucket_lifecycle_days, 365)
  )

  # ---------------------------------------------------------------------------
  # Merge: Booleans by staged precedence and by OR
  # ---------------------------------------------------------------------------
  # Three sources per switch: base.tfvars, env/common.hcl and the enabled
  # frameworks. A stack that read env/common.hcl directly would bypass the
  # merge, and a framework that switches a service on would have no effect.
  #
  # Switches that base.tfvars ships as `true` follow the staged precedence
  # rule: a value the operator sets in env/common.hcl
  # wins — including `false` — because `_operator_<key>` distinguishes null
  # (not set, fall through) from an explicit value. When the operator is
  # silent, the OR over base.tfvars and the frameworks decides. An operator
  # `false` therefore really disables the service on the next apply.
  #
  # Switches that base.tfvars ships as `false` keep the plain OR fold: any
  # layer can switch them on, and an operator `false` changes nothing that
  # is not already off unless a framework mandates it.
  _operator_enable_guardduty = try(local.common.locals.enable_guardduty, null)
  enable_guardduty = (
    local._operator_enable_guardduty != null
    ? local._operator_enable_guardduty
    : anytrue(concat(
      [try(local.base.enable_guardduty, false)],
      [for _, cfg in local.framework_configs : try(cfg.enable_guardduty, false)]
    ))
  )

  _operator_enable_security_hub = try(local.common.locals.enable_security_hub, null)
  enable_security_hub = (
    local._operator_enable_security_hub != null
    ? local._operator_enable_security_hub
    : anytrue(concat(
      [try(local.base.enable_security_hub, false)],
      [for _, cfg in local.framework_configs : try(cfg.enable_security_hub, false)]
    ))
  )

  _operator_enable_access_analyzer = try(local.common.locals.enable_access_analyzer, null)
  enable_access_analyzer = (
    local._operator_enable_access_analyzer != null
    ? local._operator_enable_access_analyzer
    : anytrue(concat(
      [try(local.base.enable_access_analyzer, false)],
      [for _, cfg in local.framework_configs : try(cfg.enable_access_analyzer, false)]
    ))
  )

  _operator_enable_macie = try(local.common.locals.enable_macie, null)
  enable_macie = (
    local._operator_enable_macie != null
    ? local._operator_enable_macie
    : anytrue(concat(
      [try(local.base.enable_macie, false)],
      [for _, cfg in local.framework_configs : try(cfg.enable_macie, false)]
    ))
  )

  _operator_cloudtrail_s3_data_events = try(local.common.locals.cloudtrail_s3_data_events, null)
  cloudtrail_s3_data_events = (
    local._operator_cloudtrail_s3_data_events != null
    ? local._operator_cloudtrail_s3_data_events
    : anytrue(concat(
      [try(local.base.cloudtrail_s3_data_events, false)],
      [for _, cfg in local.framework_configs : try(cfg.cloudtrail_s3_data_events, false)]
    ))
  )

  _operator_cloudtrail_lambda_data_events = try(local.common.locals.cloudtrail_lambda_data_events, null)
  cloudtrail_lambda_data_events = (
    local._operator_cloudtrail_lambda_data_events != null
    ? local._operator_cloudtrail_lambda_data_events
    : anytrue(concat(
      [try(local.base.cloudtrail_lambda_data_events, false)],
      [for _, cfg in local.framework_configs : try(cfg.cloudtrail_lambda_data_events, false)]
    ))
  )

  _operator_enable_session_manager_logging = try(local.common.locals.enable_session_manager_logging, null)
  enable_session_manager_logging = (
    local._operator_enable_session_manager_logging != null
    ? local._operator_enable_session_manager_logging
    : anytrue(concat(
      [try(local.base.enable_session_manager_logging, false)],
      [for _, cfg in local.framework_configs : try(cfg.enable_session_manager_logging, false)]
    ))
  )

  # Three layers, like its neighbours enable_macie and enable_guardduty.
  _operator_enable_elb_log_bucket = try(local.common.locals.enable_elb_log_bucket, null)
  enable_elb_log_bucket = (
    local._operator_enable_elb_log_bucket != null
    ? local._operator_enable_elb_log_bucket
    : anytrue(concat(
      [try(local.base.enable_elb_log_bucket, false)],
      [for _, cfg in local.framework_configs : try(cfg.enable_elb_log_bucket, false)]
    ))
  )

  enable_scp_revert_detection = anytrue(concat(
    [try(local.base.enable_scp_revert_detection, false)],
    [try(local.common.locals.enable_scp_revert_detection, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_scp_revert_detection, false)]
  ))

  enable_central_root_management = anytrue(concat(
    [try(local.base.enable_central_root_management, false)],
    [try(local.common.locals.enable_central_root_management, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_central_root_management, false)]
  ))

  # These four switches read all three layers as well. The three with
  # base.tfvars = true follow the staged precedence rule above: an operator
  # value in env/common.hcl decides, including false.
  _operator_guardduty_malware_protection = try(local.common.locals.guardduty_malware_protection, null)
  guardduty_malware_protection = (
    local._operator_guardduty_malware_protection != null
    ? local._operator_guardduty_malware_protection
    : anytrue(concat(
      [try(local.base.guardduty_malware_protection, false)],
      [for _, cfg in local.framework_configs : try(cfg.guardduty_malware_protection, false)]
    ))
  )

  # Macie publish policy findings
  _operator_macie_publish_policy_findings = try(local.common.locals.macie_publish_policy_findings, null)
  macie_publish_policy_findings = (
    local._operator_macie_publish_policy_findings != null
    ? local._operator_macie_publish_policy_findings
    : anytrue(concat(
      [try(local.base.macie_publish_policy_findings, false)],
      [for _, cfg in local.framework_configs : try(cfg.macie_publish_policy_findings, false)]
    ))
  )

  # GuardDuty keep malware protection snapshots
  guardduty_keep_malware_snapshots = anytrue(concat(
    [try(local.base.guardduty_keep_malware_snapshots, false)],
    [try(local.common.locals.guardduty_keep_malware_snapshots, false)],
    [for _, cfg in local.framework_configs : try(cfg.guardduty_keep_malware_snapshots, false)]
  ))

  # SNS KMS encryption for monitoring topics — OR across base.tfvars,
  # env/common.hcl and the frameworks, with the staged precedence rule above.
  _operator_sns_kms_encryption = try(local.common.locals.sns_kms_encryption, null)
  sns_kms_encryption = (
    local._operator_sns_kms_encryption != null
    ? local._operator_sns_kms_encryption
    : anytrue(concat(
      [try(local.base.sns_kms_encryption, false)],
      [for _, cfg in local.framework_configs : try(cfg.sns_kms_encryption, false)]
    ))
  )

  # ---------------------------------------------------------------------------
  # Merge: feature keys of base.tfvars
  # ---------------------------------------------------------------------------
  # These ten keys are defined in base.tfvars, and the baseline promise of
  # base.tfvars ("applied regardless of framework") only holds when the stacks
  # read them through the loader. Same three-layer rule as the neighbours: booleans by OR (all
  # module defaults are false), lists by concatenation. The stacks read
  # these locals instead of env/common.hcl.

  enable_guardduty_s3_malware_protection = anytrue(concat(
    [try(local.base.enable_guardduty_s3_malware_protection, false)],
    [try(local.common.locals.enable_guardduty_s3_malware_protection, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_guardduty_s3_malware_protection, false)]
  ))

  guardduty_s3_malware_configs = concat(
    try(local.base.guardduty_s3_malware_configs, []),
    try(local.common.locals.guardduty_s3_malware_configs, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.guardduty_s3_malware_configs, [])])
  )

  guardduty_eks_manage_agent = anytrue(concat(
    [try(local.base.guardduty_eks_manage_agent, false)],
    [try(local.common.locals.guardduty_eks_manage_agent, false)],
    [for _, cfg in local.framework_configs : try(cfg.guardduty_eks_manage_agent, false)]
  ))

  enable_securityhub_cloudwatch_forwarding = anytrue(concat(
    [try(local.base.enable_securityhub_cloudwatch_forwarding, false)],
    [try(local.common.locals.enable_securityhub_cloudwatch_forwarding, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_securityhub_cloudwatch_forwarding, false)]
  ))

  securityhub_severity_filter = concat(
    try(local.base.securityhub_severity_filter, []),
    try(local.common.locals.securityhub_severity_filter, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.securityhub_severity_filter, [])])
  )

  enable_scp_auto_revert = anytrue(concat(
    [try(local.base.enable_scp_auto_revert, false)],
    [try(local.common.locals.enable_scp_auto_revert, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_scp_auto_revert, false)]
  ))

  enable_quarantine_auto_detach = anytrue(concat(
    [try(local.base.enable_quarantine_auto_detach, false)],
    [try(local.common.locals.enable_quarantine_auto_detach, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_quarantine_auto_detach, false)]
  ))

  enable_delete_default_vpc = anytrue(concat(
    [try(local.base.enable_delete_default_vpc, false)],
    [try(local.common.locals.enable_delete_default_vpc, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_delete_default_vpc, false)]
  ))

  enable_delete_default_sg_rules = anytrue(concat(
    [try(local.base.enable_delete_default_sg_rules, false)],
    [try(local.common.locals.enable_delete_default_sg_rules, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_delete_default_sg_rules, false)]
  ))

  enable_stackset_roles = anytrue(concat(
    [try(local.base.enable_stackset_roles, false)],
    [try(local.common.locals.enable_stackset_roles, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_stackset_roles, false)]
  ))

  # ---------------------------------------------------------------------------
  # Merge: Booleans by OR — module feature switches
  # ---------------------------------------------------------------------------
  # Same three-layer rule as above. These switches guard features that the
  # documentation promises; without a loader local the module default would be
  # the only effective value.
  #
  # Two shapes are needed, because a plain OR fold cannot do both jobs at once:
  #
  #   * module default false — plain anytrue() with a try() default of false.
  #     No layer set, no feature; any layer switches it on.
  #   * module default true — the value has to fall back to true when *no* layer
  #     declares the key, and must still be switchable. A plain
  #     anytrue(…, false) would turn the feature off the moment a stack starts
  #     reading the local; an anytrue(…, true) could never be switched off. The
  #     _declared_<key> lists below therefore collect only the values that
  #     base.tfvars and the frameworks really declare and fall back to the
  #     module default when the list is empty. The operator sits in front via
  #     the staged precedence rule: a value set in env/common.hcl
  #     wins outright — including false — through `_operator_<key>`, which
  #     distinguishes null (not set) from an explicit value.
  #
  # Either way, wiring one of these locals into a stack does not change the
  # deployment on its own — only an explicit value in a configuration layer does.
  #
  # Encryption and key management
  _operator_enable_ebs_default_encryption = try(local.common.locals.enable_ebs_default_encryption, null)
  _declared_enable_ebs_default_encryption = [
    for v in concat(
      [try(local.base.enable_ebs_default_encryption, null)],
      [for _, cfg in local.framework_configs : try(cfg.enable_ebs_default_encryption, null)]
    ) : v if v != null
  ]
  enable_ebs_default_encryption = (
    local._operator_enable_ebs_default_encryption != null
    ? local._operator_enable_ebs_default_encryption
    : (
      length(local._declared_enable_ebs_default_encryption) == 0
      ? true
      : anytrue(local._declared_enable_ebs_default_encryption)
    )
  )

  enable_lambda_encryption = anytrue(concat(
    [try(local.base.enable_lambda_encryption, false)],
    [try(local.common.locals.enable_lambda_encryption, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_lambda_encryption, false)]
  ))

  enable_sqs_kms_key = anytrue(concat(
    [try(local.base.enable_sqs_kms_key, false)],
    [try(local.common.locals.enable_sqs_kms_key, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_sqs_kms_key, false)]
  ))

  # Shared by modules/logging and modules/security — both declare the switch
  # under the same name.
  enable_per_account_kms_keys = anytrue(concat(
    [try(local.base.enable_per_account_kms_keys, false)],
    [try(local.common.locals.enable_per_account_kms_keys, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_per_account_kms_keys, false)]
  ))

  # S3 and SSM public access — module default true
  _operator_enable_s3_public_access_block = try(local.common.locals.enable_s3_public_access_block, null)
  _declared_enable_s3_public_access_block = [
    for v in concat(
      [try(local.base.enable_s3_public_access_block, null)],
      [for _, cfg in local.framework_configs : try(cfg.enable_s3_public_access_block, null)]
    ) : v if v != null
  ]
  enable_s3_public_access_block = (
    local._operator_enable_s3_public_access_block != null
    ? local._operator_enable_s3_public_access_block
    : (
      length(local._declared_enable_s3_public_access_block) == 0
      ? true
      : anytrue(local._declared_enable_s3_public_access_block)
    )
  )

  _operator_enable_ssm_block_public_sharing = try(local.common.locals.enable_ssm_block_public_sharing, null)
  _declared_enable_ssm_block_public_sharing = [
    for v in concat(
      [try(local.base.enable_ssm_block_public_sharing, null)],
      [for _, cfg in local.framework_configs : try(cfg.enable_ssm_block_public_sharing, null)]
    ) : v if v != null
  ]
  enable_ssm_block_public_sharing = (
    local._operator_enable_ssm_block_public_sharing != null
    ? local._operator_enable_ssm_block_public_sharing
    : (
      length(local._declared_enable_ssm_block_public_sharing) == 0
      ? true
      : anytrue(local._declared_enable_ssm_block_public_sharing)
    )
  )

  # Session Manager and SSM
  enable_session_manager_s3_logging = anytrue(concat(
    [try(local.base.enable_session_manager_s3_logging, false)],
    [try(local.common.locals.enable_session_manager_s3_logging, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_session_manager_s3_logging, false)]
  ))

  enable_ssm_resource_data_sync = anytrue(concat(
    [try(local.base.enable_ssm_resource_data_sync, false)],
    [try(local.common.locals.enable_ssm_resource_data_sync, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_ssm_resource_data_sync, false)]
  ))

  # Security Hub region aggregation — module default true
  _declared_enable_security_hub_region_aggregation = [
    for v in concat(
      [try(local.base.enable_security_hub_region_aggregation, null)],
      [try(local.common.locals.enable_security_hub_region_aggregation, null)],
      [for _, cfg in local.framework_configs : try(cfg.enable_security_hub_region_aggregation, null)]
    ) : v if v != null
  ]
  enable_security_hub_region_aggregation = (
    length(local._declared_enable_security_hub_region_aggregation) == 0
    ? true
    : anytrue(local._declared_enable_security_hub_region_aggregation)
  )

  # Audit Manager report bucket
  enable_audit_manager_bucket = anytrue(concat(
    [try(local.base.enable_audit_manager_bucket, false)],
    [try(local.common.locals.enable_audit_manager_bucket, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_audit_manager_bucket, false)]
  ))

  # GuardDuty protection plans — module default true for the four
  # data-source plans, false for EKS runtime monitoring.
  _declared_guardduty_s3_protection = [
    for v in concat(
      [try(local.base.guardduty_s3_protection, null)],
      [try(local.common.locals.guardduty_s3_protection, null)],
      [for _, cfg in local.framework_configs : try(cfg.guardduty_s3_protection, null)]
    ) : v if v != null
  ]
  guardduty_s3_protection = (
    length(local._declared_guardduty_s3_protection) == 0
    ? true
    : anytrue(local._declared_guardduty_s3_protection)
  )

  _declared_guardduty_eks_protection = [
    for v in concat(
      [try(local.base.guardduty_eks_protection, null)],
      [try(local.common.locals.guardduty_eks_protection, null)],
      [for _, cfg in local.framework_configs : try(cfg.guardduty_eks_protection, null)]
    ) : v if v != null
  ]
  guardduty_eks_protection = (
    length(local._declared_guardduty_eks_protection) == 0
    ? true
    : anytrue(local._declared_guardduty_eks_protection)
  )

  _declared_guardduty_lambda_protection = [
    for v in concat(
      [try(local.base.guardduty_lambda_protection, null)],
      [try(local.common.locals.guardduty_lambda_protection, null)],
      [for _, cfg in local.framework_configs : try(cfg.guardduty_lambda_protection, null)]
    ) : v if v != null
  ]
  guardduty_lambda_protection = (
    length(local._declared_guardduty_lambda_protection) == 0
    ? true
    : anytrue(local._declared_guardduty_lambda_protection)
  )

  _declared_guardduty_rds_protection = [
    for v in concat(
      [try(local.base.guardduty_rds_protection, null)],
      [try(local.common.locals.guardduty_rds_protection, null)],
      [for _, cfg in local.framework_configs : try(cfg.guardduty_rds_protection, null)]
    ) : v if v != null
  ]
  guardduty_rds_protection = (
    length(local._declared_guardduty_rds_protection) == 0
    ? true
    : anytrue(local._declared_guardduty_rds_protection)
  )

  guardduty_eks_runtime_monitoring = anytrue(concat(
    [try(local.base.guardduty_eks_runtime_monitoring, false)],
    [try(local.common.locals.guardduty_eks_runtime_monitoring, false)],
    [for _, cfg in local.framework_configs : try(cfg.guardduty_eks_runtime_monitoring, false)]
  ))

  # Central root credentials management — module default true.
  # Centralising is the stricter state, so OR is the right direction among the
  # declared values.
  _declared_root_credentials_management = [
    for v in concat(
      [try(local.base.root_credentials_management, null)],
      [try(local.common.locals.root_credentials_management, null)],
      [for _, cfg in local.framework_configs : try(cfg.root_credentials_management, null)]
    ) : v if v != null
  ]
  root_credentials_management = (
    length(local._declared_root_credentials_management) == 0
    ? true
    : anytrue(local._declared_root_credentials_management)
  )

  # Logging: separate access log bucket (module default false) and CloudTrail
  # management events (module default true).
  enable_separate_access_logs_bucket = anytrue(concat(
    [try(local.base.enable_separate_access_logs_bucket, false)],
    [try(local.common.locals.enable_separate_access_logs_bucket, false)],
    [for _, cfg in local.framework_configs : try(cfg.enable_separate_access_logs_bucket, false)]
  ))

  _declared_cloudtrail_management_events = [
    for v in concat(
      [try(local.base.cloudtrail_management_events, null)],
      [try(local.common.locals.cloudtrail_management_events, null)],
      [for _, cfg in local.framework_configs : try(cfg.cloudtrail_management_events, null)]
    ) : v if v != null
  ]
  cloudtrail_management_events = (
    length(local._declared_cloudtrail_management_events) == 0
    ? true
    : anytrue(local._declared_cloudtrail_management_events)
  )

  # ---------------------------------------------------------------------------
  # Merge: Booleans by AND — switches whose restrictive direction is "false"
  # ---------------------------------------------------------------------------
  # allow_root_sessions permits root sessions; the restrictive value is false.
  # OR would let any single layer re-enable them, so all layers have to agree,
  # the same rule password_policy.allow_users_to_change already follows.
  allow_root_sessions = alltrue(concat(
    [try(local.base.allow_root_sessions, true)],
    [try(local.common.locals.allow_root_sessions, true)],
    [for _, cfg in local.framework_configs : try(cfg.allow_root_sessions, true)]
  ))

  # ---------------------------------------------------------------------------
  # Merge: Base-only scalars (no framework override)
  # ---------------------------------------------------------------------------
  # Identities of the two auto-remediations. Empty means "not provisioned"; the
  # config-rules stack then leaves the affected remediation out instead of
  # deploying an automation that fails on every run. Source is
  # env/common.hcl deliberately: both keys name IAM identities of one concrete
  # installation — installation configuration, not a portable baseline, so
  # base.tfvars is not a source for them (see the base.tfvars header).
  remediation_assume_role_arn       = try(local.common.locals.remediation_assume_role_arn, "")
  remediation_instance_profile_name = try(local.common.locals.remediation_instance_profile_name, "")

  guardduty_export_frequency            = try(local.base.guardduty_export_frequency, "SIX_HOURS")
  macie_publishing_frequency            = try(local.base.macie_publishing_frequency, "FIFTEEN_MINUTES")
  macie_publish_sensitive_data_findings = try(local.base.macie_publish_sensitive_data_findings, false)

  # S3 lifecycle: retention_days follows the merged retention period. A fixed
  # number in base.tfvars, independent of log_retention_days, would let the
  # lifecycle delete objects years before a framework's retention period ends
  # (cmmc, fedramp-high and hipaa require 2555 days).
  #
  # The number from base.tfvars stays in force as a lower bound: it is the
  # baseline and lies above the Glacier transition on purpose, so that the move
  # to GLACIER_IR after one year has an effect. The loader raises it to
  # log_retention_days when a framework requires more; it can never be shorter
  # than the retention period.
  _lifecycle_retention_floor = local.log_retention_days

  # try() instead of a conditional: max(null, n) fails, and a conditional would
  # evaluate both branches. A rule without retention_days thus keeps "no
  # expiration", and a rule with retention_days is raised.
  s3_lifecycle_rules = {
    for name, rule in try(local.base.s3_lifecycle_rules, {}) :
    name => merge(rule, {
      retention_days = try(max(rule.retention_days, local._lifecycle_retention_floor), null)
    })
  }

  elb_log_bucket_lifecycle = merge(
    try(local.base.elb_log_bucket_lifecycle, {}),
    {
      retention_days = try(
        max(local.base.elb_log_bucket_lifecycle.retention_days, local._lifecycle_retention_floor),
        null
      )
    }
  )
  # Two layers carry the log group name (base.tfvars and env/common.hcl).
  # env/common.hcl wins because it describes the installation; base.tfvars is
  # the fallback. Without the first term the operator's value would be ignored.
  session_manager_cloudwatch_log_group = (
    try(local.common.locals.session_manager_cloudwatch_log_group, "") != ""
    ? local.common.locals.session_manager_cloudwatch_log_group
    : try(local.base.session_manager_cloudwatch_log_group, "")
  )

  # S3 lifecycle sub-fields — passed through within s3_lifecycle_rules above
  # abort_incomplete_multipart_upload_days (number, default 7) — per-rule field
  # This is a base-only scalar embedded in each lifecycle rule object.
  # Explicit extraction for stack-level access, read by
  # stacks/management/cur/terragrunt.hcl:
  abort_incomplete_multipart_upload_days = try(local.base.abort_incomplete_multipart_upload_days, 7)

  # ---------------------------------------------------------------------------
  # Merge: Password policy field-by-field
  # ---------------------------------------------------------------------------
  # env/common.hcl is a source of its own here too. It carries a full
  # password_policy of its own, and both consuming stacks read the merged
  # loader value, so the operator's policy only takes effect through this merge.
  _base_pp       = try(local.base.password_policy, {})
  _common_pp     = try(local.common.locals.password_policy, {})
  _framework_pps = [for _, cfg in local.framework_configs : try(cfg.password_policy, {})]

  _base_pp_min_length = try(local._base_pp.minimum_length, 14)
  _base_pp_max_age    = try(local._base_pp.max_age, 90)
  _base_pp_reuse      = try(local._base_pp.password_reuse_prevention, 24)

  _common_pp_min_length = try(local._common_pp.minimum_length, 14)
  _common_pp_max_age    = try(local._common_pp.max_age, 90)
  _common_pp_reuse      = try(local._common_pp.password_reuse_prevention, 24)

  _fw_pp_min_lengths = [for pp in local._framework_pps : try(pp.minimum_length, 14)]
  _fw_pp_max_ages    = [for pp in local._framework_pps : try(pp.max_age, 90)]
  _fw_pp_reuses      = [for pp in local._framework_pps : try(pp.password_reuse_prevention, 24)]

  password_policy = {
    # Scalars: max = most restrictive for length and reuse; min = most restrictive for max_age
    minimum_length = max(concat(
      [local._base_pp_min_length, local._common_pp_min_length], local._fw_pp_min_lengths
    )...)
    max_age = min(concat(
      [local._base_pp_max_age, local._common_pp_max_age], local._fw_pp_max_ages
    )...)
    password_reuse_prevention = max(concat(
      [local._base_pp_reuse, local._common_pp_reuse], local._fw_pp_reuses
    )...)

    # Booleans: OR across base + env/common.hcl + frameworks
    require_uppercase = anytrue(concat(
      [try(local._base_pp.require_uppercase, true)],
      [try(local._common_pp.require_uppercase, true)],
      [for pp in local._framework_pps : try(pp.require_uppercase, true)]
    ))
    require_lowercase = anytrue(concat(
      [try(local._base_pp.require_lowercase, true)],
      [try(local._common_pp.require_lowercase, true)],
      [for pp in local._framework_pps : try(pp.require_lowercase, true)]
    ))
    require_numbers = anytrue(concat(
      [try(local._base_pp.require_numbers, true)],
      [try(local._common_pp.require_numbers, true)],
      [for pp in local._framework_pps : try(pp.require_numbers, true)]
    ))
    require_symbols = anytrue(concat(
      [try(local._base_pp.require_symbols, true)],
      [try(local._common_pp.require_symbols, true)],
      [for pp in local._framework_pps : try(pp.require_symbols, true)]
    ))
    hard_expiry = anytrue(concat(
      [try(local._base_pp.hard_expiry, false)],
      [try(local._common_pp.hard_expiry, false)],
      [for pp in local._framework_pps : try(pp.hard_expiry, false)]
    ))

    # Booleans: AND for allow_users_to_change (all must agree)
    allow_users_to_change = alltrue(concat(
      [try(local._base_pp.allow_users_to_change, true)],
      [try(local._common_pp.allow_users_to_change, true)],
      [for pp in local._framework_pps : try(pp.allow_users_to_change, true)]
    ))
  }

  # ---------------------------------------------------------------------------
  # Partition filtering: aws-eusc exclusions
  # ---------------------------------------------------------------------------
  eusc_excluded_identifiers = [
    "MACIE_STATUS",
  ]

  # Filter managed rules for EUSC partition
  filtered_managed_rules = local.partition == "aws-eusc" ? [
    for rule in local.managed_rules :
    rule if !contains(local.eusc_excluded_identifiers, rule.source_identifier)
  ] : local.managed_rules

  # Filter Security Hub standards for EUSC partition. Mirrors the mechanism of
  # eusc_excluded_identifiers above: standards whose arn_suffix appears in the
  # exclusion list are dropped when the partition is aws-eusc. Which standards
  # are unavailable in aws-eusc is a fact the operator or maintainer must
  # supply — the list therefore ships empty, and the filter only takes effect
  # once it is populated (entries are arn_suffix values, e.g.
  # "nist-800-53/v/5.0.0").
  eusc_excluded_standard_suffixes = []

  filtered_security_hub_standards = local.partition == "aws-eusc" ? [
    for standard in local.security_hub_standards :
    standard if !contains(local.eusc_excluded_standard_suffixes, standard.arn_suffix)
  ] : local.security_hub_standards

  # Filter Macie for EUSC partition
  filtered_enable_macie = local.partition == "aws-eusc" ? false : local.enable_macie

  # Filter Macie publishing settings for EUSC partition. The off-signal is
  # null, never "": the module validation accepts only null or one of the
  # three frequency values, so "" would make every plan/validate fail in aws-eusc.
  filtered_macie_publishing_frequency            = local.partition == "aws-eusc" ? null : local.macie_publishing_frequency
  filtered_macie_publish_sensitive_data_findings = local.partition == "aws-eusc" ? false : local.macie_publish_sensitive_data_findings

  # Filter Macie policy findings for EUSC partition
  filtered_macie_publish_policy_findings = local.partition == "aws-eusc" ? false : local.macie_publish_policy_findings

  # Filter service_access_principals for EUSC partition
  # Exclude the Identity Center principal (sso.<suffix> — not available in
  # aws-eusc). The comparison matches the service part instead of a full
  # principal string, because the configuration builds the suffix from the
  # partition and the fixed form would miss sso.amazonaws.eu.
  _common_service_access_principals = local.common.locals.service_access_principals
  filtered_service_access_principals = local.partition == "aws-eusc" ? [
    for principal in local._common_service_access_principals :
    principal if !startswith(principal.service_principal, "sso.")
  ] : local._common_service_access_principals

  # Additional TRUSTED-ACCESS principals (aws_service_access_principals of the
  # organization module). The organization stack computes that list from the
  # module toggles alone; the organization resource owns the COMPLETE list and
  # the module refuses [], so without this key a toggle combination that
  # renders nothing would have no repair path, and an adopted organization could
  # not keep the trusted services the toggles do not know. This key lets the operator (and a
  # framework) add plain service principals; merged by concatenation like
  # chatbot_policies above, the stack appends it to the toggle list.
  _additional_aws_service_access_principals = concat(
    try(local.base.additional_aws_service_access_principals, []),
    try(local.common.locals.additional_aws_service_access_principals, []),
    flatten([for _, cfg in local.framework_configs : try(cfg.additional_aws_service_access_principals, [])])
  )
  # Sibling of the sso. strip in filtered_service_access_principals directly
  # above: Identity Center does not exist in aws-eusc, and
  # the two lists must stay in step — a sso.<suffix> entry that this key
  # reintroduces into trusted access would be enabled for a service the
  # partition does not offer. The entry is a plain principal string whose
  # service part is its prefix, so the match is on "sso." and not on a full
  # principal: the suffix is built from the partition and a fixed
  # form would miss sso.amazonaws.eu. try() lets a null element pass through
  # unstripped: startswith(null, ...) is an evaluation error that would abort
  # this whole loader before the module's blank validation can refuse the
  # entry by name (tests/test_regression_trusted_services_wiring.py).
  additional_aws_service_access_principals = local.partition == "aws-eusc" ? [
    for principal in local._additional_aws_service_access_principals :
    principal if !try(startswith(principal, "sso."), false)
  ] : local._additional_aws_service_access_principals

  # ---------------------------------------------------------------------------
  # Advisory networking defaults (gated by apply_network_defaults)
  # ---------------------------------------------------------------------------
  _raw_networking_defaults = local.has_frameworks ? merge(
    [for _, cfg in local.framework_configs : try(cfg.networking_defaults, {})]...
  ) : {}

  networking_defaults = local.apply_network_defaults ? local._raw_networking_defaults : {}

  # ---------------------------------------------------------------------------
  # Pass-through: installation values without a compliance merge
  # ---------------------------------------------------------------------------
  # These values only describe this installation — ARNs, names, account and
  # region lists, per-installation collections. There is nothing to merge across
  # layers, so the loader passes them through unchanged and only supplies the
  # module default as a fallback. Two reasons for putting them here rather than
  # letting each stack read env/common.hcl directly:
  #
  #   * one façade: a stack reads local.compliance.locals.<key> for every value,
  #     no matter which rule produced it;
  #   * the project's own convention requires every key of env/common.hcl to
  #     be referenced by a stack or by this loader.
  #
  # Each default equals the module default, so wiring one of these into a stack
  # does not change the deployment. The heading of each group names the
  # consuming module.

  # Identity Center (modules/accounts)
  identity_center_permission_sets = try(local.common.locals.identity_center_permission_sets, [])
  identity_center_assignments     = try(local.common.locals.identity_center_assignments, [])

  # Bootstrap KMS alias (modules/bootstrap)
  bootstrap_kms_key_alias = try(local.common.locals.kms_key_alias, "")

  # Cost and Usage Report bucket (modules/cur)
  noncurrent_version_expiration_days = try(local.common.locals.noncurrent_version_expiration_days, 365)

  # Deployment role (modules/deployment-role)
  deployment_role_permissions_boundary_arn = try(local.common.locals.permissions_boundary_arn, "")

  # IAM users, groups, Managed Active Directory (modules/iam)
  iam_users                  = try(local.common.locals.iam_users, [])
  iam_groups                 = try(local.common.locals.iam_groups, [])
  managed_active_directories = try(local.common.locals.managed_active_directories, [])

  # CloudTrail and Config recorder details (modules/logging)
  cloudtrail_account_trails       = try(local.common.locals.cloudtrail_account_trails, [])
  cloudtrail_sns_topic_name       = try(local.common.locals.cloudtrail_sns_topic_name, "")
  cloudwatch_log_exclusions       = try(local.common.locals.cloudwatch_log_exclusions, [])
  manage_config_recorder          = try(local.common.locals.manage_config_recorder, true)
  use_config_service_linked_role  = try(local.common.locals.use_config_service_linked_role, true)
  config_recorder_custom_role_arn = try(local.common.locals.config_recorder_custom_role_arn, "")

  # Networking: VPC scaffolding and templates (modules/networking)
  dhcp_options_sets = try(local.common.locals.dhcp_options_sets, [])
  elastic_ips       = try(local.common.locals.elastic_ips, [])

  # Endpoint policies pass through the injection table: an
  # entry whose policy is __LOADER_INJECT__ receives the file content keyed by
  # its name, normalized like the organization policy families. An entry whose
  # resolved policy still carries an unresolved deployment mark is dropped —
  # the vpc-endpoint-default-policy document scopes on @@organization_id@@,
  # and with the mark in place its deny statement would lock the endpoint for
  # every principal. Dropped names appear in unresolved_policy_documents; a
  # gateway or interface endpoint that references the name then fails the
  # networking module's policy_name validation instead of shipping an
  # unrestricted or all-deny endpoint.
  _endpoint_policies_injected = [
    for p in try(local.common.locals.endpoint_policies, []) : merge(p, {
      policy = try(p.policy, "") == "__LOADER_INJECT__" ? jsonencode(jsondecode(try(local._loader_inject_map[p.name], p.policy))) : try(p.policy, "")
    })
  ]
  endpoint_policies = [
    for p in local._endpoint_policies_injected : p
    if !can(regex(local._unresolved_marker, p.policy))
  ]

  vpc_flow_logs_default = try(local.common.locals.vpc_flow_logs_default, null)
  vpc_templates         = try(local.common.locals.vpc_templates, [])

  # Networking: load balancing (modules/networking)
  load_balancers         = try(local.common.locals.load_balancers, [])
  target_groups          = try(local.common.locals.target_groups, [])
  gateway_load_balancers = try(local.common.locals.gateway_load_balancers, [])
  # Issuers an authenticated edge may name; empty trusts none.
  authenticated_edge_allowed_issuers = try(local.common.locals.authenticated_edge_allowed_issuers, [])

  # Networking: hybrid connectivity (modules/networking)
  vpc_peering               = try(local.common.locals.vpc_peering, [])
  dx_gateways               = try(local.common.locals.dx_gateways, [])
  customer_gateways         = try(local.common.locals.customer_gateways, [])
  tgw_connect_attachments   = try(local.common.locals.tgw_connect_attachments, [])
  tgw_multicast_domains     = try(local.common.locals.tgw_multicast_domains, [])
  enable_tgw_flow_logs      = try(local.common.locals.enable_tgw_flow_logs, false)
  tgw_flow_logs_destination = try(local.common.locals.tgw_flow_logs_destination, "s3")
  # Retention and S3 key prefix of the TGW flow logs; the defaults repeat the
  # module defaults.
  tgw_flow_logs_retention_days = try(local.common.locals.tgw_flow_logs_retention_days, 365)
  tgw_flow_logs_s3_path        = try(local.common.locals.tgw_flow_logs_s3_path, "tgw-flow-logs")

  # Networking: DNS, resolver, query logging (modules/networking)
  dns_firewall_rule_groups          = try(local.common.locals.dns_firewall_rule_groups, [])
  resolver_endpoints                = try(local.common.locals.resolver_endpoints, [])
  resolver_rules                    = try(local.common.locals.resolver_rules, [])
  enable_route53_query_logging      = try(local.common.locals.enable_route53_query_logging, false)
  route53_query_logging_destination = try(local.common.locals.route53_query_logging_destination, "cloudwatch")
  route53_query_logging_vpc_names   = try(local.common.locals.route53_query_logging_vpc_names, [])

  # Pipeline source and external CI (modules/pipeline).
  # external_ci_audiences is absent on purpose: its default holds a fixed DNS
  # suffix, which env/common.hcl may not carry. The pipeline stack has to derive
  # the audience from the partition.
  source_connection_arn  = try(local.common.locals.source_connection_arn, "")
  pipeline_branch_name   = try(local.common.locals.branch_name, "main")
  external_ci_thumbprint = try(local.common.locals.external_ci_thumbprint, "")

  # GuardDuty fine tuning (modules/security; the deployment targets
  # also serve modules/security-org-config)
  guardduty_deployment_targets             = try(local.common.locals.guardduty_deployment_targets, [])
  guardduty_excluded_regions               = try(local.common.locals.guardduty_excluded_regions, [])
  guardduty_s3_protection_excluded_regions = try(local.common.locals.guardduty_s3_protection_excluded_regions, [])
  guardduty_export_prefix                  = try(local.common.locals.guardduty_export_prefix, "guardduty/")
  guardduty_lifecycle_rules                = try(local.common.locals.guardduty_lifecycle_rules, null)

  # Encryption: KMS key ARNs and region exclusions (modules/security)
  ebs_default_kms_key_arn         = try(local.common.locals.ebs_default_kms_key_arn, "")
  lambda_encryption_kms_key_arn   = try(local.common.locals.lambda_encryption_kms_key_arn, "")
  ebs_encryption_excluded_regions = try(local.common.locals.ebs_encryption_excluded_regions, [])

  # Customer-managed keys for Lambda environment variables (modules/logging,
  # modules/monitoring) and CodeBuild build output (modules/pipeline), one key
  # per stack. Empty -- the default -- leaves the AWS-managed key in place and
  # every plan unchanged. A named key also gives the consuming role its grant
  # on exactly that key inside the module; the deploying identity's own
  # kms:Encrypt lives in the key policy, outside this repository.
  logging_lambda_environment_kms_key_arn    = try(local.common.locals.logging_lambda_environment_kms_key_arn, "")
  monitoring_lambda_environment_kms_key_arn = try(local.common.locals.monitoring_lambda_environment_kms_key_arn, "")
  codebuild_encryption_kms_key_arn          = try(local.common.locals.codebuild_encryption_kms_key_arn, "")

  # Session Manager and SSM (modules/security)
  session_manager_s3_bucket_name             = try(local.common.locals.session_manager_s3_bucket_name, "")
  session_manager_s3_key_prefix              = try(local.common.locals.session_manager_s3_key_prefix, "ssm-sessions/")
  session_manager_kms_key_id                 = try(local.common.locals.session_manager_kms_key_id, "")
  session_manager_attach_policy_to_roles     = try(local.common.locals.session_manager_attach_policy_to_roles, [])
  ssm_document_share_targets                 = try(local.common.locals.ssm_document_share_targets, [])
  ssm_resource_data_sync_prefix              = try(local.common.locals.ssm_resource_data_sync_prefix, "ssm-inventory/")
  ssm_block_public_sharing_excluded_accounts = try(local.common.locals.ssm_block_public_sharing_excluded_accounts, [])

  # Security Hub and Macie: region lists (modules/security)
  security_hub_aggregation_regions = try(local.common.locals.security_hub_aggregation_regions, [])
  security_hub_excluded_regions    = try(local.common.locals.security_hub_excluded_regions, [])
  macie_excluded_regions           = try(local.common.locals.macie_excluded_regions, [])

  # Audit Manager report storage (modules/security)
  audit_manager_bucket_kms_key_arn  = try(local.common.locals.audit_manager_bucket_kms_key_arn, "")
  audit_manager_reports_destination = try(local.common.locals.audit_manager_reports_destination, null)

  # S3 account public access and resource policy enforcement
  # (modules/security)
  s3_public_access_block_excluded_accounts = try(local.common.locals.s3_public_access_block_excluded_accounts, [])
  resource_policy_enforcement_lambda_arn   = try(local.common.locals.resource_policy_enforcement_lambda_arn, "")

  # ---------------------------------------------------------------------------
  # Resource adoption: declarative import blocks from the adoption list
  # ---------------------------------------------------------------------------
  # configurations/base/resource-adoptions.json is the adoption list for
  # existing resources (docs/resource-adoption.md). Each entry names a stack
  # (path below stacks/) and the addresses it takes over:
  #
  #   { "stack": "management/logging",
  #     "adressen": [ { "to": "aws_s3_bucket.central_logs",
  #                     "id": "existing-bucket-name",
  #                     "art": "s3-bucket" } ] }
  #
  # The default is the empty list: no entry, no import block, unchanged plan.
  # Rendering happens once here; the consuming stacks emit the rendered text
  # through a `generate "imports"` block. Exactly one import block per address
  # entry; an entry of art "s3-bucket" additionally gets a check block that
  # warns when the named bucket is not findable in the target account.
  resource_adoptions = jsondecode(file("${get_repo_root()}/configurations/base/resource-adoptions.json"))

  _adoption_header = <<-EOT
    # Generated by the adoption list configurations/base/resource-adoptions.json.
    # One import block per entry; an empty list renders no blocks and leaves
    # the plan unchanged. See docs/resource-adoption.md.
  EOT

  adoption_imports_by_stack = {
    for stack in distinct([for gruppe in local.resource_adoptions : gruppe.stack]) :
    stack => join("\n", concat(
      [local._adoption_header],
      flatten([
        for gruppe in local.resource_adoptions : [
          for adresse in gruppe.adressen : <<-EOT
            import {
              to = ${adresse.to}
              id = "${adresse.id}"
            }
          EOT
        ] if gruppe.stack == stack
      ]),
      flatten([
        for gi, gruppe in local.resource_adoptions : [
          for ai, adresse in gruppe.adressen : <<-EOT
            check "adoption_${gi}_${ai}_bucket_findable" {
              data "aws_s3_bucket" "adoption_${gi}_${ai}" {
                bucket = "${adresse.id}"
              }
              assert {
                condition     = data.aws_s3_bucket.adoption_${gi}_${ai}.id == "${adresse.id}"
                error_message = "Adoption entry ${adresse.to}: bucket ${adresse.id} was not found in the target account."
              }
            }
          EOT
          if adresse.art == "s3-bucket"
        ] if gruppe.stack == stack
      ]),
    ))
  }
}
