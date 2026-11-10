# IAM module: Baseline roles, SAML providers, customer-managed policies

# --- Partition Detection ---
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  dns_suffix = data.aws_partition.current.dns_suffix
  arn_prefix = "arn:${local.partition}"

  # Roles as map for for_each (name → definition)
  roles_map = { for role in var.roles : role.name => role }

  # SAML providers as map for for_each
  saml_providers_map = { for sp in var.saml_providers : sp.name => sp }

  # Customer-managed policies as map for for_each
  policies_map = { for p in var.customer_managed_policies : p.name => p }
}

# =============================================================================
# Account-name resolution in policy documents
# =============================================================================
#
# Trust policies, inline policies and customer-managed policy documents reach
# this module as JSON strings from the configuration layer, so they cannot carry
# a Terraform reference. Without a resolution step every cross-account principal
# would have to name a 12-digit account ID literally in the configuration — the
# duplication var.account_ids exists to avoid ("Account name → account ID for
# trust policies", README.md).
#
# The mark is @@account_id:<account name>@@, the same @@…@@ form
# configurations/loader.hcl already uses for the organization ID and the home
# region. split("@@", document) yields alternating segments: even indices are
# literal text, odd indices are marks. A mark this module does not know is
# restored unchanged, so marks of other kinds — and a document without any mark
# — pass through untouched.

locals {
  account_id_marks = {
    for name, id in var.account_ids : "account_id:${name}" => id
  }

  resolved_role_trust_policies = {
    for name, role in local.roles_map : name => join("", [
      for index, segment in split("@@", role.assume_role_policy) :
      index % 2 == 0 ? segment : lookup(local.account_id_marks, segment, "@@${segment}@@")
    ])
  }

  resolved_role_inline_policies = {
    for name, role in local.roles_map : name => [
      for inline in role.inline_policies : {
        name = inline.name
        policy = join("", [
          for index, segment in split("@@", inline.policy) :
          index % 2 == 0 ? segment : lookup(local.account_id_marks, segment, "@@${segment}@@")
        ])
      }
    ]
  }

  resolved_policy_documents = {
    for name, policy in local.policies_map : name => join("", [
      for index, segment in split("@@", policy.policy) :
      index % 2 == 0 ? segment : lookup(local.account_id_marks, segment, "@@${segment}@@")
    ])
  }

  # An account mark that survives resolution names an account var.account_ids
  # does not carry. Left alone it would end up inside an IAM document, where AWS
  # rejects it at apply time with a message that does not mention the cause.
  unresolved_account_marks = distinct(flatten([
    for document in concat(
      values(local.resolved_role_trust_policies),
      flatten([
        for inlines in values(local.resolved_role_inline_policies) :
        [for inline in inlines : inline.policy]
      ]),
      values(local.resolved_policy_documents),
    ) : regexall("@@account_id:[^@]*@@", document)
  ]))
}

check "account_name_marks_resolve" {
  assert {
    condition     = length(local.unresolved_account_marks) == 0
    error_message = "unresolved account marks in IAM policy documents [${join(", ", local.unresolved_account_marks)}]. Every @@account_id:<name>@@ mark must name a key of var.account_ids; the iam stack fills that map from the accounts stack, which is empty until the accounts have been created."
  }
}

# =============================================================================
# IAM Roles — from roles list with trust policy, managed policies, inline policies
# =============================================================================

resource "aws_iam_role" "this" {
  for_each = local.roles_map

  name                 = each.value.name
  path                 = each.value.path
  max_session_duration = each.value.max_session_duration
  assume_role_policy   = local.resolved_role_trust_policies[each.key]
  permissions_boundary = (
    each.value.permissions_boundary == null || each.value.permissions_boundary == "" ? null :
    can(regex("^arn:", each.value.permissions_boundary)) ? each.value.permissions_boundary :
    aws_iam_policy.this[each.value.permissions_boundary].arn
  )
}

# --- Role policy attachments and inline policies ------------------------------
#
# Managed and inline policies live in standalone resources
# (aws_iam_role_policy_attachment, aws_iam_role_policy); exclusive
# management is carried by
# aws_iam_role_policy_attachments_exclusive and aws_iam_role_policies_exclusive:
# every role of var.roles gets one of each, so a policy attached out of band is
# removed on the next apply. The exclusive inline list also carries the
# tlz-mad-secret-access-* policies aws_iam_role_policy.mad_secret_access writes
# to roles named in secret_access_role_names — the two writers must not fight.

locals {
  # Resolved managed policy ARNs per role. An entry is a partition-neutral
  # policy name (optionally with a path such as service-role/...) that the
  # module expands with the current partition's ARN prefix; a full ARN passes
  # through unchanged.
  role_managed_policy_arns = {
    for name, role in local.roles_map : name => [
      for entry in role.managed_policy_arns :
      startswith(entry, "arn:") ? entry : "${local.arn_prefix}:iam::aws:policy/${entry}"
    ]
  }

  # Flatten role → managed policy attachments, keyed like the user and group
  # attachments below.
  role_policy_attachments = merge([
    for name, arns in local.role_managed_policy_arns : {
      for arn in arns :
      "${name}:${arn}" => {
        role_name  = name
        policy_arn = arn
      }
    }
  ]...)

  # Flatten role → inline policies (documents resolved above).
  role_inline_policies = merge([
    for name, inlines in local.resolved_role_inline_policies : {
      for inline in inlines :
      "${name}:${inline.name}" => {
        role_name   = name
        policy_name = inline.name
        policy      = inline.policy
      }
    }
  ]...)

  # Inline policy names per role for the exclusive resource: the declared
  # inline policies plus the tlz-mad-secret-access-* policies that
  # aws_iam_role_policy.mad_secret_access attaches to this role.
  role_exclusive_inline_policy_names = {
    for name, role in local.roles_map : name => concat(
      [for inline in role.inline_policies : inline.name],
      [
        for entry in values(local.managed_ad_secret_role_map) :
        "tlz-mad-secret-access-${entry.ad_name}"
        if entry.role_name == name
      ]
    )
  }
}

resource "aws_iam_role_policy_attachment" "roles" {
  for_each = local.role_policy_attachments

  role       = aws_iam_role.this[each.value.role_name].name
  policy_arn = each.value.policy_arn
}

resource "aws_iam_role_policy_attachments_exclusive" "this" {
  for_each = local.roles_map

  role_name   = aws_iam_role.this[each.key].name
  policy_arns = local.role_managed_policy_arns[each.key]

  depends_on = [aws_iam_role_policy_attachment.roles]
}

resource "aws_iam_role_policy" "roles" {
  for_each = local.role_inline_policies

  name   = each.value.policy_name
  role   = aws_iam_role.this[each.value.role_name].id
  policy = each.value.policy
}

resource "aws_iam_role_policies_exclusive" "this" {
  for_each = local.roles_map

  role_name    = aws_iam_role.this[each.key].name
  policy_names = local.role_exclusive_inline_policy_names[each.key]

  depends_on = [aws_iam_role_policy.roles, aws_iam_role_policy.mad_secret_access]
}

# =============================================================================
# IAM Instance Profiles — for roles with instance_profile = true
# =============================================================================

locals {
  instance_profile_roles = {
    for name, role in local.roles_map : name => role
    if role.instance_profile
  }
}

resource "aws_iam_instance_profile" "this" {
  for_each = local.instance_profile_roles

  name = each.value.name
  role = aws_iam_role.this[each.key].name
}

# =============================================================================
# SAML identity providers — from the saml_providers list
# =============================================================================

resource "aws_iam_saml_provider" "this" {
  for_each = local.saml_providers_map

  name                   = each.value.name
  saml_metadata_document = each.value.saml_metadata_document
}

# =============================================================================
# Customer-managed IAM policies — from the customer_managed_policies list
# =============================================================================

resource "aws_iam_policy" "this" {
  for_each = local.policies_map

  name   = each.value.name
  policy = local.resolved_policy_documents[each.key]
}

# =============================================================================
# IAM users — from the iam_users list
# =============================================================================

locals {
  users_map  = { for u in var.iam_users : u.name => u }
  groups_map = { for g in var.iam_groups : g.name => g }

  # Flatten user→group memberships for group_membership resources
  user_group_memberships = {
    for g in var.iam_groups : g.name => [
      for u in var.iam_users : u.name
      if contains(u.groups, g.name)
    ]
  }

  # Flatten user→policy attachments. Entries are resolved to full ARNs before
  # they key the map (partition-neutral policy names), so moving a
  # configuration from ARNs to names changes no resource address.
  user_policy_attachments = merge([
    for u in var.iam_users : {
      for arn in [
        for entry in u.managed_policy_arns :
        startswith(entry, "arn:") ? entry : "${local.arn_prefix}:iam::aws:policy/${entry}"
      ] :
      "${u.name}:${arn}" => {
        user_name  = u.name
        policy_arn = arn
      }
    }
  ]...)

  # Flatten group→policy attachments — same name resolution as for users.
  group_policy_attachments = merge([
    for g in var.iam_groups : {
      for arn in [
        for entry in g.managed_policy_arns :
        startswith(entry, "arn:") ? entry : "${local.arn_prefix}:iam::aws:policy/${entry}"
      ] :
      "${g.name}:${arn}" => {
        group_name = g.name
        policy_arn = arn
      }
    }
  ]...)
}

resource "aws_iam_user" "this" {
  for_each = local.users_map

  name                 = each.value.name
  permissions_boundary = each.value.permissions_boundary
}

resource "aws_iam_user_policy_attachment" "this" {
  for_each   = local.user_policy_attachments
  user       = aws_iam_user.this[each.value.user_name].name
  policy_arn = each.value.policy_arn
}

# =============================================================================
# IAM User — Console Login Profile (skip when disable_console_access = true)
# =============================================================================

locals {
  users_with_console_access = {
    for name, user in local.users_map : name => user
    if !user.disable_console_access
  }
}

resource "aws_iam_user_login_profile" "this" {
  for_each = local.users_with_console_access

  user                    = aws_iam_user.this[each.key].name
  password_reset_required = true
}

# =============================================================================
# IAM User — Initial Console Password in Secrets Manager
# =============================================================================
# The login profile above lets the provider generate the initial password
# (aws_iam_user_login_profile takes no password input); the secret stores that
# value, the one that signs the user in, the way break-glass.tf does. It must
# be changed at first sign-in (password_reset_required), after which the
# stored value is spent. variables.tf refuses auto_generate_password together
# with disable_console_access: without a login profile there is no password.

locals {
  users_with_auto_password = {
    for name, user in local.users_with_console_access : name => user
    if user.auto_generate_password
  }
}

resource "aws_secretsmanager_secret" "user_password" {
  for_each = local.users_with_auto_password

  name        = "tlz/iam-user/${each.key}/password"
  description = "Initial console password for IAM user ${each.key} (reset required at first sign-in)"
  # Optional customer-managed key; the empty default keeps the Secrets Manager
  # service key (aws/secretsmanager) — the secret is encrypted either way.
  kms_key_id = var.secrets_kms_key_arn != "" ? var.secrets_kms_key_arn : null
}

resource "aws_secretsmanager_secret_version" "user_password" {
  for_each = local.users_with_auto_password

  secret_id     = aws_secretsmanager_secret.user_password[each.key].id
  secret_string = aws_iam_user_login_profile.this[each.key].password
}

# =============================================================================
# IAM groups — from the iam_groups list
# =============================================================================

resource "aws_iam_group" "this" {
  for_each = local.groups_map
  name     = each.value.name
}

resource "aws_iam_group_membership" "this" {
  for_each = {
    for name, members in local.user_group_memberships : name => members
    if length(members) > 0
  }

  name  = "${each.key}-membership"
  group = aws_iam_group.this[each.key].name
  users = [for u in each.value : aws_iam_user.this[u].name]
}

resource "aws_iam_group_policy_attachment" "this" {
  for_each   = local.group_policy_attachments
  group      = aws_iam_group.this[each.value.group_name].name
  policy_arn = each.value.policy_arn
}

# =============================================================================
# Service Catalog Propagation Role — cross-account portfolio sharing
# =============================================================================

resource "aws_iam_role" "service_catalog_propagation" {
  count = var.enable_service_catalog ? 1 : 0

  name = "tlz-service-catalog-propagation"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/iam/service-catalog-propagation-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))

  tags = {
    ManagedBy = "TLZ"
  }
}

resource "aws_iam_role_policy" "service_catalog_propagation" {
  count = var.enable_service_catalog ? 1 : 0

  name = "tlz-service-catalog-propagation"
  role = aws_iam_role.service_catalog_propagation[0].id

  policy = jsonencode(jsondecode(file("${path.module}/../../configurations/policies/iam/service-catalog-propagation-policy.json")))
}

# =============================================================================
# Managed Active Directory — MicrosoftAD and ADConnector support
# =============================================================================

locals {
  managed_ad_map = { for d in var.managed_active_directories : d.name => d }

  # Split by directory type for separate resource blocks
  microsoft_ad_map = {
    for name, d in local.managed_ad_map : name => d
    if d.directory_type == "MicrosoftAD"
  }

  ad_connector_map = {
    for name, d in local.managed_ad_map : name => d
    if d.directory_type == "ADConnector"
  }
}

# --- Directory credentials ---------------------------------------------------
#
# Managed Microsoft AD: the module owns the admin credential, so it generates a
# random password and stores it in Secrets Manager (same pattern as the IAM user
# passwords above), encrypted with the per-directory KMS key defined below. The
# secret name matches the tlz/mad/<directory>/* prefix that
# aws_iam_role_policy.mad_secret_access grants read access to.
#
# AD Connector: the password belongs to an existing on-premises service account
# (connect_settings.customer_username) and cannot be generated. It is read from
# the Secrets Manager secret named in password_secret_name.

resource "random_password" "directory_admin" {
  for_each = local.microsoft_ad_map

  length           = 32
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = "!@#$%^&*()-_=+"
}

# The secret name, account and region come from secret_config (providers.tf
# derives the effective name and the placement alias). A placed secret cannot
# use the per-directory KMS key: the key is regional and lives in the
# management account, so a secret in another account or region falls back to
# the Secrets Manager service key of its destination (aws/secretsmanager) —
# still encrypted at rest, documented in the README.
resource "aws_secretsmanager_secret" "directory_admin" {
  for_each = local.microsoft_ad_map
  provider = aws.mad_secret

  name        = local.mad_admin_secret_names[each.key]
  description = "Admin password of Managed Microsoft AD ${each.key}"
  kms_key_id = (
    each.value.secret_config.account == null && each.value.secret_config.region == null
    ? aws_kms_key.mad_admin_secret[each.key].arn
    : (var.secrets_kms_key_arn != "" ? var.secrets_kms_key_arn : null)
  )
}

resource "aws_secretsmanager_secret_version" "directory_admin" {
  for_each = local.microsoft_ad_map
  provider = aws.mad_secret

  secret_id     = aws_secretsmanager_secret.directory_admin[each.key].id
  secret_string = random_password.directory_admin[each.key].result
}

data "aws_secretsmanager_secret_version" "ad_connector_password" {
  for_each = local.ad_connector_map

  secret_id = each.value.password_secret_name
}

resource "aws_directory_service_directory" "this" {
  for_each = local.microsoft_ad_map

  name        = each.value.domain_name
  password    = random_password.directory_admin[each.key].result
  edition     = each.value.edition
  type        = "MicrosoftAD"
  description = each.value.description
  short_name  = each.value.net_bios_domain_name

  # lookup() instead of a direct index: a missing key must fail on the
  # preconditions below (naming directory and key), not with a bare
  # "Invalid index" that hides which directory is misconfigured. The
  # placeholder default keeps the bootstrap plan alive (the iam stack mocks
  # the networking outputs as empty maps for validate/plan — vpc_id is a
  # required attribute, so null would kill exactly that plan); it cannot
  # reach an apply, because a filled map with a missing key fails the
  # precondition and the real networking outputs replace the mocks at apply.
  vpc_settings {
    vpc_id = lookup(var.vpc_ids, each.value.vpc_name, "vpc-unresolved")
    subnet_ids = [
      for sn in each.value.subnet_names :
      lookup(var.subnet_ids, "${each.value.vpc_name}.${sn}", "subnet-unresolved")
    ]
  }

  tags = {
    Name = each.value.name
  }

  lifecycle {
    # Empty maps are the bootstrap case: the iam stack mocks the networking
    # outputs for validate/plan before networking is applied, and the plan
    # must run through. A non-empty map with a missing key is a typo and
    # fails here, naming directory and key instead of a bare "Invalid index".
    precondition {
      condition     = length(var.vpc_ids) == 0 || contains(keys(var.vpc_ids), each.value.vpc_name)
      error_message = "Managed AD directory '${each.value.name}': vpc_name '${each.value.vpc_name}' is not a key of vpc_ids. Fix the vpc_name to match a VPC the networking module exports (known keys: ${join(", ", keys(var.vpc_ids))})."
    }

    precondition {
      condition = length(var.subnet_ids) == 0 || alltrue([
        for sn in each.value.subnet_names :
        contains(keys(var.subnet_ids), "${each.value.vpc_name}.${sn}")
      ])
      error_message = "Managed AD directory '${each.value.name}': subnet_names ${jsonencode(each.value.subnet_names)} must all resolve as '${each.value.vpc_name}.<subnet_name>' keys of subnet_ids. Fix the subnet names to match the networking module's exports."
    }
  }
}

resource "aws_directory_service_directory" "ad_connector" {
  for_each = local.ad_connector_map

  name        = each.value.domain_name
  password    = data.aws_secretsmanager_secret_version.ad_connector_password[each.key].secret_string
  type        = "ADConnector"
  size        = each.value.edition == "Enterprise" ? "Large" : "Small"
  description = each.value.description
  short_name  = each.value.net_bios_domain_name

  # lookup() with placeholder defaults instead of a direct index — see
  # vpc_settings of the MicrosoftAD resource above; same preconditions below.
  connect_settings {
    vpc_id = lookup(var.vpc_ids, each.value.vpc_name, "vpc-unresolved")
    subnet_ids = [
      for sn in each.value.subnet_names :
      lookup(var.subnet_ids, "${each.value.vpc_name}.${sn}", "subnet-unresolved")
    ]
    customer_dns_ips  = each.value.connect_settings.customer_dns_ips
    customer_username = each.value.connect_settings.customer_username
  }

  tags = {
    Name = each.value.name
  }

  lifecycle {
    precondition {
      condition     = length(var.vpc_ids) == 0 || contains(keys(var.vpc_ids), each.value.vpc_name)
      error_message = "AD Connector '${each.value.name}': vpc_name '${each.value.vpc_name}' is not a key of vpc_ids. Fix the vpc_name to match a VPC the networking module exports (known keys: ${join(", ", keys(var.vpc_ids))})."
    }

    precondition {
      condition = length(var.subnet_ids) == 0 || alltrue([
        for sn in each.value.subnet_names :
        contains(keys(var.subnet_ids), "${each.value.vpc_name}.${sn}")
      ])
      error_message = "AD Connector '${each.value.name}': subnet_names ${jsonencode(each.value.subnet_names)} must all resolve as '${each.value.vpc_name}.<subnet_name>' keys of subnet_ids. Fix the subnet names to match the networking module's exports."
    }
  }
}

# Merged directory ID map for downstream references (resolver rules, sharing, logs)
locals {
  all_directory_ids = merge(
    { for name, dir in aws_directory_service_directory.this : name => dir.id },
    { for name, dir in aws_directory_service_directory.ad_connector : name => dir.id }
  )
}

# =============================================================================
# Managed AD — Route53 Resolver Rule
# Creates a FORWARD resolver rule for the AD domain when resolver_rule_name is
# set: AD domains resolve only against the directory's own DNS servers, so the
# rule forwards queries for the domain to those servers through an outbound
# Resolver endpoint. A SYSTEM rule cannot do this — it switches the domain
# back to VPC-standard resolution and overrides any FORWARD rule for it.
# =============================================================================

locals {
  managed_ad_resolver_rules = {
    for name, ad in local.managed_ad_map : name => ad
    if ad.resolver_rule_name != null
  }

  # Flatten share targets: one entry per AD × consumer account combination.
  # Directory Service shares a directory with accounts only (ShareTarget.Type
  # accepts ACCOUNT), so the targets are account IDs, validated in variables.tf.
  managed_ad_shared_accounts = merge([
    for name, ad in local.managed_ad_map : {
      for account_id in ad.shared_account_ids :
      "${name}:${account_id}" => {
        ad_name        = name
        account_target = account_id
      }
    }
  ]...)

  managed_ad_log_subscriptions = {
    for name, ad in local.managed_ad_map : name => ad
    if ad.log_group_name != null
  }

  # Directories whose log group the module creates itself: log_retention_days
  # names the retention, log_group_name the group. Without log_retention_days
  # the subscription keeps pointing at an externally managed group — the
  # previous behaviour, unchanged.
  managed_ad_created_log_groups = {
    for name, ad in local.managed_ad_map : name => ad
    if ad.log_group_name != null && ad.log_retention_days != null
  }
}

resource "aws_route53_resolver_rule" "managed_ad" {
  for_each = local.managed_ad_resolver_rules

  domain_name = each.value.domain_name
  name        = each.value.resolver_rule_name
  rule_type   = "FORWARD"

  # Route 53 Resolver accepts a FORWARD rule only with an outbound endpoint
  # (same rule as modules/networking/route53.tf). The placeholder default
  # keeps the bootstrap mock plan alive — the iam stack mocks the networking
  # outputs as empty maps for validate/plan; the precondition below blocks
  # any apply path with a missing key.
  resolver_endpoint_id = lookup(var.resolver_endpoint_ids, each.value.resolver_endpoint_name, "rslvr-out-unresolved")

  # AD Connector: the directory's DNS servers are the on-premises servers the
  # operator configures — known at plan time.
  dynamic "target_ip" {
    for_each = each.value.directory_type == "ADConnector" ? each.value.connect_settings.customer_dns_ips : []
    content {
      ip = target_ip.value
    }
  }

  # Managed Microsoft AD: the directory provisions exactly two DNS servers
  # (one per domain controller pair), but their addresses are only known
  # after apply — a dynamic block cannot expand over the unknown set, so
  # two fixed blocks index into it.
  dynamic "target_ip" {
    for_each = each.value.directory_type == "MicrosoftAD" ? [0, 1] : []
    content {
      ip = tolist(aws_directory_service_directory.this[each.key].dns_ip_addresses)[target_ip.value]
    }
  }

  tags = {
    Name       = each.value.resolver_rule_name
    ManagedAD  = each.value.name
    DomainName = each.value.domain_name
  }

  lifecycle {
    # Same bootstrap rule as the directory resources: empty resolver_endpoint_ids
    # is the mocked plan before networking, a missing key on a filled map is
    # a typo and fails here naming directory and key.
    precondition {
      condition     = length(var.resolver_endpoint_ids) == 0 || contains(keys(var.resolver_endpoint_ids), each.value.resolver_endpoint_name)
      error_message = "Managed AD directory '${each.value.name}': resolver_endpoint_name '${each.value.resolver_endpoint_name}' is not a key of resolver_endpoint_ids. Fix the name to match an outbound endpoint the networking module exports (known keys: ${join(", ", keys(var.resolver_endpoint_ids))})."
    }
  }
}

# A resolver rule changes DNS behaviour only in VPCs it is associated with.
# vpc_associations on the directory object creates the association here;
# VPCs outside this module associate via the managed_ad_resolver_rule_ids
# output instead.
locals {
  managed_ad_rule_associations = merge([
    for name, ad in local.managed_ad_resolver_rules : {
      for vpc_name in ad.vpc_associations :
      "${name}:${vpc_name}" => {
        ad_name  = name
        vpc_name = vpc_name
      }
    }
  ]...)
}

resource "aws_route53_resolver_rule_association" "managed_ad" {
  for_each = local.managed_ad_rule_associations

  resolver_rule_id = aws_route53_resolver_rule.managed_ad[each.value.ad_name].id
  # Placeholder default for the bootstrap mock plan — see vpc_settings of
  # the MicrosoftAD resource; the precondition below blocks any apply path.
  vpc_id = lookup(var.vpc_ids, each.value.vpc_name, "vpc-unresolved")
  name   = "${each.value.ad_name}-${each.value.vpc_name}"

  lifecycle {
    # Same bootstrap rule as the directory resources: empty vpc_ids is the
    # mocked plan before networking, a missing key on a filled map is a typo.
    precondition {
      condition     = length(var.vpc_ids) == 0 || contains(keys(var.vpc_ids), each.value.vpc_name)
      error_message = "Managed AD directory '${each.value.ad_name}': vpc_associations entry '${each.value.vpc_name}' is not a key of vpc_ids. Fix the VPC name to match a VPC the networking module exports (known keys: ${join(", ", keys(var.vpc_ids))})."
    }
  }
}

# A rule without any association is silently ineffective — warn, do not block:
# the association may intentionally happen outside this module through the
# managed_ad_resolver_rule_ids output.
check "managed_ad_resolver_rules_associated" {
  assert {
    condition = alltrue([
      for name, ad in local.managed_ad_resolver_rules :
      length(ad.vpc_associations) > 0
    ])
    error_message = "Managed AD resolver rules without a VPC association: ${join(", ", [for name, ad in local.managed_ad_resolver_rules : name if length(ad.vpc_associations) == 0])}. A Route 53 Resolver rule only changes DNS behaviour in VPCs it is associated with — set vpc_associations on the directory, or associate the rule elsewhere via the managed_ad_resolver_rule_ids output."
  }
}

# =============================================================================
# Managed AD — Directory Sharing
# Shares the directory with the consumer accounts listed in shared_account_ids.
# Directory Service supports exactly one share target type: ACCOUNT. Sharing
# with an organizational unit is not offered by the API, so the module takes
# account IDs and rejects anything else in the variable validation.
# =============================================================================

resource "aws_directory_service_shared_directory" "this" {
  for_each = local.managed_ad_shared_accounts

  directory_id = local.all_directory_ids[each.value.ad_name]
  notes        = "Shared by Landing Zone"

  target {
    id   = each.value.account_target
    type = "ACCOUNT"
  }
}

# =============================================================================
# Managed AD — Directory Sharing with Organizational Units
# share_targets.organizational_units names OUs whose member accounts receive
# the directory; excluded_accounts subtracts from that expansion. The
# resolution is a configuration computation over the stack-supplied maps
# (account_ids, ou_name_to_id, account_ou_ids) — Directory Service itself
# accepts account targets only, so the module resolves OU names to the
# accounts they contain, the same declared-maps pattern as the SSM document
# sharing in modules/security.
# =============================================================================

locals {
  # Which accounts the direct list already shares with — an account reached
  # both directly and through an OU must produce exactly one share.
  managed_ad_direct_share_ids = {
    for name, ad in local.managed_ad_map : name => ad.shared_account_ids
  }

  # OU ID → account IDs it contains, derived from the two stack-supplied maps.
  managed_ad_ou_id_to_account_ids = {
    for ou_id in distinct(values(var.account_ou_ids)) : ou_id => [
      for account_name, assigned_ou_id in var.account_ou_ids :
      var.account_ids[account_name]
      if assigned_ou_id == ou_id && contains(keys(var.account_ids), account_name)
    ]
  }

  # Excluded accounts per directory, names resolved through account_ids.
  managed_ad_excluded_account_ids = {
    for name, ad in local.managed_ad_map : name => [
      for entry in ad.share_targets.excluded_accounts :
      can(regex("^[0-9]{12}$", entry)) ? entry : var.account_ids[entry]
    ]
  }

  # OU expansion per directory: member accounts of the named OUs, minus the
  # excluded accounts, minus everything the direct list already covers.
  managed_ad_ou_share_accounts = {
    for name, ad in local.managed_ad_map : name => [
      for account_id in distinct(flatten([
        for ou in ad.share_targets.organizational_units :
        lookup(local.managed_ad_ou_id_to_account_ids, lookup(var.ou_name_to_id, ou, ""), [])
      ])) : account_id
      if !contains(local.managed_ad_excluded_account_ids[name], account_id) && !contains(local.managed_ad_direct_share_ids[name], account_id)
    ]
  }

  managed_ad_ou_shared_accounts_map = merge([
    for name, accounts in local.managed_ad_ou_share_accounts : {
      for account_id in accounts :
      "${name}:${account_id}" => {
        ad_name        = name
        account_target = account_id
      }
    }
  ]...)

  # OU share targets that resolve to no account: the name is known (the
  # validation guarantees that), but no declared account is placed in it, so
  # the directory reaches fewer accounts than the entry suggests.
  managed_ad_share_empty_ous = distinct(flatten([
    for name, ad in local.managed_ad_map : [
      for ou in ad.share_targets.organizational_units :
      ou
      if length(lookup(local.managed_ad_ou_id_to_account_ids, lookup(var.ou_name_to_id, ou, ""), [])) == 0
    ]
  ]))
}

check "managed_ad_share_empty_ou_warning" {
  assert {
    condition     = length(local.managed_ad_share_empty_ous) == 0
    error_message = "One or more managed_active_directories share_targets organizational units resolve to no account [${join(", ", local.managed_ad_share_empty_ous)}]. The OU name is known, but account_ou_ids places no account in it — the directory is shared with fewer accounts than the entry suggests."
  }
}

resource "aws_directory_service_shared_directory" "from_organizational_units" {
  for_each = local.managed_ad_ou_shared_accounts_map

  directory_id = local.all_directory_ids[each.value.ad_name]
  notes        = "Shared by Landing Zone"

  target {
    id   = each.value.account_target
    type = "ACCOUNT"
  }
}

# =============================================================================
# Managed AD — Log Group and Log Subscription
# Subscribes directory events to a CloudWatch Log Group. With
# log_retention_days the module creates the group itself and controls its
# retention; without it the subscription reads an externally managed group,
# exactly as before.
# =============================================================================

resource "aws_cloudwatch_log_group" "managed_ad" {
  for_each = local.managed_ad_created_log_groups

  name              = each.value.log_group_name
  retention_in_days = each.value.log_retention_days
  # Optional customer-managed key; null keeps the CloudWatch service
  # encryption — the behaviour of an externally created group.
  kms_key_id = each.value.log_group_kms_key_arn
}

resource "aws_directory_service_log_subscription" "this" {
  for_each = local.managed_ad_log_subscriptions

  directory_id = local.all_directory_ids[each.key]
  # Reading the created group's name (instead of the input string) carries the
  # dependency edge: the group exists before the subscription points at it.
  log_group_name = (
    each.value.log_retention_days != null
    ? aws_cloudwatch_log_group.managed_ad[each.key].name
    : each.value.log_group_name
  )
}

# =============================================================================
# Managed AD — Admin Secret Access for Instance Roles
# Grants secretsmanager:GetSecretValue on MAD admin secret ARN to instance roles
# =============================================================================

locals {
  # Build a map of AD name → list of instance role names that need secret access
  managed_ad_secret_access = {
    for name, ad in local.managed_ad_map : name => ad
    if ad.directory_type == "MicrosoftAD" && length(ad.secret_access_role_names) > 0
  }

  # Flatten: one entry per AD × role combination
  managed_ad_secret_role_map = merge([
    for name, ad in local.managed_ad_secret_access : {
      for role_name in ad.secret_access_role_names :
      "${name}:${role_name}" => {
        ad_name   = name
        role_name = role_name
      }
    }
  ]...)
}

resource "aws_iam_role_policy" "mad_secret_access" {
  for_each = local.managed_ad_secret_role_map

  name = "tlz-mad-secret-access-${each.value.ad_name}"
  # Reference the module-managed role directly (pattern of
  # aws_iam_role_policy.roles) so the first apply orders the policy after
  # the role instead of racing it. try() keeps role names that live outside
  # var.roles working — the reference alone carries the dependency edge.
  role = try(aws_iam_role.this[each.value.role_name].id, each.value.role_name)

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/iam/mad-secret-access-policy.json", {
    arn_prefix  = local.arn_prefix
    secret_name = local.mad_admin_secret_names[each.value.ad_name]
  })))
}

# =============================================================================
# Managed AD — KMS Key for Admin Secrets
# Creates a KMS key for encrypting MAD admin secrets in Secrets Manager
# =============================================================================

# One key per directory whose secret stays local. A placed secret (see
# secret_config) uses the service key of its destination instead — a regional
# management-account key cannot encrypt it, and an unused key would only cost.
locals {
  mad_local_secret_map = {
    for name, ad in local.microsoft_ad_map : name => ad
    if ad.secret_config.account == null && ad.secret_config.region == null
  }
}

resource "aws_kms_key" "mad_admin_secret" {
  for_each = local.mad_local_secret_map

  description             = "KMS key for Managed AD admin secrets - ${each.key}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/iam/mad-admin-secret-kms-key-policy.json", {
    arn_prefix = local.arn_prefix
    account_id = data.aws_caller_identity.current.account_id
    dns_suffix = local.dns_suffix
    # kms:ViaService carries the region (secretsmanager.<region>.<suffix>);
    # the key and the secret it encrypts live in the provider region.
    region = data.aws_region.current.region
  })))

  tags = {
    Name      = "tlz-mad-admin-secret-${each.key}"
    ManagedBy = "TLZ"
  }
}

resource "aws_kms_alias" "mad_admin_secret" {
  for_each = local.mad_local_secret_map

  name          = "alias/tlz/mad/${each.key}/secret"
  target_key_id = aws_kms_key.mad_admin_secret[each.key].key_id
}

# =============================================================================
# CloudFormation StackSet Roles
# Administration role (management account) and Execution role (member accounts)
# =============================================================================

# --- StackSet Administration Role (management account only) ---

resource "aws_iam_role" "stackset_admin" {
  count = var.enable_stackset_roles && var.is_management_account ? 1 : 0

  name = "AWSCloudFormationStackSetAdministrationRole"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/iam/stackset-admin-trust-policy.json", {
    dns_suffix = local.dns_suffix
  })))

  tags = {
    ManagedBy = "TLZ"
  }
}

resource "aws_iam_role_policy" "stackset_admin" {
  count = var.enable_stackset_roles && var.is_management_account ? 1 : 0

  name = "AssumeExecutionRole"
  role = aws_iam_role.stackset_admin[0].id

  policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/iam/stackset-admin-policy.json", {
    arn_prefix = local.arn_prefix
  })))
}

# --- StackSet Execution Role (member accounts only) ---

resource "aws_iam_role" "stackset_execution" {
  count = var.enable_stackset_roles && !var.is_management_account ? 1 : 0

  name = "AWSCloudFormationStackSetExecutionRole"

  assume_role_policy = jsonencode(jsondecode(templatefile("${path.module}/../../configurations/policies/iam/stackset-execution-trust-policy.json", {
    arn_prefix            = local.arn_prefix
    management_account_id = var.management_account_id
  })))

  tags = {
    ManagedBy = "TLZ"
  }
}

resource "aws_iam_role_policy_attachment" "stackset_execution" {
  count = var.enable_stackset_roles && !var.is_management_account ? 1 : 0

  role       = aws_iam_role.stackset_execution[0].name
  policy_arn = "${local.arn_prefix}:iam::aws:policy/AdministratorAccess"
}

# =============================================================================
# Cross-account deployment_targets warnings
# =============================================================================

locals {
  roles_with_targets = [
    for r in var.roles : r.name
    if length(r.deployment_targets) > 0
  ]

  policies_with_targets = [
    for p in var.customer_managed_policies : p.name
    if length(p.deployment_targets) > 0
  ]

  users_with_targets = [
    for u in var.iam_users : u.name
    if length(u.deployment_targets) > 0
  ]

  groups_with_targets = [
    for g in var.iam_groups : g.name
    if length(g.deployment_targets) > 0
  ]
}

check "roles_deployment_targets_warning" {
  assert {
    condition     = length(local.roles_with_targets) == 0
    error_message = "roles with deployment_targets detected [${join(", ", local.roles_with_targets)}]. deployment_targets is accepted for configuration compatibility, but Terraform cannot dynamically create cross-account providers. Use Terragrunt per-account stacks for cross-account deployment."
  }
}

check "customer_managed_policies_deployment_targets_warning" {
  assert {
    condition     = length(local.policies_with_targets) == 0
    error_message = "customer_managed_policies with deployment_targets detected [${join(", ", local.policies_with_targets)}]. deployment_targets is accepted for configuration compatibility, but Terraform cannot dynamically create cross-account providers. Use Terragrunt per-account stacks for cross-account deployment."
  }
}

check "iam_users_deployment_targets_warning" {
  assert {
    condition     = length(local.users_with_targets) == 0
    error_message = "iam_users with deployment_targets detected [${join(", ", local.users_with_targets)}]. deployment_targets is accepted for configuration compatibility, but Terraform cannot dynamically create cross-account providers. Use Terragrunt per-account stacks for cross-account deployment."
  }
}

check "iam_groups_deployment_targets_warning" {
  assert {
    condition     = length(local.groups_with_targets) == 0
    error_message = "iam_groups with deployment_targets detected [${join(", ", local.groups_with_targets)}]. deployment_targets is accepted for configuration compatibility, but Terraform cannot dynamically create cross-account providers. Use Terragrunt per-account stacks for cross-account deployment."
  }
}
