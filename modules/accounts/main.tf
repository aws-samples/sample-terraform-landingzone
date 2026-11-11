# Top-level OUs for name → ID resolution
# Uses external ou_name_to_id map (from Organization module) when available,
# falls back to data-source-based resolution for standalone usage.

# Fallback: resolve Organization Root ID via data source when not passed.
# Neither data source is read while var.ou_name_to_id is supplied: the map
# alone resolves every OU name.
data "aws_organizations_organization" "current" {
  count = var.organization_root_id == "" && length(var.ou_name_to_id) == 0 ? 1 : 0
}

locals {
  resolved_root_id = var.organization_root_id != "" ? var.organization_root_id : try(data.aws_organizations_organization.current[0].roots[0].id, "")
}

data "aws_organizations_organizational_units" "root" {
  count     = length(var.ou_name_to_id) == 0 ? 1 : 0
  parent_id = local.resolved_root_id
}

locals {
  # Fallback map when var.ou_name_to_id is empty.
  # Scope: only the direct children of the organization root — the data source
  # lists one level. Nested OUs are NOT contained here; resolving an OU below
  # level 1 requires var.ou_name_to_id (supplied by the organization module,
  # which keys all levels by their simple name).
  data_source_ou_map = {
    for ou in try(data.aws_organizations_organizational_units.root[0].children, []) :
    ou.name => ou.id
  }
  ou_name_to_id = length(var.ou_name_to_id) > 0 ? var.ou_name_to_id : local.data_source_ou_map

  # OU Path Resolution:
  # If an OU name contains "/", treat it as a hierarchical path and resolve it
  # through the LAST segment (leaf OU name). For simple names without "/", use
  # direct lookup.
  ou_lookup_keys = {
    for acct in var.accounts : acct.email => (
      acct.organizational_unit_name != null && strcontains(acct.organizational_unit_name, "/")
      ? element(split("/", acct.organizational_unit_name), length(split("/", acct.organizational_unit_name)) - 1)
      : acct.organizational_unit_name
    )
  }

  # Resolve each account's target OU by ID or by name.
  # An unresolvable name yields null — never the organization root: placing an
  # account in the root would silently move it outside every OU-bound SCP, RCP,
  # tag policy and control. The precondition on aws_organizations_account.this
  # rejects that case before any account is created.
  resolved_accounts = {
    for acct in var.accounts : acct.email => merge(acct, {
      target_ou_id = (
        acct.organizational_unit_id != null
        ? acct.organizational_unit_id
        : try(local.ou_name_to_id[local.ou_lookup_keys[acct.email]], null)
      )
    })
  }

  # Accounts whose target OU could not be resolved, for a descriptive error
  unresolvable_ou_paths = [
    for acct in var.accounts : "${acct.name}:${acct.organizational_unit_name}"
    if local.resolved_accounts[acct.email].target_ou_id == null
  ]

  # Accounts requesting GovCloud linking
  govcloud_accounts = [
    for acct in var.accounts : acct.name
    if acct.enable_govcloud
  ]

  # Warm account IDs — accounts marked as warm/standby (only when account warming is enabled)
  warm_account_ids = var.enable_account_warming ? [
    for email, acct in aws_organizations_account.this :
    acct.id
    if try(local.resolved_accounts[email].warm, false)
  ] : []

  # Names of the warm-marked accounts. Known at plan time — a NEW account's ID
  # is a computed value the first plan cannot render — so the warm-account
  # warning below stays readable in the very plan that creates the account.
  warm_account_names = var.enable_account_warming ? [
    for acct in local.resolved_accounts : acct.name
    if try(acct.warm, false)
  ] : []

  # Names of the accounts declared in an ignored OU (the organization module's
  # ignored_ou_ids: ignore = true, or below such an OU). Read from the DECLARED
  # OU, which is known at plan time; a console move is a drift the plan shows.
  # These accounts stay declared and created, but leave the active_* outputs,
  # so no downstream stack assumes a role in them.
  suspended_account_names = [
    for acct in local.resolved_accounts : acct.name
    if acct.target_ou_id != null && contains(var.ignored_ou_ids, acct.target_ou_id)
  ]
}

# Account creation with API throttling protection.
# AWS Organizations allows max 5 concurrent CreateAccount requests.
# Solution: `terraform apply -parallelism=5` or Terragrunt configuration.
# The module itself creates all accounts via for_each — parallelism
# is controlled at the execution level (Terraform/Terragrunt).

locals {
  # Role CreateAccount makes inside each new member account. Two roles, two
  # variables: account_access_role_name is the role this module's
  # deployment-account provider and the stacks ASSUME to reach existing
  # accounts; created_account_role_name is the one a NEW account is created
  # with. A variable default cannot reference another variable, so the
  # fallback is resolved here: null keeps the two names identical.
  created_account_role_name = coalesce(var.created_account_role_name, var.account_access_role_name)
}

resource "aws_organizations_account" "this" {
  for_each = local.resolved_accounts

  name                       = each.value.name
  email                      = each.value.email
  role_name                  = local.created_account_role_name
  iam_user_access_to_billing = each.value.iam_user_access_to_billing
  close_on_deletion          = var.close_on_deletion
  # A quarantined account is created inside the quarantine OU, where the
  # quarantine SCP already applies; its declared OU stays its deployment scope.
  parent_id = each.value.quarantined ? var.quarantine_ou_id : each.value.target_ou_id

  tags = merge(
    var.default_tags,
    each.value.tags,
    each.value.description != "" ? { Description = each.value.description } : {},
  )

  lifecycle {
    ignore_changes = [role_name, iam_user_access_to_billing]

    # Hard dependency: every account must have a resolvable target OU.
    # Without this the unresolved case would be applied as parent_id = null,
    # which AWS accepts by placing the account directly under the organization
    # root — outside every OU-bound SCP, RCP, tag policy and control.
    precondition {
      condition     = length(local.unresolvable_ou_paths) == 0
      error_message = "Unresolvable target OU for accounts [${join(", ", local.unresolvable_ou_paths)}]. The OU name (or the leaf segment of a path like 'Parent/Child') must exist as a key in ou_name_to_id. Without ou_name_to_id only the direct children of the organization root are resolvable, so nested OUs require the map from the organization module. Known keys: [${join(", ", sort(keys(local.ou_name_to_id)))}]."
    }

    # A quarantined account needs the quarantine OU; without it parent_id
    # would be "" and AWS would refuse or, worse, place the account elsewhere.
    precondition {
      condition     = !each.value.quarantined || var.quarantine_ou_id != ""
      error_message = "quarantined = true on ${each.value.name} but no quarantine OU: set quarantine_ou_name with enable_quarantine_scp = true in the organization configuration, or remove the flag."
    }
  }
}

# --- Partition Detection ---
data "aws_partition" "current" {}

# --- GovCloud Linking Warning ---
# aws_organizations_account does not have a direct govcloud parameter.
# GovCloud linking requires manual steps or AWS CLI after account creation.

check "govcloud_partition_warning" {
  assert {
    condition     = length(local.govcloud_accounts) == 0 || data.aws_partition.current.partition == "aws"
    error_message = "enable_govcloud is set on accounts [${join(", ", local.govcloud_accounts)}] but the current partition is '${data.aws_partition.current.partition}' (not 'aws'). GovCloud linking is only available in the commercial (aws) partition."
  }
}

check "govcloud_manual_linking_instructions" {
  assert {
    condition = length(local.govcloud_accounts) == 0
    error_message = join("\n", [
      "GovCloud linking requested for accounts: [${join(", ", local.govcloud_accounts)}].",
      "The Terraform AWS provider aws_organizations_account does not support direct GovCloud account creation (verified: provider ~> 6.x).",
      "To create linked GovCloud accounts, use the AWS CLI:",
      "  1. aws organizations create-gov-cloud-account --account-name <name> --email <email> --role-name OrganizationAccountAccessRole",
      "  2. aws organizations describe-create-account-status --create-account-request-id <request-id>",
      "  3. The GovCloud account ID is in the GovCloudAccountId field of the response.",
      "Prerequisites: The commercial account must exist first. GovCloud linking creates a separate account with its own ID.",
    ])
  }
}

# --- Warm Account Warning ---
# Warm accounts are created but skip security/networking configuration.

check "warm_accounts_skip_config_warning" {
  assert {
    condition = length(local.warm_account_ids) == 0
    error_message = join(" ", [
      "Warm accounts detected: [${join(", ", local.warm_account_names)}].",
      "Warm accounts are created in AWS Organizations but skip security and networking configuration.",
      "Downstream modules should exclude warm account IDs from deployment targets.",
      "To promote a warm account to full configuration, set warm = false and re-run the pipeline.",
    ])
  }
}

# warm = true only takes effect while enable_account_warming is true — with
# the toggle off the flag is silently ignored (documented on the variable),
# so the plan itself names the ineffective flags instead of hiding them.

check "warm_flags_without_toggle" {
  assert {
    condition = var.enable_account_warming || !anytrue([for a in var.accounts : a.warm])
    error_message = join(" ", [
      "Accounts carry warm = true, but enable_account_warming is false, so the flag has no effect:",
      "[${join(", ", [for a in var.accounts : a.name if a.warm])}].",
      "These accounts receive the full security and networking configuration.",
      "Set enable_account_warming = true to activate the warm exclusion, or remove the warm flags.",
    ])
  }
}

# --- Suspended Account Notice ---
# An account declared in an ignored OU is out of every fan-out; the plan names
# it so that a declaration moved there by mistake does not go unnoticed.

check "suspended_accounts_named" {
  assert {
    condition = length(local.suspended_account_names) == 0
    error_message = join(" ", [
      "Suspended accounts: [${join(", ", local.suspended_account_names)}].",
      "These accounts are declared in an OU marked ignore = true (or below one) and are no deployment targets:",
      "no downstream stack configures them, and resources they still hold stay as they are.",
      "To bring an account back, declare it in a working OU and apply the accounts unit.",
    ])
  }
}

# --- Control Tower Enrollment Guidance ---
# CT enrollment is a separate workflow from account creation.
# aws_organizations_account creates the account in Organizations.
# CT enrollment applies CT baselines and guardrails to the account.
# These are distinct operations — CT enrollment requires the account
# to exist in a CT-governed OU first.

check "control_tower_enrollment_guidance" {
  assert {
    condition = !var.enable_control_tower_enrollment
    error_message = join(" ", [
      "Control Tower enrollment is enabled.",
      "CT enrollment is a separate workflow from account creation via aws_organizations_account.",
      "To enroll accounts: (1) Ensure the account is in a CT-governed OU,",
      "(2) Use the AWS Control Tower console → Organization → Enroll account,",
      "or run 'aws controltower register-organizational-unit --organizational-unit-id <ou-id>'.",
      "The aws_controltower_control resource applies guardrails to OUs but does not enroll individual accounts.",
      "For automated enrollment, use Service Catalog Account Factory.",
    ])
  }
}

# --- Unresolvable OU Paths ---
# Rejected by the precondition on aws_organizations_account.this — a warning
# would not stop an apply, and the resulting account would sit outside every
# OU-bound policy.

# --- Deployment Account Provider ---
# Declared by this module in providers.tf as aws.deployment_account.
# When enable_deployment_account is false, the default provider is used.

# --- SSM Parameters for Cross-Account Discovery ---
# Writes account data to SSM Parameter Store so that cross-account
# Terragrunt units can read them at parse time via run_cmd + aws ssm.
# This eliminates the need for env/accounts.hcl in CI/CD pipelines.
#
# Two parameter forms per account:
#   /tlz/accounts/<account-name>/metadata — JSON record (account ID, name,
#     organizational unit, email) for tooling that needs the full record.
#   /tlz/accounts/<account-name>/id — the twelve-digit account ID as plain
#     text. The cross-account sidecars resolve this one with a single
#     `aws ssm get-parameter --output text` call, so no JSON parsing is
#     needed inside run_cmd.
#
# Two resource blocks per form with for_each guards implement conditional
# provider routing (Terraform does not support dynamic provider selection).

# Write SSM to Management Account (default — when Deployment Account is disabled)
resource "aws_ssm_parameter" "account_id_local" {
  #checkov:skip=CKV_AWS_337:type is the literal "String", which SSM does not KMS-encrypt; key_id applies only to SecureString (checkov 3.3.16 SSMParameterUsesCMK passes non-SecureString)
  for_each = var.enable_deployment_account ? {} : aws_organizations_account.this

  name = "/tlz/accounts/${each.value.name}/metadata"
  type = "String"
  value = jsonencode({
    account_id          = each.value.id
    account_name        = each.value.name
    organizational_unit = each.value.parent_id
    email               = each.value.email
  })

  tags = var.default_tags
}

# Write SSM to Deployment Account (when Deployment Account is enabled)
resource "aws_ssm_parameter" "account_id_deployment" {
  #checkov:skip=CKV_AWS_337:type is the literal "String", which SSM does not KMS-encrypt; key_id applies only to SecureString (checkov 3.3.16 SSMParameterUsesCMK passes non-SecureString)
  for_each = var.enable_deployment_account ? aws_organizations_account.this : {}
  provider = aws.deployment_account

  name = "/tlz/accounts/${each.value.name}/metadata"
  type = "String"
  value = jsonencode({
    account_id          = each.value.id
    account_name        = each.value.name
    organizational_unit = each.value.parent_id
    email               = each.value.email
  })

  tags = var.default_tags
}

# Plain account ID to Management Account (default)
resource "aws_ssm_parameter" "account_plain_id_local" {
  #checkov:skip=CKV_AWS_337:type is the literal "String", which SSM does not KMS-encrypt; key_id applies only to SecureString (checkov 3.3.16 SSMParameterUsesCMK passes non-SecureString)
  for_each = var.enable_deployment_account ? {} : aws_organizations_account.this

  name  = "/tlz/accounts/${each.value.name}/id"
  type  = "String"
  value = each.value.id

  tags = var.default_tags
}

# Plain account ID to Deployment Account (when Deployment Account is enabled)
resource "aws_ssm_parameter" "account_plain_id_deployment" {
  #checkov:skip=CKV_AWS_337:type is the literal "String", which SSM does not KMS-encrypt; key_id applies only to SecureString (checkov 3.3.16 SSMParameterUsesCMK passes non-SecureString)
  for_each = var.enable_deployment_account ? aws_organizations_account.this : {}
  provider = aws.deployment_account

  name  = "/tlz/accounts/${each.value.name}/id"
  type  = "String"
  value = each.value.id

  tags = var.default_tags
}

# --- IAM Account Alias (management account) ---
# The alias replaces the 12-digit account ID in the AWS sign-in URL. It is a
# property of the account the provider authenticates to, so this resource can
# only name the account the stack runs in — the management account. Aliases
# for the accounts this module CREATES would each need their own provider
# configuration, which Terraform cannot produce per for_each entry; setting
# them stays a per-account deployment concern.

resource "aws_iam_account_alias" "management" {
  count = var.management_account_alias != "" ? 1 : 0

  account_alias = var.management_account_alias
}

# --- Quarantine OU ---
# An account declared with quarantined = true is created inside the quarantine
# OU, under the quarantine SCP, and configured by the fan-out through the
# exempt access role. Both lists are known at plan time, so the checks below
# read in the very plan that creates the account.

locals {
  quarantined_account_names = [
    for acct in local.resolved_accounts : acct.name
    if acct.quarantined
  ]

  # Role names the built-in quarantine SCP document exempts; every other
  # principal in a quarantined account is denied every action.
  quarantine_exempt_role_pattern = "^(AWSControlTowerExecution|TLZDeploymentRole|tlz-.*|OrganizationAccountAccessRole)$"

  quarantine_non_exempt_roles = [
    for role in distinct([var.account_access_role_name, local.created_account_role_name]) : role
    if !can(regex(local.quarantine_exempt_role_pattern, role))
  ]
}

check "quarantined_accounts_named" {
  assert {
    condition = length(local.quarantined_account_names) == 0
    error_message = join(" ", [
      "Quarantined accounts: [${join(", ", local.quarantined_account_names)}].",
      "They are created inside the quarantine OU, where the quarantine SCP denies every action to every principal except the exempt access roles.",
      "To release an account, set quarantined = false on its entry and apply this unit, which moves it to its declared OU.",
    ])
  }
}

check "quarantine_exempts_access_roles" {
  assert {
    condition = length(local.quarantined_account_names) == 0 || length(local.quarantine_non_exempt_roles) == 0
    error_message = join(" ", [
      "Quarantined accounts [${join(", ", local.quarantined_account_names)}] are reached through roles the built-in quarantine SCP does not exempt: [${join(", ", local.quarantine_non_exempt_roles)}].",
      "The document exempts AWSControlTowerExecution, TLZDeploymentRole, tlz-* and OrganizationAccountAccessRole; every other principal is denied every action, so the fan-out would fail in these accounts.",
      "Use an exempt role name, or exempt the role in a custom quarantine_scp_content.",
    ])
  }
}
