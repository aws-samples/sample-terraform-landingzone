# =============================================================================
# IAM Module Tests (modules/iam)
# =============================================================================
# Coverage:
#   - Toggle-off: enable_service_catalog = false, enable_stackset_roles = false
#     and empty collections → zero resources
#   - Default configuration: roles, SAML providers, policies, users, groups
#   - Custom configuration: management account StackSet role, Service Catalog
#     propagation role, instance profiles, inline policies, managed AD
#   - Custom configuration (member account): StackSet execution role
#   - Validation failures: role name, SAML provider name, user name,
#     management account ID, managed AD (AD Connector without connect_settings,
#     AD Connector without password_secret_name, non-account share target)
#   - Directory passwords are never literals in the module; directories are
#     shared with accounts only

mock_provider "aws" {
  # A real directory always reports its DNS servers; the generated mock value
  # for the computed set is empty, and the run with command = apply persists
  # that empty set into the test state — the FORWARD resolver rule's fixed
  # target_ip indices in later plan runs would trip over it.
  mock_resource "aws_directory_service_directory" {
    defaults = {
      dns_ip_addresses = ["10.0.0.100", "10.0.0.101"]
    }
  }

  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }
}

mock_provider "random" {}

# Placement alias for directory admin secrets (secret_config.account/region).
mock_provider "aws" {
  alias = "mad_secret"
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-off — no toggles enabled, no collections → zero resources
# -----------------------------------------------------------------------------
run "toggles_off_no_resources" {
  command = plan

  variables {
    enable_service_catalog = false
    enable_stackset_roles  = false
    is_management_account  = false
  }

  assert {
    condition     = length(aws_iam_role.this) == 0
    error_message = "No IAM roles must be created when roles is empty."
  }

  assert {
    condition     = length(aws_iam_instance_profile.this) == 0
    error_message = "No instance profiles must be created when roles is empty."
  }

  assert {
    condition     = length(aws_iam_saml_provider.this) == 0
    error_message = "No SAML providers must be created when saml_providers is empty."
  }

  assert {
    condition     = length(aws_iam_policy.this) == 0
    error_message = "No customer-managed policies must be created when the list is empty."
  }

  assert {
    condition     = length(aws_iam_user.this) == 0 && length(aws_iam_user_login_profile.this) == 0
    error_message = "No IAM users or login profiles must be created when iam_users is empty."
  }

  assert {
    condition     = length(aws_iam_group.this) == 0 && length(aws_iam_group_membership.this) == 0
    error_message = "No IAM groups or memberships must be created when iam_groups is empty."
  }

  assert {
    condition     = length(aws_secretsmanager_secret.user_password) == 0 && length(aws_secretsmanager_secret_version.user_password) == 0
    error_message = "No password secrets must be created when iam_users is empty."
  }

  assert {
    condition     = length(random_password.directory_admin) == 0 && length(aws_secretsmanager_secret.directory_admin) == 0
    error_message = "No directory admin passwords or secrets must be created when managed_active_directories is empty."
  }

  assert {
    condition     = length(aws_iam_role.service_catalog_propagation) == 0 && length(aws_iam_role_policy.service_catalog_propagation) == 0
    error_message = "No Service Catalog propagation role must be created when enable_service_catalog is false."
  }

  assert {
    condition     = length(aws_iam_role.stackset_admin) == 0 && length(aws_iam_role.stackset_execution) == 0
    error_message = "No StackSet roles must be created when enable_stackset_roles is false."
  }

  assert {
    condition     = length(aws_directory_service_directory.this) == 0 && length(aws_directory_service_directory.ad_connector) == 0
    error_message = "No directories must be created when managed_active_directories is empty."
  }

  assert {
    condition     = length(aws_kms_key.mad_admin_secret) == 0 && length(aws_route53_resolver_rule.managed_ad) == 0
    error_message = "No managed AD side resources must be created when the list is empty."
  }

  assert {
    condition     = output.service_catalog_propagation_role_arn == ""
    error_message = "service_catalog_propagation_role_arn must be empty when the toggle is off."
  }

  assert {
    condition     = output.stackset_admin_role_arn == null && output.stackset_execution_role_arn == null
    error_message = "StackSet role ARN outputs must be null when the toggle is off."
  }

  assert {
    condition     = length(output.role_arns) == 0 && length(output.policy_arns) == 0 && length(output.saml_provider_arns) == 0
    error_message = "Map outputs must be empty when nothing is configured."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — baseline roles, provider, policy, users
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  variables {
    roles = [
      {
        name = "TlzReadOnlyRole"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { AWS = "arn:aws:iam::111111111111:root" }
            Action    = "sts:AssumeRole"
          }]
        })
        managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
      }
    ]

    # The AWS provider requires at least 1000 characters of metadata
    saml_providers = [
      {
        name                   = "corporate-idp"
        saml_metadata_document = "<EntityDescriptor>${join("", [for i in range(150) : "0123456789"])}</EntityDescriptor>"
      }
    ]

    customer_managed_policies = [
      {
        name = "TlzDenyRegions"
        policy = jsonencode({
          Version   = "2012-10-17"
          Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
        })
      }
    ]

    iam_users = [
      {
        name   = "break-glass-user"
        groups = ["Administrators"]
      }
    ]

    iam_groups = [
      {
        name                = "Administrators"
        managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
      }
    ]
  }

  assert {
    condition     = length(aws_iam_role.this) == 1
    error_message = "One IAM role must be created."
  }

  assert {
    condition     = aws_iam_role.this["TlzReadOnlyRole"].permissions_boundary == null
    error_message = "Roles without permissions_boundary must not set one."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.roles["TlzReadOnlyRole:arn:aws:iam::aws:policy/ReadOnlyAccess"].policy_arn == "arn:aws:iam::aws:policy/ReadOnlyAccess"
    error_message = "A role's managed policy must be attached through the standalone attachment resource."
  }

  assert {
    condition     = length(aws_iam_role_policy_attachments_exclusive.this["TlzReadOnlyRole"].policy_arns) == 1 && contains(aws_iam_role_policy_attachments_exclusive.this["TlzReadOnlyRole"].policy_arns, "arn:aws:iam::aws:policy/ReadOnlyAccess")
    error_message = "The exclusive attachment resource must carry exactly the role's declared managed policies."
  }

  assert {
    condition     = length(aws_iam_role_policies_exclusive.this["TlzReadOnlyRole"].policy_names) == 0
    error_message = "A role without inline policies must carry an empty exclusive inline list, so out-of-band inline policies are removed."
  }

  assert {
    condition     = length(aws_iam_instance_profile.this) == 0
    error_message = "No instance profile must be created when instance_profile is false."
  }

  assert {
    condition     = length(aws_iam_saml_provider.this) == 1
    error_message = "One SAML provider must be created."
  }

  assert {
    condition     = length(aws_iam_policy.this) == 1
    error_message = "One customer-managed policy must be created."
  }

  assert {
    condition     = length(aws_iam_user.this) == 1 && length(aws_iam_user_login_profile.this) == 1
    error_message = "A login profile must be created for users with console access."
  }

  assert {
    condition     = length(aws_secretsmanager_secret.user_password) == 0
    error_message = "No password secret must be created when auto_generate_password is false."
  }

  assert {
    condition     = length(aws_iam_group.this) == 1 && length(aws_iam_group_membership.this) == 1
    error_message = "Group and membership must be created for group members."
  }

  assert {
    condition     = length(aws_iam_group_policy_attachment.this) == 1
    error_message = "Group managed policy attachment must be created."
  }

  assert {
    condition     = length(output.role_arns) == 1 && length(output.user_names) == 1 && length(output.group_names) == 1
    error_message = "Outputs must expose the created roles, users and groups."
  }

  assert {
    condition     = length(output.deployment_targets.roles) == 0
    error_message = "deployment_targets output must be empty without configured targets."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration (management account) — toggles on,
# instance profile, inline policies, boundary by policy name, managed AD
# -----------------------------------------------------------------------------
run "custom_configuration_management_account" {
  command = plan

  # The policy ARN is computed; pinned for the plan so the boundary
  # assertion below compares known values.
  override_resource {
    target          = aws_iam_policy.this
    override_during = plan
    values = {
      arn = "arn:aws:iam::123456789012:policy/TlzBoundary"
    }
  }

  variables {
    enable_service_catalog = true
    enable_stackset_roles  = true
    is_management_account  = true
    management_account_id  = "123456789012"

    customer_managed_policies = [
      {
        name = "TlzBoundary"
        policy = jsonencode({
          Version   = "2012-10-17"
          Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }]
        })
      }
    ]

    roles = [
      {
        name = "TlzEc2Role"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { Service = "ec2.amazonaws.com" }
            Action    = "sts:AssumeRole"
          }]
        })
        instance_profile     = true
        permissions_boundary = "TlzBoundary"
        inline_policies = [
          {
            name = "AllowDescribe"
            policy = jsonencode({
              Version   = "2012-10-17"
              Statement = [{ Effect = "Allow", Action = "ec2:Describe*", Resource = "*" }]
            })
          }
        ]
      }
    ]

    iam_users = [
      {
        name                   = "automation-user"
        disable_console_access = true
      },
      {
        name                   = "console-user"
        auto_generate_password = true
      }
    ]

    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }

    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }

    resolver_endpoint_ids = {
      "central-outbound" = "rslvr-out-0123456789abcdef0"
    }

    managed_active_directories = [
      {
        name                     = "tlz-directory"
        directory_type           = "MicrosoftAD"
        edition                  = "Enterprise"
        vpc_name                 = "shared-vpc"
        subnet_names             = ["private-a", "private-b"]
        domain_name              = "corp.example.com"
        resolver_rule_name       = "corp-example-com"
        resolver_endpoint_name   = "central-outbound"
        vpc_associations         = ["shared-vpc"]
        shared_account_ids       = ["111111111111", "222222222222"]
        log_group_name           = "/aws/directoryservice/tlz"
        secret_access_role_names = ["TlzEc2Role"]
      }
    ]
  }

  # --- Service Catalog propagation role ---
  assert {
    condition     = length(aws_iam_role.service_catalog_propagation) == 1
    error_message = "Service Catalog propagation role must be created when enabled."
  }

  assert {
    condition     = aws_iam_role.service_catalog_propagation[0].name == "tlz-service-catalog-propagation"
    error_message = "Service Catalog propagation role name must be tlz-service-catalog-propagation."
  }

  assert {
    condition     = length(aws_iam_role_policy.service_catalog_propagation) == 1
    error_message = "Service Catalog propagation role policy must be created when enabled."
  }

  # --- StackSet roles: admin in management account only ---
  assert {
    condition     = length(aws_iam_role.stackset_admin) == 1
    error_message = "StackSet administration role must be created in the management account."
  }

  assert {
    condition     = aws_iam_role.stackset_admin[0].name == "AWSCloudFormationStackSetAdministrationRole"
    error_message = "StackSet administration role must use the AWS-expected name."
  }

  assert {
    condition     = length(aws_iam_role.stackset_execution) == 0
    error_message = "StackSet execution role must not be created in the management account."
  }

  assert {
    condition     = output.stackset_execution_role_arn == null
    error_message = "stackset_execution_role_arn must be null in the management account."
  }

  # --- Instance profile and boundary by policy name ---
  assert {
    condition     = length(aws_iam_instance_profile.this) == 1
    error_message = "Instance profile must be created for roles with instance_profile = true."
  }

  assert {
    condition     = length(output.instance_profile_arns) == 1
    error_message = "instance_profile_arns output must expose the created instance profile."
  }

  # The boundary is named "TlzBoundary", a key of customer_managed_policies;
  # the role must carry that policy's ARN (pinned for the plan by the
  # override_resource of this run), not the bare name.
  assert {
    condition     = aws_iam_role.this["TlzEc2Role"].permissions_boundary == aws_iam_policy.this["TlzBoundary"].arn
    error_message = "A permissions_boundary given by policy name must resolve to the ARN of the module's customer-managed policy of that name."
  }

  # --- Auto-generated password and console access suppression ---
  assert {
    condition     = keys(aws_secretsmanager_secret.user_password) == ["console-user"] && length(aws_secretsmanager_secret_version.user_password) == 1
    error_message = "The initial password of an auto_generate_password user must be stored in Secrets Manager."
  }

  # Without secrets_kms_key_arn the secret must keep
  # the Secrets Manager service key (kms_key_id unset).
  assert {
    condition = alltrue([
      for _, secret in aws_secretsmanager_secret.user_password : secret.kms_key_id == null
    ])
    error_message = "Without secrets_kms_key_arn the password secret must not name a KMS key (service key aws/secretsmanager applies)."
  }

  assert {
    condition     = keys(aws_iam_user_login_profile.this) == ["console-user"]
    error_message = "No login profile must be created when disable_console_access is true."
  }

  # --- Managed Active Directory ---
  assert {
    condition     = length(aws_directory_service_directory.this) == 1 && length(aws_directory_service_directory.ad_connector) == 0
    error_message = "A MicrosoftAD directory must be created and no AD Connector."
  }

  assert {
    condition     = aws_directory_service_directory.this["tlz-directory"].edition == "Enterprise"
    error_message = "Managed AD edition must match the input."
  }

  assert {
    condition     = one(aws_directory_service_directory.this["tlz-directory"].vpc_settings).vpc_id == "vpc-0123456789abcdef0"
    error_message = "Managed AD must resolve the VPC ID from vpc_ids."
  }

  assert {
    condition     = length(one(aws_directory_service_directory.this["tlz-directory"].vpc_settings).subnet_ids) == 2
    error_message = "Managed AD must resolve both subnet IDs from subnet_ids."
  }

  assert {
    condition     = length(aws_route53_resolver_rule.managed_ad) == 1
    error_message = "Resolver rule must be created when resolver_rule_name is set."
  }

  assert {
    condition     = aws_route53_resolver_rule.managed_ad["tlz-directory"].rule_type == "FORWARD"
    error_message = "The resolver rule must be a FORWARD rule — a SYSTEM rule switches the AD domain back to VPC-standard resolution and cannot reach the directory's DNS servers."
  }

  assert {
    condition     = aws_route53_resolver_rule.managed_ad["tlz-directory"].resolver_endpoint_id == "rslvr-out-0123456789abcdef0"
    error_message = "The FORWARD rule must route through the outbound endpoint resolved from resolver_endpoint_ids."
  }

  # --- Directory admin password -----------------------------------------------
  # The admin password is never a literal in the module source: it is
  # generated per directory and stored in Secrets Manager under the tlz/mad/<directory>/* prefix, encrypted with the
  # directory's KMS key.
  assert {
    condition     = length(random_password.directory_admin) == 1
    error_message = "A password must be generated for each Managed Microsoft AD."
  }

  assert {
    condition     = random_password.directory_admin["tlz-directory"].length == 32
    error_message = "Generated directory admin passwords must be 32 characters long."
  }

  assert {
    condition     = length(aws_secretsmanager_secret.directory_admin) == 1 && length(aws_secretsmanager_secret_version.directory_admin) == 1
    error_message = "Generated directory admin passwords must be stored in Secrets Manager."
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].name == "tlz/mad/tlz-directory/admin-password"
    error_message = "The admin secret must use the tlz/mad/<directory>/ prefix that the secret access policy grants."
  }

  # --- end directory admin password -------------------------------------------

  # --- Directory share targets ------------------------------------------------
  # Share targets are account IDs, sent as target type ACCOUNT, and each one
  # produces exactly one ACCOUNT share.
  assert {
    condition     = length(aws_directory_service_shared_directory.this) == 2
    error_message = "One shared directory entry must be created per share target account."
  }

  assert {
    condition = alltrue([
      one(aws_directory_service_shared_directory.this["tlz-directory:111111111111"].target).id == "111111111111",
      one(aws_directory_service_shared_directory.this["tlz-directory:222222222222"].target).id == "222222222222",
    ])
    error_message = "Each share target must carry the configured account ID."
  }

  assert {
    condition = alltrue([
      for share in values(aws_directory_service_shared_directory.this) :
      one(share.target).type == "ACCOUNT"
    ])
    error_message = "Directory shares must use target type ACCOUNT — the API supports no other type."
  }
  # --- end directory share targets --------------------------------------------

  assert {
    condition     = length(aws_directory_service_log_subscription.this) == 1
    error_message = "Log subscription must be created when log_group_name is set."
  }

  assert {
    condition     = length(aws_iam_role_policy.mad_secret_access) == 1
    error_message = "Secret access policy must be created for each secret_access_role_names entry."
  }

  # --- Secret access policy scope ---------------------------------------------
  # The block above asserts the secret NAME "that the secret access policy
  # grants" but does not read the policy; a Resource widened to the bare "*"
  # would grant secretsmanager:GetSecretValue on every secret in the account.
  # Read the rendered policy the module actually produces (not the template
  # text, not the input variables) and bind each Resource element to the
  # created secret: a Secrets Manager secret ARN that names this directory's
  # admin secret, never the bare wildcard. Resource may legally be a string or
  # a list — flatten([...]) reads both forms alike.
  assert {
    condition = length(jsondecode(aws_iam_role_policy.mad_secret_access["tlz-directory:TlzEc2Role"].policy).Statement) > 0 && alltrue(flatten([
      for s in jsondecode(aws_iam_role_policy.mad_secret_access["tlz-directory:TlzEc2Role"].policy).Statement : [
        for r in flatten([s.Resource]) :
        r != "*"
        && startswith(r, "arn:aws:secretsmanager:")
        && endswith(r, ":secret:${aws_secretsmanager_secret.directory_admin["tlz-directory"].name}*")
      ]
    ]))
    error_message = "The secret access policy must scope every Resource to the directory's own admin secret ARN (arn:<partition>:secretsmanager:*:*:secret:tlz/mad/<directory>/admin-password*) — a Resource of \"*\" would let the instance role read every secret in the account."
  }
  # --- end secret access policy scope -----------------------------------------

  assert {
    condition     = length(aws_kms_key.mad_admin_secret) == 1 && length(aws_kms_alias.mad_admin_secret) == 1
    error_message = "A KMS key and alias must be created for MicrosoftAD admin secrets."
  }

  assert {
    condition     = aws_kms_alias.mad_admin_secret["tlz-directory"].name == "alias/tlz/mad/tlz-directory/secret"
    error_message = "MAD admin secret KMS alias must follow the tlz naming scheme."
  }

  # --- Wildcard principal of the MAD secret key policy -------------------------
  # The statement for Secrets Manager names Principal "*". A bare
  # kms:ViaService = "secretsmanager.amazonaws.com" lacks the region that the
  # condition key carries and never matches. Every statement with the wildcard
  # principal must bind the caller to this account and the service to this
  # region, read from the rendered policy.
  assert {
    condition = alltrue([
      for s in jsondecode(aws_kms_key.mad_admin_secret["tlz-directory"].policy).Statement :
      try(s.Condition.StringEquals["kms:CallerAccount"], "") == "123456789012"
      && try(s.Condition.StringEquals["kms:ViaService"], "") == "secretsmanager.eu-central-1.amazonaws.com"
      if try(s.Principal.AWS, "") == "*"
    ]) && length([for s in jsondecode(aws_kms_key.mad_admin_secret["tlz-directory"].policy).Statement : s if try(s.Principal.AWS, "") == "*"]) == 1
    error_message = "The Principal \"*\" statement of the MAD secret key policy must carry kms:CallerAccount = the account ID and kms:ViaService = secretsmanager.<region>.<dns suffix>."
  }
  # --- end wildcard principal --------------------------------------------------
}

# -----------------------------------------------------------------------------
# Scenario 3b: Custom configuration (member account) — execution role only
# -----------------------------------------------------------------------------
run "custom_configuration_member_account" {
  command = plan

  variables {
    enable_stackset_roles = true
    is_management_account = false
    management_account_id = "123456789012"
  }

  assert {
    condition     = length(aws_iam_role.stackset_execution) == 1
    error_message = "StackSet execution role must be created in member accounts."
  }

  assert {
    condition     = aws_iam_role.stackset_execution[0].name == "AWSCloudFormationStackSetExecutionRole"
    error_message = "StackSet execution role must use the AWS-expected name."
  }

  # The decoded document, not a substring: the account's root as principal or
  # a second statement would keep a substring check green.
  assert {
    condition = jsondecode(aws_iam_role.stackset_execution[0].assume_role_policy).Statement == [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/AWSCloudFormationStackSetAdministrationRole" }
        Action    = "sts:AssumeRole"
      },
    ]
    error_message = "Execution role trust policy must hold exactly one statement: sts:AssumeRole for the management account's AWSCloudFormationStackSetAdministrationRole."
  }

  assert {
    condition     = aws_iam_role_policy_attachment.stackset_execution[0].policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"
    error_message = "Execution role must attach AdministratorAccess using the detected partition."
  }

  assert {
    condition     = length(aws_iam_role.stackset_admin) == 0
    error_message = "StackSet administration role must not be created in member accounts."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3c: AD Connector configuration
# -----------------------------------------------------------------------------
run "custom_configuration_ad_connector" {
  command = plan

  variables {
    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }

    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }

    resolver_endpoint_ids = { "central-outbound" = "rslvr-out-0123456789abcdef0" }

    managed_active_directories = [
      {
        name                   = "onprem-connector"
        directory_type         = "ADConnector"
        vpc_name               = "shared-vpc"
        subnet_names           = ["private-a", "private-b"]
        domain_name            = "onprem.example.com"
        password_secret_name   = "tlz/ad-connector/onprem/service-account"
        resolver_rule_name     = "onprem-example-com"
        resolver_endpoint_name = "central-outbound"
        vpc_associations       = ["shared-vpc"]
        connect_settings = {
          customer_dns_ips  = ["10.0.0.10", "10.0.0.11"]
          customer_username = "Administrator"
        }
      }
    ]
  }

  # --- FORWARD rule targets the connector's on-premises DNS servers ----------
  # The connector's DNS IPs come from configuration, so plan already knows
  # both target_ip blocks (the MicrosoftAD side is only known after apply).
  assert {
    condition     = aws_route53_resolver_rule.managed_ad["onprem-connector"].rule_type == "FORWARD"
    error_message = "The resolver rule must be a FORWARD rule."
  }

  assert {
    condition     = [for t in aws_route53_resolver_rule.managed_ad["onprem-connector"].target_ip : t.ip] == ["10.0.0.10", "10.0.0.11"]
    error_message = "The FORWARD rule must target both customer_dns_ips of the AD Connector."
  }

  assert {
    condition     = length(aws_directory_service_directory.ad_connector) == 1 && length(aws_directory_service_directory.this) == 0
    error_message = "An AD Connector must be created and no MicrosoftAD directory."
  }

  assert {
    condition     = aws_directory_service_directory.ad_connector["onprem-connector"].size == "Small"
    error_message = "AD Connector size must default to Small for Standard edition."
  }

  assert {
    condition     = length(aws_kms_key.mad_admin_secret) == 0
    error_message = "AD Connectors must not create MAD admin secret KMS keys."
  }

  # --- Directory password (AD Connector side) ---------------------------------
  # The connector authenticates with an existing on-premises service account,
  # so its password is read from Secrets Manager instead of being hardcoded or
  # generated.
  assert {
    condition     = length(random_password.directory_admin) == 0
    error_message = "AD Connector passwords must not be generated — they belong to the on-premises directory."
  }

  assert {
    condition     = data.aws_secretsmanager_secret_version.ad_connector_password["onprem-connector"].secret_id == "tlz/ad-connector/onprem/service-account"
    error_message = "The AD Connector password must be read from the configured Secrets Manager secret."
  }
  # --- end directory password (AD Connector side) -----------------------------
}

# -----------------------------------------------------------------------------
# Scenario 3d: the applied directory password is the generated secret value
#
# Uses `command = apply` (against mock providers, no AWS calls) because the
# generated password and the KMS key ARN are unknown during the plan phase.
# -----------------------------------------------------------------------------
run "regression_directory_password_comes_from_generated_secret" {
  command = apply

  variables {
    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }

    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }

    managed_active_directories = [
      {
        name         = "tlz-directory"
        vpc_name     = "shared-vpc"
        subnet_names = ["private-a", "private-b"]
        domain_name  = "corp.example.com"
      }
    ]
  }

  assert {
    condition     = aws_directory_service_directory.this["tlz-directory"].password == random_password.directory_admin["tlz-directory"].result
    error_message = "The directory password must be the generated value, never a literal from the module source."
  }

  assert {
    condition     = aws_secretsmanager_secret_version.directory_admin["tlz-directory"].secret_string == random_password.directory_admin["tlz-directory"].result
    error_message = "The stored secret must contain exactly the password the directory was created with."
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].kms_key_id == aws_kms_key.mad_admin_secret["tlz-directory"].arn
    error_message = "The admin secret must be encrypted with the directory's own KMS key."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3e: custom configuration — account names in policy documents are
# resolved through var.account_ids
#
# The mark @@account_id:<name>@@ is resolved in trust policies, inline
# policies and customer-managed policy documents, so a cross-account principal
# need not name a 12-digit account ID literally in the configuration.
# -----------------------------------------------------------------------------
run "account_names_in_policy_documents_are_resolved" {
  command = plan

  variables {
    account_ids = {
      audit         = "111111111111"
      "log-archive" = "222222222222"
    }
    customer_managed_policies = [
      {
        name = "TlzAuditRead"
        policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect   = "Allow"
            Action   = "s3:GetObject"
            Resource = "arn:aws:s3:::tlz-@@account_id:log-archive@@-logs/*"
          }]
        })
      }
    ]
    roles = [
      {
        name = "TlzAuditRole"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { AWS = "arn:aws:iam::@@account_id:audit@@:root" }
            Action    = "sts:AssumeRole"
          }]
        })
        inline_policies = [
          {
            name = "AllowLogArchiveRead"
            policy = jsonencode({
              Version = "2012-10-17"
              Statement = [{
                Effect   = "Allow"
                Action   = "sts:AssumeRole"
                Resource = "arn:aws:iam::@@account_id:log-archive@@:role/TLZReadOnly"
              }]
            })
          }
        ]
      }
    ]
  }

  assert {
    condition     = strcontains(aws_iam_role.this["TlzAuditRole"].assume_role_policy, "arn:aws:iam::111111111111:root")
    error_message = "The account name in the trust policy must be resolved to the account ID."
  }

  assert {
    condition     = !strcontains(aws_iam_role.this["TlzAuditRole"].assume_role_policy, "@@")
    error_message = "No mark must remain in the resolved trust policy."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.roles["TlzAuditRole:AllowLogArchiveRead"].policy, "arn:aws:iam::222222222222:role/TLZReadOnly")
    error_message = "The account name in an inline policy must be resolved to the account ID."
  }

  assert {
    condition     = strcontains(aws_iam_policy.this["TlzAuditRead"].policy, "tlz-222222222222-logs")
    error_message = "The account name in a customer-managed policy document must be resolved to the account ID."
  }

  assert {
    condition     = length(local.unresolved_account_marks) == 0
    error_message = "Every mark of this scenario names a key of account_ids, so none must remain unresolved."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3f: an unknown account name is reported instead of silently kept
#
# The check block makes the cause visible in the plan. Without it the mark would
# travel into the IAM document and AWS would reject it at apply time with a
# message that never mentions the unknown account name.
# -----------------------------------------------------------------------------
run "unknown_account_name_in_policy_document_is_reported" {
  command = plan

  variables {
    account_ids = {
      audit = "111111111111"
    }
    roles = [
      {
        name = "TlzAuditRole"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { AWS = "arn:aws:iam::@@account_id:sandbox@@:root" }
            Action    = "sts:AssumeRole"
          }]
        })
      }
    ]
  }

  expect_failures = [
    check.account_name_marks_resolve,
  ]

  assert {
    condition     = local.unresolved_account_marks == tolist(["@@account_id:sandbox@@"])
    error_message = "The unknown account name must be named in the diagnosis."
  }

  assert {
    condition     = strcontains(aws_iam_role.this["TlzAuditRole"].assume_role_policy, "@@account_id:sandbox@@")
    error_message = "An unknown mark must be restored unchanged, never dropped."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3g: a document without any mark passes through unchanged
#
# The resolution runs over every policy document, so this is the case that
# matters for every existing configuration: split/join must reproduce the input
# byte for byte, and marks of other kinds must survive.
# -----------------------------------------------------------------------------
run "policy_documents_without_account_marks_are_unchanged" {
  command = plan

  variables {
    account_ids = {
      audit = "111111111111"
    }
    customer_managed_policies = [
      {
        name   = "TlzOrgScoped"
        policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringNotEquals\":{\"aws:PrincipalOrgID\":\"@@organization_id@@\"}}}]}"
      }
    ]
    roles = [
      {
        name = "TlzPlainRole"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { Service = "ec2.amazonaws.com" }
            Action    = "sts:AssumeRole"
          }]
        })
      }
    ]
  }

  assert {
    condition     = aws_iam_role.this["TlzPlainRole"].assume_role_policy == var.roles[0].assume_role_policy
    error_message = "A trust policy without marks must reach the role unchanged."
  }

  assert {
    condition     = aws_iam_policy.this["TlzOrgScoped"].policy == var.customer_managed_policies[0].policy
    error_message = "A mark of another kind must survive the account-name resolution unchanged."
  }

  assert {
    condition     = length(local.unresolved_account_marks) == 0
    error_message = "A document without account marks must produce no diagnosis."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4a: Validation failure — invalid role name
# -----------------------------------------------------------------------------
run "invalid_role_name_rejected" {
  command = plan

  variables {
    roles = [
      {
        name               = "invalid role name!"
        assume_role_policy = "{}"
      }
    ]
  }

  expect_failures = [
    var.roles,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4b: Validation failure — invalid SAML provider name
# -----------------------------------------------------------------------------
run "invalid_saml_provider_name_rejected" {
  command = plan

  variables {
    saml_providers = [
      {
        name                   = "invalid provider!"
        saml_metadata_document = "<EntityDescriptor/>"
      }
    ]
  }

  expect_failures = [
    var.saml_providers,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4c: Validation failure — invalid IAM user name
# -----------------------------------------------------------------------------
run "invalid_iam_user_name_rejected" {
  command = plan

  variables {
    iam_users = [
      {
        name = "invalid user!"
      }
    ]
  }

  expect_failures = [
    var.iam_users,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4d: Validation failure — invalid management account ID
# -----------------------------------------------------------------------------
run "invalid_management_account_id_rejected" {
  command = plan

  variables {
    management_account_id = "12345"
  }

  expect_failures = [
    var.management_account_id,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4e: Validation failure — AD Connector without connect_settings
# -----------------------------------------------------------------------------
run "invalid_ad_connector_without_connect_settings_rejected" {
  command = plan

  variables {
    managed_active_directories = [
      {
        name                 = "broken-connector"
        directory_type       = "ADConnector"
        vpc_name             = "shared-vpc"
        subnet_names         = ["private-a", "private-b"]
        domain_name          = "onprem.example.com"
        password_secret_name = "tlz/ad-connector/onprem/service-account"
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4f: Validation failure — AD Connector without password_secret_name
# -----------------------------------------------------------------------------
run "invalid_ad_connector_without_password_secret_rejected" {
  command = plan

  variables {
    managed_active_directories = [
      {
        name           = "onprem-connector"
        directory_type = "ADConnector"
        vpc_name       = "shared-vpc"
        subnet_names   = ["private-a", "private-b"]
        domain_name    = "onprem.example.com"
        connect_settings = {
          customer_dns_ips  = ["10.0.0.10"]
          customer_username = "Administrator"
        }
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4g: Validation failure — share target that is not an account ID
# -----------------------------------------------------------------------------
run "invalid_directory_share_target_rejected" {
  command = plan

  variables {
    managed_active_directories = [
      {
        name               = "tlz-directory"
        vpc_name           = "shared-vpc"
        subnet_names       = ["private-a", "private-b"]
        domain_name        = "corp.example.com"
        shared_account_ids = ["ou-abc1-11111111"]
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

# -----------------------------------------------------------------------------
# Optional CMK for auto-generated password secrets
#
# A configured secrets_kms_key_arn reaches the kms_key_id
# of every password secret. The empty-default counterpart is asserted in
# scenario custom_configuration_management_account.
# -----------------------------------------------------------------------------
run "regression_secrets_kms_key_reaches_password_secret" {
  command = plan

  variables {
    iam_users = [
      {
        name                   = "automation-user"
        auto_generate_password = true
      }
    ]
    secrets_kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/00000000-1111-2222-3333-444444444444"
  }

  assert {
    condition = alltrue([
      for _, secret in aws_secretsmanager_secret.user_password :
      secret.kms_key_id == "arn:aws:kms:eu-central-1:123456789012:key/00000000-1111-2222-3333-444444444444"
    ])
    error_message = "A configured secrets_kms_key_arn must reach the kms_key_id of every password secret."
  }

  assert {
    condition     = length(aws_secretsmanager_secret.user_password) == 1
    error_message = "The auto_generate_password user must produce exactly one password secret."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4h: Validation failure — malformed secrets_kms_key_arn
# -----------------------------------------------------------------------------
run "invalid_secrets_kms_key_arn_rejected" {
  command = plan

  variables {
    secrets_kms_key_arn = "not-a-kms-arn"
  }

  expect_failures = [
    var.secrets_kms_key_arn,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 4i: Validation failure — auto_generate_password without console
# access. The secret stores the login profile's generated password; a user
# without a login profile has none, so the combination is refused instead of
# storing a value that signs nobody in.
# -----------------------------------------------------------------------------
run "auto_password_without_console_access_rejected" {
  command = plan

  variables {
    iam_users = [
      {
        name                   = "automation-user"
        auto_generate_password = true
        disable_console_access = true
      }
    ]
  }

  expect_failures = [
    var.iam_users,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 5: Role path and maximum session duration
# Entries without the two fields keep the AWS defaults: path / and 3600 seconds
# are the values AWS applies to a role without them.
# -----------------------------------------------------------------------------
run "role_path_and_session_duration_defaults_keep_the_plan" {
  command = plan

  variables {
    roles = [
      {
        name = "TlzPlainRole"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { Service = "ec2.amazonaws.com" }
            Action    = "sts:AssumeRole"
          }]
        })
      }
    ]
  }

  assert {
    condition     = aws_iam_role.this["TlzPlainRole"].path == "/"
    error_message = "A role without path must keep the IAM default path /."
  }

  assert {
    condition     = aws_iam_role.this["TlzPlainRole"].max_session_duration == 3600
    error_message = "A role without max_session_duration must keep the IAM default of 3600 seconds."
  }
}

run "role_path_and_session_duration_reach_the_role" {
  command = plan

  variables {
    roles = [
      {
        name = "TlzScopedRole"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { Service = "ec2.amazonaws.com" }
            Action    = "sts:AssumeRole"
          }]
        })
        path                 = "/landing-zone/security/"
        max_session_duration = 43200
      }
    ]
  }

  assert {
    condition     = aws_iam_role.this["TlzScopedRole"].path == "/landing-zone/security/"
    error_message = "The declared role path must reach aws_iam_role.path."
  }

  assert {
    condition     = aws_iam_role.this["TlzScopedRole"].max_session_duration == 43200
    error_message = "The declared session duration must reach aws_iam_role.max_session_duration."
  }
}

run "invalid_role_path_rejected" {
  command = plan

  variables {
    roles = [
      {
        name               = "TlzBadPathRole"
        assume_role_policy = "{}"
        path               = "landing-zone"
      }
    ]
  }

  expect_failures = [
    var.roles,
  ]
}

run "invalid_role_session_duration_rejected" {
  command = plan

  variables {
    roles = [
      {
        name                 = "TlzShortSessionRole"
        assume_role_policy   = "{}"
        max_session_duration = 900
      }
    ]
  }

  expect_failures = [
    var.roles,
  ]
}

# -----------------------------------------------------------------------------
# Scenario 6: Managed AD metadata, log retention, secret placement and
# OU share targets
# -----------------------------------------------------------------------------

# An entry of the previous form: no description, no NetBIOS name, no
# log_retention_days, no secret_config, no share_targets. The plan keeps its
# shape — externally managed log group, fixed secret name, per-directory KMS
# key, shares only from the direct account list.
run "managed_ad_metadata_defaults_keep_the_plan" {
  command = plan

  variables {
    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }
    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }
    managed_active_directories = [
      {
        name               = "tlz-directory"
        directory_type     = "MicrosoftAD"
        vpc_name           = "shared-vpc"
        subnet_names       = ["private-a", "private-b"]
        domain_name        = "corp.example.com"
        shared_account_ids = ["111111111111"]
        log_group_name     = "/aws/directoryservice/tlz"
      }
    ]
  }

  assert {
    condition     = aws_directory_service_directory.this["tlz-directory"].description == null
    error_message = "A directory without description must plan none."
  }

  # short_name is optional+computed, so the mock provider fills it at plan —
  # the default is asserted at the variable, the wiring in the custom run.
  assert {
    condition     = var.managed_active_directories[0].net_bios_domain_name == null
    error_message = "An entry without net_bios_domain_name must default to null."
  }

  assert {
    condition     = length(aws_cloudwatch_log_group.managed_ad) == 0
    error_message = "Without log_retention_days the module must not create a log group."
  }

  assert {
    condition     = aws_directory_service_log_subscription.this["tlz-directory"].log_group_name == "/aws/directoryservice/tlz"
    error_message = "Without log_retention_days the subscription must keep reading the external group name."
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].name == "tlz/mad/tlz-directory/admin-password"
    error_message = "Without secret_config the admin secret must keep its fixed name."
  }

  assert {
    condition     = length(aws_kms_key.mad_admin_secret) == 1
    error_message = "A locally stored admin secret must keep its per-directory KMS key."
  }

  assert {
    condition     = length(aws_directory_service_shared_directory.from_organizational_units) == 0
    error_message = "Without share_targets no OU-derived share may be planned."
  }

  assert {
    condition     = length(aws_directory_service_shared_directory.this) == 1
    error_message = "The direct account list must keep producing its shares."
  }
}

# Full outfit: description and NetBIOS name on the directory, module-created
# log group with retention, custom secret name, OU share targets resolved to
# member accounts minus exclusions and minus the direct list.
run "managed_ad_metadata_reaches_the_directory" {
  command = plan

  variables {
    account_ids = {
      "workload-a" = "333333333333"
      "workload-b" = "444444444444"
      "workload-c" = "555555555555"
    }
    ou_name_to_id = {
      "Workloads" = "ou-abcd-11111111"
    }
    account_ou_ids = {
      "workload-a" = "ou-abcd-11111111"
      "workload-b" = "ou-abcd-11111111"
      "workload-c" = "ou-abcd-11111111"
    }
    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }
    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }
    managed_active_directories = [
      {
        name                 = "tlz-directory"
        directory_type       = "MicrosoftAD"
        description          = "Corporate directory of the landing zone"
        net_bios_domain_name = "CORP"
        vpc_name             = "shared-vpc"
        subnet_names         = ["private-a", "private-b"]
        domain_name          = "corp.example.com"
        shared_account_ids   = ["333333333333"]
        log_group_name       = "/aws/directoryservice/tlz"
        log_retention_days   = 365
        secret_config = {
          admin_secret_name = "landing-zone/directory/corp-admin"
        }
        share_targets = {
          organizational_units = ["Workloads"]
          excluded_accounts    = ["workload-b"]
        }
      }
    ]
  }

  assert {
    condition     = aws_directory_service_directory.this["tlz-directory"].description == "Corporate directory of the landing zone"
    error_message = "The declared description must reach the directory."
  }

  assert {
    condition     = aws_directory_service_directory.this["tlz-directory"].short_name == "CORP"
    error_message = "The declared NetBIOS name must reach short_name."
  }

  assert {
    condition     = aws_cloudwatch_log_group.managed_ad["tlz-directory"].name == "/aws/directoryservice/tlz"
    error_message = "With log_retention_days the module must create the named log group."
  }

  assert {
    condition     = aws_cloudwatch_log_group.managed_ad["tlz-directory"].retention_in_days == 365
    error_message = "The declared retention must reach the created log group."
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].name == "landing-zone/directory/corp-admin"
    error_message = "The declared admin_secret_name must reach the secret."
  }

  # OU expansion: workload-a is already covered by the direct list,
  # workload-b is excluded — exactly workload-c remains.
  assert {
    condition     = length(aws_directory_service_shared_directory.from_organizational_units) == 1
    error_message = "Exactly one OU-derived share must remain after exclusion and direct-list deduplication."
  }

  assert {
    condition     = aws_directory_service_shared_directory.from_organizational_units["tlz-directory:555555555555"].target[0].id == "555555555555"
    error_message = "The OU-derived share must target the remaining member account."
  }
}

# A placed secret: account and region set, no per-directory KMS key, no
# instance-role grant (the validation forbids that combination, so the
# fixture carries none).
run "managed_ad_secret_placement_switches_the_key" {
  command = plan

  variables {
    account_ids = {
      "audit" = "666666666666"
    }
    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }
    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }
    managed_active_directories = [
      {
        name           = "tlz-directory"
        directory_type = "MicrosoftAD"
        vpc_name       = "shared-vpc"
        subnet_names   = ["private-a", "private-b"]
        domain_name    = "corp.example.com"
        secret_config = {
          account = "audit"
          region  = "eu-central-1"
        }
      }
    ]
  }

  assert {
    condition     = length(aws_kms_key.mad_admin_secret) == 0
    error_message = "A placed secret must not create the regional management-account KMS key."
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].kms_key_id == null
    error_message = "A placed secret must fall back to the service key of its destination."
  }
}

# The role name only feeds the mad_secret provider alias (providers.tf: the
# assume_role role_arn in the placement account). Provider configuration is
# not plan-assertable, so this run pins that a non-default name is accepted
# and the placement path still plans; the validation is pinned below.
run "mad_secret_access_role_accepts_a_custom_name" {
  command = plan

  variables {
    account_ids = {
      "audit" = "666666666666"
    }
    vpc_ids = {
      "shared-vpc" = "vpc-0123456789abcdef0"
    }
    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }
    mad_secret_access_role_name = "TLZSecretPlacementRole"
    managed_active_directories = [
      {
        name           = "tlz-directory"
        directory_type = "MicrosoftAD"
        vpc_name       = "shared-vpc"
        subnet_names   = ["private-a", "private-b"]
        domain_name    = "corp.example.com"
        secret_config = {
          account = "audit"
          region  = "eu-central-1"
        }
      }
    ]
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].name == "tlz/mad/tlz-directory/admin-password"
    error_message = "With a custom placement role name the placed secret must still plan under its fixed name."
  }

  assert {
    condition     = aws_secretsmanager_secret.directory_admin["tlz-directory"].kms_key_id == null
    error_message = "The custom role name must not change the placed secret's key fallback."
  }
}

run "mad_secret_access_role_invalid_name_rejected" {
  command = plan

  variables {
    # "/" is outside the allowed IAM role-name character set — a path-form
    # value (role/with/path) must fail the validation, not build a broken ARN.
    mad_secret_access_role_name = "role/with/path"
  }

  expect_failures = [var.mad_secret_access_role_name]
}

run "managed_ad_unknown_vpc_name_fails_the_precondition" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name         = "tlz-directory"
        vpc_name     = "typo-vpc"
        subnet_names = ["private-a"]
        domain_name  = "corp.example.com"
      }
    ]
  }

  # The precondition names directory and key instead of a bare "Invalid index".
  expect_failures = [
    aws_directory_service_directory.this,
  ]
}

run "managed_ad_bootstrap_mock_plan_runs_through" {
  command = plan

  variables {
    # The bootstrap case: the iam stack mocks the networking outputs as empty
    # maps for validate/plan before networking is applied. The plan must run
    # through instead of crashing on an index into the empty maps.
    vpc_ids    = {}
    subnet_ids = {}
    managed_active_directories = [
      {
        name         = "tlz-directory"
        vpc_name     = "shared-vpc"
        subnet_names = ["private-a"]
        domain_name  = "corp.example.com"
      }
    ]
  }

  assert {
    condition     = length(aws_directory_service_directory.this) == 1
    error_message = "The directory must still be planned during a bootstrap plan with mocked (empty) networking outputs."
  }
}

run "managed_ad_vpc_association_created" {
  command = plan

  variables {
    vpc_ids = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = {
      "shared-vpc.private-a" = "subnet-0123456789abcdef0"
      "shared-vpc.private-b" = "subnet-0123456789abcdef1"
    }
    resolver_endpoint_ids = { "central-outbound" = "rslvr-out-0123456789abcdef0" }
    managed_active_directories = [
      {
        name                   = "tlz-directory"
        vpc_name               = "shared-vpc"
        subnet_names           = ["private-a", "private-b"]
        domain_name            = "corp.example.com"
        resolver_rule_name     = "corp-example-com"
        resolver_endpoint_name = "central-outbound"
        vpc_associations       = ["shared-vpc"]
      }
    ]
  }

  assert {
    condition     = length(aws_route53_resolver_rule_association.managed_ad) == 1
    error_message = "vpc_associations must create exactly one resolver rule association."
  }

  assert {
    condition     = aws_route53_resolver_rule_association.managed_ad["tlz-directory:shared-vpc"].vpc_id == "vpc-0123456789abcdef0"
    error_message = "The association must resolve the VPC ID from vpc_ids."
  }
}

run "resolver_rule_without_endpoint_rejected" {
  command = plan

  variables {
    managed_active_directories = [
      {
        name               = "tlz-directory"
        vpc_name           = "shared-vpc"
        subnet_names       = ["private-a", "private-b"]
        domain_name        = "corp.example.com"
        resolver_rule_name = "corp-example-com"
      }
    ]
  }

  # A FORWARD rule is only accepted with an outbound endpoint — a rule
  # request without resolver_endpoint_name must fail at validation.
  expect_failures = [
    var.managed_active_directories,
  ]
}

run "invalid_netbios_name_rejected" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name                 = "tlz-directory"
        vpc_name             = "shared-vpc"
        subnet_names         = ["private-a"]
        domain_name          = "corp.example.com"
        net_bios_domain_name = "THIS-NAME-IS-TOO-LONG"
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

run "invalid_log_retention_rejected" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name               = "tlz-directory"
        vpc_name           = "shared-vpc"
        subnet_names       = ["private-a"]
        domain_name        = "corp.example.com"
        log_group_name     = "/aws/directoryservice/tlz"
        log_retention_days = 42
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

run "log_retention_without_group_name_rejected" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name               = "tlz-directory"
        vpc_name           = "shared-vpc"
        subnet_names       = ["private-a"]
        domain_name        = "corp.example.com"
        log_retention_days = 365
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

run "secret_placement_with_role_grant_rejected" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name                     = "tlz-directory"
        vpc_name                 = "shared-vpc"
        subnet_names             = ["private-a"]
        domain_name              = "corp.example.com"
        secret_access_role_names = ["TlzEc2Role"]
        secret_config = {
          account = "111111111111"
        }
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

run "diverging_secret_placements_rejected" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name         = "tlz-directory-a"
        vpc_name     = "shared-vpc"
        subnet_names = ["private-a"]
        domain_name  = "corp-a.example.com"
        secret_config = {
          account = "111111111111"
        }
      },
      {
        name         = "tlz-directory-b"
        vpc_name     = "shared-vpc"
        subnet_names = ["private-a"]
        domain_name  = "corp-b.example.com"
        secret_config = {
          account = "222222222222"
        }
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

run "unknown_share_target_ou_rejected" {
  command = plan

  variables {
    vpc_ids    = { "shared-vpc" = "vpc-0123456789abcdef0" }
    subnet_ids = { "shared-vpc.private-a" = "subnet-0123456789abcdef0" }
    managed_active_directories = [
      {
        name         = "tlz-directory"
        vpc_name     = "shared-vpc"
        subnet_names = ["private-a"]
        domain_name  = "corp.example.com"
        share_targets = {
          organizational_units = ["Nonexistent"]
        }
      }
    ]
  }

  expect_failures = [
    var.managed_active_directories,
  ]
}

# -----------------------------------------------------------------------------
# Break-glass access package
# -----------------------------------------------------------------------------

run "break_glass_off_no_resources" {
  command = plan

  variables {
    enable_break_glass = false
  }

  assert {
    condition     = length(aws_iam_user.break_glass) == 0 && length(aws_iam_user_login_profile.break_glass) == 0 && length(aws_secretsmanager_secret.break_glass_password) == 0
    error_message = "Without enable_break_glass no break-glass user, login profile or secret may be planned."
  }
}

run "break_glass_creates_the_numbered_set" {
  command = plan

  variables {
    enable_break_glass = true
    break_glass_config = {
      user_count           = 3
      permissions_boundary = "arn:aws:iam::111111111111:policy/tlz-boundary"
    }
  }

  assert {
    condition     = length(aws_iam_user.break_glass) == 3
    error_message = "user_count = 3 must produce exactly three break-glass users."
  }

  assert {
    condition     = contains(keys(aws_iam_user.break_glass), "tlz-break-glass-01") && contains(keys(aws_iam_user.break_glass), "tlz-break-glass-03")
    error_message = "The users must carry the numbered names <prefix>-01 … -03 with the default prefix."
  }

  assert {
    condition     = alltrue([for u in aws_iam_user.break_glass : u.permissions_boundary == "arn:aws:iam::111111111111:policy/tlz-boundary"])
    error_message = "Every break-glass user must carry the mandatory permissions boundary."
  }

  assert {
    condition     = alltrue([for a in aws_iam_user_policy_attachment.break_glass_admin : a.policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess"])
    error_message = "Every break-glass user must receive AdministratorAccess (within the boundary), partition-correct via arn_prefix."
  }

  assert {
    condition     = alltrue([for p in aws_iam_user_login_profile.break_glass : p.password_reset_required])
    error_message = "Every login profile must force a password reset at first sign-in — that retires the state copy of the initial password."
  }

  assert {
    condition     = length(aws_secretsmanager_secret.break_glass_password) == 3 && contains(keys(aws_secretsmanager_secret.break_glass_password), "tlz-break-glass-02")
    error_message = "Every user's initial password must land in a Secrets Manager secret tlz/break-glass/<user>/password."
  }
}

run "break_glass_without_config_rejected" {
  command = plan

  variables {
    enable_break_glass = true
  }

  expect_failures = [var.break_glass_config]
}

run "break_glass_count_bounds_rejected" {
  command = plan

  variables {
    enable_break_glass = true
    break_glass_config = {
      user_count           = 11
      permissions_boundary = "arn:aws:iam::111111111111:policy/tlz-boundary"
    }
  }

  expect_failures = [var.break_glass_config]
}

run "break_glass_boundary_shape_rejected" {
  command = plan

  variables {
    enable_break_glass = true
    break_glass_config = {
      permissions_boundary = "tlz-boundary"
    }
  }

  expect_failures = [var.break_glass_config]
}
# -----------------------------------------------------------------------------
# Scenario: Partition-neutral managed policy names — under a mock
# partition the module expands a policy name (optionally with a path) to the
# partition's ARN for roles, users and groups; a full ARN passes through
# unchanged, so an existing configuration keeps its behaviour.
# -----------------------------------------------------------------------------
run "policy_names_build_partition_arns" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }
  variables {
    roles = [
      {
        name = "Backup-Role"
        assume_role_policy = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect    = "Allow"
            Principal = { Service = "backup.amazonaws.eu" }
            Action    = "sts:AssumeRole"
          }]
        })
        managed_policy_arns = [
          "service-role/AWSBackupServiceRolePolicyForBackup",
          "arn:aws-eusc:iam::aws:policy/AmazonSSMManagedInstanceCore",
        ]
      }
    ]
    iam_users = [
      {
        name                = "break-glass-user"
        managed_policy_arns = ["ReadOnlyAccess"]
      }
    ]
    iam_groups = [
      {
        name                = "Administrators"
        managed_policy_arns = ["AdministratorAccess"]
      }
    ]
  }
  assert {
    condition     = aws_iam_role_policy_attachment.roles["Backup-Role:arn:aws-eusc:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"].policy_arn == "arn:aws-eusc:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    error_message = "A policy name with path must become the partition's managed policy ARN."
  }
  assert {
    condition     = aws_iam_role_policy_attachment.roles["Backup-Role:arn:aws-eusc:iam::aws:policy/AmazonSSMManagedInstanceCore"].policy_arn == "arn:aws-eusc:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "A full managed policy ARN must pass through unchanged."
  }
  assert {
    condition     = contains(aws_iam_role_policy_attachments_exclusive.this["Backup-Role"].policy_arns, "arn:aws-eusc:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup") && contains(aws_iam_role_policy_attachments_exclusive.this["Backup-Role"].policy_arns, "arn:aws-eusc:iam::aws:policy/AmazonSSMManagedInstanceCore")
    error_message = "The exclusive attachment resource must carry the role's full resolved managed policy list."
  }
  assert {
    condition     = aws_iam_user_policy_attachment.this["break-glass-user:arn:aws-eusc:iam::aws:policy/ReadOnlyAccess"].policy_arn == "arn:aws-eusc:iam::aws:policy/ReadOnlyAccess"
    error_message = "A user policy name must become the partition's managed policy ARN."
  }
  assert {
    condition     = aws_iam_group_policy_attachment.this["Administrators:arn:aws-eusc:iam::aws:policy/AdministratorAccess"].policy_arn == "arn:aws-eusc:iam::aws:policy/AdministratorAccess"
    error_message = "A group policy name must become the partition's managed policy ARN."
  }
}

# -----------------------------------------------------------------------------
# The stored user password must be the one that signs in
#
# aws_iam_user_login_profile takes no password input and generates its own, so
# a separately generated random value would never be set on the user. The
# secret of an auto_generate_password user must hold the login profile's
# generated password. `command = apply` against the mock providers
# (no AWS call) because that attribute is known only after apply; the run is
# the last of the file so the state it leaves reaches no other run.
# -----------------------------------------------------------------------------
run "regression_user_password_secret_holds_the_login_password" {
  command = apply

  variables {
    iam_users = [
      {
        name                   = "console-user"
        auto_generate_password = true
      }
    ]
  }

  assert {
    condition     = aws_secretsmanager_secret_version.user_password["console-user"].secret_string == aws_iam_user_login_profile.this["console-user"].password
    error_message = "The password secret must store the initial password of the user's login profile, not a separately generated value."
  }
}
