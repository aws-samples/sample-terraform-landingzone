# =============================================================================
# Service Catalog Module Tests (modules/service-catalog)
# =============================================================================
# Mandatory scenarios:
#   1. Toggle-Off — the module has NO enable_* variable. Resource creation is
#      driven solely by the portfolios list, so the empty list is the module's
#      creation toggle: portfolios = [] => zero resources.
#   2. Default configuration — no inputs at all (portfolios defaults to []).
#   3. Custom configuration — portfolio with products and a launch constraint,
#      portfolio sharing (account / organization / OU targets) and principal
#      associations.
#   4. Validation failures — empty provider_name, empty product owner,
#      unsupported principal_type, missing/malformed product template_url.
#   5. Every product reaches its provisioning artifact with a template source.
#
# Providers used directly by the module: aws (default only, no aliases).
# The module reads data.aws_partition.current for its partition guard;
# the default mock partition is aws, the aws-eusc scenario
# overrides it.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }
}

# -----------------------------------------------------------------------------
# Scenario 1: Toggle-Off equivalent — empty portfolio list => zero resources
# -----------------------------------------------------------------------------
run "empty_portfolios" {
  command = plan

  variables {
    portfolios = []
  }

  assert {
    condition     = length(aws_servicecatalog_portfolio.this) == 0
    error_message = "No portfolios must be created when list is empty."
  }

  assert {
    condition     = length(aws_servicecatalog_product.this) == 0
    error_message = "No products must be created when list is empty."
  }

  assert {
    condition     = length(aws_servicecatalog_product_portfolio_association.this) == 0
    error_message = "No product-portfolio associations must be created when list is empty."
  }

  assert {
    condition     = length(aws_servicecatalog_constraint.launch) == 0
    error_message = "No launch constraints must be created when list is empty."
  }

  assert {
    condition     = length(aws_servicecatalog_portfolio_share.this) == 0
    error_message = "No shares must be created when list is empty."
  }

  assert {
    condition     = length(aws_servicecatalog_principal_portfolio_association.this) == 0
    error_message = "No principal associations must be created when list is empty."
  }

  assert {
    condition     = length(output.portfolio_ids) == 0
    error_message = "portfolio_ids output must be empty."
  }

  assert {
    condition     = length(output.product_ids) == 0
    error_message = "product_ids output must be empty."
  }
}

# -----------------------------------------------------------------------------
# Scenario 2: Default configuration — no inputs, portfolios defaults to []
# -----------------------------------------------------------------------------
run "default_configuration" {
  command = plan

  assert {
    condition     = length(aws_servicecatalog_portfolio.this) == 0
    error_message = "Module defaults must not create any portfolio."
  }

  assert {
    condition     = length(aws_servicecatalog_product.this) == 0
    error_message = "Module defaults must not create any product."
  }

  assert {
    condition     = length(output.portfolio_ids) == 0
    error_message = "Module defaults must yield an empty portfolio_ids map."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3: Custom configuration — portfolio with products and constraint
# -----------------------------------------------------------------------------
run "single_portfolio_with_products" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        description   = "Engineering portfolio"
        provider_name = "Platform Team"
        products = [
          {
            name                   = "VPC-Template"
            owner                  = "Platform Team"
            template_url           = "https://s3.amazonaws.com/templates/vpc.yaml"
            launch_constraint_role = "arn:aws:iam::123456789012:role/LaunchRole"
          },
          {
            name         = "EC2-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/ec2.yaml"
          },
        ]
      },
    ]
  }

  # Portfolio
  assert {
    condition     = length(aws_servicecatalog_portfolio.this) == 1
    error_message = "One portfolio must be created."
  }

  assert {
    condition     = aws_servicecatalog_portfolio.this["Engineering"].name == "Engineering"
    error_message = "Portfolio name must match."
  }

  assert {
    condition     = aws_servicecatalog_portfolio.this["Engineering"].description == "Engineering portfolio"
    error_message = "Portfolio description must match."
  }

  assert {
    condition     = aws_servicecatalog_portfolio.this["Engineering"].provider_name == "Platform Team"
    error_message = "Portfolio provider_name must match."
  }

  # Products
  assert {
    condition     = length(aws_servicecatalog_product.this) == 2
    error_message = "Two products must be created."
  }

  assert {
    condition     = aws_servicecatalog_product.this["Engineering/VPC-Template"].name == "VPC-Template"
    error_message = "Products must be keyed as <portfolio>/<product>."
  }

  assert {
    condition     = aws_servicecatalog_product.this["Engineering/VPC-Template"].type == "CLOUD_FORMATION_TEMPLATE"
    error_message = "Products must be created as CloudFormation template products."
  }

  assert {
    condition     = one(aws_servicecatalog_product.this["Engineering/VPC-Template"].provisioning_artifact_parameters).template_url == "https://s3.amazonaws.com/templates/vpc.yaml"
    error_message = "The provisioning artifact must reference the product template URL."
  }

  # --- Template source on every artifact --------------------------------------
  # template_url is mandatory and always present on the provisioning
  # artifact, so no product ends up without a template source.
  assert {
    condition = alltrue([
      for product in values(aws_servicecatalog_product.this) :
      one(product.provisioning_artifact_parameters).template_url != null &&
      one(product.provisioning_artifact_parameters).template_url != ""
    ])
    error_message = "Every provisioning artifact must carry a template source."
  }

  assert {
    condition     = one(aws_servicecatalog_product.this["Engineering/EC2-Template"].provisioning_artifact_parameters).template_url == "https://s3.amazonaws.com/templates/ec2.yaml"
    error_message = "Each product must reach its own template URL."
  }
  # --- end template source -----------------------------------------------------

  # Product-portfolio associations
  assert {
    condition     = length(aws_servicecatalog_product_portfolio_association.this) == 2
    error_message = "Two product-portfolio associations must be created."
  }

  # Launch constraint (only VPC-Template has one)
  assert {
    condition     = length(aws_servicecatalog_constraint.launch) == 1
    error_message = "One launch constraint must be created for the product with a constraint role."
  }

  assert {
    condition     = aws_servicecatalog_constraint.launch["Engineering/VPC-Template"].type == "LAUNCH"
    error_message = "The constraint must be of type LAUNCH."
  }

  assert {
    condition     = strcontains(aws_servicecatalog_constraint.launch["Engineering/VPC-Template"].parameters, "arn:aws:iam::123456789012:role/LaunchRole")
    error_message = "The launch constraint parameters must carry the constraint role ARN."
  }
}

# -----------------------------------------------------------------------------
# Scenario 3b: Sharing and principal associations, share type derivation
# -----------------------------------------------------------------------------
run "portfolio_sharing_and_principals" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Shared"
        provider_name = "Central IT"
        share_targets = [
          "o-abcde12345",
          "111111111111",
          # The three legal forms: the OU form is the ou-… ID, not an ARN.
          "ou-abc1-11111111",
        ]
        principal_associations = [
          {
            principal_arn  = "arn:aws:iam::123456789012:role/DevRole"
            principal_type = "IAM"
          },
          {
            principal_arn = "arn:aws:iam::123456789012:role/OpsRole"
          },
        ]
      },
    ]
  }

  # Portfolio shares
  assert {
    condition     = length(aws_servicecatalog_portfolio_share.this) == 3
    error_message = "One portfolio share per share target must be created."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Shared/o-abcde12345"].type == "ORGANIZATION"
    error_message = "An organization id target must be shared with type ORGANIZATION."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Shared/111111111111"].type == "ACCOUNT"
    error_message = "A 12-digit account id target must be shared with type ACCOUNT."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Shared/ou-abc1-11111111"].type == "ORGANIZATIONAL_UNIT"
    error_message = "An ou-… ID target must be shared with type ORGANIZATIONAL_UNIT."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Shared/o-abcde12345"].share_principals == true
    error_message = "Portfolio shares must propagate principals."
  }

  # Principal associations
  assert {
    condition     = length(aws_servicecatalog_principal_portfolio_association.this) == 2
    error_message = "Two principal associations must be created."
  }

  assert {
    condition     = aws_servicecatalog_principal_portfolio_association.this["Shared/arn:aws:iam::123456789012:role/OpsRole"].principal_type == "IAM"
    error_message = "principal_type must default to IAM."
  }
}

# -----------------------------------------------------------------------------
# Scenario 4: Validation failures
# -----------------------------------------------------------------------------
run "empty_provider_name_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = ""
      },
    ]
  }

  expect_failures = [var.portfolios]
}

run "empty_product_owner_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = ""
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

# A product without a usable template source is rejected at plan time
# instead of failing when Service Catalog refuses the artifact.
run "empty_product_template_url_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = ""
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

run "malformed_product_template_url_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "templates/vpc.yaml"
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

run "invalid_principal_type_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        principal_associations = [
          {
            principal_arn  = "arn:aws:iam::123456789012:role/DevRole"
            principal_type = "SSO"
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

# -----------------------------------------------------------------------------
# Scenario 5: Product metadata, constraints, TagOptions, versions and share
# flags
# -----------------------------------------------------------------------------

# A portfolio that sets none of the optional fields gets the defaults:
# default artifact v1, no extra constraints, no TagOptions, share
# with principal propagation and without TagOption sharing.
run "product_extensions_default_keeps_the_plan" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        share_targets = ["111111111111"]
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
          },
        ]
      },
    ]
  }

  assert {
    condition     = one(aws_servicecatalog_product.this["Engineering/VPC-Template"].provisioning_artifact_parameters).name == "v1"
    error_message = "Without versions the default artifact must keep the name v1."
  }

  assert {
    condition     = length(aws_servicecatalog_provisioning_artifact.additional) == 0
    error_message = "Without versions no additional artifact may be planned."
  }

  assert {
    condition     = length(aws_servicecatalog_constraint.notification) == 0
    error_message = "Without constraints.notifications no notification constraint may be planned."
  }

  assert {
    condition     = length(aws_servicecatalog_constraint.resource_update) == 0
    error_message = "Without a tag_update decision no RESOURCE_UPDATE constraint may be planned."
  }

  assert {
    condition     = length(aws_servicecatalog_tag_option.this) == 0
    error_message = "Without tag_options no TagOption may be planned."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Engineering/111111111111"].share_principals == true
    error_message = "The share must keep propagating principal associations by default."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Engineering/111111111111"].share_tag_options == false
    error_message = "The share must not carry TagOptions by default."
  }
}

run "product_metadata_versions_and_constraints_reach_the_plan" {
  command = plan

  variables {
    portfolios = [
      {
        name              = "Engineering"
        provider_name     = "Platform Team"
        share_targets     = ["111111111111"]
        share_tag_options = true
        # Propagation off: only directly associated principals see the share.
        propagate_principal_associations = false
        tag_options = [
          { key = "Team", values = ["platform", "network"] },
        ]
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
            description  = "Baseline VPC"
            distributor  = "Platform Engineering"
            support = {
              description = "Office hours 9-17 CET"
              email       = "platform@example.com"
              url         = "https://support.example.com/vpc"
            }
            constraints = {
              notifications = ["arn:aws:sns:eu-central-1:123456789012:provisioning-events"]
              tag_update    = true
            }
            tag_options = [
              { key = "Team", values = ["platform"] },
              { key = "CostCenter", values = ["cc-100"] },
            ]
            versions = [
              { name = "1.0.0", description = "Initial release" },
              { name = "1.1.0", description = "Adds IPv6", template_url = "https://s3.amazonaws.com/templates/vpc-v2.yaml" },
            ]
          },
        ]
      },
    ]
  }

  # --- Product metadata ---
  assert {
    condition     = aws_servicecatalog_product.this["Engineering/VPC-Template"].description == "Baseline VPC"
    error_message = "The product description must reach the product."
  }

  assert {
    condition     = aws_servicecatalog_product.this["Engineering/VPC-Template"].distributor == "Platform Engineering"
    error_message = "The distributor must reach the product."
  }

  assert {
    condition     = aws_servicecatalog_product.this["Engineering/VPC-Template"].support_email == "platform@example.com"
    error_message = "The support email must reach the product."
  }

  assert {
    condition     = aws_servicecatalog_product.this["Engineering/VPC-Template"].support_url == "https://support.example.com/vpc"
    error_message = "The support URL must reach the product."
  }

  # --- Versions: the first replaces the default artifact, the second is an
  # additional artifact falling back to nothing (it has its own URL) ---
  assert {
    condition     = one(aws_servicecatalog_product.this["Engineering/VPC-Template"].provisioning_artifact_parameters).name == "1.0.0"
    error_message = "The first version must replace the default artifact name."
  }

  assert {
    condition     = one(aws_servicecatalog_product.this["Engineering/VPC-Template"].provisioning_artifact_parameters).template_url == "https://s3.amazonaws.com/templates/vpc.yaml"
    error_message = "A first version without template_url must use the product's."
  }

  assert {
    condition     = length(aws_servicecatalog_provisioning_artifact.additional) == 1
    error_message = "The second version must become exactly one additional artifact."
  }

  assert {
    condition     = aws_servicecatalog_provisioning_artifact.additional["Engineering/VPC-Template/1.1.0"].template_url == "https://s3.amazonaws.com/templates/vpc-v2.yaml"
    error_message = "A version with its own template_url must carry it."
  }

  # --- Constraints ---
  assert {
    condition     = aws_servicecatalog_constraint.notification["Engineering/VPC-Template"].type == "NOTIFICATION"
    error_message = "The notification constraint must be planned as NOTIFICATION."
  }

  assert {
    condition     = strcontains(aws_servicecatalog_constraint.notification["Engineering/VPC-Template"].parameters, "arn:aws:sns:eu-central-1:123456789012:provisioning-events")
    error_message = "The notification constraint must carry the SNS topic ARN."
  }

  assert {
    condition     = aws_servicecatalog_constraint.resource_update["Engineering/VPC-Template"].type == "RESOURCE_UPDATE"
    error_message = "The tag-update decision must be planned as RESOURCE_UPDATE."
  }

  assert {
    condition     = strcontains(aws_servicecatalog_constraint.resource_update["Engineering/VPC-Template"].parameters, "\"TagUpdateOnProvisionedProduct\":\"ALLOWED\"")
    error_message = "tag_update = true must render TagUpdateOnProvisionedProduct ALLOWED."
  }

  # --- TagOptions: (Team, platform) is declared at the portfolio AND the
  # product — deduplicated to one resource, associated at both levels ---
  assert {
    condition     = length(aws_servicecatalog_tag_option.this) == 3
    error_message = "Exactly three distinct TagOption pairs must be planned — (Team, platform) is declared twice and deduplicated."
  }

  assert {
    condition     = length(aws_servicecatalog_tag_option_resource_association.portfolio) == 2
    error_message = "The portfolio must be associated with its two declared pairs."
  }

  assert {
    condition     = length(aws_servicecatalog_tag_option_resource_association.product) == 2
    error_message = "The product must be associated with its two declared pairs."
  }

  # --- Share flags ---
  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Engineering/111111111111"].share_principals == false
    error_message = "propagate_principal_associations = false must reach the share."
  }

  assert {
    condition     = aws_servicecatalog_portfolio_share.this["Engineering/111111111111"].share_tag_options == true
    error_message = "share_tag_options = true must reach the share."
  }
}

run "invalid_notification_arn_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
            constraints = {
              notifications = ["provisioning-events"]
            }
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

run "invalid_support_email_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
            support = {
              email = "not-an-email"
            }
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

run "duplicate_version_names_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
            versions = [
              { name = "1.0.0" },
              { name = "1.0.0" },
            ]
          },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

run "tag_option_without_values_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        tag_options = [
          { key = "Team", values = [] },
        ]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

# -----------------------------------------------------------------------------
# A share target must be a 12-digit account ID, an o-… organization ID or an
# ou-… organizational unit ID — the form decides the portfolio share type.
# Anything else (an account name, for example) is refused at plan time rather
# than by AWS at apply time.
# -----------------------------------------------------------------------------
run "invalid_share_target_rejected" {
  command = plan

  variables {
    portfolios = [
      {
        name          = "Shared"
        provider_name = "Central IT"
        # An account NAME, not an account ID.
        share_targets = ["workload-prod"]
      },
    ]
  }

  expect_failures = [var.portfolios]
}

# -----------------------------------------------------------------------------
# Scenario: aws-eusc skips Service Catalog with a warning
# -----------------------------------------------------------------------------
# The availability table in docs/multi-partition.md documents Service Catalog
# as not available in aws-eusc (AWS Services by Region, eusc-de-east-1). The
# module follows the Macie pattern of modules/security: all resources are
# derived from the partition-gated list and a check block reports the skip.
run "eusc_skips_service_catalog_with_warning" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }

  variables {
    portfolios = [
      {
        name          = "Engineering"
        provider_name = "Platform Team"
        products = [
          {
            name         = "VPC-Template"
            owner        = "Platform Team"
            template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
          },
        ]
      },
    ]
  }

  expect_failures = [
    check.service_catalog_partition_availability,
  ]

  assert {
    condition     = length(aws_servicecatalog_portfolio.this) == 0 && length(aws_servicecatalog_product.this) == 0
    error_message = "No Service Catalog resources must be created in the aws-eusc partition."
  }

  assert {
    condition     = length(output.portfolio_ids) == 0
    error_message = "portfolio_ids must stay empty in the aws-eusc partition."
  }
}

# -----------------------------------------------------------------------------
# Scenario: aws-eusc without portfolios — no warning
# -----------------------------------------------------------------------------
# Counterpart to the scenario above: the availability check must only fire
# when portfolios were actually configured. This run declares no
# expect_failures, so a check that fired here would fail the test.
run "eusc_without_portfolios_no_warning" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws-eusc"
      dns_suffix = "amazonaws.eu"
    }
  }

  variables {
    portfolios = []
  }

  assert {
    condition     = length(aws_servicecatalog_portfolio.this) == 0
    error_message = "No portfolios must be created in the aws-eusc partition."
  }
}
