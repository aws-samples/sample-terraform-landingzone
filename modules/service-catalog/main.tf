# Service Catalog module — portfolios, products, constraints, sharing, principal associations
#
# Creates Service Catalog portfolios with nested products, launch constraints,
# org-wide portfolio sharing, and IAM/SSO principal associations.

# The module builds no ARN; the partition data source exists for the guard
# below. Service Catalog is not available in the aws-eusc partition (AWS
# Services by Region, eusc-de-east-1), so
# every resource is derived from local.portfolios_effective, which is empty
# there — the Macie pattern of modules/security.
data "aws_partition" "current" {}

locals {
  is_eusc = data.aws_partition.current.partition == "aws-eusc"

  # Source of every derivation in this module: empty in aws-eusc.
  portfolios_effective = local.is_eusc ? [] : var.portfolios
}

# Without this check the skip would be silent: configured portfolios would
# look like they took effect. The check warns instead of failing (same
# convention as macie_partition_availability in modules/security).
check "service_catalog_partition_availability" {
  assert {
    condition     = !(length(var.portfolios) > 0 && local.is_eusc)
    error_message = "portfolios are configured but Service Catalog is not available in the aws-eusc partition. All Service Catalog resources are skipped in this deployment. Remove the portfolios entries to suppress this warning."
  }
}

# --- Flatten nested structures for for_each ---

locals {
  # Portfolios by name, for per-portfolio flags read by the share resource
  portfolios_by_name = { for p in local.portfolios_effective : p.name => p }

  # Flatten products across all portfolios
  products = flatten([
    for portfolio in local.portfolios_effective : [
      for product in portfolio.products : {
        portfolio_name           = portfolio.name
        product_name             = product.name
        owner                    = product.owner
        template_url             = product.template_url
        description              = product.description
        distributor              = product.distributor
        support                  = product.support
        launch_constraint_role   = product.launch_constraint_role
        constraint_notifications = product.constraints.notifications
        constraint_tag_update    = product.constraints.tag_update
        tag_options              = product.tag_options
        versions                 = product.versions
      }
    ]
  ])

  products_map = {
    for p in local.products : "${p.portfolio_name}/${p.product_name}" => p
  }

  # Flatten share targets across all portfolios.
  # The portfolio share type follows the target form; var.portfolios accepts
  # exactly the three forms below, so nothing falls through to
  # the ORGANIZATIONAL_UNIT branch by accident:
  #   - 12-digit account ID → ACCOUNT
  #   - o-…  organization ID → ORGANIZATION
  #   - ou-… organizational unit ID → ORGANIZATIONAL_UNIT
  shares = flatten([
    for portfolio in local.portfolios_effective : [
      for target in portfolio.share_targets : {
        portfolio_name = portfolio.name
        target         = target
        type = (
          can(regex("^\\d{12}$", target)) ? "ACCOUNT" :
          can(regex("^o-[a-z0-9]+$", target)) ? "ORGANIZATION" :
          "ORGANIZATIONAL_UNIT"
        )
      }
    ]
  ])

  shares_map = {
    for s in local.shares : "${s.portfolio_name}/${s.target}" => s
  }

  # Flatten principal associations across all portfolios
  principals = flatten([
    for portfolio in local.portfolios_effective : [
      for assoc in portfolio.principal_associations : {
        portfolio_name = portfolio.name
        principal_arn  = assoc.principal_arn
        principal_type = assoc.principal_type
      }
    ]
  ])

  principals_map = {
    for p in local.principals : "${p.portfolio_name}/${p.principal_arn}" => p
  }

  # Products that have a launch constraint role
  constrained_products = {
    for k, v in local.products_map : k => v if v.launch_constraint_role != null
  }

  # Products with notification constraints / a tag-update decision
  notification_products = {
    for k, v in local.products_map : k => v if length(v.constraint_notifications) > 0
  }
  tag_update_products = {
    for k, v in local.products_map : k => v if v.constraint_tag_update != null
  }

  # Additional provisioning-artifact versions: everything after the first
  # entry, which replaces the default artifact on the product itself.
  additional_versions = merge([
    for key, product in local.products_map : {
      for version in(length(product.versions) > 1 ? slice(product.versions, 1, length(product.versions)) : []) :
      "${key}/${version.name}" => {
        product_key  = key
        name         = version.name
        description  = version.description
        template_url = version.template_url != "" ? version.template_url : product.template_url
      }
    }
  ]...)

  # TagOptions: one (key, value) pair is one aws_servicecatalog_tag_option.
  # TagOptions are account-global and keyed by their pair, so the pairs are
  # deduplicated across all portfolios and products and each distinct pair is
  # created exactly once; the associations below attach them per resource.
  # jsonencode([key, value]) is the map key — unlike a separator it cannot
  # collide with characters inside key or value.
  portfolio_tag_option_pairs = {
    for p in local.portfolios_effective : p.name => distinct(flatten([
      for to in p.tag_options : [for v in to.values : { key = to.key, value = v }]
    ]))
  }
  product_tag_option_pairs = {
    for k, v in local.products_map : k => distinct(flatten([
      for to in v.tag_options : [for value in to.values : { key = to.key, value = value }]
    ]))
  }

  tag_options_map = {
    for pair in distinct(concat(
      flatten(values(local.portfolio_tag_option_pairs)),
      flatten(values(local.product_tag_option_pairs)),
    )) : jsonencode([pair.key, pair.value]) => pair
  }

  portfolio_tag_option_links = merge([
    for name, pairs in local.portfolio_tag_option_pairs : {
      for pair in pairs :
      "${name}/${jsonencode([pair.key, pair.value])}" => {
        portfolio_name = name
        pair_key       = jsonencode([pair.key, pair.value])
      }
    }
  ]...)

  product_tag_option_links = merge([
    for key, pairs in local.product_tag_option_pairs : {
      for pair in pairs :
      "${key}/${jsonencode([pair.key, pair.value])}" => {
        product_key = key
        pair_key    = jsonencode([pair.key, pair.value])
      }
    }
  ]...)
}

# =============================================================================
# Portfolios
# =============================================================================

resource "aws_servicecatalog_portfolio" "this" {
  for_each = local.portfolios_by_name

  name          = each.value.name
  description   = each.value.description
  provider_name = each.value.provider_name
}

# =============================================================================
# Products
# =============================================================================

resource "aws_servicecatalog_product" "this" {
  for_each = local.products_map

  name        = each.value.product_name
  owner       = each.value.owner
  type        = "CLOUD_FORMATION_TEMPLATE"
  description = each.value.description
  distributor = each.value.distributor

  support_description = each.value.support.description
  support_email       = each.value.support.email
  support_url         = each.value.support.url

  # template_url is required by the variable validation, so the provisioning
  # artifact always has a template source. The first versions entry replaces
  # the default artifact; without versions the artifact is named v1, uses
  # the product's template_url and has no description.
  provisioning_artifact_parameters {
    name        = length(each.value.versions) > 0 ? each.value.versions[0].name : "v1"
    description = length(each.value.versions) > 0 ? each.value.versions[0].description : null
    type        = "CLOUD_FORMATION_TEMPLATE"
    template_url = (
      length(each.value.versions) > 0 && each.value.versions[0].template_url != ""
      ? each.value.versions[0].template_url
      : each.value.template_url
    )
  }
}

# Additional provisioning-artifact versions (versions[1..] of each product)
resource "aws_servicecatalog_provisioning_artifact" "additional" {
  for_each = local.additional_versions

  name         = each.value.name
  description  = each.value.description
  product_id   = aws_servicecatalog_product.this[each.value.product_key].id
  type         = "CLOUD_FORMATION_TEMPLATE"
  template_url = each.value.template_url
}

resource "aws_servicecatalog_product_portfolio_association" "this" {
  for_each = local.products_map

  portfolio_id = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  product_id   = aws_servicecatalog_product.this[each.key].id
}

# =============================================================================
# Launch Constraints (only for products with a constraint role)
# =============================================================================

resource "aws_servicecatalog_constraint" "launch" {
  for_each = local.constrained_products

  portfolio_id = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  product_id   = aws_servicecatalog_product.this[each.key].id
  type         = "LAUNCH"

  parameters = jsonencode({
    RoleArn = each.value.launch_constraint_role
  })

  depends_on = [aws_servicecatalog_product_portfolio_association.this]
}

# =============================================================================
# Notification Constraints (SNS topics on provisioning events)
# =============================================================================

resource "aws_servicecatalog_constraint" "notification" {
  for_each = local.notification_products

  portfolio_id = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  product_id   = aws_servicecatalog_product.this[each.key].id
  type         = "NOTIFICATION"

  parameters = jsonencode({
    NotificationArns = each.value.constraint_notifications
  })

  depends_on = [aws_servicecatalog_product_portfolio_association.this]
}

# =============================================================================
# Tag-Update Constraints (RESOURCE_UPDATE)
# Only products whose constraints.tag_update carries a decision get one;
# null (the default) creates none.
# =============================================================================

resource "aws_servicecatalog_constraint" "resource_update" {
  for_each = local.tag_update_products

  portfolio_id = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  product_id   = aws_servicecatalog_product.this[each.key].id
  type         = "RESOURCE_UPDATE"

  parameters = jsonencode({
    Version = "2.0"
    Properties = {
      TagUpdateOnProvisionedProduct = each.value.constraint_tag_update ? "ALLOWED" : "NOT_ALLOWED"
    }
  })

  depends_on = [aws_servicecatalog_product_portfolio_association.this]
}

# =============================================================================
# TagOptions
# One resource per distinct (key, value) pair — TagOptions are account-global
# and the API rejects duplicates — associated per portfolio and per product.
# =============================================================================

resource "aws_servicecatalog_tag_option" "this" {
  for_each = local.tag_options_map

  key   = each.value.key
  value = each.value.value
}

resource "aws_servicecatalog_tag_option_resource_association" "portfolio" {
  for_each = local.portfolio_tag_option_links

  resource_id   = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  tag_option_id = aws_servicecatalog_tag_option.this[each.value.pair_key].id
}

resource "aws_servicecatalog_tag_option_resource_association" "product" {
  for_each = local.product_tag_option_links

  resource_id   = aws_servicecatalog_product.this[each.value.product_key].id
  tag_option_id = aws_servicecatalog_tag_option.this[each.value.pair_key].id
}

# =============================================================================
# Portfolio Sharing (org-wide)
# share_principals propagates principal-name associations (IAM_PATTERN) into
# the receiving accounts — configurable per portfolio, true by default.
# share_tag_options additionally carries the
# portfolio's TagOptions into the share.
# =============================================================================

resource "aws_servicecatalog_portfolio_share" "this" {
  for_each = local.shares_map

  portfolio_id      = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  principal_id      = each.value.target
  type              = each.value.type
  share_principals  = local.portfolios_by_name[each.value.portfolio_name].propagate_principal_associations
  share_tag_options = local.portfolios_by_name[each.value.portfolio_name].share_tag_options
}

# =============================================================================
# Principal Associations
# =============================================================================

resource "aws_servicecatalog_principal_portfolio_association" "this" {
  for_each = local.principals_map

  portfolio_id   = aws_servicecatalog_portfolio.this[each.value.portfolio_name].id
  principal_arn  = each.value.principal_arn
  principal_type = each.value.principal_type
}
