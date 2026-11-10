variable "portfolios" {
  description = "Service Catalog portfolios with nested products, share targets, and principal associations. Products carry optional metadata (description, distributor, support contact), notification and tag-update constraints, TagOptions and named versions; portfolios carry optional TagOptions, their share flag (share_tag_options) and the propagation flag for principal-name associations. Every one of these fields is optional."
  type = list(object({
    name          = string
    description   = optional(string, "")
    provider_name = string
    # share_principals of the portfolio share: propagates principal-NAME
    # associations (principal_type IAM_PATTERN) into the receiving accounts.
    # Default true.
    propagate_principal_associations = optional(bool, true)
    # Whether portfolio shares also carry the portfolio's TagOptions.
    share_tag_options = optional(bool, false)
    tag_options = optional(list(object({
      key    = string
      values = list(string)
    })), [])
    # template_url is the only template source Service Catalog accepts through
    # the provisioning artifact — the provider has no inline template argument.
    products = optional(list(object({
      name         = string
      owner        = string
      template_url = string
      description  = optional(string, null)
      distributor  = optional(string, null)
      support = optional(object({
        description = optional(string, null)
        email       = optional(string, null)
        url         = optional(string, null)
      }), {})
      launch_constraint_role = optional(string, null)
      constraints = optional(object({
        # SNS topic ARNs notified on provisioning events (NOTIFICATION
        # constraint). The ARN prefix is checked without a fixed partition.
        notifications = optional(list(string), [])
        # true/false creates a RESOURCE_UPDATE constraint that allows or
        # forbids tag updates on provisioned products; null (the default)
        # creates none.
        tag_update = optional(bool, null)
      }), {})
      tag_options = optional(list(object({
        key    = string
        values = list(string)
      })), [])
      # Named provisioning-artifact versions. The first entry replaces the
      # default artifact (name v1); further entries become additional
      # artifacts. A version without template_url uses the product's.
      versions = optional(list(object({
        name         = string
        description  = optional(string, null)
        template_url = optional(string, "")
      })), [])
    })), [])
    # share_targets: portfolio share targets, each becoming an
    # aws_servicecatalog_portfolio_share (no RAM resource is involved).
    # Three forms are accepted,
    # and the form decides the share type: a 12-digit account ID (ACCOUNT),
    # an o-… organization ID (ORGANIZATION), or an ou-… organizational unit
    # ID (ORGANIZATIONAL_UNIT). Unlike deployment_targets (cross-account
    # deployment scope for Terragrunt per-account stacks), share_targets
    # controls who receives the portfolio share.
    share_targets = optional(list(string), [])
    principal_associations = optional(list(object({
      principal_arn  = string
      principal_type = optional(string, "IAM")
    })), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for p in var.portfolios :
      length(trimspace(p.name)) > 0 && length(trimspace(p.provider_name)) > 0
    ])
    error_message = "Each portfolio must have a non-empty name and a non-empty provider_name."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products :
        length(trimspace(product.name)) > 0 && length(trimspace(product.owner)) > 0
      ]
    ]))
    error_message = "Each product must have a non-empty name and a non-empty owner."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products :
        can(regex("^(https://|s3://)", trimspace(product.template_url)))
      ]
    ]))
    error_message = "Each product must have a template_url pointing at the CloudFormation template (https:// or s3:// URL). It is the only template source a provisioning artifact accepts; a product without it is rejected by Service Catalog."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for assoc in p.principal_associations :
        contains(["IAM", "IAM_PATTERN"], assoc.principal_type)
      ]
    ]))
    error_message = "Each principal_associations entry must use principal_type IAM or IAM_PATTERN."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products : [
          for arn in product.constraints.notifications :
          can(regex("^arn:", arn))
        ]
      ]
    ]))
    error_message = "Each constraints.notifications entry must be an SNS topic ARN (arn:...). The partition is not pinned — commercial and sovereign partitions both pass."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products :
        product.support.email == null || can(regex("^[^@]+@[^@]+\\.[^@]+$", product.support.email))
      ]
    ]))
    error_message = "Each support.email must be a valid email address (e.g., team@example.com)."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products :
        product.support.url == null || can(regex("^https?://", product.support.url))
      ]
    ]))
    error_message = "Each support.url must be an http:// or https:// URL."
  }

  # TagOption limits of the Service Catalog API: key 1-128 characters, each
  # value 1-256 characters, and a key needs at least one value — an entry
  # without values would silently create nothing.
  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for to in concat(p.tag_options, flatten([for product in p.products : product.tag_options])) :
        length(to.key) >= 1 && length(to.key) <= 128 && length(to.values) >= 1 && alltrue([
          for v in to.values : length(v) >= 1 && length(v) <= 256
        ])
      ]
    ]))
    error_message = "Each tag_options entry needs a key of 1-128 characters and at least one value of 1-256 characters — the Service Catalog TagOption limits."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products : [
          for version in product.versions :
          length(trimspace(version.name)) > 0
        ]
      ]
    ]))
    error_message = "Each versions entry must have a non-empty name — the name identifies the provisioning artifact."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products :
        length(distinct([for version in product.versions : version.name])) == length(product.versions)
      ]
    ]))
    error_message = "Version names must be unique per product — two artifacts of one product cannot share a name."
  }

  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for product in p.products : [
          for version in product.versions :
          version.template_url == "" || can(regex("^(https://|s3://)", trimspace(version.template_url)))
        ]
      ]
    ]))
    error_message = "Each versions template_url must be empty (the product's template_url is used) or an https:// or s3:// URL."
  }

  # Exactly three target forms are legal, and the form decides the share
  # type. Anything else — an account NAME, for example — would be classified
  # as an organizational unit and rejected only by AWS at apply time.
  validation {
    condition = alltrue(flatten([
      for p in var.portfolios : [
        for target in p.share_targets :
        can(regex("^[0-9]{12}$", target)) || can(regex("^o-[a-z0-9]{10,32}$", target)) || can(regex("^ou-[a-z0-9]+-[a-z0-9]+$", target))
      ]
    ]))
    error_message = "Each share_targets entry must be a 12-digit account ID, an organization ID (o-…) or an organizational unit ID (ou-…) — the form decides the portfolio share type."
  }
}
