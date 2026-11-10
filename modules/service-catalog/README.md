# Service Catalog Module

Creates Service Catalog portfolios with nested products, launch constraints, org-wide portfolio sharing, and IAM/SSO principal associations.

Every product needs a `template_url` (`https://` or `s3://`) pointing at its CloudFormation template. A provisioning artifact accepts no inline template, so the URL is the only template source; a missing or malformed URL is rejected before the plan is applied.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `portfolios` | Service Catalog portfolios with nested products, share targets, and principal associations. Product metadata, constraints, TagOptions, versions and the share flags are described under [Product Metadata, Constraints, TagOptions and Versions](#product-metadata-constraints-tagoptions-and-versions) | `list(object)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| `portfolio_ids` | Map of portfolio name to portfolio ID |
| `product_ids` | Map of portfolio/product key to product ID |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_servicecatalog_portfolio`
- `aws_servicecatalog_product`
- `aws_servicecatalog_provisioning_artifact`
- `aws_servicecatalog_product_portfolio_association`
- `aws_servicecatalog_constraint`
- `aws_servicecatalog_tag_option`
- `aws_servicecatalog_tag_option_resource_association`
- `aws_servicecatalog_portfolio_share`
- `aws_servicecatalog_principal_portfolio_association`

## Product Metadata, Constraints, TagOptions and Versions

Each product may carry a `description`, a `distributor` and a `support` contact (`description`, `email`, `url`) — shown to consumers in the Service Catalog console. Two constraint kinds join the launch constraint:

- `constraints.notifications` — a list of SNS topic ARNs that receive provisioning events (a NOTIFICATION constraint per product). The ARN prefix is checked without pinning a partition.
- `constraints.tag_update` — `true` or `false` creates a RESOURCE_UPDATE constraint that allows or forbids tag updates on provisioned products; unset (the default) creates none.

`tag_options` (at the portfolio and at the product) declare TagOption keys with their allowed values. One `(key, value)` pair becomes one TagOption resource — pairs are deduplicated across all declarations, because TagOptions are account-global and the API rejects duplicates — and is associated with every portfolio and product that declares it.

`versions` names the provisioning-artifact versions of a product. The first entry replaces the default artifact (named `v1` when `versions` is empty); further entries become additional artifacts. A version without `template_url` uses the product's. Version names must be unique per product.

Per portfolio, `share_tag_options` carries the portfolio's TagOptions into its shares, and `propagate_principal_associations` controls whether principal-NAME associations (`principal_type = "IAM_PATTERN"`) propagate into the receiving accounts — the default is `true`.

```hcl
portfolios = [
  {
    name              = "Engineering"
    provider_name     = "Platform Team"
    share_targets     = ["o-abcde12345"]
    share_tag_options = true
    tag_options       = [{ key = "Team", values = ["platform"] }]

    products = [
      {
        name         = "VPC-Template"
        owner        = "Platform Team"
        template_url = "https://s3.amazonaws.com/templates/vpc.yaml"
        description  = "Baseline VPC"
        distributor  = "Platform Engineering"
        support      = { email = "platform@example.com", url = "https://support.example.com" }
        constraints = {
          notifications = ["arn:aws:sns:eu-central-1:123456789012:provisioning-events"]
          tag_update    = true
        }
        versions = [
          { name = "1.0.0", description = "Initial release" },
          { name = "1.1.0", template_url = "https://s3.amazonaws.com/templates/vpc-v2.yaml" },
        ]
      },
    ]
  },
]
```

## Usage Example

```hcl
module "service_catalog" {
  source = "./modules/service-catalog"

  portfolios = [
    {
      name          = "LandingZonePortfolio"
      description   = "Landing Zone self-service products"
      provider_name = "CloudOps"
      products = [
        {
          name         = "VPCProduct"
          owner        = "NetworkTeam"
          template_url = "https://s3.amazonaws.com/bucket/vpc.yaml"
        }
      ]
      share_targets = ["o-abc123"]
    }
  ]
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
