# Budgets Module

Creates AWS Budgets for cost monitoring and alerting. The management account
carries the primary budget; further budgets and the distribution to member
accounts are driven by the same configuration.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `enable_budgets` | Enable AWS Budgets for cost monitoring and alerting | `bool` | `false` | no |
| `budget_config` | Primary AWS Budget with thresholds, notification targets, cost-type filters and distribution targets | `object` | `{}` | no |
| `additional_budgets` | Further AWS Budgets beside the primary one; each entry carries the same attributes as `budget_config` plus a required `name` | `list(object)` | `[]` | no |
| `deployment_account_name` | Stack directory name of the account this deployment runs in; empty means the management deployment | `string` | `""` | no |
| `default_tags` | Tags applied to all resources | `map(string)` | `{}` | no |

Every notification entry must name at least one subscriber
(`subscriber_email_addresses` or `subscriber_sns_topic_arns`) — a threshold
without a subscriber is rejected at plan time, because the Budgets API refuses
it only after the budget itself was created, leaving a tainted half-created
resource behind.

## Outputs

| Name | Description |
|------|-------------|
| `budget_id` | ID of the primary budget (empty string when budgets are disabled or when this deployment does not carry the primary budget) |
| `budget_ids` | Map of budget key (`this` for the primary budget, `additional-<name>` for further budgets) to budget ID for every budget this deployment creates |

## Resources

The module creates one resource type, in `main.tf`, and only while `enable_budgets` is set:

- `aws_budgets_budget` (one per selected budget)

## Cost-type filters

Eleven optional boolean attributes select which charges count toward a
budget. They are the flat keys of `budget_config` (and of every
`additional_budgets` entry): `include_credit`, `include_discount`,
`include_other_subscription`, `include_recurring`, `include_refund`,
`include_subscription`, `include_support`, `include_tax`, `include_upfront`,
`use_amortized`, `use_blended`.

Unset attributes keep the account defaults (include everything, unblended
view); a budget without any of them renders no cost-type block at all, so an
existing configuration keeps its plan. `use_amortized` and `use_blended` are
mutually exclusive — the API rejects the pair, and the module rejects it at
plan time.

```hcl
budget_config = {
  limit_amount   = "2000"
  include_credit = false
  include_refund = false
}
```

## Multiple budgets and distribution to member accounts

`additional_budgets` carries further budgets beside the primary one. Each
entry names its budget and may list `deployment_targets`: the stack directory
names of the accounts that should carry it (plus the literal `management`
for the management account itself).

Selection rules:

- The management deployment (empty `deployment_account_name`) always creates
  the primary budget, plus every budget without targets or listing
  `management`.
- A member-account deployment creates exactly the budgets whose
  `deployment_targets` list its directory name — including the primary
  budget when `budget_config.deployment_targets` lists it.

Distribution runs over per-account stack units: copy
`stacks/workload-dev/budgets/` (together with its `cross_account.hcl`) into
the account folder. The unit self-selects — it runs only when a budget of the
configuration lists its directory name — and passes that name as
`deployment_account_name`. An entry without a matching unit is silently
ignored; a `check` block on the management deployment reminds of the
contract whenever targets are configured.

```hcl
additional_budgets = [
  {
    name         = "workload-dev-budget"
    limit_amount = "500"
    deployment_targets = ["workload-dev"]
    notifications = [
      { threshold = 90, subscriber_email_addresses = ["finance@example.com"] },
    ]
  },
]
```

## Usage Example

```hcl
module "budgets" {
  source = "./modules/budgets"

  enable_budgets = true

  budget_config = {
    limit_amount   = "5000"
    include_credit = false
    notifications = [
      {
        threshold                  = 80
        subscriber_email_addresses = ["finance@example.com"]
      },
      {
        threshold                 = 100
        notification_type         = "FORECASTED"
        subscriber_sns_topic_arns = ["arn:aws:sns:eu-central-1:123456789012:budget-alerts"]
      },
    ]
  }

  additional_budgets = [
    { name = "sandbox-cap", limit_amount = "250" },
  ]
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
