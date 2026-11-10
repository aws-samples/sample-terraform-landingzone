# Deployment Role Module

Creates the TLZDeploymentRole IAM role in the Management Account, allowing the Deployment Account to assume it for Landing Zone Terraform operations.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `deployment_account_id` | Account ID of the Deployment Account that can assume this role | `string` | — | yes |
| `role_name` | Name of the IAM role to create in the Management Account | `string` | `"TLZDeploymentRole"` | no |
| `permissions_boundary_arn` | Optional ARN of a permissions boundary to attach to the role | `string` | `""` | no |
| `narrow_grants` | Select the narrow inline policy document: the guardduty, securityhub, macie2, access-analyzer, sso, sso-directory and identitystore `service:*` grants are replaced by the actions the modules' resource types call. `false` keeps the default document byte-identical | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| `role_arn` | ARN of the TLZ Deployment Role |
| `role_name` | Name of the TLZ Deployment Role |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_iam_role`
- `time_sleep`
- `aws_iam_role_policy`

## Inline policy documents

The inline policy is read from one of two files in `configurations/policies/deployment/`, selected by `narrow_grants`:

| `narrow_grants` | Document | Security-service and Identity Center grants |
|-----------------|----------|---------------------------------------------|
| `false` (default) | `role-inline-policy.json` | `guardduty:*`, `securityhub:*`, `macie2:*`, `access-analyzer:*`, `sso:*`, `sso-directory:*`, `identitystore:*` on `*` |
| `true` | `role-inline-policy-narrow.json` | 98 enumerated actions, one row per resource type the modules declare — see the [policies README](../../configurations/policies/deployment/README.md) |

Outside those seven grants the two documents are identical; `budgets:*`, `controltower:*` and `servicecatalog:*` are out of scope and stay in both. `tests/test_deployment_role_narrow_grants.py` pins the narrow document to the modules' resource types and to the default document (it may grant nowhere more), and `tests/deployment-role.tftest.hcl` pins the wiring: the flag reaches the rendered policy, the default renders the default document byte for byte.

How the default flips: the operator sets `deployment_role_narrow_grants = true` in `env/common.hcl` (the stack passes it through), runs one organization-wide apply with it on, and only after that apply has gone through does the module default move to `true` — the first document is kept until then so that nothing changes for a deployment that does not set the flag.

## Usage Example

```hcl
module "deployment_role" {
  source = "./modules/deployment-role"

  deployment_account_id    = "123456789012"
  role_name                = "TLZDeploymentRole"
  permissions_boundary_arn = ""
  narrow_grants            = false
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
