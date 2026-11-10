# Backup Module

Creates AWS Backup Vaults in the Management Account with optional cross-account access policies and auto-created KMS encryption keys.

`deployment_targets` names the accounts that may write into a vault. Each entry is either a 12-digit account ID or an account name that exists as a key in `account_ids`; the module resolves names through that map and rejects anything else before the plan is applied, so no unresolved name can end up inside a principal ARN.

`policy` attaches a full access policy document to a vault instead: a JSON string, typically read from a file next to the other policy documents under `configurations/policies/`. The plan checks that the string decodes and carries the `Version` and `Statement` fields, and refuses a vault that sets both `policy` and `deployment_targets` — both describe the one access policy of the vault. Without either attribute no policy resource is created.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `backup_vaults` | List of AWS Backup Vault definitions | `list(object)` | `[]` | no |
| `account_ids` | Map of account names to account IDs, used for resolving deployment_targets | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `backup_vault_names` | List of created backup vault names |
| `backup_vault_arns` | Map of backup vault names to their ARNs |

## Resources

The module creates the resource types below, all of them in `main.tf`. Which of them a run actually creates depends on the inputs — the `enable_*` toggles and the collections that are filled.

- `aws_kms_key`
- `aws_kms_alias`
- `aws_backup_vault`
- `aws_backup_vault_policy`

## Usage Example

```hcl
module "backup" {
  source = "./modules/backup"

  backup_vaults = [
    {
      name               = "central-vault"
      deployment_targets = ["audit", "log-archive"]
    },
    {
      name        = "encrypted-vault"
      kms_key_arn = "arn:aws:kms:eu-central-1:123456789012:key/example-key-id"
    },
    {
      # Full access policy from a document instead of deployment_targets.
      name   = "locked-vault"
      policy = file("${path.root}/policies/backup-vault-deny-delete.json")
    },
  ]

  # Keys of this map are the account names usable in deployment_targets.
  account_ids = module.accounts.account_ids
}
```

## Further Documentation

- [Configuration Reference](../../docs/configuration-reference.md) — Full variable reference
- [Architecture](../../docs/architecture.md) — Module design and dependencies
