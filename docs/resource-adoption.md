# Resource Adoption

Take existing resources — above all central log buckets and existing
accounts — under the management of this configuration, as an explicit,
one-time migration step. The resource itself is not replaced: an adopted
bucket keeps its name and the objects it holds at the import, an adopted
account keeps its identity. An adopted bucket does NOT keep its lifecycle
rules: the module's lifecycle configuration replaces them at the first apply,
and from then on the module's retention decides which objects stay (see
[Adopting a Bucket](#adopting-a-bucket)).

## How It Works

Adoption is driven by a versioned adoption list and rendered into
declarative `import` blocks; no CLI import commands are needed:

1. **Adoption list** — `configurations/base/resource-adoptions.json` names,
   per entry, a stack (path below `stacks/`) and the addresses it takes
   over. The versioned default is the empty list `[]`: no entry, no import
   block, and the plan of an existing deployment stays unchanged.
2. **Rendering** — `configurations/loader.hcl` renders exactly one `import`
   block per address entry (local `adoption_imports_by_stack`). An entry of
   art `s3-bucket` additionally gets a `check` block that warns at plan time
   when the named bucket is not findable in the target account.
3. **Emission** — each wired stack emits the rendered text of its own stack
   key through a `generate "imports"` block into `adoption-imports.tf`.

```json
[
  {
    "stack": "management/logging",
    "adressen": [
      {
        "to": "aws_s3_bucket.central_logs",
        "id": "existing-central-logs-bucket",
        "art": "s3-bucket"
      }
    ]
  }
]
```

Entry fields: `to` is the resource address inside the stack's root module,
`id` is the import ID of the resource type, `art` selects companion
behaviour (`s3-bucket` adds the findability check; any other value adds
none).

Version floor: declarative `import` blocks require Terraform 1.5, their
`for_each` form 1.7. Every module of this project pins
`required_version >= 1.14`, so both forms are available.

## Adopting a Bucket

An adopted bucket keeps its name. Set the matching `adopted_*` key in
`env/common.hcl` so the module derives its resources from the existing name
instead of the conventional one, then add the adoption entry:

```hcl
# env/common.hcl
adopted_central_log_bucket_name = "existing-central-logs-bucket"
```

After the import, the module's declared companion resources — encryption
configuration, versioning, public access block, bucket policy and lifecycle
configuration — capture the adopted bucket. Any deviation from the declared
posture shows up in the plan and is corrected by the apply.

The lifecycle configuration is not imported; the module creates it. S3 keeps
one lifecycle configuration per bucket, so that first apply replaces every
rule the adopted bucket had. An object older than the module's expiration
(`log_retention_days`, or the per-prefix `s3_lifecycle_rules` the stack passes)
is deleted at the next lifecycle run, and every rule the bucket had for other
prefixes is gone. To keep the existing rules, write them into the bucket's
full rule set before the apply — `central_log_bucket_lifecycle_rules` for the
central log bucket, `access_logs_bucket_lifecycle_rules`,
`elb_log_bucket_lifecycle_rules` and `vpc_flow_logs_bucket_lifecycle_rules`
for the other three — and read the plan of
`aws_s3_bucket_lifecycle_configuration.*` before applying. Custom policy documents can be supplied
through the `*_bucket_policies` inputs (with `allow_bucket_policy_overrides`
for full replacements) when the existing policy must be preserved verbatim.

## Adoptable Resources

| Resource | Stack | Address (`to`) | Import ID (`id`) |
|---|---|---|---|
| Central log bucket | `management/logging` | `aws_s3_bucket.central_logs` | bucket name |
| Separate access logs bucket | `management/logging` | `aws_s3_bucket.access_logs[0]` | bucket name |
| ELB log bucket | `management/logging` | `aws_s3_bucket.elb_logs[0]` | bucket name |
| VPC flow logs bucket | `management/logging` | `aws_s3_bucket.vpc_flow_logs[0]` | bucket name |
| CloudWatch data protection policy | `management/logging` | `aws_cloudwatch_log_data_protection_policy.additional["<log-group>"]` | log group name |
| CloudWatch subscription filter | `management/logging` | `aws_cloudwatch_log_subscription_filter.this["<name>"]` | `<log-group-name>|<filter-name>` |
| Config recorder (management account) | `management/logging` | `aws_config_configuration_recorder.this` | recorder name |
| Config delivery channel (management account) | `management/logging` | `aws_config_delivery_channel.this` | channel name |
| Config recorder (audit account) | `audit/config-recorder` | `aws_config_configuration_recorder.this` | recorder name |
| Config recorder (log archive account) | `log-archive/config-recorder` | `aws_config_configuration_recorder.this` | recorder name |
| Config recorder (member account) | `management/config-recorder-members` | `aws_config_configuration_recorder.acct_<account_id>` | recorder name |
| GuardDuty findings export | `management/security` | `aws_guardduty_publishing_destination.this[0]` | `<detector-id>:<destination-id>` |
| Macie activation | `management/security` | `aws_macie2_account.this[0]` | account ID |
| Existing account | `management/accounts` | `aws_organizations_account.this["<email>"]` | 12-digit account ID |

The corresponding `adopted_*` name keys exist for the four log buckets;
other resources have fixed names or identity-bound IDs and need no name key.

## Adopting an Existing Account

The AWS Organizations membership handshake has no provider resource, so
joining an existing account to the organization is a one-time manual step:

1. **Invite by hand (once):** send the invitation from the management
   account (console or `aws organizations invite-account-to-organization`)
   and accept it in the target account. This step is not automated — no
   Lambda path exists for the handshake, by design.
2. **Declare the account:** add the account to `accounts` in
   `env/common.hcl` (name, email, OU) and record its ID in
   `env/accounts.hcl` (`workload_accounts`).
3. **Adopt it:** add an adoption entry on
   `aws_organizations_account.this["<email>"]` with the account ID — the
   module's `for_each` keys accounts by their e-mail address, so the address
   carries the e-mail, not the account name — then run
   the plan of `management/accounts`. The plan shows the adoption instead of
   an account creation.

## Procedure and Error Handling

1. Add the entry (and, for buckets, the `adopted_*` key), run
   `terragrunt plan` in the affected stack, and read the plan: it shows the
   import plus whatever posture changes the declared configuration applies.
2. Apply. Afterwards, remove nothing: the entry may stay — an already
   imported address renders a no-op on later runs — or be removed once the
   state carries the resource.

There are no silent fallbacks:

- An import whose ID does not resolve fails the plan with the Terraform
  error message.
- A bucket entry whose bucket is not findable raises a `check` warning at
  plan time (`adoption_*_bucket_findable`).
- An empty adoption list renders no blocks; the generated
  `adoption-imports.tf` then carries only a comment.

## Further reading

- [Getting Started](getting-started.md) — Step-by-step setup and first deployment
- [Operations](operations.md) — Day-2 operations, adding accounts
- [Configuration Reference](configuration-reference.md) — Full variable reference
- [OU Deployment](ou-deployment.md) — Deploy resources across an OU
