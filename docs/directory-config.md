# Directory Config

Declarative first-fill of an AWS Managed Microsoft AD from the landing zone
configuration: one configuration instance joins the managed directory and
runs the setup (users, groups, password policy) through SSM documents whose
PowerShell content is a configuration string. No script file lives in the
repository, no `local-exec` provisioner runs on the operator's machine, and
no external data source is read — everything the stack creates is a
declared AWS resource.

## How It Works

1. **Directory** — `modules/iam` creates the Managed Microsoft AD
   (`managed_active_directories`) and exposes its ID, fully qualified
   domain name and DNS addresses as outputs (`managed_ad_ids`,
   `managed_ad_domain_names`, `managed_ad_dns_addresses`).
2. **Configuration instance** — `stacks/management/directory-config` builds
   one instance from `modules/ec2-compute` (`directory_config_instances`
   with its launch template; the Windows AMI is a per-entry input). A
   launch template whose `http_tokens` is `"optional"` is acknowledged by
   name on `directory_config_imdsv1_acknowledged_launch_templates`; see
   [EC2 Compute](ec2-compute.md#instance-metadata).
3. **Domain join** — the stack derives an `aws_ssm_association` with the
   AWS-managed document `AWS-JoinDirectoryServiceDomain`; directory ID,
   domain name and DNS addresses come from the iam stack outputs, keyed by
   `directory_config_directory_name`.
4. **Directory setup** — `directory_config_ssm_documents` carries the
   PowerShell steps as `aws_ssm_document` entries (content strings, JSON or
   YAML), `directory_config_ssm_associations` targets them at the instance
   by key. Switch: `enable_directory_config`, default off.

The entry schemas are documented in `env/common.hcl.example` and in the
module README (`modules/ec2-compute/README.md`).

## Operational Boundary

Terraform manages the instance, the documents and the associations — not
the objects the setup steps create inside the directory:

- The directory contents (users, groups, the password policy) are **not
  Terraform state**. A plan reflects changes to the instance, the document
  content or the association — never the current state inside the
  directory.
- Drift through manual directory changes is **not detected**. Someone who
  deletes or alters a user in the directory produces no plan diff;
  reconciling directory contents lies with operations.
- Re-running an association re-executes the document. Setup steps should
  therefore be written idempotently (create-if-missing), so a repeated run
  converges instead of failing.
- Secrets (initial passwords and the like) belong in Secrets Manager or SSM
  SecureString parameters, referenced from the PowerShell steps — not in
  the document string in the configuration.

## Further reading

- [EC2 Compute](ec2-compute.md) — The shared compute building blocks
- [Module README](../modules/ec2-compute/README.md) — Inputs, outputs and usage examples
- [Configuration Reference](configuration-reference.md) — All variables, types, defaults, validations
