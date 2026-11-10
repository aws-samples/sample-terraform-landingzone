# Changelog

This file lists what changed in the published repository, one section per version, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.29] - 2026-11-10

### Added

- A front page with a quick start, security considerations, cost notes and the module diagram, and a
  Makefile with the offline checks `init`, `fmt`, `validate`, `lint`, `scan` and `test`.
- The complete reader documentation: the guides under `docs/`, a README in every module and
  configuration folder, and the diagram images in `docs/diagrams/img/`.
- The `LICENSE` (MIT-0), `CODE_OF_CONDUCT.md` and `CONTRIBUTING.md` files.
- Module `member-roles` and stack `stacks/management/member-roles` (switch `enable_member_roles`):
  they create the roles whose `deployment_targets` name a member account, such as `Backup-Role`.
- A misspelt or unknown `source_identifier` in a framework overlay fails the offline tests.

### Changed

- SCP change detection runs in `us-east-1`, where AWS Organizations delivers its events, whatever
  region the organization stack uses; before, a stack in another region received no event.
- Account move automation runs in `us-east-1` for the same reason.
- Upgrade: outside `us-east-1` the first plan replaces both functions, and every address in
  `scp_revert_notification_emails` must confirm its subscription again before it gets alerts.
- Quarantine release is manual: `enable_quarantine_auto_detach` only sends the notification.
- The Security Hub baseline no longer suppresses Config.1, GuardDuty.1, SecurityHub.1, Macie.1,
  IAM.28 and EC2.7; IAM.28 shows failed in every member account until you disable that control.
- Config rules and conformance packs reach member accounts once the Audit account exists; the packs
  are organization conformance packs that honour exclusions and replace existing account-level packs.
- `env/common.hcl.example` sets `delete_default_vpc = false`, so the example leaves the rules of an
  account's default security group alone.
- The organization module's KMS keys keep their identity across the change to one key per region
  (`moved` blocks); the module README has an upgrade section.
- The configuration reference describes every setting, and `cur_config` names the report bucket.
- The diagrams are redrawn on the official AWS Architecture Icons.
- Modules, stacks, configurations and guides are in English throughout.

### Removed

- The quarantine auto-detach function, its settings `quarantine_auto_detach_dlq_name` and
  `quarantine_auto_detach_log_retention_days`, and its output `quarantine_auto_detach_lambda_arn`.
- The unread setting `deployment_account_email`.

### Fixed

- The organization-wide apply no longer fails in the Audit account and finds every account:
  cross-account account ID lookups read the home region, whatever region the AWS CLI uses.
- The logging stack stops without a Log-Archive account ID, and the OU deployment stacks refuse an
  empty set of active accounts, instead of applying without them.
- An adopted organization keeps policy types the landing zone does not manage: name them in
  `additional_enabled_policy_types` in `env/common.hcl`.
- The deployment account's pipeline roles can assume `TLZDeploymentRole` again.
- The data-perimeter resource control policy is no longer dropped silently: while
  `import_organization_id` or `log_archive_account_id` is unset, every plan warns and the output
  `rcp_documents_unresolved` names it.
- SCP auto-revert restores the content of the last apply, reports a change it cannot undo and skips
  `TLZDeploymentRole` and its own role; a target that leaves the allow list gets `FullAWSAccess` back.
- SNS topics fed by EventBridge receive their events: they use a customer-managed key that
  EventBridge may publish with.
- Pipeline, ecs variant: the Fargate trigger target carries a network configuration, so it applies.
- Pipeline, ecs variant: a task without a security group is refused at plan unless
  `ecs_use_default_security_group` acknowledges the VPC's default group.
- The security module's GuardDuty and Macie export rules for the central log bucket's lifecycle need
  `replace_central_log_bucket_lifecycle = true`, so the bucket has one owner.
- Log deliveries reach the encrypted buckets: the keys and the central bucket policy grant
  `delivery.logs`, the ELB log bucket uses SSE-S3, and the EBS default key grants Auto Scaling.
- `iam_users`: the password secret holds the password that signs in, and `auto_generate_password`
  with `disable_console_access` is refused.
- Networking: a cross-account `route53_zones` association is refused at plan instead of failing at
  apply.
- The cmmc overlay names `INSTANCES_IN_VPC`, the real identifier of ec2-instances-in-vpc.
- `make lint` runs tflint in every module and customization directory.
- Guides and READMEs no longer claim more than the code does about the default VPC, the central log
  bucket's account, Config rule coverage, `Backup-Role`, retention prefixes and firewall priorities.

### Security

- `base-guardrails-1` denies setting the tag `ManagedBy=TLZ` to every principal except the exempt
  landing-zone roles, because Security Hub suppression rules trust that tag.
- `ProtectIAMRoles` also protects `TLZDeploymentRole`, the four pipeline role names and
  `OrganizationAccountAccessRole`, so a member account cannot claim a guardrail exemption name.
- Pipeline: `branch_name` and `repository_name` refuse `*` and `?`, which would widen the OIDC
  trust of the external CI role.
- Networking: an ingress rule open to every port from the internet needs
  `acknowledge_world_open_all_protocols` in more forms (ports 0-65535 or 1-65535, sources /0 or /1).
- Security Hub no longer hides IAM.1 and SSM.1 findings.
- The Managed AD secret key is bound to its own account and region.

## [0.5.28] - 2026-11-09

### Fixed

- Destroy on the S3 backend keeps the state bucket and lock table until the end:
  `docs/getting-started.md` and `docs/operations.md` exclude both bootstrap units from the run and
  destroy them last, the management bootstrap last of all.
- The single-pass apply line of `docs/getting-started.md` reads
  `(cd stacks && terragrunt run --all -- apply)`.

## [0.5.27] - 2026-11-05

### Fixed

- The quick start runs plan and apply in subshells, so you stay in the repository root and the
  commands of `docs/getting-started.md` work from there.
- `docs/getting-started.md`: the single-pass apply runs in `stacks`, and the Config recorder check
  names the management account, whose recorder it lists.
