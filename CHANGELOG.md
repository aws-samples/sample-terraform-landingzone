# Changelog

This file lists what changed in the published repository, one section per version, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.30] - 2026-11-11

### Added

- Module `security-org-config` runs the finding consumers in the Audit account: the GuardDuty
  findings export, the Macie classification export, the Security Hub finding aggregator, the
  automation rules and the disabled controls of the delegated administrator, and it enrols the
  existing accounts as Security Hub members. Only there do export, rules and aggregation reach every
  member account's findings.
- The central log bucket and its key admit the GuardDuty and Macie exports of the Audit account
  (`finding_export_source_account_ids`, set by the logging stack once the Audit account resolves).
- Stack `stacks/audit/monitoring`: the GuardDuty and Security Hub EventBridge rules, the SNS topics
  and the findings dashboard in the Audit account; `audit_sns_email_targets` and `audit_sns_topics`
  set its targets, and the management lists apply when they are absent.
- Quarantine at OU level: `quarantine_ou_name` names a declared OU the quarantine SCP is attached to,
  and the output `quarantine_ou_id` hands its id on. The example declares the OU `Quarantine`.
- `accounts[].quarantined = true` creates a new account inside the quarantine OU, under the
  quarantine SCP from its first second, while its declared OU stays its deployment scope;
  `quarantined = false` moves it there. The plan names the quarantined accounts and warns when the
  access role is one the SCP does not exempt.
- Module `workload-networking` and stack `stacks/workload-dev/networking`: the security groups,
  target groups and internal load balancers a workload account must own itself, in the VPCs the
  management account shares with it (`workload_security_groups`, `workload_target_groups`,
  `workload_load_balancers`); `workload-compute` takes them from there, and both follow
  `enable_workload_compute`. The workload compute module refuses at plan a target group of another
  account, which AWS refused at apply before.
- `docs/getting-started.md` gains the section "Deployment account mode" with the order of the first
  apply and the destroy order per mode; `docs/architecture.md` gains "Credential chain": the four
  identities and which one each unit's provider and state backend use, for an operator and for the
  pipeline. `env/common.hcl.example` explains the switch and the profile the pipeline writes.

### Changed

- The finding consumers move to the Audit account: with `security_finding_consumers_in_audit`
  (`env/common.hcl`, default true) and an Audit account, the next apply destroys the GuardDuty
  export, the Macie export, the Security Hub aggregator and the automation rules in the management
  account and creates them in the Audit account. Set the key to false before upgrading to keep
  today's layout.
- Upgrade: during that apply the management account's own findings are unexported for the minutes
  between destroy and create; findings already exported stay in the bucket. Every address in
  `sns_email_targets` receives a second subscription confirmation from the Audit account's topics
  unless `audit_sns_email_targets` names other addresses. `docs/operations.md` describes the move,
  the migration and the rollback.
- The pipeline module takes the new required input `aws_profile` and requires the key `management`
  in `deployment_role_arns`; a caller outside the stacks must set both.
- Giving an existing security group rule or route a `name` changes its key, so the first plan after
  that replaces the entry once.
- With `enable_security = false`, the first plan removes Macie trusted access from the organization.

### Fixed

- The deployment account mode reaches its state and its roles: with `enable_deployment_account = true`
  every unit runs as `aws_profile` and its state backend assumes the deployment account's access role
  in the `assume_role` block Terraform accepts; the deployment-role unit no longer assumes the role it
  creates, the pipeline unit runs in the deployment account, and a bootstrap unit called under the
  wrong mode is refused.
- The pipeline has the profile its stacks name: the build steps of the CodePipeline variant and the
  command of the ECS variant write an `aws_profile` entry into the container that assumes the
  management deployment role before Terragrunt starts.
- `env/common.hcl.example` plans the organization unit: it ships `service_access_principals = []`
  with the delegated administrators as a commented example, and the VPC Block Public Access policy
  targets the Security, Infrastructure and Workloads OUs instead of account names.
- The accounts unit plans before the first apply: its first plan gets a placeholder id for every
  declared OU, and its deployment-account provider uses `aws_profile`. An account placed by an OU
  path (`Workloads/Dev`) or by OU id alone no longer stops `terragrunt run --all` while the
  configuration is parsed.
- The first `run --all -- apply` skips units whose dependency is switched off: the config recorders
  follow `enable_logging`, `audit/security-org-config` and Macie trusted access follow
  `enable_security`, and `management/cur` no longer reads the logging stack; before, these failed
  with "detected no outputs". `docs/operations.md` explains switching off.
- Networking no longer waits for the Config rules: in `terragrunt run --all`, networking, iam and the
  units after them start two levels earlier. Nothing in a deployed organization changes.
- The `Error creating` retry in `stacks/root.hcl` is removed; it matched no AWS provider error.
- The quick start and the guide set `TG_PROVIDER_CACHE=1`: one provider download per run.
- `End-User-Policy` lets a bounded role change role policies only on roles with the same boundary,
  and its role-creation deny accepts the boundary. Roles of `member-roles` reach accounts in nested
  OUs.
- SCP auto-revert undoes a detach only for policies the module manages, never for the quarantine
  SCP; `scp_revert_exempt_principal_arns` exempts your own role.
- SCPs may hold 10,240 characters, the AWS limit. The account-move function, which only logs events,
  no longer holds `organizations:MoveAccount`.
- Logging: the central bucket no longer logs into itself, which delivered nothing; the separate
  access logs bucket uses SSE-S3; the log bucket key admits the Macie export and CloudTrail Lake
  event data stores; the ELB log bucket admits load balancers of the organization only; an
  auto-created replica gets Object Lock when the central bucket has it. All of these change in
  place, nothing is replaced.
- Networking: zone-scoped resolver rules take effect, each rule associated with the zone's VPCs;
  private subnets use the NAT gateway in their own zone; a second DNS firewall rule group on a VPC
  gets its own priority.
- Networking: IPAM-fed VPCs plan and apply; interface endpoint groups and peering routes read the
  allocated CIDR, and VPCs, subnets and IPv6 ranges wait for the pool's CIDR.
- Networking: an application load balancer without a security group and a Transit Gateway attachment
  without a subnet are refused at plan; the README usage example plans.
- Networking: an optional `name` on security group rules and routes keys them by name, so removing an
  earlier entry no longer replaces the later ones.
- `ignore = true` on an OU takes effect and covers every OU below it: an account declared there is
  created and kept but leaves `active_account_ids` and `active_account_ou_ids`, joins no
  `ou_deployments` membership, and its per-account units (`stacks/<account>/*`) are skipped without
  an account lookup, so no unit assumes a role the deny-all policy would refuse. The plan names such
  accounts as `suspended_account_names`; `docs/operations.md` describes how to move an account to
  `Suspended` and what to destroy first.
- The guide creates the AWS Config service-linked role before the recorders, and the
  management-account layout of the finding consumers is documented as seeing the management
  account's findings only.

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
