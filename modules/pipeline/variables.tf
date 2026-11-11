# Pipeline Module — Variables

variable "pipeline_type" {
  description = "Type of CI/CD pipeline to create: codepipeline, ecs, or external"
  type        = string
  default     = "codepipeline"

  validation {
    condition     = contains(["codepipeline", "ecs", "external"], var.pipeline_type)
    error_message = "pipeline_type must be codepipeline, ecs, or external."
  }
}

variable "repository_name" {
  description = "Repository the pipeline sources from. codepipeline: full repository ID of the CodeConnections source (owner/repo). ecs: name of the CodeCommit repository in this account whose pushes to branch_name trigger the task — the trigger rule is scoped to exactly that repository, so the name must be a CodeCommit repository name (letters, digits, . _ -; no slash)."
  type        = string

  validation {
    condition     = length(var.repository_name) > 0
    error_message = "repository_name must be non-empty — a repository name is required for the pipeline source."
  }

  # The external variant writes this name into the OIDC subject condition,
  # which is a StringLike (external.tf): a '*' or '?' here would let other
  # repositories assume TLZExternalCIRole.
  validation {
    condition     = !can(regex("[*?]", var.repository_name))
    error_message = "repository_name must not contain '*' or '?': the external CI trust policy matches the OIDC subject with StringLike, so a wildcard would widen who may assume the role."
  }

  # The ECS trigger builds the CodeCommit repository ARN from this name and
  # matches EventBridge events on it. A full repository ID (owner/repo) — the
  # shape the codepipeline variant takes — would yield an ARN no CodeCommit
  # event carries, and the trigger would never fire.
  validation {
    condition     = var.pipeline_type != "ecs" || can(regex("^[A-Za-z0-9._-]{1,100}$", var.repository_name))
    error_message = "pipeline_type is ecs, so repository_name must be the name of a CodeCommit repository in this account (1-100 characters of letters, digits, '.', '_' and '-'; no '/'). The ECS variant triggers on CodeCommit repository state change events of exactly this repository; a CodeConnections repository ID (owner/repo) has no such events."
  }
}

variable "source_connection_arn" {
  description = "ARN of the existing CodeConnections/CodeStar connection that provides the pipeline source. Required for pipeline_type codepipeline — the CodePipeline variant is not created while this is empty. Must stay empty for pipeline_type ecs: the ECS variant triggers on CodeCommit events only, and a connection source emits none."
  type        = string
  default     = ""

  validation {
    condition = (
      var.source_connection_arn == "" ||
      can(regex("^arn:[a-z0-9-]+:(codestar-connections|codeconnections):[a-z0-9-]+:[0-9]{12}:connection/[0-9a-fA-F-]+$", var.source_connection_arn))
    )
    error_message = "source_connection_arn must be empty or a connection ARN (arn:<partition>:codeconnections|codestar-connections:<region>:<account-id>:connection/<uuid>)."
  }

  # The two variants use two different source models. codepipeline detects
  # pushes through the connection itself (CodePipeline V2 git trigger); the ecs
  # variant has no pipeline and listens to "CodeCommit Repository State Change"
  # events on the default bus. A repository reached through a connection
  # (GitHub, GitLab, Bitbucket) emits no such event, so a connection ARN with
  # the ecs variant described a trigger that could never fire — silently.
  validation {
    condition     = var.pipeline_type != "ecs" || var.source_connection_arn == ""
    error_message = "pipeline_type is ecs but source_connection_arn is set. The ECS variant's only trigger is the EventBridge rule on CodeCommit repository state change events of repository_name; a repository reached through a CodeConnections connection (GitHub, GitLab, Bitbucket) emits no such event, so the trigger would never fire. Use pipeline_type = \"codepipeline\" for a connection source, or leave source_connection_arn empty and name a CodeCommit repository in repository_name."
  }
}

variable "branch_name" {
  description = "Branch name to trigger the pipeline on"
  type        = string
  default     = "main"

  validation {
    condition     = length(var.branch_name) > 0
    error_message = "branch_name must be non-empty — a branch name is required for the pipeline trigger."
  }

  # Same reason as on repository_name: the OIDC subject is a StringLike.
  validation {
    condition     = !can(regex("[*?]", var.branch_name))
    error_message = "branch_name must not contain '*' or '?': the external CI trust policy matches the OIDC subject with StringLike, so a wildcard would widen which branches may assume the role."
  }
}

variable "aws_profile" {
  description = "Name of the AWS profile the stacks run with -- the aws_profile of env/common.hcl, which Terragrunt writes into every unit's provider.tf and backend.tf. A build container has no such profile, so the build steps of the codepipeline variant and the command of the ecs variant write one of this name into ~/.aws/config before Terragrunt starts: it assumes deployment_role_arns[\"management\"] with the container's own credentials (credential_source = EcsContainer, the role CodeBuild or ECS attached to the container). From there the pipeline walks exactly the operator's path: that role in the management account, the member access roles and the state bucket's role from it. The name itself is free; a laptop keeps its own ~/.aws/config entry of the same name. The external variant writes no file -- its runner exports the OIDC session and the profile uses credential_source = Environment (see the module README)."
  type        = string

  # The name lands inside a single-quoted shell word of the build command; a
  # quote or whitespace would break it, and an empty name leaves Terragrunt's
  # files pointing at a profile nobody wrote.
  validation {
    condition     = length(var.aws_profile) > 0 && !can(regex("['\\s]", var.aws_profile))
    error_message = "aws_profile must be a non-empty profile name without quotes or whitespace: the build writes a profile of this name that assumes the management deployment role, and Terragrunt's provider.tf and backend.tf name the same profile."
  }
}

variable "deployment_role_arns" {
  description = "Map of account name to Deployment Role ARN for cross-account access. The key \"management\" is required: it is the role the pipeline's profile (aws_profile) assumes before Terragrunt starts, and every further hop -- member access roles, the state bucket's role -- is made from it. Every entry is granted to the pipeline's roles for sts:AssumeRole."
  type        = map(string)

  validation {
    condition = alltrue([
      for name, arn in var.deployment_role_arns :
      can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):iam::[0-9]{12}:role/", arn))
    ])
    error_message = "Each deployment_role_arns value must be a valid IAM role ARN (arn:<partition>:iam::<account-id>:role/<name>)."
  }

  validation {
    condition     = contains(keys(var.deployment_role_arns), "management")
    error_message = "deployment_role_arns must carry the key \"management\": the pipeline's build writes a profile that assumes exactly that entry before Terragrunt starts, and the stacks' provider and backend run from it."
  }
}

variable "approval_notification_email" {
  description = "Email address for pipeline approval notifications"
  type        = string
  default     = ""

  validation {
    condition     = var.approval_notification_email == "" || can(regex("^[^@]+@[^@]+\\.[^@]+$", var.approval_notification_email))
    error_message = "approval_notification_email must be empty or a valid email address (e.g., user@example.com)."
  }
}

variable "enable_pipeline_notifications" {
  description = "Publish pipeline execution state changes (see pipeline_notification_states) to the approval SNS topic via EventBridge rules. Applies to the CodePipeline variant; false (the default) creates no rule and leaves the plan unchanged."
  type        = bool
  default     = false
}

variable "pipeline_notification_states" {
  description = "Pipeline execution states that are reported when enable_pipeline_notifications is set. One EventBridge rule per state."
  type        = list(string)
  default     = ["STARTED", "SUCCEEDED", "FAILED", "SUPERSEDED", "CANCELED"]

  validation {
    condition = alltrue([
      for state in var.pipeline_notification_states :
      contains(["STARTED", "SUCCEEDED", "RESUMED", "FAILED", "CANCELED", "SUPERSEDED", "STOPPED", "STOPPING"], state)
    ])
    error_message = "Each pipeline_notification_states entry must be one of the CodePipeline execution states STARTED, SUCCEEDED, RESUMED, FAILED, CANCELED, SUPERSEDED, STOPPED or STOPPING."
  }

  validation {
    condition     = length(var.pipeline_notification_states) > 0
    error_message = "pipeline_notification_states must not be empty — with the toggle on, an empty list would silently report nothing."
  }

  validation {
    condition     = length(distinct(var.pipeline_notification_states)) == length(var.pipeline_notification_states)
    error_message = "pipeline_notification_states must not contain duplicates."
  }
}

# --- Upsert-safe resource names -------------------------------------------
# SNS CreateTopic, EventBridge PutRule and ECS CreateCluster are upserts or
# idempotent creates: an apply against an account already carrying the name
# reports "create" while silently ADOPTING the live resource, and `terraform
# test`'s automatic teardown then DELETES it. Every such fixed name of this
# module is therefore a variable defaulting to the module's standard name (a live plan
# stays empty); an apply-test overrides them with tlz-l4test- names. The
# pipeline stack lives in the DEPLOYMENT account, where the organization
# guardrails (SCPs) do apply — the tlz- pin on the topic and rule names is
# real protection there, not only a namespace invariant.

variable "approval_topic_name" {
  description = "Name of the SNS topic that carries manual-approval notifications and (with enable_pipeline_notifications) the pipeline state changes of the CodePipeline variant. The default is the module's standard name. SNS CreateTopic is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live deployment account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live topic, e-mail subscription and topic policy included. That a pipeline stack is not deployed yet is NOT a safety property: the first deployment creates the topic under this default. The name must stay inside the tlz- namespace: the organization guardrails (ProtectSNSTopics) protect only arn:*:sns:*:*:tlz-* from tampering, so this validation carries the invariant. A changed default is a destroy/create of a deployed topic, so leave it at the literal below in production."
  type        = string
  default     = "tlz-pipeline-approval"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9_-]{1,252}$", var.approval_topic_name))
    error_message = "approval_topic_name must start with tlz- and be 1-256 characters of letters, digits, underscore or hyphen in total — the AWS SNS topic naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "pipeline_state_rule_name_prefix" {
  description = "Prefix of the per-state EventBridge rule names of the CodePipeline variant's notifications (created when enable_pipeline_notifications is true): each rule is named <prefix>-<lowercased state>, so the default yields tlz-pipeline-state-failed, tlz-pipeline-state-succeeded and so on — the module's standard names. EventBridge PutRule is an UPSERT: an account already carrying a rule of that name is silently adopted rather than failing, so any apply-test of this module against a live deployment account must override this with a test-scoped prefix (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rules and their targets. The prefix must stay inside the tlz- namespace: the organization guardrails (ProtectEventBridgeRules) protect only arn:*:events:*:*:rule/tlz-* from tampering; this validation carries the invariant. Bounded to 53 characters so the longest state suffix (-superseded) still fits the 64-character rule-name limit. A changed default is a destroy/create of every deployed state rule, so leave it at the literal below in production."
  type        = string
  default     = "tlz-pipeline-state"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,49}$", var.pipeline_state_rule_name_prefix))
    error_message = "pipeline_state_rule_name_prefix must start with tlz- and be 1-53 characters of letters, digits, dot, underscore or hyphen in total, so that <prefix>-<state> stays within the 64-character EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "ecs_log_retention_in_days" {
  description = "Retention in days for the ecs variant's CloudWatch log group (/ecs/tlz-pipeline, created when pipeline_type is ecs). 0 means never expire."
  type        = number
  default     = 365

  # CloudWatch accepts only this fixed set of retention values; 0 means never
  # expire. Any other number is rejected at apply time.
  validation {
    condition = contains(
      [0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653],
      var.ecs_log_retention_in_days
    )
    error_message = "ecs_log_retention_in_days must be one of the CloudWatch retention values: 0 (never expire), 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653."
  }
}

variable "ecs_cluster_name" {
  description = "Name of the ECS cluster of the ecs variant (created when pipeline_type is ecs). The default is the module's standard name. ECS CreateCluster is IDEMPOTENT: it returns an existing cluster of the same name instead of failing, so any apply-test of this module against a live deployment account must override this with a test-scoped name (tlz-l4test-) — otherwise the test silently adopts the live cluster and `terraform test`'s automatic teardown deletes it (an idle cluster deletes without complaint). Deliberately NOT pinned to the tlz- namespace: no organization guardrail names an ECS cluster ARN, so there is no protection for a validation to preserve; keep the prefix anyway for legibility. The task-definition family (a new revision is registered on every apply, never adopted) and the log group /ecs/tlz-pipeline (CreateLogGroup is create-only) keep their fixed names. A changed default is a destroy/create of a deployed cluster, so leave it at the literal below in production."
  type        = string
  default     = "tlz-pipeline"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,255}$", var.ecs_cluster_name))
    error_message = "ecs_cluster_name must be 1-255 characters of letters, digits, underscore or hyphen — the ECS cluster naming rule."
  }
}

variable "ecs_approval_topic_name" {
  description = "Name of the SNS topic that carries the ecs variant's approval notifications (created when pipeline_type is ecs). Same contract as approval_topic_name: the default is the module's standard name, SNS CreateTopic is an UPSERT so a live apply-test must override it with a tlz-l4test- name, and the tlz- prefix keeps the topic under the organization guardrails (ProtectSNSTopics protects only arn:*:sns:*:*:tlz-*). A changed default is a destroy/create of a deployed topic."
  type        = string
  default     = "tlz-ecs-pipeline-approval"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9_-]{1,252}$", var.ecs_approval_topic_name))
    error_message = "ecs_approval_topic_name must start with tlz- and be 1-256 characters of letters, digits, underscore or hyphen in total — the AWS SNS topic naming rule inside the guardrail-protected tlz- namespace."
  }
}

variable "ecs_trigger_rule_name" {
  description = "Name of the EventBridge rule that starts the ecs variant's Fargate task on a CodeCommit push (created when pipeline_type is ecs). The default is the module's standard name. EventBridge PutRule is an UPSERT: an account already carrying this name is silently adopted rather than failing, so any apply-test of this module against a live deployment account must override this with a test-scoped name (tlz-l4test-) — otherwise `terraform test`'s automatic teardown deletes the live rule and the ECS target that is the variant's only trigger. The name must stay inside the tlz- namespace: the organization guardrails (ProtectEventBridgeRules) protect only arn:*:events:*:*:rule/tlz-* from tampering. A changed default is a destroy/create of a deployed rule."
  type        = string
  default     = "tlz-ecs-pipeline-trigger"

  validation {
    condition     = can(regex("^tlz-[a-zA-Z0-9._-]{1,60}$", var.ecs_trigger_rule_name))
    error_message = "ecs_trigger_rule_name must start with tlz- and be 1-64 characters of letters, digits, dot, underscore or hyphen in total — the EventBridge rule naming rule inside the guardrail-protected tlz- namespace."
  }
}

# --- ECS variant: the Fargate task's network --------------------------------
# The task definition of the ecs variant is awsvpc/FARGATE (ecs.tf), and
# EventBridge REFUSES an ECS target with a FARGATE launch type that carries no
# NetworkConfiguration: PutTargets answers "400 ValidationException:
# Parameter NetworkConfiguration must be specified for target tlz-ecs-pipeline
# when launch type is FARGATE". A mock provider accepts any PutTargets, so
# the mocked tests cannot catch a target built without one.
#
# The network is the CALLER's to name, never derived here: a data source on
# the default VPC would hide the dependency and place the task — which holds
# the role that assumes every deployment role — in a network nobody chose,
# and this landing zone's networking module strips the default security group
# of every VPC it manages to zero ingress and egress. The three variables are
# optional so the codepipeline and external variants (which have no task) keep
# planning unchanged; the subnet list becomes MANDATORY exactly when
# pipeline_type is ecs, refused at plan time with a message that names the
# variable, instead of twenty seconds into the apply by EventBridge.
#
# The security-group list matters for the same reason: with it empty, EventBridge ACCEPTS the target and ECS attaches
# the DEFAULT security group of the subnets' VPC — which, in a VPC this landing
# zone manages, has no egress rule at all, so every triggered task fails to
# pull its image or reach an AWS API: late, on every trigger, and with nothing
# in the plan that said so. An ecs variant that names no group is therefore
# refused at plan time as well — unless the caller states, through
# ecs_use_default_security_group, that the subnets' VPC keeps a default group
# whose egress rules were checked (a VPC this landing zone does not manage; a
# blanket requirement would false-red that legitimate shape). The refusal is a
# `validation`, not a test-time assert, on purpose: a failed assert does not
# stop terraform 1.16.1, a failed validation does, before any provider call.
#
# Two stages guard that shape, each catching the case the other cannot:
#   validation (here)      — no group named AND no acknowledgement: refused
#                            from the variables alone, before any provider
#                            call. It can only read variables, so the flag is
#                            the caller's WORD about the world.
#   precondition (ecs.tf)  — no group named, acknowledged, but the default
#                            group of the subnets' VPC in FACT has no egress
#                            rule covering HTTPS: the module reads that group
#                            (aws_subnet → aws_security_group →
#                            aws_vpc_security_group_rules →
#                            aws_vpc_security_group_rule) and the EventBridge
#                            target refuses at plan time, before any resource
#                            is created. This is the managed-VPC case the flag
#                            cannot see.

variable "ecs_subnet_ids" {
  description = "Subnet IDs the ecs variant's Fargate task is started in (created when pipeline_type is ecs; ignored by the other two variants). REQUIRED for pipeline_type ecs: the task definition is awsvpc/FARGATE and EventBridge refuses a FARGATE target without a network configuration (PutTargets 400 ValidationException), so an ecs variant without subnets cannot be applied by anyone. Private subnets of the deployment account's VPC are the expected shape; the task pulls its image and reaches AWS APIs, so those subnets need a route out (NAT gateway or interface endpoints) — see ecs_assign_public_ip for the public-subnet alternative. Deliberately never derived from a data source on the default VPC: that would hide the dependency and place a task holding the deployment-assume role in a network the caller did not choose."
  type        = list(string)
  default     = []

  validation {
    condition     = var.pipeline_type != "ecs" || length(var.ecs_subnet_ids) > 0
    error_message = "pipeline_type is ecs but ecs_subnet_ids is empty. The ECS variant's Fargate task runs in awsvpc network mode and EventBridge refuses its target without a network configuration (\"Parameter NetworkConfiguration must be specified … when launch type is FARGATE\"), so the variant cannot be applied without at least one subnet. Set ecs_subnet_ids to the subnet IDs the task should start in (and ecs_security_group_ids to the groups it should carry)."
  }

  validation {
    condition     = alltrue([for id in var.ecs_subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", id))])
    error_message = "Each ecs_subnet_ids entry must be a subnet ID (subnet- followed by 8 or 17 hexadecimal characters), not a subnet name — the value is handed to EventBridge as-is."
  }

  validation {
    condition     = length(distinct(var.ecs_subnet_ids)) == length(var.ecs_subnet_ids)
    error_message = "ecs_subnet_ids must not contain duplicates."
  }
}

variable "ecs_security_group_ids" {
  description = "Security group IDs the ecs variant's Fargate task carries (created when pipeline_type is ecs; ignored by the other two variants). REQUIRED for pipeline_type ecs unless ecs_use_default_security_group is true: with no group named ECS attaches the DEFAULT security group of the subnets' VPC — and in a VPC managed by this landing zone's networking module that group is stripped of every ingress and egress rule (modules/networking/security-groups.tf, aws_default_security_group.vpc), so EventBridge accepts the target and every triggered task then fails to reach anything; the terragrunt plan it runs never starts. Name a group that allows outbound HTTPS. The value is handed to EventBridge as-is, so it must be IDs, not names."
  type        = list(string)
  default     = []

  validation {
    condition     = var.pipeline_type != "ecs" || length(var.ecs_security_group_ids) > 0 || var.ecs_use_default_security_group
    error_message = "pipeline_type is ecs but ecs_security_group_ids is empty and ecs_use_default_security_group is false. With no group named, ECS attaches the DEFAULT security group of the subnets' VPC; in a VPC managed by this landing zone's networking module that group has no egress rule at all (aws_default_security_group.vpc), so EventBridge would accept the target and every triggered task would then fail to pull its image or reach an AWS API — late, on every trigger. Set ecs_security_group_ids to at least one group that allows outbound HTTPS, or set ecs_use_default_security_group = true to state that the subnets' VPC keeps a default group whose egress rules you have checked."
  }

  validation {
    condition     = alltrue([for id in var.ecs_security_group_ids : can(regex("^sg-[0-9a-f]{8,17}$", id))])
    error_message = "Each ecs_security_group_ids entry must be a security group ID (sg- followed by 8 or 17 hexadecimal characters), not a group name — the value is handed to EventBridge as-is."
  }

  validation {
    condition     = length(distinct(var.ecs_security_group_ids)) == length(var.ecs_security_group_ids)
    error_message = "ecs_security_group_ids must not contain duplicates."
  }
}

variable "ecs_use_default_security_group" {
  description = "Explicit acknowledgement that the ecs variant's Fargate task may run with the DEFAULT security group of the subnets' VPC, i.e. with ecs_security_group_ids left empty (read only when pipeline_type is ecs; ignored by the other two variants). Default false: an ecs variant that names no security group is then refused at plan time. Set true only when the subnets' VPC is NOT managed by this landing zone's networking module — which strips the default group of every ingress and egress rule — and that VPC's default group allows outbound HTTPS. The flag is the caller's word, and the module does not take it alone: when the task will carry the default group, ecs.tf reads that group's rules (aws_subnet, aws_security_group, aws_vpc_security_group_rules, aws_vpc_security_group_rule — ec2:Describe* at plan time) and the EventBridge target refuses through a precondition when no egress rule allows all traffic or TCP covering port 443. The target itself names no security group either way."
  type        = bool
  default     = false
}

variable "ecs_assign_public_ip" {
  description = "Whether the ecs variant's Fargate task gets a public IP address (created when pipeline_type is ecs; ignored by the other two variants). Default false: the expected placement is a private subnet with a route out through a NAT gateway or interface endpoints. Set true only when ecs_subnet_ids names PUBLIC subnets and the task has no other route to pull its image and reach AWS APIs — a Fargate task in a public subnet without a public IP cannot start its container."
  type        = bool
  default     = false
}

variable "ecs_task_image" {
  description = "Container image the ecs variant's Fargate task runs (read only when pipeline_type is ecs; ignored by the other two variants). Default: the third-party alpine/terragrunt image at tag tf1.16.1, pinned by its multi-arch index digest. That tag is not an arbitrary choice — it is the terraform version this repo's own container pins (tools/local-test/Containerfile, TERRAFORM_VERSION=1.16.1), so a bump means reading the new tag's digest from the registry, never copying a tag reference. The digest, not the tag, is what ECS resolves — a tag is a mutable pointer the publisher can move under a task that holds the deployment-assume role; the plan and apply build steps of the codepipeline variant pin their terragrunt download for the same reason. Override to run the task from a registry you control (ECR is the expected shape for an account that must not reach Docker Hub at all); the validation refuses any reference without an @sha256: digest, so an override cannot silently reintroduce a moving tag. NOT verified by this module: what the image contains. Only its immutability is pinned here; when bumping, read the digest from both the Docker Hub tag API and the registry manifest (docker-content-digest) and check that they agree."
  type        = string
  default     = "alpine/terragrunt:tf1.16.1@sha256:2a31ab9878c8a4a39d7ff79d66202b5a3910e128c60f63cb6b579fa8616b145f"

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.ecs_task_image))
    error_message = "ecs_task_image must name the image by digest (…@sha256:<64 hex>), not by tag alone — a tag is a mutable pointer, and the task that pulls it holds the role that can assume every deployment_role_arns entry."
  }
}

variable "external_ci_provider" {
  description = "External CI provider for OIDC federation: github or gitlab"
  type        = string
  default     = "github"

  validation {
    condition     = contains(["github", "gitlab"], var.external_ci_provider)
    error_message = "external_ci_provider must be github or gitlab."
  }
}

variable "external_ci_thumbprint" {
  description = "TLS certificate thumbprint for the external CI OIDC provider"
  type        = string
  default     = ""

  # An OIDC provider thumbprint is the SHA-1 fingerprint of the IdP certificate:
  # exactly 40 hexadecimal characters.
  validation {
    condition     = var.external_ci_thumbprint == "" || can(regex("^[0-9a-fA-F]{40}$", var.external_ci_thumbprint))
    error_message = "external_ci_thumbprint must be empty or a 40-character hexadecimal SHA-1 certificate thumbprint."
  }
}

variable "external_ci_audiences" {
  description = "List of audiences for the external CI OIDC provider"
  type        = list(string)
  default     = ["sts.amazonaws.com"]

  validation {
    condition     = length(var.external_ci_audiences) > 0
    error_message = "external_ci_audiences must not be empty — an OIDC provider without an audience accepts no token."
  }

  validation {
    condition     = alltrue([for audience in var.external_ci_audiences : trimspace(audience) != ""])
    error_message = "external_ci_audiences must not contain empty entries."
  }

  validation {
    condition     = length(distinct(var.external_ci_audiences)) == length(var.external_ci_audiences)
    error_message = "external_ci_audiences must not contain duplicates."
  }
}

variable "codebuild_encryption_kms_key_arn" {
  type        = string
  default     = ""
  description = "Customer-managed KMS key that encrypts the build output of both CodeBuild projects (the Terragrunt plan and apply stages). Empty — the default — leaves CodeBuild on the AWS-managed S3 key alias/aws/s3, which is what the module shipped before this knob existed: the plan is unchanged for anyone who does not set it. When set, the key reaches both projects AND the module grants the CodeBuild service role the five key operations it needs (Encrypt, Decrypt, ReEncrypt, GenerateDataKey, DescribeKey) on exactly that key; without them every build fails at artifact upload. A customer-managed key carries a monthly charge; the AWS-managed key does not. Note the artifact bucket itself is encrypted separately (aws_s3_bucket_server_side_encryption_configuration.artifacts, AES256) — naming a key here does not change the bucket's own default."

  validation {
    condition     = var.codebuild_encryption_kms_key_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.codebuild_encryption_kms_key_arn))
    error_message = "codebuild_encryption_kms_key_arn must be empty or a valid KMS key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>)."
  }
}
