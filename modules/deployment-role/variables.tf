# Deployment Role Module — Variables

variable "deployment_account_id" {
  description = "Account ID of the Deployment Account that can assume this role"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.deployment_account_id))
    error_message = "deployment_account_id must be a 12-digit AWS account ID."
  }
}

variable "role_name" {
  description = "Name of the IAM role to create in the Management Account"
  type        = string
  default     = "TLZDeploymentRole"

  validation {
    condition     = length(var.role_name) > 0 && can(regex("^[a-zA-Z0-9+=,.@_-]+$", var.role_name))
    error_message = "role_name must be non-empty and contain only alphanumeric characters and +=,.@_- characters."
  }
}

variable "permissions_boundary_arn" {
  description = "Optional ARN of a permissions boundary to attach to the role"
  type        = string
  default     = ""

  validation {
    condition     = var.permissions_boundary_arn == "" || can(regex("^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):iam::[0-9]{12}:policy/", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be empty or a valid IAM policy ARN (arn:<partition>:iam::<account-id>:policy/<path>)."
  }
}

variable "narrow_grants" {
  description = "Select the narrow inline policy document: the guardduty, securityhub, macie2, access-analyzer, sso, sso-directory and identitystore `service:*` grants are replaced by the actions the modules' resource types call. false keeps the default document byte-identical. The default flips to true after one organization-wide apply with the flag on has gone through."
  type        = bool
  default     = false
}
