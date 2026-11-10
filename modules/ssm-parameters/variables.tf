variable "ssm_parameters" {
  description = "List of SSM Parameter definitions. Each entry creates an aws_ssm_parameter resource in the management account."
  type = list(object({
    name               = string
    type               = string
    value              = string
    deployment_targets = optional(list(string), [])
    # KMS key (ID, ARN or alias) for a SecureString entry. null keeps the
    # AWS-managed alias/aws/ssm key; String and StringList are not encrypted.
    key_id = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for p in var.ssm_parameters :
      contains(["String", "StringList", "SecureString"], p.type)
    ])
    error_message = "Each ssm_parameters type must be String, StringList, or SecureString."
  }

  validation {
    condition = alltrue([
      for p in var.ssm_parameters :
      length(p.name) > 0
    ])
    error_message = "Each ssm_parameters entry must have a non-empty name."
  }

  validation {
    condition = alltrue([
      for p in var.ssm_parameters :
      p.key_id == null || p.type == "SecureString"
    ])
    error_message = "key_id is only valid on SecureString ssm_parameters entries; String and StringList values are not KMS-encrypted."
  }

  # key_id takes the forms the SSM API documents for KeyId and nothing else:
  # a bare key id (UUID or multi-Region mrk-<32 hex>), a key ARN, an alias
  # name (alias/<name>) or an alias ARN, in any partition. Anything else --
  # including "" -- names no key and would fail only at apply; null is the way
  # to the AWS-managed alias/aws/ssm key.
  validation {
    condition = alltrue([
      for p in var.ssm_parameters :
      p.key_id == null || can(regex(
        "^((arn:aws(-[a-z]+)*:kms:[a-z0-9-]+:[0-9]{12}:key/)?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})|(arn:aws(-[a-z]+)*:kms:[a-z0-9-]+:[0-9]{12}:)?alias/[a-zA-Z0-9/_-]+)$",
        p.key_id
      ))
    ])
    error_message = "Each ssm_parameters key_id must be a KMS key id, key ARN (arn:<partition>:kms:<region>:<account-id>:key/<id>), alias name (alias/<name>) or alias ARN (arn:<partition>:kms:<region>:<account-id>:alias/<name>); omit it (null) for the AWS-managed alias/aws/ssm key."
  }
}

variable "default_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default     = {}

  # AWS tag limits: key 1-128 characters, value up to 256, and the reserved
  # prefix "aws:" is refused by the API. Validating here turns an apply-time
  # rejection into a plan-time message that names the offending key.
  validation {
    condition = alltrue([
      for k, v in var.default_tags :
      length(k) >= 1 && length(k) <= 128 && length(v) <= 256 && !startswith(lower(k), "aws:")
    ])
    error_message = "Each default_tags key must be 1-128 characters, each value at most 256 characters, and no key may start with the reserved prefix \"aws:\"."
  }
}
