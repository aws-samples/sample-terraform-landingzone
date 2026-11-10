# Bootstrap module variables

variable "state_bucket_name" {
  description = "S3 bucket name for Terraform remote state"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "S3 bucket name must be 3-63 characters long and contain only lowercase letters, numbers, dots, and hyphens."
  }
}

variable "lock_table_name" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "terraform-locks"

  validation {
    condition     = length(var.lock_table_name) > 0 && length(var.lock_table_name) <= 255
    error_message = "lock_table_name must be non-empty and at most 255 characters long."
  }
}

variable "kms_key_alias" {
  description = "Optional KMS key alias for SSE-KMS encryption (empty = no custom key)"
  type        = string
  default     = ""

  validation {
    condition     = var.kms_key_alias == "" || can(regex("^[a-zA-Z0-9/_-]+$", var.kms_key_alias))
    error_message = "kms_key_alias must be empty or contain only alphanumeric characters, hyphens, underscores, and forward slashes."
  }
}
