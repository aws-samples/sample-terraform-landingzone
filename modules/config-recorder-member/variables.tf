variable "central_log_bucket_name" {
  description = "Name of the central S3 log bucket for Config delivery"
  type        = string

  validation {
    condition     = length(var.central_log_bucket_name) > 0 && can(regex("^[a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9]$", var.central_log_bucket_name))
    error_message = "central_log_bucket_name must be a valid S3 bucket name (3-63 characters, lowercase letters, numbers, dots, and hyphens)."
  }
}
