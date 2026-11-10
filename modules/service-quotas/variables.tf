variable "service_quota_increases" {
  description = "List of service quota increase requests. Each entry specifies a service code, quota code, and desired value. deployment_targets is accepted for configuration compatibility but triggers a check block warning."
  type = list(object({
    service_code       = string
    quota_code         = string
    desired_value      = number
    enabled            = optional(bool, true)
    deployment_targets = optional(list(string), [])
  }))
  default = []

  validation {
    condition = alltrue([
      for q in var.service_quota_increases :
      q.service_code != "" && q.quota_code != ""
    ])
    error_message = "Each service_quota_increases entry must have non-empty service_code and quota_code."
  }

  validation {
    condition = alltrue([
      for q in var.service_quota_increases :
      q.desired_value > 0
    ])
    error_message = "Each service_quota_increases entry must have a positive desired_value."
  }
}
