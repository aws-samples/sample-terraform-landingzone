# Minimum interface variables — every custom module should declare these three.
# Add your own variables below as needed.

variable "region" {
  description = "AWS region"
  type        = string
  # No default — this is required and passed by Terragrunt
}

variable "default_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default     = {}
}

variable "account_ids" {
  description = "Map of account name to account ID"
  type        = map(string)
  default     = {}

  # ← Declare a validation block for every input a wrong value could silently
  # break. Here: an account ID is twelve digits, and a value that is not one
  # would end up inside an ARN, where the error only surfaces at apply time.
  # customizations/_template/tests/template.tftest.hcl points its
  # expect_failures scenario at this block.
  validation {
    condition = alltrue([
      for id in values(var.account_ids) :
      length(id) == 12 && can(regex("^[0-9]+$", id))
    ])
    error_message = "Each account_ids value must be a 12-digit AWS account ID."
  }
}
