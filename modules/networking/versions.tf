terraform {
  required_version = ">= 1.14"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    # Only for the flow-log drain window in flow-logs.tf. Same constraint the
    # other modules of this repository already pin (logging, deployment-role,
    # control-tower).
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }
}
