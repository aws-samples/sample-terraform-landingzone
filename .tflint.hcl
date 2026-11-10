# TFLint configuration — referenced by the `lint` target of the Makefile
# (`tflint --init --config .tflint.hcl` followed by `tflint --config .tflint.hcl`).
#
# Both plugin versions are pinned. `tflint --init` downloads exactly the pinned
# release, which keeps the lint result reproducible across machines and CI runs.

# No `config` block on purpose: its attribute names changed between tflint
# releases, and the defaults already match how the `lint` target is invoked —
# every module is inspected where its code lives.

# Core Terraform ruleset (naming conventions, unused declarations, deprecated
# syntax). Bundled with tflint, therefore no source/version.
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

# AWS provider ruleset: invalid resource arguments, invalid instance/family
# names, missing required attributes.
plugin "aws" {
  enabled = true
  version = "0.48.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

# The project keeps every variable and output documented in the module README,
# which the interface consistency test verifies. The corresponding tflint rules
# stay enabled on purpose — they are the second, tool-side guard for the same
# convention.
rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

rule "terraform_typed_variables" {
  enabled = true
}

# Provider and Terraform version constraints are set in every module's
# versions.tf; the rule keeps that invariant enforced.
rule "terraform_required_version" {
  enabled = true
}

rule "terraform_required_providers" {
  enabled = true
}
