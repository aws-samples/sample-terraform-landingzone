# =============================================================================
# Overlay gate: every managed rule the module produces from a committed
# compliance overlay carries the parameters AWS refuses it without
# =============================================================================
# A managed rule whose identifier has a required parameter is refused by AWS
# when the overlay passes input_parameters = {}: PutOrganizationConfigRule
# answers 400 InvalidParameterValueException "The required parameter [...] is
# not present in the inputParameters", and the whole profile is undeployable.
# This gate is deliberately not a text check of the tfvars:
#
#   1. run "load_<overlay>" decodes configurations/frameworks/<overlay>.tfvars
#      with Terraform's own tfvars decoder (tests/overlay-loader), i.e. the
#      overlay as committed, not a copy of it;
#   2. run "<overlay>" plans THIS module with that managed_rules value and
#      asserts on aws_config_organization_managed_rule.this — the rules the
#      module would send to AWS — against the identifier table the loader
#      carries (provenance in tests/overlay-loader/main.tf), twice over:
#      every rule_identifier has a row in the table (closed world), and every
#      parameter the row marks mandatory is present in input_parameters.
#
# Two kinds of defect, kept apart because AWS refuses them differently and one
# fix does not cover the other:
#   - missing mandatory parameter: a real identifier, input_parameters without
#     a parameter its template marks Required (for example
#     CLOUDWATCH_ALARM_ACTION_CHECK). Caught by the parameter assert.
#   - unknown identifier: no managed rule exists under that name at all (for
#     example EC2_INSTANCES_IN_VPC; the rule ec2-instances-in-vpc is
#     identified INSTANCES_IN_VPC). Its one parameter, vpcId, is Optional, so
#     the parameter assert is structurally blind to it, and a table with rows
#     only for identifiers with a Required group would default every other
#     identifier to "nothing required". Caught by the closed-world assert.
#
# Both asserts bite: with an overlay's CLOUDWATCH_ALARM_ACTION_CHECK set to
# input_parameters = {} its run fails on the parameter assertion, and an
# identifier like EC2_INSTANCES_IN_VPC or a misspelling fails the closed-world
# assertion naming that identifier.
#
# Scope: the table has a row for every identifier the eight overlays use, so
# an identifier without a row is RED, not unchecked. A row proves AWS published
# a template under that identifier when the row was written and transcribes
# that template's Required group; it does
# not prove PutOrganizationConfigRule accepts the rule in a given account
# (only the live apply-test in tests/live/modules/config-rules/ measures that,
# for fedramp-high alone; c5-2020, cmmc, hipaa, iso-27001, nist-800-171 and
# nist-800-53 are applied nowhere, so this plan test is the only thing that
# runs the module against them at all). A valid identifier the table has not
# met is red too, until its row is added — the error message says where.
#
# Adding an overlay: the first loader run asserts the set of overlay files
# equals the eight named here, so a ninth file makes this gate red until it
# gets its own pair of run blocks below.

mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }
}

mock_provider "archive" {}

# -----------------------------------------------------------------------------
# c5-2020
# -----------------------------------------------------------------------------
run "load_c5_2020" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "c5-2020"
  }

  # Every overlay file present is covered by a run pair below — a new file
  # turns this red instead of silently going unchecked.
  assert {
    condition = output.frameworks == toset([
      "c5-2020", "cmmc", "fedramp-high", "fedramp-moderate",
      "hipaa", "iso-27001", "nist-800-171", "nist-800-53",
    ])
    error_message = "configurations/frameworks holds overlays this gate does not run: ${join(", ", sort(output.frameworks))}. Add a load_<overlay>/<overlay> run pair for each new file."
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "c5-2020 decoded to zero managed rules — the loader would test nothing."
  }
}

run "c5_2020" {
  command = plan
  variables {
    managed_rules = run.load_c5_2020.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_c5_2020.managed_rules)
    error_message = "c5-2020: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_c5_2020.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_c5_2020.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "c5-2020: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_c5_2020.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_c5_2020.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "c5-2020: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_c5_2020.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_c5_2020.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# cmmc
# -----------------------------------------------------------------------------
run "load_cmmc" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "cmmc"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "cmmc decoded to zero managed rules — the loader would test nothing."
  }
}

run "cmmc" {
  command = plan
  variables {
    managed_rules = run.load_cmmc.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_cmmc.managed_rules)
    error_message = "cmmc: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_cmmc.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_cmmc.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "cmmc: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_cmmc.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_cmmc.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "cmmc: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_cmmc.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_cmmc.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# fedramp-high
# -----------------------------------------------------------------------------
run "load_fedramp_high" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "fedramp-high"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "fedramp-high decoded to zero managed rules — the loader would test nothing."
  }
}

run "fedramp_high" {
  command = plan
  variables {
    managed_rules = run.load_fedramp_high.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_fedramp_high.managed_rules)
    error_message = "fedramp-high: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_fedramp_high.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_fedramp_high.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "fedramp-high: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_fedramp_high.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_fedramp_high.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "fedramp-high: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_fedramp_high.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_fedramp_high.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# fedramp-moderate
# -----------------------------------------------------------------------------
run "load_fedramp_moderate" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "fedramp-moderate"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "fedramp-moderate decoded to zero managed rules — the loader would test nothing."
  }
}

run "fedramp_moderate" {
  command = plan
  variables {
    managed_rules = run.load_fedramp_moderate.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_fedramp_moderate.managed_rules)
    error_message = "fedramp-moderate: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_fedramp_moderate.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_fedramp_moderate.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "fedramp-moderate: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_fedramp_moderate.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_fedramp_moderate.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "fedramp-moderate: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_fedramp_moderate.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_fedramp_moderate.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# hipaa
# -----------------------------------------------------------------------------
run "load_hipaa" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "hipaa"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "hipaa decoded to zero managed rules — the loader would test nothing."
  }
}

run "hipaa" {
  command = plan
  variables {
    managed_rules = run.load_hipaa.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_hipaa.managed_rules)
    error_message = "hipaa: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_hipaa.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_hipaa.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "hipaa: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_hipaa.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_hipaa.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "hipaa: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_hipaa.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_hipaa.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# iso-27001
# -----------------------------------------------------------------------------
run "load_iso_27001" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "iso-27001"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "iso-27001 decoded to zero managed rules — the loader would test nothing."
  }
}

run "iso_27001" {
  command = plan
  variables {
    managed_rules = run.load_iso_27001.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_iso_27001.managed_rules)
    error_message = "iso-27001: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_iso_27001.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_iso_27001.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "iso-27001: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_iso_27001.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_iso_27001.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "iso-27001: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_iso_27001.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_iso_27001.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# nist-800-171
# -----------------------------------------------------------------------------
run "load_nist_800_171" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "nist-800-171"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "nist-800-171 decoded to zero managed rules — the loader would test nothing."
  }
}

run "nist_800_171" {
  command = plan
  variables {
    managed_rules = run.load_nist_800_171.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_nist_800_171.managed_rules)
    error_message = "nist-800-171: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_nist_800_171.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_nist_800_171.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "nist-800-171: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_nist_800_171.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_nist_800_171.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "nist-800-171: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_nist_800_171.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_nist_800_171.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}

# -----------------------------------------------------------------------------
# nist-800-53
# -----------------------------------------------------------------------------
run "load_nist_800_53" {
  command = plan
  module {
    source = "./tests/overlay-loader"
  }
  variables {
    framework = "nist-800-53"
  }

  assert {
    condition     = length(output.managed_rules) > 0
    error_message = "nist-800-53 decoded to zero managed rules — the loader would test nothing."
  }
}

run "nist_800_53" {
  command = plan
  variables {
    managed_rules = run.load_nist_800_53.managed_rules
  }

  assert {
    condition     = length(aws_config_organization_managed_rule.this) == length(run.load_nist_800_53.managed_rules)
    error_message = "nist-800-53: the module produced ${length(aws_config_organization_managed_rule.this)} organization rules for ${length(run.load_nist_800_53.managed_rules)} overlay entries."
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      contains(keys(run.load_nist_800_53.mandatory_parameters), r.rule_identifier)
    ])
    error_message = "nist-800-53: rule identifiers with no row in the loader's table (misspelt, or new: read its AWS template and add the row in tests/overlay-loader/main.tf): ${join(", ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier})"
      if !contains(keys(run.load_nist_800_53.mandatory_parameters), r.rule_identifier)
    ])}"
  }

  assert {
    condition = alltrue([
      for r in aws_config_organization_managed_rule.this :
      length(setsubtract(
        toset(lookup(run.load_nist_800_53.mandatory_parameters, r.rule_identifier, [])),
        toset(try(keys(jsondecode(r.input_parameters)), []))
      )) == 0
    ])
    error_message = "nist-800-53: rules AWS would refuse for a missing mandatory parameter: ${join("; ", [
      for name, r in aws_config_organization_managed_rule.this :
      "${name} (${r.rule_identifier}) lacks ${join(", ", setsubtract(toset(lookup(run.load_nist_800_53.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), []))))}"
      if length(setsubtract(toset(lookup(run.load_nist_800_53.mandatory_parameters, r.rule_identifier, [])), toset(try(keys(jsondecode(r.input_parameters)), [])))) > 0
    ])}"
  }
}
