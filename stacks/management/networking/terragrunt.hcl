# Networking — VPCs, Transit Gateway, Route53, IPAM, Network Firewall

include "root" {
  path = find_in_parent_folders("root.hcl")
}

locals {
  common     = read_terragrunt_config(find_in_parent_folders("env/common.hcl"))
  accounts   = read_terragrunt_config(find_in_parent_folders("env/accounts.hcl"))
  compliance = read_terragrunt_config("${get_repo_root()}/configurations/loader.hcl")

  # --- authenticated edge guard (begin) ---
  # An authenticated edge hands its OIDC client secret to the listener's
  # authenticate-oidc action, and so into the Terraform STATE, whichever way
  # it arrives: client_secret_arn is read from Secrets Manager into the same
  # listener attribute. With state_backend = "local" that state is a plain
  # JSON file on the operator's disk, so any listener with an
  # authenticated_edge needs the encrypted S3 backend. A literal client_secret
  # is refused on every backend: this stack's only input is env/common.hcl, a
  # file, and the module promises the value never arrives as a literal in a
  # file — client_secret_arn is the only stack path. Both inputs are known at
  # config time, so the refusal uses the file() abort form of root.hcl's
  # _state_dir_guard: it stops before Terraform runs and before any secret is
  # read, and is a no-op ("ok") when no listener declares an edge.
  _edge_listeners = flatten([
    for lb in local.compliance.locals.load_balancers : [
      for l in try(lb.listeners, []) :
      format("load balancer %q (scheme = %q) listener port %s", lb.name, try(lb.scheme, "internal"), try(tostring(l.port), "?"))
      if try(l.authenticated_edge, null) != null
    ]
  ])
  _edge_literal_secrets = flatten([
    for lb in local.compliance.locals.load_balancers : [
      for l in try(lb.listeners, []) :
      format("load balancer %q listener port %s", lb.name, try(tostring(l.port), "?"))
      if try(l.authenticated_edge.client_secret, null) != null
    ]
  ])
  _edge_state_guard = (
    length(local._edge_literal_secrets) == 0
    && (length(local._edge_listeners) == 0 || local.common.locals.state_backend == "s3")
    ) ? "ok" : file(join(" ", compact([
      length(local._edge_literal_secrets) == 0 ? "" : format(
        "ERROR: authenticated_edge with a literal client_secret in env/common.hcl (%s). Name the secret with client_secret_arn (a Secrets Manager secret) instead; that is the only path this stack takes.",
        join("; ", local._edge_literal_secrets)
      ),
      length(local._edge_listeners) == 0 || local.common.locals.state_backend == "s3" ? "" : format(
        "ERROR: authenticated_edge while state_backend = %q (%s). The OIDC client secret is written into the Terraform state, which the local backend keeps as a plain file on disk. Set state_backend = \"s3\" in env/common.hcl after the state bootstrap, or make the load balancer scheme = \"internal\" and drop its authenticated_edge.",
        local.common.locals.state_backend, join("; ", local._edge_listeners)
      ),
  ])))
  # --- authenticated edge guard (end) ---
}

exclude {
  if      = !local.common.locals.enable_networking
  actions = ["all"]
}

terraform {
  source = "${get_repo_root()}//modules/networking"
}

dependency "config_rules" {
  config_path  = "../config-rules"
  skip_outputs = true
  # Ordering dependency only — networking doesn't need config-rules outputs
}

dependency "accounts" {
  config_path = "../accounts"

  mock_outputs = {
    active_account_ids = {}
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "logging" {
  config_path = "../logging"

  mock_outputs = {
    central_log_bucket_name = ""
    elb_log_bucket_name     = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

dependency "security" {
  config_path = "../security"

  mock_outputs = {
    per_account_cloudwatch_kms_key_arn = ""
  }
  mock_outputs_allowed_terraform_commands = ["init", "validate", "plan"]
}

inputs = {
  vpcs = local.common.locals.vpcs
  transit_gateway = local.common.locals.apply_network_defaults ? merge(
    local.common.locals.transit_gateway,
    lookup(local.compliance.locals.networking_defaults, "transit_gateway_enabled", false) ? {
      enabled = true
    } : {}
  ) : local.common.locals.transit_gateway
  route53_zones = local.common.locals.route53_zones
  network_firewall = local.common.locals.apply_network_defaults ? merge(
    local.common.locals.network_firewall,
    lookup(local.compliance.locals.networking_defaults, "network_firewall_enabled", false) ? {
      enabled = true
    } : {}
  ) : local.common.locals.network_firewall
  ipam                           = local.common.locals.ipam
  prefix_lists                   = local.common.locals.prefix_lists
  account_ids                    = dependency.accounts.outputs.active_account_ids
  central_log_bucket_name        = dependency.logging.outputs.central_log_bucket_name
  delete_default_vpc             = try(local.common.locals.delete_default_vpc, false)
  default_vpc_availability_zones = try(local.common.locals.default_vpc_availability_zones, [])
  acm_certificates               = try(local.common.locals.acm_certificates, [])
  enable_ram_sharing             = try(local.common.locals.enable_ram_sharing, false)
  # Share targets of the query logging configuration follow the same optional
  # pass-through as enable_ram_sharing (RAM sharing stays a pure opt-in).
  route53_query_logging_share_targets = try(local.common.locals.route53_query_logging_share_targets, [])
  # Material for imported certificates: optional, sensitive on the module side.
  acm_certificate_material = try(local.common.locals.acm_certificate_material, {})
  # CloudWatch log groups of the networking module follow the per-account
  # CloudWatch key of the security stack: the output carries the key ARN while
  # enable_per_account_kms_keys is active and an empty string otherwise (the
  # module then keeps the CloudWatch service default encryption).
  cloudwatch_logs_kms_key_arn = dependency.security.outputs.per_account_cloudwatch_kms_key_arn

  # --- VPC scaffolding and templates ---
  # vpc_templates is documentation/intent: the module expands the templates into
  # vpc_template_expanded_keys and warns for unknown accounts instead of
  # creating cross-account VPCs, because Terraform cannot create providers
  # dynamically. The stack only passes the value through.
  dhcp_options_sets = local.compliance.locals.dhcp_options_sets
  elastic_ips       = local.compliance.locals.elastic_ips
  endpoint_policies = local.compliance.locals.endpoint_policies
  # vpc_flow_logs_enabled from the frameworks' networking_defaults maps onto
  # vpc_flow_logs_default: when the defaults are applied, a
  # framework asks for flow logs and the operator has not configured a
  # flow-log object, the stack supplies the baseline (all traffic to the
  # central log bucket the stack already wires). An operator-supplied object
  # always wins — the framework key only fills the gap, mirroring the
  # transit_gateway_enabled / network_firewall_enabled pattern above.
  vpc_flow_logs_default = (
    local.common.locals.apply_network_defaults
    && lookup(local.compliance.locals.networking_defaults, "vpc_flow_logs_enabled", false)
    && local.compliance.locals.vpc_flow_logs_default == null
    ) ? {
    destination = "s3"
  } : local.compliance.locals.vpc_flow_logs_default
  # private_subnet_only from the frameworks' networking_defaults reaches the
  # module as an advisory flag: the module warns (check block) when public
  # subnets are configured against the framework's intent.
  private_subnet_only = (
    local.common.locals.apply_network_defaults
    && lookup(local.compliance.locals.networking_defaults, "private_subnet_only", false)
  )
  vpc_templates = local.compliance.locals.vpc_templates

  # --- Load balancing ---
  # Load balancers without an explicit access_logs block write their access
  # logs into the central ELB log bucket of the logging stack — the bucket
  # whose policy grants the ELB log delivery service write access. An empty
  # bucket name (enable_elb_log_bucket off) leaves access logging to the
  # per-LB configuration.
  load_balancers = [
    for lb in local.compliance.locals.load_balancers :
    merge(lb, {
      access_logs = try(lb.access_logs, null) != null ? lb.access_logs : (
        dependency.logging.outputs.elb_log_bucket_name != "" ? {
          bucket  = dependency.logging.outputs.elb_log_bucket_name
          prefix  = lb.name
          enabled = true
        } : null
      )
    })
  ]
  target_groups          = local.compliance.locals.target_groups
  gateway_load_balancers = local.compliance.locals.gateway_load_balancers
  # The OIDC issuers an authenticated edge may name; the module
  # refuses any other issuer and an internet-facing entry while this is empty.
  authenticated_edge_allowed_issuers = local.compliance.locals.authenticated_edge_allowed_issuers

  # --- Hybrid connectivity ---
  # The S3 destination of the TGW flow logs writes into the central log bucket
  # that central_log_bucket_name above already carries from dependency.logging;
  # the CloudWatch destination creates its own log group in the module.
  # tgw_multicast_domains is deferred in the module: a check block warns as long
  # as the list is non-empty, so the value is passed through but creates nothing.
  vpc_peering               = local.compliance.locals.vpc_peering
  dx_gateways               = local.compliance.locals.dx_gateways
  customer_gateways         = local.compliance.locals.customer_gateways
  tgw_connect_attachments   = local.compliance.locals.tgw_connect_attachments
  tgw_multicast_domains     = local.compliance.locals.tgw_multicast_domains
  enable_tgw_flow_logs      = local.compliance.locals.enable_tgw_flow_logs
  tgw_flow_logs_destination = local.compliance.locals.tgw_flow_logs_destination
  # Retention and S3 key prefix of the TGW flow logs (destination "both"
  # delivers to S3 and CloudWatch at the same time).
  tgw_flow_logs_retention_days = local.compliance.locals.tgw_flow_logs_retention_days
  tgw_flow_logs_s3_path        = local.compliance.locals.tgw_flow_logs_s3_path

  # --- DNS, resolver, query logging ---
  # enable_route53_query_logging is the feature's single toggle.
  dns_firewall_rule_groups          = local.compliance.locals.dns_firewall_rule_groups
  resolver_endpoints                = local.compliance.locals.resolver_endpoints
  resolver_rules                    = local.compliance.locals.resolver_rules
  enable_route53_query_logging      = local.compliance.locals.enable_route53_query_logging
  route53_query_logging_destination = local.compliance.locals.route53_query_logging_destination
  route53_query_logging_vpc_names   = local.compliance.locals.route53_query_logging_vpc_names
  # Shared subnet tags in recipient accounts: materialises declared tags on
  # RAM-shared subnets this account RECEIVED (aws_ec2_tag). Off by default;
  # a recipient account's networking stack sets both from its configuration.
  enable_shared_subnet_tagging = try(local.common.locals.enable_shared_subnet_tagging, false)
  shared_subnet_tags           = try(local.common.locals.shared_subnet_tags, [])
}
