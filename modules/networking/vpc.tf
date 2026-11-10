# =============================================================================
# VPCs — one per entry in var.vpcs
# =============================================================================

resource "aws_vpc" "this" {
  for_each = local.vpc_map

  # Static CIDR (when no IPAM)
  cidr_block = each.value.ipam_pool_name == null ? each.value.cidr : null

  # IPAM-based CIDR (when IPAM pool is referenced)
  ipv4_ipam_pool_id   = each.value.ipam_pool_name != null ? local.ipam_pool_ids[each.value.ipam_pool_name] : null
  ipv4_netmask_length = each.value.ipam_pool_name != null ? each.value.ipam_netmask_length : null

  # Both default to true in var.vpcs; false belongs to isolated networks with
  # their own resolver.
  enable_dns_support   = each.value.enable_dns_support
  enable_dns_hostnames = each.value.enable_dns_hostnames

  # null writes nothing and leaves the AWS default ("default") in place.
  instance_tenancy = each.value.instance_tenancy

  # Per-entry tags first, the module's own Name last: the module keys this
  # resource by name and its outputs address it by that key, so a user-supplied
  # Name must not rename it (see README, section "Tagging").
  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# =============================================================================
# VPC Secondary CIDRs
# =============================================================================

locals {
  # Flattened secondary CIDRs: "vpc_name.cidr" → { vpc_name, cidr }
  secondary_cidr_map = merge([
    for vpc in var.vpcs : {
      for idx, cidr in vpc.secondary_cidrs : "${vpc.name}.${idx}" => {
        vpc_name = vpc.name
        cidr     = cidr
      }
    }
  ]...)
}

resource "aws_vpc_ipv4_cidr_block_association" "this" {
  for_each = local.secondary_cidr_map

  vpc_id     = aws_vpc.this[each.value.vpc_name].id
  cidr_block = each.value.cidr
}

# =============================================================================
# Internet gateways — one per VPC with public subnets
# =============================================================================

locals {
  # VPCs that have at least one public subnet
  vpcs_with_public_subnets = {
    for vpc_name, vpc in local.vpc_map : vpc_name => vpc
    if length([for s in vpc.subnets : s if s.type == "public"]) > 0
  }
}

resource "aws_internet_gateway" "this" {
  for_each = local.vpcs_with_public_subnets

  vpc_id = aws_vpc.this[each.key].id

  tags = {
    Name = "${each.key}-igw"
  }
}

# =============================================================================
# VPC Peering Connections
# =============================================================================

locals {
  # Peering map: "peering_name" → peering definition
  vpc_peering_map = {
    for p in var.vpc_peering : p.name => p
  }

  # Peering routes: create routes in both requester and accepter VPCs
  # For each peering, we need routes in every subnet of the requester VPC
  # pointing to the accepter VPC CIDR, and vice versa.
  peering_routes = merge(
    # Requester VPC subnets → accepter VPC CIDR
    merge([
      for p in var.vpc_peering : {
        for s in local.vpc_map[p.requester_vpc_name].subnets :
        "${p.name}.req.${p.requester_vpc_name}.${s.name}" => {
          peering_name = p.name
          subnet_key   = "${p.requester_vpc_name}.${s.name}"
          dest_cidr    = local.vpc_map[p.accepter_vpc_name].cidr
        }
      }
    ]...),
    # Accepter VPC subnets → requester VPC CIDR
    merge([
      for p in var.vpc_peering : {
        for s in local.vpc_map[p.accepter_vpc_name].subnets :
        "${p.name}.acc.${p.accepter_vpc_name}.${s.name}" => {
          peering_name = p.name
          subnet_key   = "${p.accepter_vpc_name}.${s.name}"
          dest_cidr    = local.vpc_map[p.requester_vpc_name].cidr
        }
      }
    ]...),
  )
}

resource "aws_vpc_peering_connection" "this" {
  for_each = local.vpc_peering_map

  vpc_id      = aws_vpc.this[each.value.requester_vpc_name].id
  peer_vpc_id = aws_vpc.this[each.value.accepter_vpc_name].id
  auto_accept = each.value.auto_accept

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# Routes for peering connections — both directions
resource "aws_route" "peering" {
  for_each = local.peering_routes

  route_table_id            = aws_route_table.this[each.value.subnet_key].id
  destination_cidr_block    = each.value.dest_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.this[each.value.peering_name].id
}

# =============================================================================
# Default VPC Deletion
# =============================================================================
# When delete_default_vpc is true, Terraform "adopts" the default VPC and its
# associated resources. The aws_default_vpc resource manages the default VPC
# lifecycle — once managed, Terraform controls it.
#
# What the first apply with the toggle on changes:
#   - it takes the region's default VPC, the default subnets of the zones in
#     default_vpc_availability_zones and the default security group into state;
#     a region or listed zone without one gets a NEW default VPC or subnet
#     (the provider creates what it cannot adopt);
#   - it removes every ingress and egress rule of the default security group
#     (aws_default_security_group below declares none);
#   - adopted default subnets stop assigning public IP addresses.
# What a later destroy (toggle back to false, or destroying the stack) does:
# it deletes the default subnets of the listed zones and then tries DeleteVpc,
# which AWS refuses (DependencyViolation) because the default VPC's internet
# gateway and the default subnets of unlisted zones are not managed here. The
# default VPC stays, the security group keeps no rules, and the apply ends in
# an error. The check below says so on every plan with the toggle on.
# modules/security/default-vpc.tf adopts the same VPC through its own toggle.

check "default_vpc_two_step_removal" {
  assert {
    condition     = !var.delete_default_vpc
    error_message = "delete_default_vpc is enabled. This apply takes the default VPC of the current account and region into Terraform state with the default subnets of default_vpc_availability_zones and the default security group, REMOVES every rule of that security group, and creates a default VPC or subnet where the region or a listed zone has none. Setting the toggle back to false (or destroying the stack) deletes the listed default subnets but does NOT delete the default VPC: AWS refuses DeleteVpc while its internet gateway and the other zones' default subnets remain, so that apply ends in an error and the VPC stays. Other accounts and regions each need their own apply of this module."
  }
}

resource "aws_default_vpc" "this" {
  count = var.delete_default_vpc ? 1 : 0

  force_destroy = true

  tags = {
    Name = "default-vpc-managed"
  }
}

resource "aws_default_subnet" "this" {
  for_each = var.delete_default_vpc ? toset(var.default_vpc_availability_zones) : toset([])

  availability_zone = each.value
  force_destroy     = true

  # The provider default for a default subnet is true. The caller asked for
  # removal, not for public addresses, so an adopted (or, in a zone without
  # one, newly created) default subnet hands out none until the second apply
  # removes it.
  map_public_ip_on_launch = false

  depends_on = [aws_default_vpc.this]
}

resource "aws_default_security_group" "this" {
  count = var.delete_default_vpc ? 1 : 0

  vpc_id = aws_default_vpc.this[0].id

  # Empty ingress/egress — removes all default rules
  tags = {
    Name = "default-sg-managed"
  }
}

# =============================================================================
# DHCP Options Sets
# =============================================================================

locals {
  # Map: dhcp_name → dhcp definition
  dhcp_options_map = {
    for dhcp in var.dhcp_options_sets : dhcp.name => dhcp
  }

  # Flattened DHCP-to-VPC associations: "dhcp_name.vpc_name" → { dhcp_name, vpc_name }
  dhcp_vpc_association_map = merge([
    for dhcp in var.dhcp_options_sets : {
      for vpc_name in dhcp.vpc_names : "${dhcp.name}.${vpc_name}" => {
        dhcp_name = dhcp.name
        vpc_name  = vpc_name
      }
    }
  ]...)
}

resource "aws_vpc_dhcp_options" "this" {
  for_each = local.dhcp_options_map

  domain_name          = each.value.domain_name
  domain_name_servers  = each.value.domain_name_servers
  ntp_servers          = each.value.ntp_servers
  netbios_name_servers = each.value.netbios_name_servers
  netbios_node_type    = each.value.netbios_node_type != null ? tostring(each.value.netbios_node_type) : null

  tags = merge(each.value.tags, {
    Name = each.key
  })
}

resource "aws_vpc_dhcp_options_association" "this" {
  for_each = local.dhcp_vpc_association_map

  vpc_id          = aws_vpc.this[each.value.vpc_name].id
  dhcp_options_id = aws_vpc_dhcp_options.this[each.value.dhcp_name].id
}

# =============================================================================
# Elastic IPs
# =============================================================================

resource "aws_eip" "this" {
  for_each = {
    for eip in var.elastic_ips : eip.name => eip
  }

  domain = "vpc"

  # Merge order aligned with every other tagged resource of the module: the
  # module's Name wins over a user-supplied one (see README, section "Tagging").
  tags = merge(each.value.tags, {
    Name = each.key
  })
}

# =============================================================================
# Outposts — Local Gateway route table associations
# =============================================================================

locals {
  # Declared Outposts: "vpc_name.outpost_name" → ARN, read by aws_subnet for
  # subnets that reference an Outpost by name instead of by ARN.
  outpost_arn_map = merge([
    for vpc in var.vpcs : {
      for o in vpc.outposts : "${vpc.name}.${o.name}" => o.arn
    }
  ]...)

  # Local gateways by name: "vpc_name.local_gateway_name" → id. Route targets
  # of target_type "local_gateway" resolve against this map.
  lgw_id_map = merge([
    for vpc in var.vpcs : {
      for o in vpc.outposts : "${vpc.name}.${o.local_gateway.name}" => o.local_gateway.id
      if o.local_gateway != null
    }
  ]...)

  # Flattened associations: "vpc_name.outpost_name.route_table_name" →
  # { vpc_name, route_table_id }. Each listed local gateway route table is
  # associated with the VPC so Outpost subnets can route on-premises.
  lgw_route_table_association_map = merge([
    for vpc in var.vpcs : merge([
      for o in vpc.outposts : {
        for rt in o.local_gateway == null ? [] : o.local_gateway.route_tables :
        "${vpc.name}.${o.name}.${rt.name}" => {
          vpc_name       = vpc.name
          route_table_id = rt.id
        }
      }
    ]...)
  ]...)
}

resource "aws_ec2_local_gateway_route_table_vpc_association" "this" {
  for_each = local.lgw_route_table_association_map

  local_gateway_route_table_id = each.value.route_table_id
  vpc_id                       = aws_vpc.this[each.value.vpc_name].id

  tags = {
    Name = each.key
  }
}

# =============================================================================
# IPv6 Support
# =============================================================================

locals {
  # VPCs with an IPv6 range: the Amazon-provided /56 of enable_ipv6, an entry
  # of ipv6_cidrs, or both.
  ipv6_vpc_map = {
    for vpc in var.vpcs : vpc.name => vpc
    if vpc.enable_ipv6 || length(vpc.ipv6_cidrs) > 0
  }

  # The first IPv6 source of each VPC. It carries the association the subnets
  # derive their /64 from, and it keeps the resource key a configuration with
  # enable_ipv6 already has. The fields are spelled out instead of merged so
  # that the Amazon case cannot pick up a range or a prefix length by accident.
  ipv6_primary_source_map = {
    for vpc_name, vpc in local.ipv6_vpc_map : vpc_name => {
      amazon_provided = vpc.enable_ipv6 || try(vpc.ipv6_cidrs[0].amazon_provided, false)
      byoip_pool_id   = vpc.enable_ipv6 ? null : try(vpc.ipv6_cidrs[0].byoip_pool_id, null)
      cidr_block      = vpc.enable_ipv6 ? null : try(vpc.ipv6_cidrs[0].cidr_block, null)
      ipam_pool_name  = vpc.enable_ipv6 ? null : try(vpc.ipv6_cidrs[0].ipam_pool_name, null)
      netmask_length  = vpc.enable_ipv6 ? null : try(vpc.ipv6_cidrs[0].netmask_length, null)
    }
  }

  # Every further source: "vpc_name.idx" → the entry. enable_ipv6 occupies the
  # primary slot, so with the switch set every list entry lands here; without
  # it the first entry is the primary and the rest follow.
  ipv6_additional_source_map = merge([
    for vpc_name, vpc in local.ipv6_vpc_map : {
      for idx, source in vpc.ipv6_cidrs : "${vpc_name}.${idx}" => merge(source, {
        vpc_name = vpc_name
      })
      if idx > (vpc.enable_ipv6 ? -1 : 0)
    }
  ]...)

  # How many bits a subnet's /64 adds to the VPC's IPv6 prefix. The
  # Amazon-provided range and a BYOIP range without an explicit block are
  # always /56, an explicit block and an IPAM request carry their own prefix —
  # without this the module would cut a /56 out of a /48 and call it a subnet.
  ipv6_subnet_newbits = {
    for vpc_name, source in local.ipv6_primary_source_map : vpc_name => (
      source.cidr_block != null ? 64 - tonumber(split("/", source.cidr_block)[1]) : (
        source.netmask_length != null ? 64 - source.netmask_length : 8
      )
    )
  }

  # Subnets with IPv6 CIDR suffix specified (only in IPv6-enabled VPCs)
  ipv6_subnet_map = {
    for key, s in local.subnet_map : key => s
    if lookup(local.ipv6_vpc_map, s.vpc_name, null) != null && s.ipv6_cidr_suffix != null
  }

  # IPv6 subnets needing egress-only IGW routes (private/isolated with IPv6)
  ipv6_private_subnets = {
    for key, s in local.ipv6_subnet_map : key => s
    if contains(["private", "isolated"], s.type)
  }

  # IPv6 subnets needing IGW routes (public with IPv6)
  ipv6_public_subnets = {
    for key, s in local.ipv6_subnet_map : key => s
    if s.type == "public"
  }

  # VPCs needing an egress-only IGW. The explicit switch wins; null keeps the
  # derivation — a VPC with an IPv6 range and at least one private or isolated
  # IPv6 subnet.
  eigw_vpc_map = {
    for vpc_name, vpc in local.vpc_map : vpc_name => vpc
    if vpc.egress_only_igw != null ? vpc.egress_only_igw : (
      lookup(local.ipv6_vpc_map, vpc_name, null) != null
      && length([for key, s in local.ipv6_subnet_map : s if s.vpc_name == vpc_name && contains(["private", "isolated"], s.type)]) > 0
    )
  }
}

resource "aws_vpc_ipv6_cidr_block_association" "this" {
  for_each = local.ipv6_primary_source_map

  vpc_id = aws_vpc.this[each.key].id

  # Amazon-provided /56 — what enable_ipv6 requests. null on the
  # other sources: the argument excludes the pool and range arguments below.
  assign_generated_ipv6_cidr_block = each.value.amazon_provided ? true : null

  # BYOIP: the address pool the range comes from, and optionally the range.
  ipv6_pool       = each.value.byoip_pool_id
  ipv6_cidr_block = each.value.cidr_block

  # IPAM-sourced range: the pool by name, and the requested prefix length.
  ipv6_ipam_pool_id   = each.value.ipam_pool_name != null ? local.ipam_pool_ids[each.value.ipam_pool_name] : null
  ipv6_netmask_length = each.value.ipam_pool_name != null ? each.value.netmask_length : null
}

# --- Further IPv6 ranges of the same VPC ---
# A VPC carries up to five IPv6 ranges. The first one is the association above,
# because that is the resource key an existing configuration already has; every
# further range is keyed "vpc_name.idx" so that appending one leaves the
# existing keys alone.

resource "aws_vpc_ipv6_cidr_block_association" "additional" {
  for_each = local.ipv6_additional_source_map

  vpc_id = aws_vpc.this[each.value.vpc_name].id

  assign_generated_ipv6_cidr_block = each.value.amazon_provided ? true : null

  ipv6_pool       = each.value.byoip_pool_id
  ipv6_cidr_block = each.value.cidr_block

  ipv6_ipam_pool_id   = each.value.ipam_pool_name != null ? local.ipam_pool_ids[each.value.ipam_pool_name] : null
  ipv6_netmask_length = each.value.ipam_pool_name != null ? each.value.netmask_length : null
}

# --- Egress-Only Internet Gateways (one per IPv6-enabled VPC with private/isolated subnets) ---

resource "aws_egress_only_internet_gateway" "this" {
  for_each = local.eigw_vpc_map

  vpc_id = aws_vpc.this[each.key].id

  tags = {
    Name = "${each.key}-eigw"
  }
}

# --- IPv6 Routes: private/isolated subnets → Egress-Only IGW ---

resource "aws_route" "ipv6_private" {
  for_each = local.ipv6_private_subnets

  route_table_id              = aws_route_table.this[each.key].id
  destination_ipv6_cidr_block = "::/0"
  egress_only_gateway_id      = aws_egress_only_internet_gateway.this[each.value.vpc_name].id
}

# --- IPv6 Routes: public subnets → existing Internet Gateway ---

resource "aws_route" "ipv6_public" {
  for_each = local.ipv6_public_subnets

  route_table_id              = aws_route_table.this[each.key].id
  destination_ipv6_cidr_block = "::/0"
  gateway_id                  = aws_internet_gateway.this[each.value.vpc_name].id
}

# =============================================================================
# ACM Certificates
# =============================================================================

locals {
  acm_cert_map = { for cert in var.acm_certificates : cert.domain_name => cert }

  acm_requested_certs = {
    for domain, cert in local.acm_cert_map : domain => cert
    if cert.type == "request"
  }

  acm_dns_certs = {
    for domain, cert in local.acm_requested_certs : domain => cert
    if cert.validation_method == "DNS"
  }

  acm_email_certs = {
    for domain, cert in local.acm_requested_certs : domain => cert
    if cert.validation_method == "EMAIL"
  }

  # Validation records land only for requested DNS certificates that name one
  # of the module's zones. The keys are derived from the configuration alone
  # ("<certificate>|<domain>", the *. prefix stripped) so the map is known at
  # plan time; an apex domain and its wildcard share one record.
  acm_validation_record_map = merge([
    for domain, cert in local.acm_dns_certs : {
      for name in distinct([for d in concat([cert.domain_name], cert.subject_alternative_names) : trimprefix(d, "*.")]) :
      "${domain}|${name}" => {
        cert_key = domain
        domain   = name
        zone     = cert.validation_zone_name
      }
    } if cert.validation_zone_name != null
  ]...)

  # A zone of var.route53_zones becomes private as soon as a VPC is attached —
  # its own vpc_ids, or every VPC of this module when that list is empty. ACM
  # validates a public certificate against public DNS only and cannot read a
  # private hosted zone, so a validation record written there never completes
  # the issuance: the wait below runs into its timeout instead. The check block
  # names the affected certificates in the plan.
  acm_validation_private_zone_certs = {
    for domain, cert in local.acm_dns_certs : domain => cert.validation_zone_name
    if cert.validation_zone_name != null && anytrue([
      for zone in var.route53_zones :
      length(zone.vpc_ids) > 0 || length(var.vpcs) > 0
      if zone.name == cert.validation_zone_name
    ])
  }
}

resource "aws_acm_certificate" "this" {
  for_each = local.acm_cert_map

  # Request path — null on an import, where ACM reads the domains from the
  # certificate itself.
  domain_name               = each.value.type == "request" ? each.value.domain_name : null
  subject_alternative_names = each.value.type == "request" ? each.value.subject_alternative_names : null
  validation_method         = each.value.type == "request" ? each.value.validation_method : null
  key_algorithm             = each.value.type == "request" ? each.value.key_algorithm : null

  # Import path — the material is a variable value (acm_certificate_material,
  # sensitive), never a file in the repository.
  private_key       = each.value.type == "import" ? var.acm_certificate_material[each.key].private_key : null
  certificate_body  = each.value.type == "import" ? var.acm_certificate_material[each.key].certificate_body : null
  certificate_chain = each.value.type == "import" ? var.acm_certificate_material[each.key].certificate_chain : null

  tags = merge(each.value.tags, {
    Name = each.key
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "acm_validation" {
  for_each = local.acm_validation_record_map

  zone_id         = aws_route53_zone.private[each.value.zone].zone_id
  allow_overwrite = true
  ttl             = 60

  # The record data comes from the certificate's domain_validation_options —
  # unknown until the certificate exists, while the record's identity (the
  # for_each key) is derived from the configuration alone.
  name    = [for dvo in aws_acm_certificate.this[each.value.cert_key].domain_validation_options : dvo.resource_record_name if trimprefix(dvo.domain_name, "*.") == each.value.domain][0]
  type    = [for dvo in aws_acm_certificate.this[each.value.cert_key].domain_validation_options : dvo.resource_record_type if trimprefix(dvo.domain_name, "*.") == each.value.domain][0]
  records = [[for dvo in aws_acm_certificate.this[each.value.cert_key].domain_validation_options : dvo.resource_record_value if trimprefix(dvo.domain_name, "*.") == each.value.domain][0]]
}

resource "aws_acm_certificate_validation" "dns" {
  for_each = local.acm_dns_certs

  certificate_arn = aws_acm_certificate.this[each.key].arn

  # Only set for certificates whose records the module writes itself; null
  # keeps the wait-only behaviour for externally validated certificates.
  validation_record_fqdns = each.value.validation_zone_name != null ? [
    for key, record in aws_route53_record.acm_validation : record.fqdn if startswith(key, "${each.key}|")
  ] : null
}

check "acm_email_validation_warning" {
  assert {
    condition     = length(local.acm_email_certs) == 0
    error_message = "ACM certificates with EMAIL validation detected: [${join(", ", keys(local.acm_email_certs))}]. Email validation requires manual action — check your inbox for validation emails from AWS."
  }
}

check "acm_validation_zone_is_private_warning" {
  assert {
    condition     = length(local.acm_validation_private_zone_certs) == 0
    error_message = "ACM certificates whose validation_zone_name names a private hosted zone detected: [${join(", ", [for domain, zone in local.acm_validation_private_zone_certs : "${domain} -> ${zone}"])}]. The module writes the validation records, but ACM reads public DNS only and cannot validate against a private zone, so the issuance wait runs into its timeout. Use a zone without an attached VPC, or leave validation_zone_name unset and create the records in the public DNS of the domain."
  }
}
