"""regression: IPAM-fed VPCs, subnets and IPv6 ranges did not wait for the pool's CIDR.

An IPAM pool allocates only from a CIDR provisioned to it, but the VPC, the
subnet and the IPv6 range associations of modules/networking referenced the
pool ID alone. Nothing ordered them after aws_vpc_ipam_pool_cidr, so a first
apply could ask an empty pool for a range. The test reads each resource block
and requires a depends_on on both pool CIDR resources.
"""

import re
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / "modules/networking"
RESOURCES = [
    ("vpc.tf", "aws_vpc", "this"),
    ("subnets.tf", "aws_subnet", "this"),
    ("vpc.tf", "aws_vpc_ipv6_cidr_block_association", "this"),
    ("vpc.tf", "aws_vpc_ipv6_cidr_block_association", "additional"),
]


def _block(text, rtype, name):
    start = text.index(f'resource "{rtype}" "{name}" {{')
    depth = 0
    for i in range(text.index("{", start), len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start : i + 1]
    raise AssertionError(f"unterminated block {rtype}.{name}")


@pytest.mark.parametrize("filename,rtype,name", RESOURCES)
def test_ipam_fed_resource_depends_on_pool_cidrs(filename, rtype, name):
    block = _block((MODULE / filename).read_text(encoding="utf-8"), rtype, name)
    match = re.search(r"^\s*depends_on\s*=\s*\[([^\]]*)\]", block, re.MULTILINE)
    assert match, f"{rtype}.{name} has no depends_on"
    targets = {t.strip() for t in match.group(1).split(",") if t.strip()}
    assert {"aws_vpc_ipam_pool_cidr.this", "aws_vpc_ipam_pool_cidr.additional"} <= targets, (
        f"{rtype}.{name} must depend on both pool CIDR resources, has {sorted(targets)}"
    )
