"""regression: the quarantine OU reaches both units from env/common.hcl.

The quarantine SCP is attached to the OU named in ``quarantine_ou_name`` by the
organization unit, and the accounts unit creates an account declared with
``quarantined = true`` inside that OU, whose id it reads from the organization
unit's output ``quarantine_ou_id``. Rendered from the example: the organization
unit passes ``quarantine_ou_name = "Quarantine"`` to its module, the accounts
unit passes ``quarantine_ou_id`` from the dependency, and its first plan, before
the organization unit has applied, gets a placeholder id so a quarantined
account resolves.

Staging, the stand-in ``aws`` and the render come from
tests/test_regression_org_apply_paths.py. No credentials, no AWS call.
"""

import re

from test_regression_org_apply_paths import _render, _rewrite, _stage
from test_regression_org_apply_paths import pytestmark as needs_terragrunt

pytestmark = needs_terragrunt

OU_ID_RE = re.compile(r"^ou-[a-z0-9]+-[a-z0-9]+$")


def test_regression_organization_unit_names_the_quarantine_ou(tmp_path):
    root, env, _ = _stage(tmp_path)
    inputs = _render(root, "stacks/management/organization", env)["inputs"]
    assert inputs["enable_quarantine_scp"] is True
    assert inputs["quarantine_ou_name"] == "Quarantine", inputs.get("quarantine_ou_name")
    assert inputs["quarantine_ou_name"] in {ou["name"] for ou in inputs["organizational_units"]}, (
        "the example must declare the OU it names in quarantine_ou_name"
    )


def test_regression_accounts_unit_reads_the_quarantine_ou_from_the_dependency(tmp_path):
    root, env, _ = _stage(tmp_path)
    unit = "stacks/management/accounts"
    text = (root / unit / "terragrunt.hcl").read_text()
    assert re.search(r"^\s*quarantine_ou_id\s*=\s*dependency\.organization\.outputs\.quarantine_ou_id\s*$", text, re.M), (
        "the accounts unit must take quarantine_ou_id from the organization unit"
    )
    rendered = _render(root, unit, env)
    mock = rendered["dependency"]["organization"]["mock_outputs"]
    assert OU_ID_RE.match(mock["quarantine_ou_id"]), (
        "with quarantine_ou_name set the first plan needs a placeholder id, got %r" % mock.get("quarantine_ou_id")
    )
    assert rendered["inputs"]["quarantine_ou_id"] == mock["quarantine_ou_id"]
    # Without a quarantine OU the mock stays empty, so the module refuses a
    # quarantined account instead of planning it into a placeholder.
    _rewrite(root / "env/common.hcl", '  quarantine_ou_name            = "Quarantine"\n', "")
    rendered = _render(root, unit, env)
    assert rendered["inputs"]["quarantine_ou_id"] == "", rendered["inputs"]["quarantine_ou_id"]
