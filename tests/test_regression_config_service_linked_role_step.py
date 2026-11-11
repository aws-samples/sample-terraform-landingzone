"""regression: the AWS Config recorders reference the service-linked role
AWSServiceRoleForConfig and no module creates it, while one comment claimed
the recorder creates it and the getting-started guide had no step for it.

The guide must name the step before the recorders are applied, and no text
may claim that the role appears by itself.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_regression_guide_creates_the_config_service_linked_role():
    guide = (REPO / "docs/getting-started.md").read_text(encoding="utf-8")
    step = guide.find("create-service-linked-role --aws-service-name config.")
    assert step >= 0, "docs/getting-started.md must name the create-service-linked-role step for AWS Config"
    assert step < guide.find("# Pass 2:"), "the step must come before Pass 2, which applies the member recorders"


def test_regression_no_text_claims_the_role_appears_by_itself():
    recorder = (REPO / "modules/logging/config-recorder.tf").read_text(encoding="utf-8")
    readme = (REPO / "modules/config-recorder-member/README.md").read_text(encoding="utf-8")
    assert "creates it automatically" not in recorder
    assert "carry it" not in readme
