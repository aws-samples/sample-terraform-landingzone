"""regression: the Security Hub automation rule resource exists twice and must not drift.

modules/security (management account) and modules/security-org-config (Audit
account, the delegated administrator) both declare
``aws_securityhub_automation_rule.this`` from the same ``security_hub_automation_rules``
input: the management module keeps the rules while the finding consumers stay
there, the administrator module carries them once they move. A field added to
one copy and not the other would make the same configuration deploy different
rules depending on where the consumers run. This pins the two resource blocks
to byte-identical text.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FILES = (
    REPO / "modules/security/securityhub.tf",
    REPO / "modules/security-org-config/consumers.tf",
)
HEADER = 'resource "aws_securityhub_automation_rule" "this" {'


def _block(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line == HEADER]
    assert len(starts) == 1, "%s: expected one %r, found %d" % (path.relative_to(REPO), HEADER, len(starts))
    start = starts[0]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start : end + 1])


def test_automation_rule_blocks_are_identical():
    blocks = {p.relative_to(REPO).as_posix(): _block(p) for p in FILES}
    (first, first_text), (second, second_text) = blocks.items()
    assert first_text.count("\n") > 300, "%s: the rule block is shorter than the full criteria set" % first
    assert first_text == second_text, (
        "the aws_securityhub_automation_rule.this blocks of %s and %s differ; "
        "change both copies or the same rules deploy differently per account" % (first, second)
    )
