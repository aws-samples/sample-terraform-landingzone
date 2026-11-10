"""regression: the setting deployment_account_email was documented but never read.

No stack and not the configuration loader read it, so a reader who set it
changed nothing. The deployment account is declared as an ``accounts`` entry
and its ID recorded in env/accounts.hcl. This test keeps the setting out of
the code, the examples and the reference documentation.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ROOTS = ("modules", "stacks", "configurations", "env", "docs", "customizations")
PATTERNS = ("*.hcl", "*.tf", "*.example", "*.md", "*.tfvars", "*.json")


def test_deployment_account_email_is_not_documented_or_read():
    files = [REPO / "README.md"] + [
        path for root in ROOTS for pattern in PATTERNS for path in (REPO / root).rglob(pattern)
        if ".terraform" not in path.parts
    ]
    hits = [
        str(path.relative_to(REPO))
        for path in files
        if "deployment_account_email" in path.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not hits, hits
