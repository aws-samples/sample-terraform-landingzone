"""regression: rows of the reference tables shipped with an empty description.

docs/configuration-reference.md and the module READMEs list every setting in
tables with a ``Description`` column. Rows with an empty cell there left the
reader with a name and a default only. This test finds every table whose
header row has a ``Description`` column, in docs/configuration-reference.md
and in every modules/*/README.md, and fails on a data row whose description
cell is empty or only a dash.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FILES = [REPO / "docs/configuration-reference.md", *sorted(REPO.glob("modules/*/README.md"))]
PLACEHOLDERS = {"", "-", "—", "–"}
SEPARATOR = re.compile(r"^\|[\s:|-]+\|$")


def _cells(line):
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def _description_rows(path):
    """(line number, first cell, description cell) of every data row of a Description table."""
    column = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.lstrip().startswith("|"):
            column = None
        elif column is None:
            header = [c.lower() for c in _cells(line)]
            column = next((i for i, h in enumerate(header) if "description" in h), -1)
        elif column >= 0 and not SEPARATOR.match(line.strip()):
            cells = _cells(line)
            yield number, cells[0], cells[column] if column < len(cells) else ""


def test_every_reference_row_has_a_description():
    rows = [(p, *r) for p in FILES for r in _description_rows(p)]
    # The tables must be found at all, or the test would pass on nothing.
    assert len(rows) > 500, f"only {len(rows)} description rows found"
    empty = [
        f"{p.relative_to(REPO)}:{n}: {name}" for p, n, name, desc in rows if desc in PLACEHOLDERS
    ]
    assert not empty, "rows without a description:\n" + "\n".join(empty)
