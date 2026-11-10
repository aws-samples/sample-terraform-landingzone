"""regression: two clones sharing one local state directory are refused.

Two clones of this repository on one machine, both with ``state_backend =
"local"`` and the same state directory -- the per-user default ``~/.tlz-state``,
or one ``TLZ_STATE_DIR`` exported for both -- read and write the SAME per-unit
state files: the second deployment plans against the first one's state.
``stacks/root.hcl`` therefore binds a state directory to one clone (marker
file, fail closed, no migration):

  * the first run in a state directory writes ``<state_dir>/.tlz-clone``
    carrying the clone's absolute repository path (``get_repo_root()``);
  * every later run compares that path with its own; a single clone never
    notices, an explicit ``TLZ_STATE_DIR`` is honoured (the marker lives
    wherever the state directory resolves);
  * a DIFFERENT clone is refused at Terragrunt config time -- before any
    backend is initialised -- with one message naming both clone paths and
    the two remedies: ``export TLZ_STATE_DIR=<dir>`` for this clone, or
    remove ``<state_dir>/.tlz-clone`` if the old clone is gone;
  * a non-local backend writes no marker and never refuses.

How it is measured: the tracked tree is staged under ``tmp_path`` (twice for
the two-clones cases), an env/common.hcl is written from env/common.hcl.example
with the chosen backend, a stand-in ``aws`` first on PATH answers
ParameterNotFound (nothing reaches AWS), HOME points into ``tmp_path`` so that
no run can touch the real ``~/.tlz-state``, and ``terragrunt render`` of the
organization unit (includes root.hcl, no dependency blocks) is the verdict.
Without ``terragrunt`` on PATH the test skips and says so.
"""

import os
import re
import shutil
import subprocess  # nosec B404 -- the suite drives git/terragrunt/bash with argv lists, never a shell
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
UNIT = "stacks/management/organization"
MARKER = ".tlz-clone"

STANDIN_AWS = (
    "#!/usr/bin/env bash\n"
    "echo 'An error occurred (ParameterNotFound) when calling the GetParameter operation: stand-in'\n"
    "exit 254\n"
)

pytestmark = pytest.mark.skipif(
    shutil.which("terragrunt") is None,
    reason="terragrunt not on PATH: the state clone guard is measured by terragrunt render",
)


def _tracked_files():
    out = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(REPO), "ls-files", "-z"],
        check=True, capture_output=True,
    ).stdout.decode()
    return [p for p in out.split("\0") if p]


def _sub_one(pattern, repl, text):
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    assert n == 1, "env/common.hcl.example has no line matching %r" % pattern
    return new


def _stage_clone(tmp_path, name, backend):
    """One staged copy of the tracked tree -- one clone -- with env/common.hcl set to `backend`."""
    root = tmp_path / name
    for rel in _tracked_files():
        src = REPO / rel
        if not src.is_file():
            continue
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    common = (root / "env/common.hcl.example").read_text()
    common = _sub_one(r'^(\s*state_backend\s*=\s*)"local"', r'\g<1>"%s"' % backend, common)
    (root / "env/common.hcl").write_text(common)
    shutil.copy2(root / "env/accounts.hcl.example", root / "env/accounts.hcl")
    subprocess.run(["git", "init", "-q", str(root)], check=True)  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
    return root


def _env(tmp_path, state_dir):
    """The environment of a run: stand-in aws, HOME inside tmp_path, TLZ_STATE_DIR when given.

    HOME is redirected on every run, so the default state directory of a run
    without TLZ_STATE_DIR is <tmp_path>/home/.tlz-state and never the
    developer's real one.
    """
    bin_dir = tmp_path / "bin"
    if not bin_dir.exists():
        bin_dir.mkdir()
        aws = bin_dir / "aws"
        aws.write_text(STANDIN_AWS)
        aws.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = "%s%s%s" % (bin_dir, os.pathsep, env.get("PATH", ""))
    env["HOME"] = str(home)
    env.pop("TLZ_STATE_DIR", None)
    if state_dir is not None:
        env["TLZ_STATE_DIR"] = str(state_dir)
    env["TG_NON_INTERACTIVE"] = "true"
    env["TG_NO_COLOR"] = "true"
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(var, None)
    return env


def _toplevel(root):
    """What get_repo_root() answers for a clone: git's resolved top-level path."""
    return subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _render(root, env):
    return subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
        ["terragrunt", "render", "--json", "--log-level", "error"],
        cwd=root / UNIT, env=env, capture_output=True, text=True, timeout=300,
    )


def _render_ok(root, env):
    proc = _render(root, env)
    assert proc.returncode == 0, "terragrunt render failed (rc=%d):\n%s" % (
        proc.returncode, proc.stderr[-3000:],
    )
    return proc


def _marker(state_dir):
    return Path(state_dir) / MARKER


def test_first_run_writes_the_marker_with_the_clone_path(tmp_path):
    state_dir = tmp_path / "state"
    root = _stage_clone(tmp_path, "clone-a", "local")
    assert not state_dir.exists()

    _render_ok(root, _env(tmp_path, state_dir))

    marker = _marker(state_dir)
    assert marker.is_file(), "the first run left no %s in the state directory" % marker
    recorded = marker.read_text().strip()
    assert os.path.isabs(recorded), "the marker does not carry an absolute path: %r" % recorded
    assert recorded == _toplevel(root), (
        "the marker names %r, the clone's repository root is %r" % (recorded, _toplevel(root))
    )


def test_the_same_clone_renders_again_and_the_marker_stays(tmp_path):
    state_dir = tmp_path / "state"
    root = _stage_clone(tmp_path, "clone-a", "local")
    env = _env(tmp_path, state_dir)

    _render_ok(root, env)
    before = _marker(state_dir).read_text()
    _render_ok(root, env)
    _render_ok(root, env)

    assert _marker(state_dir).read_text() == before, "a repeated run of the same clone rewrote the marker"
    assert before.strip() == _toplevel(root)


def test_the_default_directory_gets_the_marker_when_tlz_state_dir_is_unset(tmp_path):
    """No TLZ_STATE_DIR: the marker lands in $HOME/.tlz-state, the per-user default that two clones share."""
    root = _stage_clone(tmp_path, "clone-a", "local")
    env = _env(tmp_path, None)

    _render_ok(root, env)

    marker = _marker(Path(env["HOME"]) / ".tlz-state")
    assert marker.is_file(), "the default state directory got no %s" % marker
    assert marker.read_text().strip() == _toplevel(root)


def test_a_second_clone_in_the_same_state_directory_is_refused(tmp_path):
    state_dir = tmp_path / "state"
    root_a = _stage_clone(tmp_path, "clone-a", "local")
    root_b = _stage_clone(tmp_path, "clone-b", "local")
    env = _env(tmp_path, state_dir)

    _render_ok(root_a, env)
    proc = _render(root_b, env)

    assert proc.returncode != 0, (
        "a second clone rendered against a state directory that belongs to %s: both "
        "deployments would read and write the same per-unit state files" % _toplevel(root_a)
    )
    msg = " ".join(proc.stderr.split())
    for needle in (
        _toplevel(root_a),            # the clone the directory belongs to
        _toplevel(root_b),            # this clone
        str(_marker(state_dir)),      # the marker, and remedy 2: remove it if the old clone is gone
        "TLZ_STATE_DIR",              # remedy 1: a directory of its own for this clone
    ):
        assert needle in msg, "the refusal does not name %r:\n%s" % (needle, proc.stderr[-3000:])
    assert _marker(state_dir).read_text().strip() == _toplevel(root_a), (
        "the refused clone overwrote the marker"
    )
    # The first clone is untouched by the refusal of the second.
    _render_ok(root_a, env)


def test_an_explicit_tlz_state_dir_gives_the_second_clone_its_own_directory(tmp_path):
    """Remedy 1: TLZ_STATE_DIR per clone -- each directory is bound to its own clone."""
    shared = tmp_path / "state"
    own = tmp_path / "own" / "state-b"
    root_a = _stage_clone(tmp_path, "clone-a", "local")
    root_b = _stage_clone(tmp_path, "clone-b", "local")

    _render_ok(root_a, _env(tmp_path, shared))
    assert _render(root_b, _env(tmp_path, shared)).returncode != 0
    _render_ok(root_b, _env(tmp_path, own))

    assert _marker(own).read_text().strip() == _toplevel(root_b)
    assert _marker(shared).read_text().strip() == _toplevel(root_a)
    assert not (Path(_env(tmp_path, own)["HOME"]) / ".tlz-state").exists(), (
        "an explicit TLZ_STATE_DIR was set, yet the default directory was touched"
    )


def test_removing_the_marker_hands_the_directory_to_the_next_clone(tmp_path):
    """Remedy 2: the old clone is gone -- remove the marker, the next run binds the directory anew."""
    state_dir = tmp_path / "state"
    root_a = _stage_clone(tmp_path, "clone-a", "local")
    root_b = _stage_clone(tmp_path, "clone-b", "local")
    env = _env(tmp_path, state_dir)

    _render_ok(root_a, env)
    assert _render(root_b, env).returncode != 0
    _marker(state_dir).unlink()

    _render_ok(root_b, env)
    assert _marker(state_dir).read_text().strip() == _toplevel(root_b)


def test_s3_backend_writes_no_marker_and_never_refuses(tmp_path):
    state_dir = tmp_path / "state"
    root_a = _stage_clone(tmp_path, "clone-a", "s3")
    root_b = _stage_clone(tmp_path, "clone-b", "s3")
    env = _env(tmp_path, state_dir)

    _render_ok(root_a, env)
    _render_ok(root_b, env)
    _render_ok(root_a, env)

    assert not _marker(state_dir).exists(), "a non-local backend wrote a clone marker"
    assert not state_dir.exists(), "a non-local backend created the local state directory"
    assert not (Path(env["HOME"]) / ".tlz-state").exists()


NOT_REGULAR = "is not a regular file"


def _release_fifo_readers(fifo):
    """Give any guard still blocked reading `fifo` an EOF, so a hang does not outlive the test."""
    for _ in range(64):
        try:
            fd = os.open(str(fifo), os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            return  # ENXIO: no reader left (or the FIFO is gone)
        os.close(fd)


def test_a_directory_at_the_marker_path_is_refused_with_the_guards_message(tmp_path):
    """regression: a FIFO or directory at <state_dir>/.tlz-clone hangs or crashes the clone guard instead of a bounded refusal.

    A directory passes `-r`, the read fails, and `set -u` must not end the
    guard with `recorded: unbound variable` instead of its own refusal.
    """
    state_dir = tmp_path / "state"
    _marker(state_dir).mkdir(parents=True)
    root = _stage_clone(tmp_path, "clone-a", "local")

    proc = _render(root, _env(tmp_path, state_dir))

    assert proc.returncode != 0, "a directory at %s rendered as if it were a marker" % _marker(state_dir)
    msg = " ".join(proc.stderr.split())
    assert NOT_REGULAR in msg, "the refusal does not carry the guard's message:\n%s" % proc.stderr[-3000:]
    assert str(_marker(state_dir)) in msg, "the refusal does not name the marker path:\n%s" % proc.stderr[-3000:]
    assert _marker(state_dir).is_dir(), "the guard replaced the directory it should have refused"


def test_a_fifo_at_the_marker_path_is_refused_within_a_bounded_time(tmp_path):
    """regression: a FIFO or directory at <state_dir>/.tlz-clone hangs or crashes the clone guard instead of a bounded refusal.

    A FIFO with no writer passes `-r`, and a blocking read would hang every
    Terragrunt parse of every unit with no diagnostic.
    """
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    fifo = _marker(state_dir)
    os.mkfifo(str(fifo))
    root = _stage_clone(tmp_path, "clone-a", "local")

    try:
        proc = subprocess.run(  # nosec B603 B607 -- argv list of this repository's paths and literals, no shell
            ["terragrunt", "render", "--json", "--log-level", "error"],
            cwd=root / UNIT, env=_env(tmp_path, state_dir),
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            "terragrunt render hung for 60 s with a FIFO at %s: the clone guard blocks "
            "reading it instead of refusing" % fifo
        )
    finally:
        _release_fifo_readers(fifo)

    assert proc.returncode != 0, "a FIFO at %s rendered as if it were a marker" % fifo
    msg = " ".join(proc.stderr.split())
    assert NOT_REGULAR in msg, "the refusal does not carry the guard's message:\n%s" % proc.stderr[-3000:]
    assert str(fifo) in msg, "the refusal does not name the marker path:\n%s" % proc.stderr[-3000:]


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="running as root: `-r` is true for a mode 0o000 file, the unreadable refusal cannot be observed",
)
def test_an_unreadable_regular_marker_is_refused(tmp_path):
    """regression: a FIFO or directory at <state_dir>/.tlz-clone hangs or crashes the clone guard instead of a bounded refusal.

    Pins the refusal that already held: a plain marker that cannot be read.
    """
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    marker = _marker(state_dir)
    marker.write_text("/somewhere/else\n")
    marker.chmod(0o000)
    root = _stage_clone(tmp_path, "clone-a", "local")

    try:
        proc = _render(root, _env(tmp_path, state_dir))
    finally:
        marker.chmod(0o600)

    assert proc.returncode != 0, "an unreadable marker at %s rendered" % marker
    msg = " ".join(proc.stderr.split())
    assert "cannot be read" in msg, "the refusal does not carry the guard's message:\n%s" % proc.stderr[-3000:]
