"""Unit tests for scripts/lfsNameQuery.py

Covers force_remove, branch_has_lfsconfig, clone_repo_skip_lfs,
get_all_branches_lfs_mapping and main. External `git` invocations are
mocked via subprocess.run patching, so these tests do not require a
real git binary.
"""
import os
import stat
import subprocess
import sys
from unittest import mock

import pytest

# Ensure the script is importable regardless of the CWD pytest runs from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import lfsNameQuery  # noqa: E402


@pytest.fixture(autouse=True)
def _ensure_git_bin(monkeypatch):
    """Guarantee GIT_BIN is set even when the CI runner has no git binary."""
    if not lfsNameQuery.GIT_BIN:
        monkeypatch.setattr(lfsNameQuery, "GIT_BIN", "/usr/bin/git")


# ---------- force_remove ----------

class TestForceRemove:
    def test_missing_path_is_noop(self, tmp_path):
        missing = tmp_path / "does-not-exist"
        lfsNameQuery.force_remove(str(missing))  # no exception

    def test_file_removed(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello", encoding="utf-8")
        lfsNameQuery.force_remove(str(f))
        assert not f.exists()

    def test_dir_removed_with_nested_content(self, tmp_path):
        d = tmp_path / "sub"
        d.mkdir()
        (d / "inner.txt").write_text("x", encoding="utf-8")
        lfsNameQuery.force_remove(str(d))
        assert not d.exists()

    def test_readonly_file_removed(self, tmp_path):
        f = tmp_path / "ro.txt"
        f.write_text("hello", encoding="utf-8")
        os.chmod(str(f), stat.S_IREAD)
        lfsNameQuery.force_remove(str(f))
        assert not f.exists()

    def test_remove_failure_is_swallowed(self, tmp_path):
        # os.remove raises OSError -> force_remove must not propagate
        f = tmp_path / "target.txt"
        f.write_text("x", encoding="utf-8")
        with mock.patch("os.remove", side_effect=OSError("perm")):
            lfsNameQuery.force_remove(str(f))  # no exception

    def test_handle_remove_readonly_callback_recovers(self, tmp_path):
        target = tmp_path / "cb.txt"
        target.write_text("x", encoding="utf-8")
        os.chmod(str(target), stat.S_IREAD)
        # Simulate rmtree onerror callback invocation
        lfsNameQuery._handle_remove_readonly(os.remove, str(target), None)
        assert not target.exists()

    def test_handle_remove_readonly_swallows_oserror(self):
        # chmod raises -> callback should not propagate
        with mock.patch("os.chmod", side_effect=OSError("nope")):
            lfsNameQuery._handle_remove_readonly(os.remove, "/nonexistent", None)


# ---------- branch_has_lfsconfig ----------

class TestBranchHasLfsconfig:
    def test_returns_true_when_lfsconfig_listed(self):
        stub = mock.Mock(stdout=".gitignore\n.lfsconfig\nREADME.md\n")
        with mock.patch("subprocess.run", return_value=stub):
            assert lfsNameQuery.branch_has_lfsconfig("/tmp/repo", "main") is True

    def test_returns_false_when_lfsconfig_missing(self):
        stub = mock.Mock(stdout="README.md\nother\n")
        with mock.patch("subprocess.run", return_value=stub):
            assert lfsNameQuery.branch_has_lfsconfig("/tmp/repo", "main") is False

    def test_returns_false_on_exception(self):
        with mock.patch("subprocess.run", side_effect=RuntimeError("boom")):
            assert lfsNameQuery.branch_has_lfsconfig("/tmp/repo", "main") is False


# ---------- clone_repo_skip_lfs ----------

class TestCloneRepoSkipLfs:
    def test_unsupported_platform_raises(self):
        with pytest.raises(ValueError):
            lfsNameQuery.clone_repo_skip_lfs("bad-platform", "o", "r")

    def test_url_without_credentials(self, tmp_path):
        target = tmp_path / "clone-target"
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            result = lfsNameQuery.clone_repo_skip_lfs(
                "gitee", "owner", "repo", target_dir=str(target)
            )
        assert result == str(target)
        args = run.call_args[0][0]
        assert args[1] == "clone"
        assert args[2] == "https://gitee.com/owner/repo.git"

    def test_url_with_username_and_token(self, tmp_path):
        target = tmp_path / "clone-target"
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            lfsNameQuery.clone_repo_skip_lfs(
                "gitee", "owner", "repo",
                username="alice", token="s3cret", target_dir=str(target),
            )
        url = run.call_args[0][0][2]
        assert "alice" in url
        assert "s3cret" in url
        assert "gitee.com" in url

    def test_url_with_token_only_uses_platform_token_auth(self, tmp_path):
        # gitcode branch: token present, username defaults to gitcode_user
        target = tmp_path / "clone-target"
        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run:
            lfsNameQuery.clone_repo_skip_lfs(
                "gitcode", "owner", "repo", token="tok", target_dir=str(target),
            )
        url = run.call_args[0][0][2]
        assert "gitcode_user" in url
        assert "tok" in url
        assert "gitcode.com" in url

    def test_clone_failure_raises_runtime_error(self, tmp_path):
        err = subprocess.CalledProcessError(1, ["git", "clone"], stderr="denied")
        with mock.patch("subprocess.run", side_effect=err):
            with pytest.raises(RuntimeError) as exc:
                lfsNameQuery.clone_repo_skip_lfs(
                    "gitcode", "owner", "repo", token="bad",
                    target_dir=str(tmp_path / "t"),
                )
        assert "gitcode" in str(exc.value)


# ---------- get_all_branches_lfs_mapping ----------

class TestGetAllBranchesLfsMapping:
    def test_skips_branches_without_lfsconfig(self):
        branches = mock.Mock(stdout="  main\n  dev\n", returncode=0)
        with mock.patch("subprocess.run", return_value=branches), \
             mock.patch.object(lfsNameQuery, "branch_has_lfsconfig", return_value=False):
            mapping = lfsNameQuery.get_all_branches_lfs_mapping("/tmp/repo")
        assert mapping == {}

    def test_collects_lfs_files_from_branch(self):
        branches = mock.Mock(stdout="* main\n", returncode=0)
        checkout = mock.Mock(returncode=0)
        lfs_ls = mock.Mock(
            stdout='{"files":[{"oid":"abc","name":"big.bin","size":123}]}',
            returncode=0,
        )
        with mock.patch("subprocess.run", side_effect=[branches, checkout, lfs_ls]), \
             mock.patch.object(lfsNameQuery, "branch_has_lfsconfig", return_value=True):
            mapping = lfsNameQuery.get_all_branches_lfs_mapping("/tmp/repo")
        assert "abc" in mapping
        assert mapping["abc"]["name"] == "big.bin"
        assert mapping["abc"]["size"] == 123
        assert mapping["abc"]["branches"] == ["main"]

    def test_lfs_command_nonzero_returncode_yields_empty_mapping(self):
        branches = mock.Mock(stdout="* main\n", returncode=0)
        checkout = mock.Mock(returncode=0)
        lfs_fail = mock.Mock(stdout="", returncode=1)
        with mock.patch("subprocess.run", side_effect=[branches, checkout, lfs_fail]), \
             mock.patch.object(lfsNameQuery, "branch_has_lfsconfig", return_value=True):
            mapping = lfsNameQuery.get_all_branches_lfs_mapping("/tmp/repo")
        assert mapping == {}

    def test_wraps_unexpected_exception_as_runtime_error(self):
        with mock.patch("subprocess.run", side_effect=OSError("no git")):
            with pytest.raises(RuntimeError):
                lfsNameQuery.get_all_branches_lfs_mapping("/tmp/repo")


# ---------- main ----------

class TestMain:
    def test_returns_true_on_success(self, tmp_path):
        out = tmp_path / "out.json"
        with mock.patch.object(lfsNameQuery, "clone_repo_skip_lfs", return_value=str(tmp_path)), \
             mock.patch.object(lfsNameQuery, "get_all_branches_lfs_mapping",
                               return_value={"oid": {"name": "f", "size": 1, "branches": ["main"]}}), \
             mock.patch.object(lfsNameQuery, "force_remove"):
            assert lfsNameQuery.main("gitee", "o", "r", output_file=str(out)) is True
        assert out.exists()

    def test_returns_false_on_failure(self, tmp_path):
        with mock.patch.object(lfsNameQuery, "clone_repo_skip_lfs",
                               side_effect=RuntimeError("nope")), \
             mock.patch.object(lfsNameQuery, "force_remove"):
            assert lfsNameQuery.main(
                "gitee", "o", "r", output_file=str(tmp_path / "out.json"),
            ) is False

    def test_gitcode_without_token_warns_but_continues(self, tmp_path, capsys):
        with mock.patch.object(lfsNameQuery, "clone_repo_skip_lfs", return_value=str(tmp_path)), \
             mock.patch.object(lfsNameQuery, "get_all_branches_lfs_mapping", return_value={}), \
             mock.patch.object(lfsNameQuery, "force_remove"):
            assert lfsNameQuery.main(
                "gitcode", "o", "r", output_file=str(tmp_path / "out.json"),
            ) is True
        assert "GitCode" in capsys.readouterr().out
